#!/usr/bin/env python3
"""Build immutable Lambda and web artifacts for a Kenning deployment.

The script deliberately does not deploy anything. The resulting files can be
uploaded by CI, tested in development, and later promoted without rebuilding.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from release_manifest import SHA_RE, sha256_file
from release_identity import release_identity as build_release_identity


ROOT = Path(__file__).resolve().parent.parent
SITE_ROOT = ROOT / "portal"
LAMBDA_MODULES = (
    "guard.py",
    "proof.py",
    "capture.py",
    "citation.py",
    "identity.py",
    "policy.py",
    "policy_bundle.py",
    "audit.py",
    "audit_delivery.py",
    "federation.py",
    "metrics.py",
    "model_registry.py",
    "governance.py",
    "aws_adapter.py",
    "integration_adapters.py",
    "starter_rules.py",
    "tenant.py",
    "workload_identity.py",
    "control_plane.py",
    "report.py",
    "store.py",
    "auth.py",
    "lambda_function.py",
)


def _zip_files(output: Path, source_dir: Path, names: tuple[str, ...]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in names:
            source = source_dir / name
            if not source.is_file():
                raise FileNotFoundError(f"required release source is missing: {source}")
            info = zipfile.ZipInfo(name)
            info.date_time = (2020, 1, 1, 0, 0, 0)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, source.read_bytes())


def _tar_directory(output: Path, source_dir: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output, "w:gz", compresslevel=9) as archive:
        for path in sorted(source_dir.rglob("*")):
            relative = path.relative_to(source_dir)
            info = archive.gettarinfo(str(path), arcname=str(relative))
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = 0
            if path.is_file():
                with path.open("rb") as handle:
                    archive.addfile(info, handle)
            else:
                archive.addfile(info)


def _build_web(
    output_dir: Path,
    web_api_url: str,
    deployment_environment: str = "development",
    identity: dict[str, object] | None = None,
) -> Path:
    web_dir = output_dir / "web"
    if web_dir.exists():
        shutil.rmtree(web_dir)
    with tempfile.TemporaryDirectory(prefix="kenning-web-build-") as temp_dir:
        built_dir = Path(temp_dir) / "dist"
        environment = os.environ.copy()
        environment["VITE_KENNING_API_URL"] = web_api_url
        environment["VITE_KENNING_DEPLOYMENT_ENVIRONMENT"] = deployment_environment
        if identity:
            environment["VITE_KENNING_RELEASE_ID"] = str(identity["release_id"])
            environment["VITE_KENNING_RELEASE_NAME"] = str(identity["release_name"])
            environment["VITE_KENNING_RELEASE_VERSION"] = str(identity["release_version"])
        subprocess.run(
            [
                "npm",
                "--prefix",
                str(SITE_ROOT),
                "run",
                "build",
                "--",
                "--outDir",
                str(built_dir),
            ],
            check=True,
            cwd=ROOT,
            env=environment,
        )
        subprocess.run(
            [str(ROOT / "scripts" / "prepare_portal_dist.sh"), str(built_dir)],
            check=True,
            cwd=ROOT,
        )
        shutil.copytree(built_dir, web_dir)
    return web_dir


def build_artifacts(
    output_dir: Path,
    environment: str,
    source_commit: str,
    web_api_url: str,
    release_id: str,
    release_version: str | None = None,
    release_sequence: int | None = None,
) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    lambda_artifact = output_dir / "lambda.zip"
    fetcher_artifact = output_dir / "citation-fetcher.zip"
    if release_sequence is None:
        trailing_number = "".join(character for character in release_id[::-1] if character.isdigit())[::-1]
        release_sequence = int(trailing_number) if trailing_number else 1
    identity = build_release_identity(
        release_id=release_id,
        sequence=release_sequence,
        release_version=release_version,
    )
    (output_dir / "release-identity.json").write_text(
        json.dumps(identity, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    web_dir = _build_web(output_dir, web_api_url, deployment_environment=environment, identity=identity)
    (web_dir / "release.json").write_text(json.dumps(identity, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    web_artifact = output_dir / "web.tar.gz"

    _zip_files(lambda_artifact, ROOT / "app", LAMBDA_MODULES)
    _zip_files(fetcher_artifact, ROOT / "app", ("citation_fetcher.mjs",))
    _tar_directory(web_artifact, web_dir)

    artifacts = {
        "lambda": {"path": lambda_artifact.name, "sha256": sha256_file(lambda_artifact)},
        "citation_fetcher": {"path": fetcher_artifact.name, "sha256": sha256_file(fetcher_artifact)},
        "web": {"path": web_artifact.name, "sha256": sha256_file(web_artifact)},
    }
    metadata = {
        "schema_version": 1,
        "release_id": release_id,
        "environment": environment,
        "source_commit": source_commit,
        "web_api_url": web_api_url,
        "release_identity": identity,
        "artifacts": artifacts,
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    (output_dir / "artifact-metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    (output_dir / "checksums.txt").write_text(
        "\n".join(f"{value['sha256']}  {value['path']}" for value in artifacts.values()) + "\n"
    )
    return metadata


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--environment", default="development")
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--release-version")
    parser.add_argument("--release-sequence", type=int)
    parser.add_argument(
        "--web-api-url",
        required=True,
        help="Value compiled into the web application, usually same-origin or a development API URL.",
    )
    args = parser.parse_args()
    if args.environment != "development":
        parser.error("this build entry point is development-only; production promotion must reuse its output")
    if not SHA_RE.fullmatch(args.source_commit or ""):
        parser.error("--source-commit must be a full lowercase 40-character Git SHA")
    if not args.release_id:
        parser.error("--release-id is required")
    build_artifacts(
        args.output_dir,
        args.environment,
        args.source_commit,
        args.web_api_url,
        args.release_id,
        release_version=args.release_version,
        release_sequence=args.release_sequence,
    )
    print(f"Built development release artifacts in {args.output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
