#!/usr/bin/env python3
"""Create and validate release manifests used by the promotion workflows."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:
    from release_identity import validate_release_identity
except ModuleNotFoundError:  # pragma: no cover - used when imported as scripts.release_manifest
    from scripts.release_identity import validate_release_identity


REQUIRED_CHECKS = (
    "unit-and-contract",
    "prd-traceability",
    "performance-guard",
    "openapi-contract",
    "web-build",
    "release-identity",
    "development-deployed-api-mcp",
    "development-deployed-browser",
    "development-smoke",
)
REQUIRED_PRODUCTION_CHECKS = (
    "production-identity",
    "production-deployed-api-mcp",
    "production-smoke",
    "production-browser",
    "production-operational",
)
REQUIRED_ROLLBACK_CHECKS = (
    "rollback-identity",
    "rollback-deployed-api-mcp",
    "rollback-smoke",
    "rollback-browser",
    "rollback-operational",
)
MAX_CANDIDATE_AGE_HOURS = 24
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ISO_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
FORBIDDEN_KEY_PARTS = ("secret", "password", "private_key", "pat_value", "credential_value")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not ISO_TIMESTAMP_RE.fullmatch(value):
        raise ValueError(f"{field} must be an RFC3339 UTC timestamp")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field} must be an RFC3339 UTC timestamp") from error


def _normalise_check_records(checks: list[dict[str, Any]], completed_at: str) -> list[dict[str, Any]]:
    normalised: list[dict[str, Any]] = []
    for check in checks:
        record = dict(check)
        record.setdefault("completed_at", completed_at)
        normalised.append(record)
    return normalised


def _assert_no_secret_keys(value: Any, path: str = "manifest") -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            lowered = str(key).lower()
            if any(part in lowered for part in FORBIDDEN_KEY_PARTS):
                raise ValueError(f"manifest contains forbidden credential field: {path}.{key}")
            _assert_no_secret_keys(nested, f"{path}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _assert_no_secret_keys(nested, f"{path}[{index}]")


def _artifact_records(artifact_root: Path) -> dict[str, dict[str, str]]:
    names = {
        "lambda": "lambda.zip",
        "citation_fetcher": "citation-fetcher.zip",
        "web": "web.tar.gz",
    }
    records = {}
    for key, name in names.items():
        path = artifact_root / name
        if not path.is_file():
            raise ValueError(f"required artifact is missing: {path}")
        records[key] = {"path": name, "sha256": sha256_file(path)}
    return records


def validate_artifact_metadata(
    metadata: dict[str, Any],
    *,
    artifact_root: Path,
    expected_environment: str = "development",
    expected_source_commit: str | None = None,
    expected_release_id: str | None = None,
) -> None:
    _assert_no_secret_keys(metadata)
    if metadata.get("schema_version") != 1:
        raise ValueError("unsupported artifact metadata schema")
    if metadata.get("environment") != expected_environment:
        raise ValueError(f"artifact environment must be {expected_environment}")
    if expected_release_id is not None and metadata.get("release_id") != expected_release_id:
        raise ValueError("artifact release_id does not match the expected release")
    source_commit = metadata.get("source_commit")
    if not isinstance(source_commit, str) or not SHA_RE.fullmatch(source_commit):
        raise ValueError("artifact source_commit must be a full lowercase 40-character Git SHA")
    if expected_source_commit is not None and source_commit != expected_source_commit:
        raise ValueError("artifact source_commit does not match the expected commit")
    release_identity = metadata.get("release_identity")
    if release_identity is not None:
        if not isinstance(release_identity, dict):
            raise ValueError("artifact release_identity must be an object")
        validate_release_identity(release_identity, expected_release_id=metadata.get("release_id"))
    artifacts = metadata.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ValueError("artifact metadata is missing artifacts")
    for key in ("lambda", "citation_fetcher", "web"):
        record = artifacts.get(key)
        if not isinstance(record, dict) or not record.get("path"):
            raise ValueError(f"artifact metadata is missing: {key}")
        relative_path = record["path"]
        if not isinstance(relative_path, str) or not re.fullmatch(r"[a-z0-9._-]+", relative_path):
            raise ValueError(f"invalid artifact metadata path: {key}")
        expected_digest = record.get("sha256")
        if not isinstance(expected_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
            raise ValueError(f"invalid artifact metadata digest: {key}")
        artifact_path = artifact_root / relative_path
        if not artifact_path.is_file():
            raise ValueError(f"artifact metadata file is missing: {artifact_path}")
        if sha256_file(artifact_path) != expected_digest:
            raise ValueError(f"artifact metadata digest mismatch: {key}")


def build_manifest(
    *,
    release_id: str,
    source_commit: str,
    environment: str,
    artifact_root: Path,
    checks: list[dict[str, Any]],
    deployment_id: str,
    deployed_at: str | None = None,
    workflow_run_id: str | None = None,
    repository: str | None = None,
    source_ref: str | None = None,
    ticket_refs: list[str] | None = None,
    pull_request_refs: list[str] | None = None,
    change_summary: str | None = None,
    known_limitations: str | None = None,
    created_by: str | None = None,
    rollback_target: str | None = None,
) -> dict[str, Any]:
    checks_completed_at = _now()
    manifest = {
        "schema_version": 1,
        "status": "release_candidate",
        "release_id": release_id,
        "source_commit": source_commit,
        "environment": environment,
        "artifacts": _artifact_records(artifact_root),
        "development": {
            "deployment_id": deployment_id,
            "deployed_at": deployed_at or _now(),
            "verification": "passed",
        },
        "checks": _normalise_check_records(checks, checks_completed_at),
        "checks_completed_at": checks_completed_at,
        "release_context": {
            "repository": repository or "local",
            "source_ref": source_ref or source_commit,
            "workflow_run_id": workflow_run_id or "local",
            "ticket_refs": ticket_refs or [],
            "pull_request_refs": pull_request_refs or [],
            "change_summary": change_summary or "local test manifest",
            "known_limitations": known_limitations or "None recorded",
            "created_by": created_by or "local",
        },
        "created_at": _now(),
        "rollback_target": rollback_target,
    }
    identity_path = artifact_root / "release-identity.json"
    if identity_path.is_file():
        release_identity = json.loads(identity_path.read_text(encoding="utf-8"))
        if not isinstance(release_identity, dict):
            raise ValueError("release identity must be an object")
        validate_release_identity(release_identity, expected_release_id=release_id)
        manifest["release_identity"] = release_identity
    validate_manifest(manifest, artifact_root=artifact_root, expected_environment="development")
    return manifest


def validate_manifest(
    manifest: dict[str, Any],
    *,
    artifact_root: Path | None = None,
    expected_environment: str = "development",
    expected_source_commit: str | None = None,
    max_age_hours: float | None = None,
) -> None:
    _assert_no_secret_keys(manifest)
    required_fields = (
        "schema_version",
        "status",
        "release_id",
        "source_commit",
        "environment",
        "artifacts",
        "development",
        "checks",
        "checks_completed_at",
        "release_context",
        "created_at",
        "rollback_target",
    )
    missing = [field for field in required_fields if field not in manifest]
    if missing:
        raise ValueError(f"manifest is missing required fields: {', '.join(missing)}")
    if manifest["schema_version"] != 1:
        raise ValueError("unsupported release manifest schema")
    if manifest["status"] != "release_candidate":
        raise ValueError("manifest is not a release candidate")
    if manifest["environment"] != expected_environment:
        raise ValueError(f"manifest environment must be {expected_environment}")
    source_commit = manifest["source_commit"]
    if not isinstance(source_commit, str) or not SHA_RE.fullmatch(source_commit):
        raise ValueError("manifest source_commit must be a full lowercase 40-character Git SHA")
    if expected_source_commit is not None and source_commit != expected_source_commit:
        raise ValueError("manifest source_commit does not match the expected commit")
    if not isinstance(manifest["release_id"], str) or not manifest["release_id"]:
        raise ValueError("manifest release_id is required")
    release_identity = manifest.get("release_identity")
    if release_identity is not None:
        if not isinstance(release_identity, dict):
            raise ValueError("manifest release_identity must be an object")
        validate_release_identity(release_identity, expected_release_id=manifest["release_id"])

    development = manifest["development"]
    if not isinstance(development, dict) or not development.get("deployment_id"):
        raise ValueError("development deployment_id is required")
    if development.get("verification") != "passed":
        raise ValueError("development verification must be passed")
    _parse_timestamp(development.get("deployed_at"), "development.deployed_at")
    _parse_timestamp(manifest.get("checks_completed_at"), "checks_completed_at")
    _parse_timestamp(manifest.get("created_at"), "created_at")

    context = manifest["release_context"]
    if not isinstance(context, dict):
        raise ValueError("release_context must be an object")
    for key in ("repository", "source_ref", "workflow_run_id", "created_by"):
        if not isinstance(context.get(key), str) or not context[key]:
            raise ValueError(f"release_context.{key} is required")
    for key in ("change_summary", "known_limitations"):
        if not isinstance(context.get(key), str) or not context[key].strip():
            raise ValueError(f"release_context.{key} is required")
    for key in ("ticket_refs", "pull_request_refs"):
        if not isinstance(context.get(key), list) or not all(isinstance(item, str) and item for item in context[key]):
            raise ValueError(f"release_context.{key} must be a list of non-empty strings")

    checks = manifest["checks"]
    if not isinstance(checks, list):
        raise ValueError("manifest checks must be a list")
    names = []
    for check in checks:
        if not isinstance(check, dict) or not check.get("name"):
            raise ValueError("each manifest check needs a name")
        if not isinstance(check.get("command"), str) or not check["command"]:
            raise ValueError(f"manifest check is missing command: {check.get('name', 'unknown')}")
        if check["name"] in names:
            raise ValueError(f"duplicate manifest check: {check['name']}")
        names.append(check["name"])
        if check.get("result") != "passed":
            raise ValueError(f"required check did not pass: {check['name']}")
        if not check.get("run_id"):
            raise ValueError(f"manifest check is missing run_id: {check['name']}")
        _parse_timestamp(check.get("completed_at"), f"checks[{check['name']}].completed_at")
    missing_checks = [name for name in REQUIRED_CHECKS if name not in names]
    if missing_checks:
        raise ValueError(f"manifest is missing required checks: {', '.join(missing_checks)}")

    artifacts = manifest["artifacts"]
    for key in ("lambda", "citation_fetcher", "web"):
        record = artifacts.get(key) if isinstance(artifacts, dict) else None
        if not isinstance(record, dict) or not record.get("path") or not re.fullmatch(r"[a-z0-9._-]+", record["path"]):
            raise ValueError(f"invalid artifact record: {key}")
        if not re.fullmatch(r"[0-9a-f]{64}", str(record.get("sha256", ""))):
            raise ValueError(f"invalid artifact digest: {key}")
        if artifact_root is not None:
            artifact_path = artifact_root / record["path"]
            if not artifact_path.is_file():
                raise ValueError(f"manifest artifact is missing: {artifact_path}")
            if sha256_file(artifact_path) != record["sha256"]:
                raise ValueError(f"artifact digest mismatch: {key}")

    if max_age_hours is not None:
        ensure_candidate_fresh(manifest, max_age_hours=max_age_hours)


def ensure_candidate_fresh(
    manifest: dict[str, Any],
    *,
    max_age_hours: float = MAX_CANDIDATE_AGE_HOURS,
    now: datetime | None = None,
) -> None:
    """Reject a candidate whose required checks are older than the freshness window."""

    if max_age_hours <= 0:
        raise ValueError("max_age_hours must be positive")
    checked_at = _parse_timestamp(manifest.get("checks_completed_at"), "checks_completed_at")
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    age = current - checked_at
    if age > timedelta(hours=max_age_hours):
        raise ValueError(
            f"release candidate is stale: checks completed {age.total_seconds() / 3600:.2f} hours ago"
        )
    if age < timedelta(minutes=-5):
        raise ValueError("release candidate checks_completed_at is too far in the future")
    for check in manifest.get("checks", []):
        check_completed_at = _parse_timestamp(
            check.get("completed_at"),
            f"checks[{check.get('name', 'unknown')}].completed_at",
        )
        check_age = current - check_completed_at
        if check_age > timedelta(hours=max_age_hours):
            raise ValueError(
                f"release candidate check is stale: {check.get('name', 'unknown')} "
                f"completed {check_age.total_seconds() / 3600:.2f} hours ago"
            )
        if check_age < timedelta(minutes=-5):
            raise ValueError(
                f"release candidate check completed_at is too far in the future: "
                f"{check.get('name', 'unknown')}"
            )


def validate_production_manifest(
    manifest: dict[str, Any],
    *,
    artifact_root: Path | None = None,
    expected_source_commit: str | None = None,
) -> None:
    """Validate a manifest that records a completed production release."""

    _assert_no_secret_keys(manifest)
    if manifest.get("status") != "released":
        raise ValueError("manifest is not a released production manifest")
    candidate = copy.deepcopy(manifest)
    candidate["status"] = "release_candidate"
    candidate.pop("production", None)
    validate_manifest(
        candidate,
        artifact_root=artifact_root,
        expected_environment="development",
        expected_source_commit=expected_source_commit,
    )
    production = manifest.get("production")
    if not isinstance(production, dict):
        raise ValueError("production record is required")
    required = (
        "target_environment",
        "deployment_id",
        "deployed_at",
        "deployment_started_at",
        "deployment_completed_at",
        "configuration_digest",
        "account_id",
        "region",
        "approval",
        "verification",
        "migration_plan",
    )
    missing = [field for field in required if field not in production]
    if missing:
        raise ValueError(f"production record is missing: {', '.join(missing)}")
    if production["target_environment"] != "production":
        raise ValueError("production target_environment must be production")
    if not production["deployment_id"]:
        raise ValueError("production deployment_id is required")
    if not isinstance(production["configuration_digest"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", production["configuration_digest"]):
        raise ValueError("production configuration_digest must be a sha256 digest")
    _parse_timestamp(production["deployed_at"], "production.deployed_at")
    started_at = _parse_timestamp(production["deployment_started_at"], "production.deployment_started_at")
    completed_at = _parse_timestamp(production["deployment_completed_at"], "production.deployment_completed_at")
    if completed_at < started_at:
        raise ValueError("production deployment_completed_at must not precede deployment_started_at")
    if not isinstance(production["account_id"], str) or not re.fullmatch(r"\d{12}", production["account_id"]):
        raise ValueError("production account_id must be a 12-digit AWS account ID")
    if not isinstance(production["region"], str) or not re.fullmatch(r"[a-z0-9-]+", production["region"]):
        raise ValueError("production region is invalid")
    approval = production["approval"]
    if (
        not isinstance(approval, dict)
        or not isinstance(approval.get("user"), str)
        or not approval["user"]
        or not isinstance(approval.get("source"), str)
        or not approval["source"]
    ):
        raise ValueError("production approval must include user and source")
    approval_source = approval["source"]
    approval_user = approval["user"]
    change_author = manifest["release_context"]["created_by"]
    if approval_source not in {"solo-operator-confirmation", "aws-codepipeline-manual-approval"}:
        raise ValueError(
            "production approval source must be solo-operator-confirmation or "
            "aws-codepipeline-manual-approval"
        )
    if approval_user.casefold() != change_author.casefold():
        raise ValueError("production approval must be recorded by the release owner")
    _parse_timestamp(approval.get("approved_at"), "production.approval.approved_at")
    verification = production["verification"]
    if not isinstance(verification, dict) or verification.get("result") != "passed":
        raise ValueError("production verification must be passed")
    _parse_timestamp(verification.get("completed_at"), "production.verification.completed_at")
    verification_checks = verification.get("checks")
    if not isinstance(verification_checks, list) or not all(isinstance(item, str) and item for item in verification_checks):
        raise ValueError("production verification checks must be a list of names")
    missing_checks = [name for name in REQUIRED_PRODUCTION_CHECKS if name not in verification_checks]
    if missing_checks:
        raise ValueError(f"production verification is missing: {', '.join(missing_checks)}")
    if not isinstance(production["migration_plan"], str) or not production["migration_plan"].strip():
        raise ValueError("production migration_plan is required")
    expected_artifact_digests = {
        key: record["sha256"] for key, record in manifest["artifacts"].items()
    }
    if production.get("artifact_digests") != expected_artifact_digests:
        raise ValueError("production artifact_digests must match the released artifact digests")


def promote_manifest(
    candidate: dict[str, Any],
    *,
    artifact_root: Path,
    deployment_id: str,
    approval_user: str,
    approval_source: str,
    account_id: str,
    region: str,
    verification: dict[str, Any],
    configuration_digest: str,
    rollback_target: str | None = None,
    promoted_at: str | None = None,
    migration_plan: str = "none",
    deployment_started_at: str | None = None,
    deployment_completed_at: str | None = None,
) -> dict[str, Any]:
    validate_manifest(candidate, artifact_root=artifact_root, expected_environment="development")
    promoted = copy.deepcopy(candidate)
    promoted["status"] = "released"
    promoted["rollback_target"] = rollback_target
    completed_at = deployment_completed_at or promoted_at or _now()
    started_at = deployment_started_at or promoted_at or completed_at
    promoted["production"] = {
        "target_environment": "production",
        "deployment_id": deployment_id,
        "deployed_at": completed_at,
        "deployment_started_at": started_at,
        "deployment_completed_at": completed_at,
        "configuration_digest": configuration_digest,
        "account_id": account_id,
        "region": region,
        "migration_plan": migration_plan,
        "approval": {
            "user": approval_user,
            "source": approval_source,
            "approved_at": promoted_at or completed_at,
        },
        "verification": verification,
        "artifact_digests": {
            key: record["sha256"] for key, record in candidate["artifacts"].items()
        },
    }
    validate_production_manifest(promoted, artifact_root=artifact_root)
    return promoted


def build_rollback_record(
    target_manifest: dict[str, Any],
    *,
    artifact_root: Path,
    rollback_id: str,
    failed_release_id: str,
    incident_ref: str,
    reason: str,
    requested_by: str,
    approval_user: str,
    approval_source: str,
    deployment_id: str,
    account_id: str,
    region: str,
    verification: dict[str, Any],
    configuration_digest: str,
    completed_at: str | None = None,
    started_at: str | None = None,
    approved_at: str | None = None,
) -> dict[str, Any]:
    validate_production_manifest(target_manifest, artifact_root=artifact_root)
    finished = completed_at or _now()
    _parse_timestamp(finished, "completed_at")
    started = started_at or finished
    started_datetime = _parse_timestamp(started, "started_at")
    finished_datetime = _parse_timestamp(finished, "completed_at")
    if finished_datetime < started_datetime:
        raise ValueError("completed_at must not precede started_at")
    approval_timestamp = approved_at or finished
    _parse_timestamp(approval_timestamp, "approved_at")
    record = {
        "schema_version": 1,
        "record_type": "rollback",
        "status": "rolled_back",
        "rollback_id": rollback_id,
        "target_release_id": target_manifest["release_id"],
        "failed_release_id": failed_release_id,
        "incident_ref": incident_ref,
        "reason": reason,
        "requested_by": requested_by,
        "approval": {
            "user": approval_user,
            "source": approval_source,
            "approved_at": approval_timestamp,
        },
        "target": {
            "source_commit": target_manifest["source_commit"],
            "artifact_digests": {
                key: value["sha256"] for key, value in target_manifest["artifacts"].items()
            },
        },
        "production": {
            "target_environment": "production",
            "deployment_id": deployment_id,
            "account_id": account_id,
            "region": region,
            "configuration_digest": configuration_digest,
            "started_at": started,
            "completed_at": finished,
            "verification": verification,
        },
        "created_at": _now(),
    }
    _assert_no_secret_keys(record)
    if not isinstance(configuration_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", configuration_digest):
        raise ValueError("rollback configuration_digest must be a sha256 digest")
    if not all(isinstance(value, str) and value for value in (requested_by, approval_user, approval_source)):
        raise ValueError("rollback approval and requesting operator fields must be non-empty strings")
    if record["approval"]["source"] != "solo-operator-confirmation":
        raise ValueError("rollback approval source must be solo-operator-confirmation")
    if approval_user.casefold() != requested_by.casefold():
        raise ValueError("solo rollback confirmation must be recorded by the requesting operator")
    if not isinstance(verification, dict) or verification.get("result") != "passed":
        raise ValueError("rollback verification must be passed")
    _parse_timestamp(verification.get("completed_at"), "production.verification.completed_at")
    verification_checks = verification.get("checks")
    if not isinstance(verification_checks, list) or not all(isinstance(item, str) and item for item in verification_checks):
        raise ValueError("rollback verification checks must be a list of names")
    missing_checks = [name for name in REQUIRED_ROLLBACK_CHECKS if name not in verification_checks]
    if missing_checks:
        raise ValueError(f"rollback verification is missing: {', '.join(missing_checks)}")
    return record


def _read_checks(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text())
    if not isinstance(payload, list):
        raise ValueError("checks file must contain a JSON list")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create")
    create.add_argument("--release-id", required=True)
    create.add_argument("--source-commit", required=True)
    create.add_argument("--artifact-root", type=Path, required=True)
    create.add_argument("--checks-file", type=Path, required=True)
    create.add_argument("--deployment-id", required=True)
    create.add_argument("--deployed-at")
    create.add_argument("--workflow-run-id", required=True)
    create.add_argument("--repository", required=True)
    create.add_argument("--source-ref", required=True)
    create.add_argument("--ticket-ref", action="append", default=[])
    create.add_argument("--pull-request-ref", action="append", default=[])
    create.add_argument("--change-summary", required=True)
    create.add_argument("--known-limitations", required=True)
    create.add_argument("--created-by", required=True)
    create.add_argument("--rollback-target")
    create.add_argument("--output", type=Path, required=True)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--artifact-root", type=Path, required=True)
    verify.add_argument("--source-commit")
    verify.add_argument("--max-age-hours", type=float)

    verify_artifacts = subparsers.add_parser("verify-artifacts")
    verify_artifacts.add_argument("--metadata", type=Path, required=True)
    verify_artifacts.add_argument("--artifact-root", type=Path, required=True)
    verify_artifacts.add_argument("--source-commit")
    verify_artifacts.add_argument("--release-id")

    promote = subparsers.add_parser("promote")
    promote.add_argument("--candidate", type=Path, required=True)
    promote.add_argument("--artifact-root", type=Path, required=True)
    promote.add_argument("--deployment-id", required=True)
    promote.add_argument("--approval-user", required=True)
    promote.add_argument("--approval-source", required=True)
    promote.add_argument("--account-id", required=True)
    promote.add_argument("--region", required=True)
    promote.add_argument("--verification-file", type=Path, required=True)
    promote.add_argument("--configuration-digest", required=True)
    promote.add_argument("--rollback-target")
    promote.add_argument("--promoted-at")
    promote.add_argument("--deployment-started-at")
    promote.add_argument("--deployment-completed-at")
    promote.add_argument("--migration-plan", default="none")
    promote.add_argument("--output", type=Path, required=True)

    production_verify = subparsers.add_parser("verify-production")
    production_verify.add_argument("--manifest", type=Path, required=True)
    production_verify.add_argument("--artifact-root", type=Path, required=True)
    production_verify.add_argument("--source-commit")

    rollback = subparsers.add_parser("rollback-record")
    rollback.add_argument("--target-manifest", type=Path, required=True)
    rollback.add_argument("--artifact-root", type=Path, required=True)
    rollback.add_argument("--rollback-id", required=True)
    rollback.add_argument("--failed-release-id", required=True)
    rollback.add_argument("--incident-ref", required=True)
    rollback.add_argument("--reason", required=True)
    rollback.add_argument("--requested-by", required=True)
    rollback.add_argument("--approval-user", required=True)
    rollback.add_argument("--approval-source", required=True)
    rollback.add_argument("--deployment-id", required=True)
    rollback.add_argument("--account-id", required=True)
    rollback.add_argument("--region", required=True)
    rollback.add_argument("--verification-file", type=Path, required=True)
    rollback.add_argument("--configuration-digest", required=True)
    rollback.add_argument("--approved-at")
    rollback.add_argument("--completed-at")
    rollback.add_argument("--deployment-started-at")
    rollback.add_argument("--output", type=Path, required=True)

    args = parser.parse_args()
    try:
        if args.command == "create":
            manifest = build_manifest(
                release_id=args.release_id,
                source_commit=args.source_commit,
                environment="development",
                artifact_root=args.artifact_root,
                checks=_read_checks(args.checks_file),
                deployment_id=args.deployment_id,
                deployed_at=args.deployed_at,
                workflow_run_id=args.workflow_run_id,
                repository=args.repository,
                source_ref=args.source_ref,
                ticket_refs=args.ticket_ref,
                pull_request_refs=args.pull_request_ref,
                change_summary=args.change_summary,
                known_limitations=args.known_limitations,
                created_by=args.created_by,
                rollback_target=args.rollback_target,
            )
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(manifest, indent=2) + "\n")
        elif args.command == "verify":
            manifest = json.loads(args.manifest.read_text())
            validate_manifest(
                manifest,
                artifact_root=args.artifact_root,
                expected_environment="development",
                expected_source_commit=args.source_commit,
                max_age_hours=args.max_age_hours,
            )
        elif args.command == "verify-artifacts":
            metadata = json.loads(args.metadata.read_text())
            validate_artifact_metadata(
                metadata,
                artifact_root=args.artifact_root,
                expected_environment="development",
                expected_source_commit=args.source_commit,
                expected_release_id=args.release_id,
            )
        elif args.command == "promote":
            candidate = json.loads(args.candidate.read_text())
            verification = json.loads(args.verification_file.read_text())
            manifest = promote_manifest(
                candidate,
                artifact_root=args.artifact_root,
                deployment_id=args.deployment_id,
                approval_user=args.approval_user,
                approval_source=args.approval_source,
                account_id=args.account_id,
                region=args.region,
                verification=verification,
                configuration_digest=args.configuration_digest,
                rollback_target=args.rollback_target,
                promoted_at=args.promoted_at,
                migration_plan=args.migration_plan,
                deployment_started_at=args.deployment_started_at,
                deployment_completed_at=args.deployment_completed_at,
            )
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(manifest, indent=2) + "\n")
        elif args.command == "verify-production":
            manifest = json.loads(args.manifest.read_text())
            validate_production_manifest(
                manifest,
                artifact_root=args.artifact_root,
                expected_source_commit=args.source_commit,
            )
        else:
            target_manifest = json.loads(args.target_manifest.read_text())
            verification = json.loads(args.verification_file.read_text())
            record = build_rollback_record(
                target_manifest,
                artifact_root=args.artifact_root,
                rollback_id=args.rollback_id,
                failed_release_id=args.failed_release_id,
                incident_ref=args.incident_ref,
                reason=args.reason,
                requested_by=args.requested_by,
                approval_user=args.approval_user,
                approval_source=args.approval_source,
                deployment_id=args.deployment_id,
                account_id=args.account_id,
                region=args.region,
                verification=verification,
                configuration_digest=args.configuration_digest,
                completed_at=args.completed_at,
                started_at=args.deployment_started_at,
                approved_at=args.approved_at,
            )
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(record, indent=2) + "\n")
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print("release manifest is valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
