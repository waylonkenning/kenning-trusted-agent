#!/usr/bin/env python3
"""Resolve the immutable user-facing identity for a release."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
NAMES_PATH = ROOT / "docs" / "RELEASE_NAMES_NZ.json"
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")


def load_name_catalog(path: Path = NAMES_PATH) -> dict[str, Any]:
    catalog = json.loads(path.read_text(encoding="utf-8"))
    names = catalog.get("names")
    if catalog.get("schema_version") != 1 or not isinstance(names, list) or not names:
        raise ValueError("the NZ release name catalog is invalid")
    if any(not isinstance(name, str) or not name.strip() for name in names):
        raise ValueError("the NZ release name catalog contains an empty name")
    if len({name.casefold() for name in names}) != len(names):
        raise ValueError("the NZ release name catalog contains duplicate names")
    return catalog


def validate_release_identity(
    identity: dict[str, Any],
    *,
    expected_release_id: str | None = None,
) -> None:
    """Validate the identity stored in a release artifact or manifest."""

    required = (
        "schema_version",
        "release_id",
        "release_version",
        "release_name",
        "release_sequence",
        "release_name_position",
        "release_name_cycle",
        "release_names_source",
    )
    missing = [field for field in required if field not in identity]
    if missing:
        raise ValueError(f"release identity is missing: {', '.join(missing)}")
    if identity["schema_version"] != 1:
        raise ValueError("unsupported release identity schema")
    release_id = identity["release_id"]
    if not isinstance(release_id, str) or not release_id or any(character.isspace() for character in release_id):
        raise ValueError("release identity release_id is invalid")
    if expected_release_id is not None and release_id != expected_release_id:
        raise ValueError("release identity release_id does not match the expected release")
    if not isinstance(identity["release_version"], str) or not VERSION_RE.fullmatch(identity["release_version"]):
        raise ValueError("release identity release_version is invalid")
    if not isinstance(identity["release_name"], str) or not identity["release_name"].strip():
        raise ValueError("release identity release_name is required")
    for field in ("release_sequence", "release_name_position", "release_name_cycle"):
        if not isinstance(identity[field], int) or identity[field] < 1:
            raise ValueError(f"release identity {field} must be a positive integer")
    if not isinstance(identity["release_names_source"], str) or not identity["release_names_source"].strip():
        raise ValueError("release identity release_names_source is required")


def release_identity(
    *,
    release_id: str,
    sequence: int,
    release_version: str | None = None,
    catalog_path: Path = NAMES_PATH,
) -> dict[str, Any]:
    if not release_id or any(character.isspace() for character in release_id):
        raise ValueError("release_id must be a non-empty value without whitespace")
    if sequence < 1:
        raise ValueError("release sequence must be a positive integer")
    catalog = load_name_catalog(catalog_path)
    names = catalog["names"]
    position = (sequence - 1) % len(names)
    version = release_version or f"0.1.{sequence}"
    if not VERSION_RE.fullmatch(version):
        raise ValueError("release_version must be a semantic version")
    return {
        "schema_version": 1,
        "release_id": release_id,
        "release_version": version,
        "release_name": names[position],
        "release_sequence": sequence,
        "release_name_position": position + 1,
        "release_name_cycle": ((sequence - 1) // len(names)) + 1,
        "release_names_source": catalog["source"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--sequence", type=int, required=True)
    parser.add_argument("--release-version")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        identity = release_identity(
            release_id=args.release_id,
            sequence=args.sequence,
            release_version=args.release_version,
        )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"release identity error: {error}", file=sys.stderr)
        return 1
    payload = json.dumps(identity, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
