#!/usr/bin/env python3
"""Generate a small, reproducible source-checkout SBOM without extra tools."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def python_components() -> list[dict[str, str]]:
    names = {"boto3", "coverage", "pytest"}
    components = []
    for distribution in importlib.metadata.distributions():
        name = distribution.metadata.get("Name") or ""
        if name.casefold() not in {value.casefold() for value in names}:
            continue
        components.append(
            {
                "type": "library",
                "bom-ref": f"pypi:{name}@{distribution.version}",
                "name": name,
                "version": distribution.version,
                "purl": f"pkg:pypi/{name.lower().replace('_', '-') }@{distribution.version}",
                "license": distribution.metadata.get("License") or "See package metadata",
            }
        )
    return sorted(components, key=lambda item: (item["name"].casefold(), item["version"]))


def npm_components() -> list[dict[str, str]]:
    lock = json.loads((ROOT / "portal" / "package-lock.json").read_text(encoding="utf-8"))
    components = []
    for location, record in sorted((lock.get("packages") or {}).items()):
        if not location or location == "" or not isinstance(record, dict) or not record.get("version"):
            continue
        name = location.removeprefix("node_modules/")
        if "/node_modules/" in name:
            name = name.rsplit("/node_modules/", 1)[-1]
        components.append(
            {
                "type": "library",
                "bom-ref": f"npm:{name}@{record['version']}",
                "name": name,
                "version": str(record["version"]),
                "purl": f"pkg:npm/{name}@{record['version']}",
                "license": "Review npm registry metadata; lockfiles do not carry a complete license record",
            }
        )
    return components


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "docs" / "SBOM.json")
    args = parser.parse_args()
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "kenning-trusted-agent", "version": "1.0.0"}},
        "components": python_components() + npm_components(),
        "properties": [
            {"name": "generation-tool", "value": "scripts/generate_sbom.py"},
            {"name": "scope", "value": "tracked Python and portal npm dependencies"},
            {"name": "exclusion", "value": "OS packages, AWS-managed services, and optional customer integrations"},
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(document['components'])} components to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
