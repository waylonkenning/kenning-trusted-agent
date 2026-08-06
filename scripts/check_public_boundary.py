#!/usr/bin/env python3
"""Reject hosted identifiers, private CI files, and marketing runtime code."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_TEXT = (
    "qjax" + "b3nja",
    "d7qmb" + "4jtoi",
    "d3rq" + "9v08mdisx5",
    "kenning" + ".co.nz",
    "MARKETING_" + "E2E_SECRET",
    "MARKETING_" + "CONTACT_RECIPIENT",
    "MARKETING_" + "CONTACT_SENDER",
    "ses" + "_client",
)


def tracked_paths() -> list[str]:
    result = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True)
    return [item for item in result.stdout.decode().split("\0") if item]


def main() -> int:
    failures: list[str] = []
    paths = tracked_paths()
    if any(path.startswith("marketing-site/") or path == "marketing-site" for path in paths):
        failures.append("marketing-site files are tracked")
    if any(path.startswith(".github/workflows/") for path in paths):
        failures.append("GitHub Actions workflows are tracked")
    for relative in paths:
        path = ROOT / relative
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for marker in FORBIDDEN_TEXT:
            if marker in content:
                failures.append(f"{relative}: {marker}")
    if failures:
        print("Public boundary check failed:", file=sys.stderr)
        print("\n".join(f"- {item}" for item in failures), file=sys.stderr)
        return 1
    print(f"Public boundary check passed ({len(paths)} tracked files).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
