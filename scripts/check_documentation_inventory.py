#!/usr/bin/env python3
"""Check that every tracked Markdown file appears in the public index."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "docs" / "DOCUMENTATION_INDEX.md"
EXCLUDED_PARTS = {".git", ".venv", "build", "dist", "node_modules", "playwright-report", "test-results", "tmp"}


def markdown_paths() -> set[str]:
    paths = set()
    for path in ROOT.rglob("*.md"):
        relative = path.relative_to(ROOT)
        if EXCLUDED_PARTS.intersection(relative.parts):
            continue
        paths.add(relative.as_posix())
    return paths


def tracked_paths() -> set[str]:
    result = subprocess.run(
        ["git", "ls-files", "*.md"], cwd=ROOT, check=True, capture_output=True, text=True
    )
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def main() -> int:
    if not INDEX.is_file():
        print(f"Missing documentation index: {INDEX}", file=sys.stderr)
        return 1
    inventory = INDEX.read_text(encoding="utf-8")
    missing = sorted(path for path in tracked_paths() if path not in inventory)
    untracked = sorted(path for path in markdown_paths() - tracked_paths() if path not in inventory)
    if missing or untracked:
        print("Markdown files missing from docs/DOCUMENTATION_INDEX.md:", file=sys.stderr)
        for path in missing + untracked:
            print(f"- {path}", file=sys.stderr)
        return 1
    print(f"Documentation inventory is complete ({len(tracked_paths())} tracked Markdown files).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
