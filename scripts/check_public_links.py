#!/usr/bin/env python3
"""Check local Markdown links in the public source tree."""

from __future__ import annotations

from pathlib import Path
import re
from urllib.parse import unquote, urlparse


ROOT = Path(__file__).resolve().parents[1]
SKIP_PARTS = {".git", ".venv", "node_modules", "dist", "build", "tmp"}
LINK_RE = re.compile(r"(?<!!)\[[^\]]*\]\((?:<([^>]+)>|([^\s)]+))")


def markdown_files() -> list[Path]:
    return [
        path
        for path in ROOT.rglob("*.md")
        if not any(part in SKIP_PARTS for part in path.relative_to(ROOT).parts)
    ]


def local_target(source: Path, raw_target: str) -> Path | None:
    target = raw_target.split("#", 1)[0].split("?", 1)[0]
    if not target:
        return None
    parsed = urlparse(target)
    if parsed.scheme or target.startswith("//"):
        return None
    return (source.parent / unquote(target)).resolve()


def main() -> int:
    missing: list[str] = []
    for source in markdown_files():
        text = source.read_text(encoding="utf-8")
        for match in LINK_RE.finditer(text):
            target = match.group(1) or match.group(2)
            resolved = local_target(source, target)
            if resolved is not None and not resolved.exists():
                missing.append(f"{source.relative_to(ROOT)} -> {target}")
    if missing:
        for item in missing:
            print(f"missing local link: {item}")
        return 1
    print(f"Public Markdown link check passed ({len(markdown_files())} files).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
