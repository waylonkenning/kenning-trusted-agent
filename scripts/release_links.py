#!/usr/bin/env python3
"""Resolve release ticket and pull-request references from workflow inputs."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


REF_RE = re.compile(r"(?:^|[\s,(])(?:[^\s/]+/[^\s/]+/)?#(\d+)(?=$|[\s),.;:])")
URL_RE = re.compile(r"/issues/(\d+)")
CLOSING_RE = re.compile(
    r"\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\b[^\n#]{0,80}#(\d+)",
    re.IGNORECASE,
)


def _refs(value: str) -> list[str]:
    found: list[str] = []
    for match in REF_RE.finditer(value or ""):
        ref = f"#{match.group(1)}"
        if ref not in found:
            found.append(ref)
    for match in URL_RE.finditer(value or ""):
        ref = f"#{match.group(1)}"
        if ref not in found:
            found.append(ref)
    return found


def resolve_links(
    *, manual_ticket_refs: str = "", manual_pull_request_refs: str = "", associated_pull_requests: list[dict[str, Any]] | None = None
) -> dict[str, list[str]]:
    pull_requests: list[str] = []
    tickets = _refs(manual_ticket_refs)
    for ref in _refs(manual_pull_request_refs):
        if ref not in pull_requests:
            pull_requests.append(ref)
    for pull_request in associated_pull_requests or []:
        number = pull_request.get("number")
        if isinstance(number, int) or (isinstance(number, str) and number.isdigit()):
            ref = f"#{number}"
            if ref not in pull_requests:
                pull_requests.append(ref)
        body = pull_request.get("body") or ""
        for match in CLOSING_RE.finditer(body):
            ref = f"#{match.group(1)}"
            if ref not in tickets:
                tickets.append(ref)
    return {"ticket_refs": tickets, "pull_request_refs": pull_requests}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manual-ticket-refs", default="")
    parser.add_argument("--manual-pull-request-refs", default="")
    parser.add_argument("--associated-pull-requests", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    payload = json.loads(args.associated_pull_requests.read_text())
    if not isinstance(payload, list):
        parser.error("associated pull requests must be a JSON list")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(
            resolve_links(
                manual_ticket_refs=args.manual_ticket_refs,
                manual_pull_request_refs=args.manual_pull_request_refs,
                associated_pull_requests=payload,
            ),
            indent=2,
        )
        + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
