#!/usr/bin/env python3
"""Local MCP stdio bridge to the deployed PAT-authenticated Guard server."""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

from invoke_pat import pat_request


DEFAULT_MCP_URL = "http://127.0.0.1:3000/mcp"
MCP_URL = os.environ.get("KENNING_MCP_URL", DEFAULT_MCP_URL)
PAT = os.environ.get("KENNING_PAT", "")


def forward(message: dict) -> dict | None:
    method = str(message.get("method") or "")
    extra_headers = []
    if method != "initialize":
        extra_headers.append("MCP-Protocol-Version: 2025-06-18")
    request = pat_request(
        MCP_URL,
        "POST",
        json.dumps(message, separators=(",", ":")).encode("utf-8"),
        PAT,
        extra_headers,
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as result:
            raw = result.read()
            if not raw:
                return None
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Remote MCP server returned HTTP {exc.code}: {detail}") from exc


def main() -> int:
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            message = json.loads(line)
            result = forward(message)
            if result is not None:
                sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
                sys.stdout.flush()
        except Exception as exc:
            request_id = message.get("id") if isinstance(message, dict) else None
            error = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32000, "message": str(exc)},
            }
            sys.stdout.write(json.dumps(error, separators=(",", ":")) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
