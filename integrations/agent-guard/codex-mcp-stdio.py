#!/usr/bin/env python3
"""Forward Codex MCP JSON-RPC messages with file-based Agent Guard credentials."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import urllib.error
import urllib.request


CREDENTIALS_PATH = Path(__file__).with_name("kenning-guard-credentials.json")


def credentials() -> tuple[str, str, str]:
    try:
        with CREDENTIALS_PATH.open(encoding="utf-8") as handle:
            values = json.load(handle)
    except (OSError, ValueError) as exc:
        raise RuntimeError("Kenning Agent Guard credentials file is invalid or missing") from exc
    if not isinstance(values, dict):
        raise RuntimeError("Kenning Agent Guard credentials file is invalid")
    mcp_url = str(values.get("mcp_url") or "").rstrip("/")
    pat = str(values.get("pat") or "")
    tenant_id = str(values.get("tenant_id") or "")
    if not mcp_url or not pat or not tenant_id:
        raise RuntimeError("Kenning Agent Guard credentials file is incomplete")
    return mcp_url, pat, tenant_id


def forward(message: dict) -> dict | None:
    mcp_url, pat, tenant_id = credentials()
    method = str(message.get("method") or "")
    headers = {
        "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {pat}",
        "Content-Type": "application/json",
        "X-Kenning-Tenant-Id": tenant_id,
    }
    if method != "initialize":
        headers["MCP-Protocol-Version"] = "2025-06-18"
    request = urllib.request.Request(
        mcp_url,
        data=json.dumps(message, separators=(",", ":")).encode("utf-8"),
        headers=headers,
        method="POST",
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
        message = None
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
