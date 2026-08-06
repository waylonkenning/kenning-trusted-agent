#!/usr/bin/env python3
"""Invoke the Kenning API with a product-managed PAT or agent credential."""

from __future__ import annotations

import argparse
import os
import sys
import urllib.error
import urllib.request


def pat_request(
    url: str,
    method: str,
    body: bytes,
    token: str,
    extra_headers: list[str] | None = None,
) -> urllib.request.Request:
    if not token or not token.startswith(("kta_pat_", "kta_agent_")):
        raise ValueError("Provide a Kenning PAT or agent credential with --token or KENNING_PAT.")
    headers = {
        "accept": "application/json, text/event-stream",
        "authorization": f"Bearer {token}",
        "content-type": "application/json",
    }
    for item in extra_headers or []:
        name, separator, value = item.partition(":")
        if not separator or not name.strip():
            raise ValueError("Headers must use NAME:VALUE format.")
        headers[name.strip()] = value.strip()
    request = urllib.request.Request(url, data=body, method=method)
    for key, value in headers.items():
        request.add_header(key, value)
    return request


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("--token", default=os.environ.get("KENNING_PAT", ""))
    parser.add_argument("--method", default="POST", choices=["GET", "POST", "PUT", "PATCH", "DELETE"])
    parser.add_argument("--body", default="{}")
    parser.add_argument("--header", action="append", default=[])
    args = parser.parse_args()
    body = args.body.encode("utf-8") if args.method != "GET" else b""
    request = pat_request(args.url, args.method, body, args.token, args.header)
    try:
        with urllib.request.urlopen(request, timeout=30) as result:
            sys.stdout.write(result.read().decode("utf-8"))
            sys.stdout.write("\n")
    except urllib.error.HTTPError as exc:
        sys.stderr.write(exc.read().decode("utf-8", errors="replace"))
        sys.stderr.write("\n")
        return exc.code
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
