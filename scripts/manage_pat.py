#!/usr/bin/env python3
"""Create, list, and revoke Kenning personal access tokens.

The plaintext token is printed only during creation. Only its SHA-256 hash is
stored in DynamoDB.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import time
import uuid


DEFAULT_SCOPES = [
    "guard:evaluate",
    "mcp:read",
    "audit:read",
    "audit:write",
    "approve:actions",
    "actions:write",
    "proof:read",
    "proof:write",
    "citation:verify",
    "identity:read",
    "identity:write",
    "policy:read",
    "policy:write",
    "policy:simulate",
    "tenant:read",
    "tenant:write",
    "tenant:retention",
    "token:admin",
    "session:create",
]


def aws_region() -> str:
    return os.environ.get("AWS_REGION") or subprocess.run(
        ["aws", "configure", "get", "region"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip() or "us-east-1"


def table_name() -> str:
    return os.environ.get("TOKEN_TABLE_NAME", "kenning-agent-guard-tokens-prototype")


def run_aws(args: list[str]) -> str:
    result = subprocess.run(["aws", *args], check=True, capture_output=True, text=True)
    return result.stdout


def create(args: argparse.Namespace) -> None:
    token_id = "pat-" + uuid.uuid4().hex[:16]
    token = "kta_pat_" + secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    scopes = [scope.strip() for scope in args.scopes.split(",") if scope.strip()] if args.scopes else DEFAULT_SCOPES
    groups = sorted({group.strip() for group in (args.groups.split(",") if args.groups else []) if group.strip()}, key=str.casefold)
    if len(groups) > 50 or any(len(group) > 128 for group in groups):
        raise SystemExit("--groups may contain at most 50 values of 128 characters each")
    item = {
        "token_hash": {"S": token_hash},
        "token_id": {"S": token_id},
        # PATs created by this bootstrap utility can be exchanged for a
        # browser session. Use the stable, non-secret token metadata ID as
        # the authenticated subject; the plaintext PAT is never persisted.
        "subject": {"S": token_id},
        "token_type": {"S": "pat"},
        "name": {"S": args.name},
        "tenant_id": {"S": args.tenant_id},
        "scopes": {"L": [{"S": scope} for scope in scopes]},
        "status": {"S": "active"},
        "created_at": {"S": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
    }
    if groups:
        item["groups"] = {"L": [{"S": group} for group in groups]}
    if args.expires_in_days > 0:
        item["expires_at"] = {"N": str(int(time.time()) + args.expires_in_days * 86400)}
    run_aws(
        [
            "dynamodb",
            "put-item",
            "--region",
            aws_region(),
            "--table-name",
            table_name(),
            "--item",
            json.dumps(item),
            "--condition-expression",
            "attribute_not_exists(token_hash)",
        ]
    )
    print("PAT created. Store this value securely; it will not be shown again.")
    print(f"token_id: {token_id}")
    print(f"tenant_id: {args.tenant_id}")
    print(f"scopes: {','.join(scopes)}")
    print(f"expires_in_days: {args.expires_in_days or 'never'}")
    print(f"token: {token}")


def list_tokens(_: argparse.Namespace) -> None:
    output = run_aws(
        [
            "dynamodb",
            "scan",
            "--region",
            aws_region(),
            "--table-name",
            table_name(),
            "--projection-expression",
            "#id, #name, tenant_id, scopes, #status, created_at, expires_at",
            "--expression-attribute-names",
            json.dumps({"#id": "token_id", "#name": "name", "#status": "status"}),
        ]
    )
    items = json.loads(output).get("Items", [])
    print(json.dumps(items, indent=2))


def revoke(args: argparse.Namespace) -> None:
    output = run_aws(
        [
            "dynamodb",
            "scan",
            "--region",
            aws_region(),
            "--table-name",
            table_name(),
            "--filter-expression",
            "token_id = :token_id",
            "--expression-attribute-values",
            json.dumps({":token_id": {"S": args.token_id}}),
            "--projection-expression",
            "token_hash",
        ]
    )
    items = json.loads(output).get("Items", [])
    if not items:
        raise SystemExit(f"PAT not found: {args.token_id}")
    for item in items:
        run_aws(
            [
                "dynamodb",
                "update-item",
                "--region",
                aws_region(),
                "--table-name",
                table_name(),
                "--key",
                json.dumps({"token_hash": item["token_hash"]}),
                "--update-expression",
                "SET #status = :revoked, revoked_at = :now",
                "--expression-attribute-names",
                json.dumps({"#status": "status"}),
                "--expression-attribute-values",
                json.dumps({":revoked": {"S": "revoked"}, ":now": {"S": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}}),
            ]
        )
    print(f"PAT revoked: {args.token_id}")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    create_parser = subparsers.add_parser("create")
    create_parser.add_argument("--name", required=True)
    create_parser.add_argument("--tenant-id", required=True)
    create_parser.add_argument("--scopes", help="Comma-separated scopes; defaults to all prototype scopes.")
    create_parser.add_argument("--groups", help="Comma-separated reviewer groups for approval policies.")
    create_parser.add_argument(
        "--expires-in-days",
        type=int,
        default=0,
        help="Token lifetime in days; use 0 for no expiry (recommended for this POC).",
    )
    create_parser.set_defaults(handler=create)

    list_parser = subparsers.add_parser("list")
    list_parser.set_defaults(handler=list_tokens)

    revoke_parser = subparsers.add_parser("revoke")
    revoke_parser.add_argument("--token-id", required=True)
    revoke_parser.set_defaults(handler=revoke)

    args = parser.parse_args()
    args.handler(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
