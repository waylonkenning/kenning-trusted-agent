"""In-process HTTP harness for API and MCP integration tests.

This keeps the API integration tests runnable on a developer machine without
requiring AWS. The Lambda handler, HTTP request shape, authentication, route
dispatch, JSON serialisation, fake persistence, and receipt signing still run
through the same production code. Deployed tests remain responsible for AWS
resource and network behaviour.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

try:
    from fixtures import FakeTable, FakeTokenTable
except ImportError:
    from tests.fixtures import FakeTable, FakeTokenTable

from app import guard
from app import lambda_function as service


class LocalKmsClient:
    """Deterministic KMS-shaped signer for local receipt verification tests."""

    def __init__(self, secret: bytes = b"kenning-local-test-kms"):
        self.secret = secret

    def sign(self, *, KeyId: str, Message: bytes, MessageType: str, SigningAlgorithm: str) -> dict[str, bytes]:
        del KeyId, MessageType, SigningAlgorithm
        return {"Signature": hmac.new(self.secret, Message, hashlib.sha256).digest()}

    def verify(
        self,
        *,
        KeyId: str,
        Message: bytes,
        MessageType: str,
        Signature: bytes,
        SigningAlgorithm: str,
    ) -> dict[str, bool]:
        del KeyId, MessageType, SigningAlgorithm
        expected = hmac.new(self.secret, Message, hashlib.sha256).digest()
        return {"SignatureValid": hmac.compare_digest(expected, Signature)}

    def get_public_key(self, *, KeyId: str) -> dict[str, Any]:
        return {
            "KeyId": KeyId,
            "KeySpec": "RSA_2048",
            "KeyUsage": "SIGN_VERIFY",
            "PublicKey": b"kenning-local-public-key",
        }


class LocalAuditTable(FakeTable):
    """Make the fake query semantics match DynamoDB ordering and limits."""

    def query(self, **kwargs: Any) -> dict[str, Any]:
        result = super().query(**kwargs)
        items = list(result.get("Items", []))
        items.sort(
            key=lambda item: (str(item.get("pk") or ""), str(item.get("sk") or "")),
            reverse=kwargs.get("ScanIndexForward") is False,
        )
        limit = int(kwargs.get("Limit") or len(items))
        return {"Items": items[:limit]}


class _LambdaHandler(BaseHTTPRequestHandler):
    server: "LocalLambdaServer"

    def _dispatch(self) -> None:
        split = urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw_body = self.rfile.read(length) if length else b""
        event: dict[str, Any] = {
            "version": "2.0",
            "rawPath": split.path or "/",
            "rawQueryString": split.query,
            "headers": {key: value for key, value in self.headers.items()},
            "queryStringParameters": {
                key: values[-1]
                for key, values in parse_qs(split.query, keep_blank_values=True).items()
            },
            "requestContext": {"http": {"method": self.command}},
            "body": raw_body.decode("utf-8") if raw_body else None,
            "isBase64Encoded": False,
        }
        result = service.lambda_handler(event, None)
        status = int(result.get("statusCode") or 500)
        self.send_response(status)
        for key, value in (result.get("headers") or {}).items():
            self.send_header(str(key), str(value))
        for cookie in result.get("cookies") or []:
            self.send_header("Set-Cookie", str(cookie))
        body = str(result.get("body") or "").encode("utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._dispatch()

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._dispatch()

    def do_PUT(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._dispatch()

    def do_DELETE(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._dispatch()

    def do_PATCH(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._dispatch()

    def do_OPTIONS(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._dispatch()

    def log_message(self, format: str, *args: Any) -> None:
        del format, args


class LocalLambdaServer(ThreadingHTTPServer):
    allow_reuse_address = True


class LocalApiFixture:
    """Own an isolated local API server and disposable in-memory credentials."""

    def __init__(self, tenant_id: str = "local-api-test", admin_tenant_id: str = "local-tenant-admin-test"):
        self.tenant_id = tenant_id
        self.admin_tenant_id = admin_tenant_id
        self.server: LocalLambdaServer | None = None
        self.thread: threading.Thread | None = None
        self.table: FakeTable | None = None
        self.token_table: FakeTokenTable | None = None
        self._old_service_table: Any = None
        self._old_service_token_table: Any = None
        self._old_kms_client: Any = None
        self._old_environment: dict[str, str | None] = {}

    @staticmethod
    def _token(token_id: str, tenant_id: str, scopes: set[str], groups: list[str] | None = None) -> tuple[str, dict[str, Any]]:
        token = f"kta_pat_local_{token_id}"
        record = {
            "token_hash": hashlib.sha256(token.encode("utf-8")).hexdigest(),
            "token_id": token_id,
            "name": token_id,
            "tenant_id": tenant_id,
            "token_type": "pat",
            "scopes": sorted(scopes),
            "groups": sorted(groups or [], key=str.casefold),
            "status": "active",
            "created_at": "2026-01-01T00:00:00Z",
            "created_by": "local-test-harness",
        }
        return token, record

    def start(self) -> dict[str, str]:
        if self.server is not None:
            raise RuntimeError("Local API fixture is already running.")

        self.table = LocalAuditTable()
        self.token_table = FakeTokenTable()
        self._old_service_table = service.table
        self._old_service_token_table = service.token_table
        self._old_kms_client = guard._kms_client_instance
        service.table = self.table
        service.token_table = self.token_table

        for name, value in {
            "RECEIPT_SIGNING_MODE": "kms",
            "RECEIPT_KMS_KEY_ID": "local-test-key",
            "RECEIPT_KMS_SIGNING_ALGORITHM": "RSASSA_PSS_SHA_256",
            "RECEIPT_SIGNING_KEY_ID": "local-test",
            "RECEIPT_SIGNING_SECRET": "local-test-secret",
            "KENNING_ENV": "local-test",
        }.items():
            self._old_environment[name] = os.environ.get(name)
            os.environ[name] = value
        guard._kms_client_instance = LocalKmsClient()

        all_scopes = set(service.PAT_SCOPES)
        base_pat, base_record = self._token("local-api-base", self.tenant_id, all_scopes)
        reviewer_pat, reviewer_record = self._token("local-api-reviewer", self.tenant_id, all_scopes, ["security"])
        proof_pat, proof_record = self._token("local-api-proof", self.tenant_id, all_scopes)
        citation_pat, citation_record = self._token("local-api-citation", self.tenant_id, all_scopes)
        identity_pat, identity_record = self._token("local-api-identity", self.tenant_id, all_scopes)
        policy_pat, policy_record = self._token("local-api-policy", self.tenant_id, all_scopes)
        tenant_pat, tenant_record = self._token("local-api-tenant-admin", self.admin_tenant_id, all_scopes)
        for record in (base_record, reviewer_record, proof_record, citation_record, identity_record, policy_record, tenant_record):
            self.token_table.put_item(Item=record)

        self.server = LocalLambdaServer(("127.0.0.1", 0), _LambdaHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, name="kenning-local-api", daemon=True)
        self.thread.start()
        return {
            "api_url": f"http://127.0.0.1:{self.server.server_port}",
            "pat": base_pat,
            "reviewer_pat": reviewer_pat,
            "proof_pat": proof_pat,
            "citation_pat": citation_pat,
            "identity_pat": identity_pat,
            "policy_pat": policy_pat,
            "tenant_pat": tenant_pat,
            "tenant_id": self.tenant_id,
            "tenant_admin_tenant_id": self.admin_tenant_id,
        }

    def stop(self) -> None:
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        if self.thread is not None:
            self.thread.join(timeout=5)
        self.server = None
        self.thread = None
        service.table = self._old_service_table
        service.token_table = self._old_service_token_table
        guard._kms_client_instance = self._old_kms_client
        for name, value in self._old_environment.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
