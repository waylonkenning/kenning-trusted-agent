"""Targeted branch coverage for federated-auth and IAM-workload paths in
app/lambda_function.py::authenticate (#271).

Covers: IAM workload agent not active/registered, unsupported bearer with no
store, federated tenant-hint mismatch, missing tenant hint, federation not
configured, opaque token without introspection, verified-tenant mismatch, and
the generic federated-token-invalid exception path.
"""

import unittest
from unittest.mock import patch

from app import lambda_function as service
from tests.test_federation import FakeTable, FakeTokenTable


def make_event(method, path, body=None, query=None, headers=None):
    event = {
        "rawPath": path,
        "requestContext": {"http": {"method": method}},
        "headers": headers or {},
    }
    if body is not None:
        event["body"] = body
    if query:
        event["queryStringParameters"] = query
    return event


def fake_jwt(tenant="demo"):
    """A structurally valid (3-segment) JWT string for hint parsing."""
    import base64
    import json
    claims = base64.urlsafe_b64encode(
        json.dumps({"tenant_id": tenant}).encode()
    ).decode().rstrip("=")
    return f"header.{claims}.signature"


class AuthenticateFederatedCoverageTests(unittest.TestCase):
    def setUp(self):
        self.table = FakeTable()
        service.table = self.table
        self.token_table = FakeTokenTable()
        service.token_table = self.token_table

    # --- IAM workload identity (line 769) ----------------------------------

    def test_iam_workload_agent_not_registered(self):
        """Line 769: mapped IAM workload agent is not active/registered."""
        iam = {"account_id": "123456789012", "role_name": "workload-role"}
        event = make_event("GET", "/v1/agents", headers={"x-kenning-tenant-id": "demo"})
        with patch.object(service, "aws_iam_context", return_value=iam), \
             patch.object(service, "map_aws_iam_principal",
                          return_value={"agent_id": "ghost-agent", "tenant_id": "demo"}):
            auth, error = service.authenticate(event)
        self.assertIsNone(auth)
        self.assertIsNotNone(error)

    # --- Unsupported bearer / no store (lines 816-817) ---------------------

    def test_federated_bearer_no_table(self):
        """Lines 816-817: non-PAT bearer token with no config store."""
        event = make_event("GET", "/v1/agents",
                           headers={"authorization": "Bearer some.opaque.token"})
        with patch.object(service, "table", None):
            auth, error = service.authenticate(event)
        self.assertIsNone(auth)
        self.assertIsNotNone(error)

    # --- Federated tenant-hint mismatch (lines 831-832) --------------------

    def test_federated_tenant_hint_mismatch(self):
        """Lines 831-832: JWT claim tenant differs from explicit header hint."""
        event = make_event("GET", "/v1/agents", headers={
            "authorization": "Bearer " + fake_jwt("demo"),
            "x-kenning-tenant-id": "other-tenant",
        })
        auth, error = service.authenticate(event)
        self.assertIsNone(auth)
        self.assertIsNotNone(error)

    # --- Missing tenant hint (lines 837-838) -------------------------------

    def test_federated_missing_tenant_hint(self):
        """Lines 837-838: opaque bearer token with no tenant hint anywhere."""
        event = make_event("GET", "/v1/agents",
                           headers={"authorization": "Bearer opaque-token-no-dots"})
        auth, error = service.authenticate(event)
        self.assertIsNone(auth)
        self.assertIsNotNone(error)

    # --- Federation not configured (lines 843-844) -------------------------

    def test_federation_not_configured(self):
        """Lines 843-844: tenant has no enabled identity provider."""
        self.table.put_item(Item={
            "pk": "TENANT#demo", "sk": "CONFIG",
            "tenant_id": "demo", "identity_provider": {"enabled": False},
        })
        event = make_event("GET", "/v1/agents", headers={
            "authorization": "Bearer " + fake_jwt("demo"),
        })
        auth, error = service.authenticate(event)
        self.assertIsNone(auth)
        self.assertIsNotNone(error)

    # --- Opaque token requires introspection (lines 852-853) ---------------

    def test_opaque_token_requires_introspection(self):
        """Lines 852-853: opaque token but provider is not introspection mode."""
        self.table.put_item(Item={
            "pk": "TENANT#demo", "sk": "CONFIG",
            "tenant_id": "demo",
            "identity_provider": {"enabled": True, "validation_mode": "jwt"},
        })
        event = make_event("GET", "/v1/agents", headers={
            "authorization": "Bearer opaque-token-no-dots",
            "x-kenning-tenant-id": "demo",
        })
        auth, error = service.authenticate(event)
        self.assertIsNone(auth)
        self.assertIsNotNone(error)

    # --- Verified tenant mismatch (lines 855-856) --------------------------

    def test_federated_verified_tenant_mismatch(self):
        """Lines 855-856: verified record tenant differs from the hint."""
        self.table.put_item(Item={
            "pk": "TENANT#demo", "sk": "CONFIG",
            "tenant_id": "demo",
            "identity_provider": {"enabled": True, "validation_mode": "jwt"},
        })
        event = make_event("GET", "/v1/agents", headers={
            "authorization": "Bearer " + fake_jwt("demo"),
        })
        with patch.object(service, "verify_federated_token",
                          return_value={"tenant_id": "evil-tenant", "subject": "x"}):
            auth, error = service.authenticate(event)
        self.assertIsNone(auth)
        self.assertIsNotNone(error)

    # --- Generic federated-token-invalid (lines 858-860) -------------------

    def test_federated_token_invalid_exception(self):
        """Lines 858-860: verification raises -> generic invalid error."""
        self.table.put_item(Item={
            "pk": "TENANT#demo", "sk": "CONFIG",
            "tenant_id": "demo",
            "identity_provider": {"enabled": True, "validation_mode": "jwt"},
        })
        event = make_event("GET", "/v1/agents", headers={
            "authorization": "Bearer " + fake_jwt("demo"),
        })
        with patch.object(service, "verify_federated_token",
                          side_effect=ValueError("bad signature")):
            auth, error = service.authenticate(event)
        self.assertIsNone(auth)
        self.assertIsNotNone(error)


if __name__ == "__main__":
    unittest.main()
