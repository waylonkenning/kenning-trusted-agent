"""Targeted tests for platform access grant branches in lambda_function.py (#271).

Covers: load_platform_grant validation, list/revoke grant handlers,
platform support read validation.
"""

import time
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


class PlatformGrantTests(unittest.TestCase):
    def setUp(self):
        self.table = FakeTable()
        service.table = self.table
        self.token_table = FakeTokenTable()
        service.token_table = self.token_table
        self.operator_auth = {"tenant_id": "demo", "token_id": "t1", "role": "admin", "subject": "op@example.com", "platform_admin": True, "scopes": ["admin"]}

    def _status(self, result):
        return result.get("statusCode", 200)

    def _body(self, result):
        import json
        raw = result.get("body", "{}")
        return json.loads(raw) if isinstance(raw, str) else raw

    def _seed_grant(self, grant_id="grant-1", tenant_id="demo", status="active", operation="read", expires_at=None):
        if expires_at is None:
            expires_at = int(time.time()) + 3600
        self.table.put_item(Item={
            "pk": f"PLATFORM_ACCESS#{grant_id}",
            "sk": "METADATA",
            "item_type": "platform_access_grant",
            "grant_id": grant_id,
            "tenant_id": tenant_id,
            "status": status,
            "operation": operation,
            "reason": "Testing support access grant",
            "expires_at": expires_at,
            "created_at": "2026-01-01T00:00:00Z",
            "created_by": "op@example.com",
        })

    # ------------------------------------------------------------------
    # load_platform_grant (lines 1988, 1992, 1996, 2006)
    # ------------------------------------------------------------------

    def test_load_platform_grant_not_operator(self):
        """Line 1988: non-operator returns error."""
        auth = {"tenant_id": "demo", "token_id": "t1", "role": "viewer", "subject": "v@example.com"}
        grant, error = service.load_platform_grant({"grant_id": "g1", "tenant_id": "demo"}, auth)
        self.assertIsNone(grant)
        self.assertIsNotNone(error)

    def test_load_platform_grant_missing_ids(self):
        """Line 1992: missing grant_id or tenant_id returns 400."""
        with patch.object(service, "require_platform_operator", return_value=None):
            grant, error = service.load_platform_grant({"grant_id": "", "tenant_id": ""}, self.operator_auth)
        self.assertIsNone(grant)
        self.assertEqual(error["statusCode"], 400)
        self.assertEqual(self._body(error).get("error"), "grant_id_and_tenant_id_required")

    def test_load_platform_grant_not_found(self):
        """Line 1996: grant not found returns 404."""
        with patch.object(service, "require_platform_operator", return_value=None):
            grant, error = service.load_platform_grant({"grant_id": "missing", "tenant_id": "demo"}, self.operator_auth)
        self.assertIsNone(grant)
        self.assertEqual(error["statusCode"], 404)

    def test_load_platform_grant_operation_not_granted(self):
        """Line 2006: operation mismatch returns 403."""
        self._seed_grant(operation="read")
        with patch.object(service, "require_platform_operator", return_value=None):
            grant, error = service.load_platform_grant({"grant_id": "grant-1", "tenant_id": "demo"}, self.operator_auth, required_operation="configuration")
        self.assertIsNone(grant)
        self.assertEqual(error["statusCode"], 403)
        self.assertEqual(self._body(error).get("error"), "platform_access_operation_not_granted")

    # ------------------------------------------------------------------
    # handle_list_platform_access_grants (lines 2018-2019, 2021)
    # ------------------------------------------------------------------

    def test_list_grants_invalid_limit(self):
        """Lines 2018-2019: non-integer limit raises ValueError."""
        with patch.object(service, "require_platform_operator", return_value=None):
            with self.assertRaises(ValueError):
                service.handle_list_platform_access_grants(make_event("GET", "/v1/platform/grants", query={"limit": "abc"}), self.operator_auth)

    def test_list_grants_limit_out_of_range(self):
        """Line 2021: out-of-range limit raises ValueError."""
        with patch.object(service, "require_platform_operator", return_value=None):
            with self.assertRaises(ValueError):
                service.handle_list_platform_access_grants(make_event("GET", "/v1/platform/grants", query={"limit": "999"}), self.operator_auth)

    # ------------------------------------------------------------------
    # handle_revoke_platform_access_grant (lines 2029, 2034, 2037)
    # ------------------------------------------------------------------

    def test_revoke_grant_not_operator(self):
        """Line 2029: non-operator returns error."""
        auth = {"tenant_id": "demo", "token_id": "t1", "role": "viewer", "subject": "v@example.com"}
        result = service.handle_revoke_platform_access_grant("grant-1", {}, auth)
        self.assertIn(result["statusCode"], (401, 403))

    def test_revoke_grant_not_active(self):
        """Line 2034: revoking non-active grant returns 409."""
        self._seed_grant(status="revoked")
        with patch.object(service, "require_platform_operator", return_value=None):
            result = service.handle_revoke_platform_access_grant("grant-1", {"reason": "Revoking this support grant now"}, self.operator_auth)
        self.assertEqual(result["statusCode"], 409)
        self.assertEqual(self._body(result).get("error"), "platform_access_grant_not_active")

    def test_revoke_grant_invalid_reason(self):
        """Line 2037: short reason raises ValueError."""
        self._seed_grant()
        with patch.object(service, "require_platform_operator", return_value=None):
            with self.assertRaises(ValueError):
                service.handle_revoke_platform_access_grant("grant-1", {"reason": "short"}, self.operator_auth)

    # ------------------------------------------------------------------
    # handle_platform_support_read (lines 2072, 2075-2076, 2078)
    # ------------------------------------------------------------------

    def test_support_read_invalid_resource(self):
        """Line 2072: invalid resource raises ValueError."""
        self._seed_grant()
        with patch.object(service, "require_platform_operator", return_value=None):
            with self.assertRaises(ValueError):
                service.handle_platform_support_read({"grant_id": "grant-1", "tenant_id": "demo", "resource": "bogus"}, self.operator_auth)

    def test_support_read_invalid_limit(self):
        """Lines 2075-2076: non-integer limit raises ValueError."""
        self._seed_grant()
        with patch.object(service, "require_platform_operator", return_value=None):
            with self.assertRaises(ValueError):
                service.handle_platform_support_read({"grant_id": "grant-1", "tenant_id": "demo", "resource": "tenant", "limit": "abc"}, self.operator_auth)

    def test_support_read_limit_out_of_range(self):
        """Line 2078: out-of-range limit raises ValueError."""
        self._seed_grant()
        with patch.object(service, "require_platform_operator", return_value=None):
            with self.assertRaises(ValueError):
                service.handle_platform_support_read({"grant_id": "grant-1", "tenant_id": "demo", "resource": "tenant", "limit": 999}, self.operator_auth)


if __name__ == "__main__":
    unittest.main()
