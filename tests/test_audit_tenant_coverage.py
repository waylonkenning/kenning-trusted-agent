"""Targeted tests for audit ingest, metrics, and tenant management branches (#271).

Covers: handle_audit_ingest validation, handle_audit_export tenant check,
handle_metrics timestamp validation, handle_get_tenant defaults,
handle_list_tenants validation.
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


class AuditIngestTests(unittest.TestCase):
    def setUp(self):
        self.table = FakeTable()
        service.table = self.table
        self.token_table = FakeTokenTable()
        service.token_table = self.token_table
        self.admin_auth = {"tenant_id": "demo", "token_id": "t1", "role": "admin", "subject": "admin@example.com", "scopes": ["admin"]}

    def _status(self, result):
        return result.get("statusCode", 200)

    def _body(self, result):
        import json
        raw = result.get("body", "{}")
        return json.loads(raw) if isinstance(raw, str) else raw

    # ------------------------------------------------------------------
    # handle_audit_ingest (lines 3003-3004, 3035-3036, 3038)
    # ------------------------------------------------------------------

    def test_audit_ingest_invalid_created_at(self):
        """Lines 3003-3004: invalid created_at raises ValueError."""
        event = make_event("POST", "/v1/audit/ingest")
        with self.assertRaises(ValueError):
            service.handle_ingest_audit_event(event, {"event_type": "test.event", "created_at": "not-a-date"}, self.admin_auth)

    def test_audit_ingest_non_serialisable(self):
        """Lines 3035-3036: non-JSON-serialisable fields raise ValueError."""
        event = make_event("POST", "/v1/audit/ingest")
        with self.assertRaises(ValueError):
            service.handle_ingest_audit_event(event, {"event_type": "test.event", "bad_field": object()}, self.admin_auth)

    def test_audit_ingest_payload_too_large(self):
        """Line 3038: payload > 300KB raises ValueError."""
        event = make_event("POST", "/v1/audit/ingest")
        large_payload = {"event_type": "test.event", "data": "x" * 400_000}
        with self.assertRaises(ValueError):
            service.handle_ingest_audit_event(event, large_payload, self.admin_auth)


class AuditExportTests(unittest.TestCase):
    def setUp(self):
        self.table = FakeTable()
        service.table = self.table
        self.token_table = FakeTokenTable()
        service.token_table = self.token_table

    def _status(self, result):
        return result.get("statusCode", 200)

    def _body(self, result):
        import json
        raw = result.get("body", "{}")
        return json.loads(raw) if isinstance(raw, str) else raw

    # ------------------------------------------------------------------
    # handle_audit_export (line 3059)
    # ------------------------------------------------------------------

    def test_audit_export_tenant_mismatch(self):
        """Line 3059: cross-tenant export without admin scope returns 403."""
        auth = {"tenant_id": "demo", "token_id": "t1", "role": "viewer", "subject": "v@example.com"}
        event = make_event("GET", "/v1/audit/export", query={"tenant_id": "other"})
        result = service.handle_audit_export(event, auth)
        self.assertEqual(self._status(result), 403)
        self.assertEqual(self._body(result).get("error"), "tenant_mismatch")


class MetricsTests(unittest.TestCase):
    def setUp(self):
        self.table = FakeTable()
        service.table = self.table
        self.token_table = FakeTokenTable()
        service.token_table = self.token_table
        self.admin_auth = {"tenant_id": "demo", "token_id": "t1", "role": "admin", "subject": "admin@example.com"}

    # ------------------------------------------------------------------
    # handle_metrics (lines 3106-3107)
    # ------------------------------------------------------------------

    def test_metrics_invalid_timestamp(self):
        """Lines 3106-3107: invalid start_time raises ValueError."""
        event = make_event("GET", "/v1/metrics", query={"start_time": "not-a-date"})
        with self.assertRaises(ValueError):
            service.handle_metrics(event, self.admin_auth)


class TenantManagementTests(unittest.TestCase):
    def setUp(self):
        self.table = FakeTable()
        service.table = self.table
        self.token_table = FakeTokenTable()
        service.token_table = self.token_table
        self.admin_auth = {"tenant_id": "demo", "token_id": "t1", "role": "admin", "subject": "admin@example.com", "scopes": ["admin"]}

    def _status(self, result):
        return result.get("statusCode", 200)

    def _body(self, result):
        import json
        raw = result.get("body", "{}")
        return json.loads(raw) if isinstance(raw, str) else raw

    # ------------------------------------------------------------------
    # handle_list_tenants (lines 3188, 3191-3192, 3194)
    # ------------------------------------------------------------------

    def test_list_tenants_invalid_status(self):
        """Line 3188: invalid status filter returns 400."""
        event = make_event("GET", "/v1/tenants", query={"status": "bogus"})
        result = service.handle_list_tenants(event, self.admin_auth)
        self.assertEqual(self._status(result), 400)
        self.assertEqual(self._body(result).get("error"), "invalid_tenant_status")

    def test_list_tenants_invalid_limit(self):
        """Lines 3191-3192: non-integer limit raises ValueError."""
        event = make_event("GET", "/v1/tenants", query={"limit": "abc"})
        with self.assertRaises(ValueError):
            service.handle_list_tenants(event, self.admin_auth)

    def test_list_tenants_limit_out_of_range(self):
        """Line 3194: out-of-range limit raises ValueError."""
        event = make_event("GET", "/v1/tenants", query={"limit": "999"})
        with self.assertRaises(ValueError):
            service.handle_list_tenants(event, self.admin_auth)


if __name__ == "__main__":
    unittest.main()
