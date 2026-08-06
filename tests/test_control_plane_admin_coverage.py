"""Targeted branch coverage for control_plane_admin session-membership and
PAT tenant-target paths in app/lambda_function.py (#271).

Covers: session admin success, session role too low, session tenant mismatch,
and the non-session tenant_target error path.
"""

import unittest

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


class ControlPlaneAdminCoverageTests(unittest.TestCase):
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

    def _seed_membership(self, subject, tenant_id, role):
        self.table.put_item(Item={
            "pk": f"USER#{subject}",
            "sk": f"MEMBERSHIP#{tenant_id}",
            "item_type": "membership",
            "subject": subject,
            "tenant_id": tenant_id,
            "role": role,
            "status": "active",
            "email": f"{subject}@demo.test",
        })

    def _session_auth(self, subject="admin-user", tenant_id="demo"):
        return {
            "token_type": "session",
            "auth_source": "session",
            "subject": subject,
            "tenant_id": tenant_id,
        }

    # --- Session admin success (lines 1033-1038) ---------------------------

    def test_session_admin_allowed(self):
        """Lines 1033-1038: active admin membership in the target tenant -> None."""
        self._seed_membership("admin-user", "demo", "admin")
        event = make_event("GET", "/v1/memberships", headers={"x-kenning-tenant-id": "demo"})
        result = service.control_plane_admin("demo", event, None, self._session_auth())
        self.assertIsNone(result)

    def test_session_role_too_low(self):
        """Line 1035: session membership role below admin -> 403."""
        self._seed_membership("viewer-user", "demo", "viewer")
        event = make_event("GET", "/v1/memberships", headers={"x-kenning-tenant-id": "demo"})
        auth = self._session_auth(subject="viewer-user")
        result = service.control_plane_admin("demo", event, None, auth)
        self.assertEqual(self._status(result), 403)
        self.assertEqual(self._body(result)["error"], "membership_role_required")

    def test_session_tenant_mismatch(self):
        """Line 1037: resolved session tenant differs from the target tenant."""
        # Active admin membership in "other"; the session resolves to "other"
        # but administration targets "demo".
        self._seed_membership("admin-user", "other", "admin")
        event = make_event("GET", "/v1/memberships", headers={"x-kenning-tenant-id": "other"})
        auth = self._session_auth(tenant_id="other")
        result = service.control_plane_admin("demo", event, None, auth)
        self.assertEqual(self._status(result), 403)
        self.assertEqual(self._body(result)["error"], "tenant_mismatch")

    # --- Non-session tenant_target error (line 1041) -----------------------

    def test_pat_tenant_target_mismatch(self):
        """Line 1041: non-admin PAT targeting a foreign tenant -> tenant_target error."""
        auth = {"tenant_id": "demo", "token_id": "t1", "scopes": ["tenant:write"]}
        event = make_event("GET", "/v1/memberships")
        # Target "foreign" but the PAT belongs to "demo" and is not admin.
        result = service.control_plane_admin("foreign", event, None, auth)
        self.assertEqual(self._status(result), 403)
        self.assertEqual(self._body(result)["error"], "tenant_mismatch")


if __name__ == "__main__":
    unittest.main()
