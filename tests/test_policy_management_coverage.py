"""Targeted tests for policy management branches (#271).

Covers: handle_create_policy, _policy_version_from_body, _policy_for_tenant,
_policy_transition, handle_delete_policy.
"""

import unittest
from unittest.mock import MagicMock, patch

from app import lambda_function as service


class PolicyManagementTests(unittest.TestCase):
    def setUp(self):
        self.mock_store = MagicMock()
        self.admin_auth = {"tenant_id": "demo", "token_id": "t1", "role": "admin", "subject": "admin@example.com", "scopes": ["admin"]}

    def _status(self, result):
        return result.get("statusCode", 200)

    def _body(self, result):
        import json
        raw = result.get("body", "{}")
        return json.loads(raw) if isinstance(raw, str) else raw

    # ------------------------------------------------------------------
    # handle_create_policy (line 3470)
    # ------------------------------------------------------------------

    def test_create_policy_version_already_exists(self):
        """Line 3470: policy version already exists returns 409."""
        with patch.object(service, "store", return_value=self.mock_store):
            self.mock_store.list_policy_versions.return_value = [{"version": 1}]
            result = service.handle_create_policy({"policy_id": "p1", "version": 1}, self.admin_auth)
        self.assertEqual(self._status(result), 409)
        self.assertEqual(self._body(result).get("error"), "policy_version_already_exists")

    # ------------------------------------------------------------------
    # _policy_version_from_body (line 3496)
    # ------------------------------------------------------------------

    def test_policy_version_from_body_invalid(self):
        """Line 3496: version < 1 returns 400."""
        version, error = service._policy_version_from_body({"version": 0})
        self.assertIsNone(version)
        self.assertEqual(error["statusCode"], 400)
        self.assertEqual(self._body(error).get("error"), "policy_version_invalid")

    # ------------------------------------------------------------------
    # _policy_for_tenant (line 3550)
    # ------------------------------------------------------------------

    def test_policy_for_tenant_tenant_mismatch(self):
        """Line 3550: tenant mismatch without admin scope returns 403."""
        with patch.object(service, "store", return_value=self.mock_store):
            self.mock_store.get_policy.return_value = {"policy_id": "p1", "tenant_id": "other", "version": 1}
            auth = {"tenant_id": "demo", "token_id": "t1", "role": "viewer", "subject": "v@example.com"}
            policy, error = service._policy_for_tenant("p1", 1, auth)
        self.assertIsNone(policy)
        self.assertEqual(error["statusCode"], 403)
        self.assertEqual(self._body(error).get("error"), "tenant_mismatch")

    # ------------------------------------------------------------------
    # _policy_transition (line 3593)
    # ------------------------------------------------------------------

    def test_policy_transition_invalid_status(self):
        """Line 3593: policy status mismatch returns 409."""
        with patch.object(service, "store", return_value=self.mock_store):
            self.mock_store.get_policy.return_value = {"policy_id": "p1", "tenant_id": "demo", "version": 1, "status": "draft"}
            result = service._policy_transition("p1", {"version": 1}, self.admin_auth, "published", "suspended", "policy.suspended")
        self.assertEqual(self._status(result), 409)
        self.assertEqual(self._body(result).get("error"), "policy_invalid_status")

    def test_policy_transition_confirmation_required(self):
        """Line 3595: missing confirm=true returns 400."""
        with patch.object(service, "store", return_value=self.mock_store):
            self.mock_store.get_policy.return_value = {"policy_id": "p1", "tenant_id": "demo", "version": 1, "status": "published"}
            result = service._policy_transition("p1", {"version": 1}, self.admin_auth, "published", "suspended", "policy.suspended")
        self.assertEqual(self._status(result), 400)
        self.assertEqual(self._body(result).get("error"), "policy_confirmation_required")


if __name__ == "__main__":
    unittest.main()
