"""Targeted tests for approval chain and grant management branches (#271).

Covers: handle_list_grants validation, handle_revoke_grant branches,
_handle_chain_decision step validation, separation of duties, denial,
and final approval with grant.
"""

import time
import unittest
from unittest.mock import MagicMock, patch

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


class GrantListRevokeTests(unittest.TestCase):
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
    # handle_list_grants (lines 4380, 4383-4384, 4386)
    # ------------------------------------------------------------------

    def test_list_grants_target_error(self):
        """Line 4380: tenant_target error propagates."""
        with patch.object(service, "tenant_target", return_value=(None, {"statusCode": 403, "body": "{}"})):
            result = service.handle_list_grants(make_event("GET", "/v1/grants"), self.admin_auth)
        self.assertEqual(self._status(result), 403)

    def test_list_grants_invalid_limit(self):
        """Lines 4383-4384: non-integer limit raises ValueError."""
        with patch.object(service, "tenant_target", return_value=("demo", None)):
            with self.assertRaises(ValueError):
                service.handle_list_grants(make_event("GET", "/v1/grants", query={"limit": "abc"}), self.admin_auth)

    def test_list_grants_limit_out_of_range(self):
        """Line 4386: out-of-range limit raises ValueError."""
        with patch.object(service, "tenant_target", return_value=("demo", None)):
            with self.assertRaises(ValueError):
                service.handle_list_grants(make_event("GET", "/v1/grants", query={"limit": "999"}), self.admin_auth)

    # ------------------------------------------------------------------
    # handle_revoke_grant (lines 4400, 4402, 4404, 4408)
    # ------------------------------------------------------------------

    def test_revoke_grant_not_found(self):
        """Line 4400: grant not found returns 404."""
        event = make_event("POST", "/v1/grants/missing/revoke")
        result = service.handle_revoke_grant(event, {}, "missing", self.admin_auth)
        self.assertEqual(self._status(result), 404)
        self.assertEqual(self._body(result).get("error"), "grant_not_found")

    def test_revoke_grant_tenant_mismatch(self):
        """Line 4402: tenant mismatch returns 403."""
        grant = {"grant_id": "g1", "tenant_id": "other", "status": "active"}
        with patch.object(service.AuditStore, "get_grant", return_value=grant):
            event = make_event("POST", "/v1/grants/g1/revoke")
            result = service.handle_revoke_grant(event, {}, "g1", self.admin_auth)
        self.assertEqual(self._status(result), 403)
        self.assertEqual(self._body(result).get("error"), "tenant_mismatch")

    def test_revoke_grant_not_active(self):
        """Line 4404: non-active grant returns 409."""
        grant = {"grant_id": "g1", "tenant_id": "demo", "status": "revoked"}
        with patch.object(service.AuditStore, "get_grant", return_value=grant):
            event = make_event("POST", "/v1/grants/g1/revoke")
            result = service.handle_revoke_grant(event, {}, "g1", self.admin_auth)
        self.assertEqual(self._status(result), 409)
        self.assertEqual(self._body(result).get("error"), "grant_not_active")

    def test_revoke_grant_update_failed(self):
        """Line 4408: revoke_grant returns None → 409."""
        grant = {"grant_id": "g1", "tenant_id": "demo", "status": "active"}
        with patch.object(service.AuditStore, "get_grant", return_value=grant):
            with patch.object(service.AuditStore, "revoke_grant", return_value=None):
                event = make_event("POST", "/v1/grants/g1/revoke")
                result = service.handle_revoke_grant(event, {}, "g1", self.admin_auth)
        self.assertEqual(self._status(result), 409)


class ChainDecisionTests(unittest.TestCase):
    def setUp(self):
        self.table = FakeTable()
        service.table = self.table
        self.token_table = FakeTokenTable()
        service.token_table = self.token_table
        self.store = service.AuditStore(self.table)
        self.admin_auth = {"tenant_id": "demo", "token_id": "t1", "role": "admin", "subject": "admin@example.com", "scopes": ["admin"], "groups": ["reviewers"]}

    def _status(self, result):
        return result.get("statusCode", 200)

    def _body(self, result):
        import json
        raw = result.get("body", "{}")
        return json.loads(raw) if isinstance(raw, str) else raw

    def _make_approval(self, steps=2, current_step=1, status="pending", requested_by="requester@example.com"):
        chain_steps = [
            {"step": i + 1, "label": f"Step {i + 1}", "status": "pending", "approver_groups": ["reviewers"], "separation_of_duties": True}
            for i in range(steps)
        ]
        return {
            "approval_id": "appr-1",
            "tenant_id": "demo",
            "status": status,
            "current_step": current_step,
            "chain_steps": chain_steps,
            "requested_by": requested_by,
            "run_id": "run-1",
            "action_id": "act-1",
            "agent_id": "agent-1",
        }

    # ------------------------------------------------------------------
    # _handle_chain_decision step validation (lines 4447-4448, 4461)
    # ------------------------------------------------------------------

    def test_chain_decision_invalid_step_type(self):
        """Lines 4447-4448: non-integer step returns 400."""
        approval = self._make_approval()
        result = service._handle_chain_decision(
            self.store, approval, "appr-1", {"step": "abc"}, "approve",
            "admin@example.com", "admin@example.com", "session", self.admin_auth,
        )
        self.assertEqual(self._status(result), 400)
        self.assertEqual(self._body(result).get("error"), "step_must_be_an_integer")

    def test_chain_decision_wrong_step(self):
        """Line 4449-4458: requesting wrong step returns 409."""
        approval = self._make_approval(current_step=1)
        result = service._handle_chain_decision(
            self.store, approval, "appr-1", {"step": 2}, "approve",
            "admin@example.com", "admin@example.com", "session", self.admin_auth,
        )
        self.assertEqual(self._status(result), 409)
        self.assertEqual(self._body(result).get("error"), "approval_step_not_actionable")

    def test_chain_decision_invalid_state(self):
        """Line 4461: current_step out of range returns 409."""
        approval = self._make_approval(steps=2, current_step=5)
        result = service._handle_chain_decision(
            self.store, approval, "appr-1", {}, "approve",
            "admin@example.com", "admin@example.com", "session", self.admin_auth,
        )
        self.assertEqual(self._status(result), 409)
        self.assertEqual(self._body(result).get("error"), "approval_chain_invalid_state")

    # ------------------------------------------------------------------
    # Denial (lines 4476)
    # ------------------------------------------------------------------

    def test_chain_decision_deny_update_failed(self):
        """Line 4476: update_approval_chain returns None → 409."""
        approval = self._make_approval()
        with patch.object(service.AuditStore, "update_approval_chain", return_value=None):
            result = service._handle_chain_decision(
                self.store, approval, "appr-1", {}, "deny",
                "admin@example.com", "admin@example.com", "session", self.admin_auth,
            )
        self.assertEqual(self._status(result), 409)
        self.assertEqual(self._body(result).get("error"), "approval_expired_or_already_decided")

    # ------------------------------------------------------------------
    # Separation of duties (lines 4509-4521)
    # ------------------------------------------------------------------

    def test_chain_decision_self_approval(self):
        """Lines 4509-4518: requester approving own action → 403."""
        approval = self._make_approval(requested_by="admin@example.com")
        result = service._handle_chain_decision(
            self.store, approval, "appr-1", {}, "approve",
            "admin@example.com", "admin@example.com", "session", self.admin_auth,
        )
        self.assertEqual(self._status(result), 403)
        self.assertEqual(self._body(result).get("error"), "separation_of_duties_violation")

    def test_chain_decision_repeat_approver(self):
        """Lines 4519-4529: same approver on second step → 403."""
        approval = self._make_approval(steps=2, current_step=2)
        approval["chain_steps"][0]["status"] = "approved"
        approval["chain_steps"][0]["approver_principal"] = "admin@example.com"
        result = service._handle_chain_decision(
            self.store, approval, "appr-1", {}, "approve",
            "admin@example.com", "admin@example.com", "session", self.admin_auth,
        )
        self.assertEqual(self._status(result), 403)
        self.assertEqual(self._body(result).get("error"), "separation_of_duties_violation")

    # ------------------------------------------------------------------
    # Approval update failed (line 4546)
    # ------------------------------------------------------------------

    def test_chain_decision_approve_update_failed(self):
        """Line 4546: update_approval_chain returns None → 409."""
        approval = self._make_approval()
        with patch.object(service.AuditStore, "update_approval_chain", return_value=None):
            result = service._handle_chain_decision(
                self.store, approval, "appr-1", {}, "approve",
                "admin@example.com", "admin@example.com", "session", self.admin_auth,
            )
        self.assertEqual(self._status(result), 409)

    # ------------------------------------------------------------------
    # Final approval with grant (line 4569)
    # ------------------------------------------------------------------

    def test_chain_decision_final_approval_with_grant(self):
        """Line 4569: final step approval with grant_duration creates grant."""
        approval = self._make_approval(steps=1, current_step=1)
        updated_approval = dict(approval)
        updated_approval["status"] = "approved"
        updated_approval["action_hash"] = "hash123"
        with patch.object(service.AuditStore, "update_approval_chain", return_value=updated_approval):
            result = service._handle_chain_decision(
                self.store, approval, "appr-1", {"grant_duration": 3600}, "approve",
                "admin@example.com", "admin@example.com", "session", self.admin_auth,
            )
        self.assertEqual(self._status(result), 200)
        body = self._body(result)
        self.assertTrue(body.get("chain_complete"))
        self.assertIn("grant", body)


if __name__ == "__main__":
    unittest.main()
