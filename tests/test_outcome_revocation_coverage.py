"""Targeted tests for outcome recording and approval revocation branches (#271).

Covers: handle_outcome validation paths, handle_revoke_approval branches,
single-step approval decision exception handling.
"""

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


class OutcomeRecordingTests(unittest.TestCase):
    def setUp(self):
        self.table = FakeTable()
        service.table = self.table
        self.token_table = FakeTokenTable()
        service.token_table = self.token_table
        self.agent_auth = {"tenant_id": "demo", "token_id": "t1", "role": "agent", "subject": "agent@example.com", "agent_id": "agent-1"}

    def _status(self, result):
        return result.get("statusCode", 200)

    def _body(self, result):
        import json
        raw = result.get("body", "{}")
        return json.loads(raw) if isinstance(raw, str) else raw

    def _seed_evaluation(self, action_id="act-1", decision="allow", action_hash="hash123", agent_id="agent-1"):
        self.table.put_item(Item={
            "pk": "TENANT#demo",
            "sk": "EVENT#2026-01-01T00:00:00Z",
            "item_type": "audit_event",
            "event_type": "action.evaluated",
            "tenant_id": "demo",
            "action_id": action_id,
            "decision": decision,
            "action_hash": action_hash,
            "agent_id": agent_id,
        })

    # ------------------------------------------------------------------
    # handle_outcome (lines 4783, 4786, 4790, 4795-4806)
    # ------------------------------------------------------------------

    def test_outcome_action_not_found(self):
        """Line 4762: missing evaluation returns 404."""
        event = make_event("POST", "/v1/actions/missing/outcome")
        result = service.handle_outcome(event, {}, "missing", self.agent_auth)
        self.assertEqual(self._status(result), 404)

    def test_outcome_hash_mismatch(self):
        """Line 4768: supplied hash mismatch returns 409."""
        self._seed_evaluation(action_hash="hash123")
        event = make_event("POST", "/v1/actions/act-1/outcome")
        result = service.handle_outcome(event, {"action_hash": "wrong"}, "act-1", self.agent_auth)
        self.assertEqual(self._status(result), 409)
        self.assertEqual(self._body(result).get("error"), "action_hash_mismatch")

    def test_outcome_approval_required_but_missing(self):
        """Line 4783: require_approval without approval_id returns 409."""
        self._seed_evaluation(decision="require_approval")
        event = make_event("POST", "/v1/actions/act-1/outcome")
        result = service.handle_outcome(event, {"status": "completed"}, "act-1", self.agent_auth)
        self.assertEqual(self._status(result), 409)
        self.assertEqual(self._body(result).get("error"), "approved_action_required")

    def test_outcome_approval_not_found(self):
        """Line 4786: approval not found returns 403."""
        self._seed_evaluation(decision="require_approval")
        event = make_event("POST", "/v1/actions/act-1/outcome")
        result = service.handle_outcome(event, {"status": "completed", "approval_id": "missing"}, "act-1", self.agent_auth)
        self.assertEqual(self._status(result), 403)
        self.assertEqual(self._body(result).get("error"), "approval_not_found_or_tenant_mismatch")

    def test_outcome_approval_not_approved(self):
        """Line 4788: pending approval returns 409."""
        self._seed_evaluation(decision="require_approval")
        self.table.put_item(Item={
            "pk": "APPROVAL#appr-1", "sk": "METADATA",
            "item_type": "approval", "approval_id": "appr-1",
            "tenant_id": "demo", "status": "pending",
            "action_id": "act-1", "action_hash": "hash123",
        })
        event = make_event("POST", "/v1/actions/act-1/outcome")
        result = service.handle_outcome(event, {"status": "completed", "approval_id": "appr-1"}, "act-1", self.agent_auth)
        self.assertEqual(self._status(result), 409)
        self.assertEqual(self._body(result).get("error"), "approval_not_approved")

    def test_outcome_approval_action_mismatch(self):
        """Line 4790: approval bound to different action returns 409."""
        self._seed_evaluation(decision="require_approval")
        self.table.put_item(Item={
            "pk": "APPROVAL#appr-1", "sk": "METADATA",
            "item_type": "approval", "approval_id": "appr-1",
            "tenant_id": "demo", "status": "approved",
            "action_id": "other-action", "action_hash": "hash123",
        })
        event = make_event("POST", "/v1/actions/act-1/outcome")
        result = service.handle_outcome(event, {"status": "completed", "approval_id": "appr-1"}, "act-1", self.agent_auth)
        self.assertEqual(self._status(result), 409)
        self.assertEqual(self._body(result).get("error"), "approval_action_mismatch")

    def test_outcome_optional_approval_mismatch(self):
        """Lines 4797-4801: optional approval with wrong action returns 409."""
        self._seed_evaluation(decision="allow")
        self.table.put_item(Item={
            "pk": "APPROVAL#appr-1", "sk": "METADATA",
            "item_type": "approval", "approval_id": "appr-1",
            "tenant_id": "demo", "status": "approved",
            "action_id": "other-action", "action_hash": "hash123",
        })
        event = make_event("POST", "/v1/actions/act-1/outcome")
        result = service.handle_outcome(event, {"status": "completed", "approval_id": "appr-1"}, "act-1", self.agent_auth)
        self.assertEqual(self._status(result), 409)
        self.assertEqual(self._body(result).get("error"), "approval_action_mismatch")

    def test_outcome_proof_error(self):
        """Line 4827: proof lookup error propagates."""
        self._seed_evaluation(decision="allow")
        event = make_event("POST", "/v1/actions/act-1/outcome")
        with patch.object(service, "_proof_for_tenant", return_value=(None, {"statusCode": 404, "body": "{}"})):
            result = service.handle_outcome(event, {"status": "completed", "proof_id": "missing"}, "act-1", self.agent_auth)
        self.assertEqual(self._status(result), 404)


class RevokeApprovalTests(unittest.TestCase):
    def setUp(self):
        self.table = FakeTable()
        service.table = self.table
        self.token_table = FakeTokenTable()
        service.token_table = self.token_table
        self.admin_auth = {"tenant_id": "demo", "token_id": "t1", "role": "admin", "subject": "admin@example.com"}

    def _status(self, result):
        return result.get("statusCode", 200)

    def _body(self, result):
        import json
        raw = result.get("body", "{}")
        return json.loads(raw) if isinstance(raw, str) else raw

    # ------------------------------------------------------------------
    # handle_revoke_approval (lines 4722, 4731)
    # ------------------------------------------------------------------

    def test_revoke_approval_tenant_mismatch(self):
        """Line 4722: tenant mismatch returns 403."""
        self.table.put_item(Item={
            "pk": "APPROVAL#appr-1", "sk": "METADATA",
            "item_type": "approval", "approval_id": "appr-1",
            "tenant_id": "other", "status": "approved",
        })
        event = make_event("POST", "/v1/approvals/appr-1/revoke")
        result = service.handle_revoke_approval(event, {}, "appr-1", self.admin_auth)
        self.assertEqual(self._status(result), 403)
        self.assertEqual(self._body(result).get("error"), "tenant_mismatch")

    def test_revoke_approval_not_found_after_revoke(self):
        """Line 4731: revoke_approval returns (None, False) → 404."""
        self.table.put_item(Item={
            "pk": "APPROVAL#appr-1", "sk": "METADATA",
            "item_type": "approval", "approval_id": "appr-1",
            "tenant_id": "demo", "status": "approved",
            "run_id": "r1", "action_id": "a1", "agent_id": "ag1",
        })
        with patch.object(service.AuditStore, "revoke_approval", return_value=(None, False)):
            event = make_event("POST", "/v1/approvals/appr-1/revoke")
            result = service.handle_revoke_approval(event, {}, "appr-1", self.admin_auth)
        self.assertEqual(self._status(result), 404)


if __name__ == "__main__":
    unittest.main()
