"""Targeted branch coverage for handle_approved_evaluation in
app/lambda_function.py (#271).

Covers the MCP approval-resume verification: approval not found, tenant
mismatch, missing action hash, action-hash mismatch, action-id mismatch,
action-core mismatch, evaluation not found, consume race, and the happy path.
"""

import unittest

from app import lambda_function as service
from tests.test_federation import FakeTable, FakeTokenTable


def base_action():
    return {
        "tenant_id": "demo",
        "environment": "development",
        "agent_id": "agent-1",
        "invoked_by": "opencode",
        "tool": "shell",
        "operation": "execute",
        "action_id": "act-resume-1",
        "parameters": {"command": "rm -rf /tmp/resume-target", "cwd": "/tmp"},
    }


class ApprovedEvaluationCoverageTests(unittest.TestCase):
    def setUp(self):
        self.table = FakeTable()
        service.table = self.table
        self.token_table = FakeTokenTable()
        service.token_table = self.token_table
        self.store = service.AuditStore(self.table)
        self.auth = {"tenant_id": "demo", "token_id": "t1", "subject": "executor@demo.test"}
        self.action = base_action()
        self.hash = service.action_hash(self.action)

    def _status(self, result):
        return result.get("statusCode", 200)

    def _body(self, result):
        import json
        raw = result.get("body", "{}")
        return json.loads(raw) if isinstance(raw, str) else raw

    def _seed_approval(self, approval_id="appr-1", **overrides):
        approval = {
            "approval_id": approval_id,
            "tenant_id": "demo",
            "status": "approved",
            "action_id": "act-resume-1",
            "action_hash": self.hash,
            "action": dict(self.action),
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": 9999999999,
        }
        approval.update(overrides)
        self.store.put_approval(approval)
        return approval

    def _seed_evaluation(self):
        self.table.put_item(Item={
            "pk": "TENANT#demo",
            "sk": "EVENT#2026-01-01T00:00:00Z#act-resume-1",
            "item_type": "audit_event",
            "event_type": "action.evaluated",
            "tenant_id": "demo",
            "action_id": "act-resume-1",
            "action_hash": self.hash,
            "agent_id": "agent-1",
            "decision": "require_approval",
        })

    def _call(self, body, action=None, approval_id="appr-1"):
        return service.handle_approved_evaluation(
            body, action or self.action, self.store, approval_id, self.auth)

    def test_approval_not_found(self):
        """Line 2829: approval does not exist."""
        result = self._call({"action_hash": self.hash}, approval_id="missing")
        self.assertEqual(self._status(result), 404)
        self.assertEqual(self._body(result)["error"], "approval_not_found")

    def test_approval_tenant_mismatch(self):
        """Line 2831: approval tenant differs from the action tenant."""
        self._seed_approval(tenant_id="other-tenant")
        result = self._call({"action_hash": self.hash})
        self.assertEqual(self._status(result), 403)
        self.assertEqual(self._body(result)["error"], "approval_tenant_mismatch")

    def test_action_hash_required(self):
        """Line 2843: no action hash supplied in the resume request."""
        self._seed_approval()
        result = self._call({})
        self.assertEqual(self._status(result), 409)
        self.assertEqual(self._body(result)["error"], "approval_action_hash_required")

    def test_action_hash_mismatch(self):
        """Line 2845: supplied hash differs from the approved hash."""
        self._seed_approval()
        result = self._call({"action_hash": "sha256:wrong"})
        self.assertEqual(self._status(result), 409)
        self.assertEqual(self._body(result)["error"], "approval_action_mismatch")

    def test_action_id_mismatch(self):
        """Lines 2847-2855: action_id differs from the approved action_id."""
        self._seed_approval()
        action = dict(self.action)
        action["action_id"] = "different-action"
        result = self._call({"action_hash": self.hash}, action=action)
        self.assertEqual(self._status(result), 409)
        self.assertEqual(self._body(result)["error"], "approval_action_id_mismatch")

    def test_action_core_mismatch(self):
        """Line 2857: approval's stored action core differs from the request."""
        altered = dict(self.action)
        altered["parameters"] = {"command": "rm -rf /etc", "cwd": "/tmp"}
        self._seed_approval(action=altered)
        result = self._call({"action_hash": self.hash})
        self.assertEqual(self._status(result), 409)
        self.assertEqual(self._body(result)["error"], "approval_action_mismatch")

    def test_evaluation_not_found(self):
        """Line 2862: no matching prior evaluation for the action."""
        self._seed_approval()
        # No evaluation seeded.
        result = self._call({"action_hash": self.hash})
        self.assertEqual(self._status(result), 409)
        self.assertEqual(self._body(result)["error"], "approval_evaluation_not_found")

    def test_consume_race_returns_conflict(self):
        """Line 2871: consume_approval fails (concurrent consume) -> 409."""
        from unittest.mock import patch as _patch
        self._seed_approval()
        self._seed_evaluation()
        # The status check passes (approved), but the conditional consume loses
        # a race and returns None.
        with _patch.object(self.store, "consume_approval", return_value=None):
            result = self._call({"action_hash": self.hash})
        self.assertEqual(self._status(result), 409)
        self.assertEqual(self._body(result)["error"], "approval_already_consumed_or_revoked")

    def test_happy_path_resumes_allow(self):
        """Line 2872: valid resume returns allow with approval_resume=True."""
        self._seed_approval()
        self._seed_evaluation()
        result = self._call({"action_hash": self.hash})
        self.assertEqual(self._status(result), 200)
        body = self._body(result)
        self.assertEqual(body.get("decision"), "allow")
        self.assertTrue(body.get("approval_resume"))


if __name__ == "__main__":
    unittest.main()
