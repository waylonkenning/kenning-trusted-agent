"""Targeted branch coverage for _apply_identity_authorization require_approval
path and handle_approval idempotent/conditional-check paths (#271).
"""

import json
import unittest
from unittest.mock import patch

from app import lambda_function as service
from tests.test_federation import FakeTable, FakeTokenTable


class IdentityAuthorizationCoverageTests(unittest.TestCase):
    def setUp(self):
        self.table = FakeTable()
        service.table = self.table
        self.token_table = FakeTokenTable()
        service.token_table = self.token_table
        self.store = service.AuditStore(self.table)

    def _seed_agent(self, **overrides):
        agent = {
            "agent_id": "agent-1",
            "tenant_id": "demo",
            "status": "active",
            "maximum_authority": "high",
            "allowed_environments": ["development"],
            "approved_tools": ["shell"],
            "may": ["shell:*"],
            "may_not": [],
            "conditions": {"human_approval_required": True},
            "delegation_chain": ["root"],
            "delegation_depth": 0,
        }
        agent.update(overrides)
        self.table.put_item(Item={
            "pk": self.store._agent_pk("agent-1", "demo"),
            "sk": "METADATA",
            "item_type": "agent",
            **agent,
        })
        return agent

    def _base_action(self):
        return {
            "tenant_id": "demo",
            "environment": "development",
            "agent_id": "agent-1",
            "invoked_by": "opencode",
            "tool": "shell",
            "operation": "execute",
            "action_id": "act-1",
            "parameters": {"command": "ls", "cwd": "/tmp"},
        }

    def test_identity_require_approval_escalates_allow(self):
        """Lines 2496-2507: identity require_approval escalates an allow decision."""
        self._seed_agent()
        decision = {
            "decision": "allow",
            "risk": "low",
            "risk_score": 10,
            "reason_codes": [],
            "reasons": [],
        }
        service._apply_identity_authorization(decision, self._base_action(), self.store, {})
        self.assertEqual(decision["decision"], "require_approval")
        self.assertEqual(decision["risk"], "high")
        self.assertGreaterEqual(decision["risk_score"], 80)
        self.assertIn("IDENTITY_APPROVAL_REQUIRED", decision["reason_codes"])

    def test_identity_require_approval_escalates_warn(self):
        """Lines 2496-2507: identity require_approval also escalates a warn decision."""
        self._seed_agent()
        decision = {
            "decision": "warn",
            "risk": "medium",
            "risk_score": 40,
            "reason_codes": [],
            "reasons": [],
        }
        service._apply_identity_authorization(decision, self._base_action(), self.store, {})
        self.assertEqual(decision["decision"], "require_approval")

    def test_identity_not_registered_no_change(self):
        """Line 2479-2480: unregistered agent leaves the decision unchanged."""
        decision = {"decision": "allow", "risk": "low", "risk_score": 10,
                    "reason_codes": [], "reasons": []}
        service._apply_identity_authorization(decision, self._base_action(), self.store, {})
        self.assertEqual(decision["decision"], "allow")


class HandleApprovalIdempotencyCoverageTests(unittest.TestCase):
    """Covers handle_approval lines 4606 (idempotent re-decision) and
    4682-4685 (conditional-check failure on update)."""

    def setUp(self):
        self.table = FakeTable()
        service.table = self.table
        self.token_table = FakeTokenTable()
        service.token_table = self.token_table
        self.store = service.AuditStore(self.table)

    def _status(self, result):
        return result.get("statusCode", 200)

    def _body(self, result):
        raw = result.get("body", "{}")
        return json.loads(raw) if isinstance(raw, str) else raw

    def _seed_approval(self, status="pending", approver=None, approver_principal=None, **overrides):
        approval = {
            "approval_id": "appr-1",
            "tenant_id": "demo",
            "run_id": "run-1",
            "action_id": "act-1",
            "agent_id": "agent-1",
            "status": status,
            "approver": approver,
            "approver_principal": approver_principal,
            "action_hash": "sha256:abc",
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": 9999999999,
        }
        approval.update(overrides)
        self.store.put_approval(approval)
        return approval

    def _auth(self):
        return {"tenant_id": "demo", "token_id": "t1", "subject": "approver@demo.test",
                "scopes": ["approve:actions"]}

    def test_idempotent_reapprove_same_approver(self):
        """Line 4606: re-approving an already-approved approval by the same approver -> 200."""
        # PAT auth resolves the principal to the token_id ("t1").
        self._seed_approval(status="approved", approver="t1",
                            approver_principal="t1")
        event = {"rawPath": "/v1/approvals/appr-1/decision",
                 "requestContext": {"http": {"method": "POST"}},
                 "headers": {}}
        body = {"decision": "approve"}
        result = service.handle_approval(event, body, "appr-1", self._auth())
        self.assertEqual(self._status(result), 200)
        self.assertIn("approval", self._body(result))

    def test_conditional_check_failure_returns_conflict(self):
        """Lines 4682-4684: update_approval raises a conditional-check failure -> 409."""
        self._seed_approval(status="pending")
        event = {"rawPath": "/v1/approvals/appr-1/decision",
                 "requestContext": {"http": {"method": "POST"}},
                 "headers": {}}
        body = {"decision": "approve"}
        # Simulate a concurrent decision: the conditional update fails.
        # _is_conditional_check_failure inspects exc.response, so a plain
        # exception carrying that attribute is sufficient (no botocore needed).
        class _ConditionalCheckFailed(Exception):
            response = {"Error": {"Code": "ConditionalCheckFailedException", "Message": "cond"}}
        # store() builds a fresh AuditStore, so patch the class method.
        with patch.object(service.AuditStore, "update_approval", side_effect=_ConditionalCheckFailed("cond")):
            result = service.handle_approval(event, body, "appr-1", self._auth())
        self.assertEqual(self._status(result), 409)
        self.assertEqual(self._body(result)["error"], "approval_expired_or_already_decided")


if __name__ == "__main__":
    unittest.main()
