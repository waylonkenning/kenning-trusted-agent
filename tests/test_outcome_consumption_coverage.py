"""Targeted branch coverage for handle_outcome approval-consumption and
idempotency paths in app/lambda_function.py (#271).

Covers: consumed-approval mismatch (require_approval and optional branches),
optional approval not found, consume_approval race fallback (with and without
an existing outcome), and the put_event duplicate-delivery fallback.
"""

import json
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


class OutcomeConsumptionCoverageTests(unittest.TestCase):
    def setUp(self):
        self.table = FakeTable()
        service.table = self.table
        self.token_table = FakeTokenTable()
        service.token_table = self.token_table
        self.auth = {"tenant_id": "demo", "token_id": "t1", "subject": "agent@example.com",
                     "agent_id": "agent-1", "scopes": ["actions:write"]}

    def _status(self, result):
        return result.get("statusCode", 200)

    def _body(self, result):
        raw = result.get("body", "{}")
        return json.loads(raw) if isinstance(raw, str) else raw

    def _seed_evaluation(self, action_id="act-1", decision="allow", action_hash="hash123",
                         agent_id="agent-1"):
        self.table.put_item(Item={
            "pk": "TENANT#demo",
            "sk": f"EVENT#2026-01-01T00:00:00Z#{action_id}",
            "item_type": "audit_event",
            "event_type": "action.evaluated",
            "tenant_id": "demo",
            "action_id": action_id,
            "decision": decision,
            "action_hash": action_hash,
            "agent_id": agent_id,
        })

    def _seed_approval(self, approval_id="appr-1", action_id="act-1", action_hash="hash123",
                       status="approved", **extra):
        item = {
            "pk": f"APPROVAL#{approval_id}", "sk": "METADATA",
            "approval_id": approval_id, "tenant_id": "demo",
            "action_id": action_id, "action_hash": action_hash,
            "status": status, "created_at": "2026-01-01T00:00:00Z",
            "expires_at": 9999999999,
        }
        item.update(extra)
        self.table.put_item(Item=item)

    def _seed_outcome(self, action_id="act-1", action_hash="hash123", status="success"):
        self.table.put_item(Item={
            "pk": "TENANT#demo",
            "sk": f"EVENT#IDEMPOTENT#action-outcome:demo:{action_id}",
            "item_type": "audit_event",
            "event_type": "action.outcome",
            "tenant_id": "demo",
            "action_id": action_id,
            "action_hash": action_hash,
            "status": status,
            "approval_id": None,
            "idempotency_key": f"action-outcome:demo:{action_id}",
        })

    def _post_outcome(self, action_id, body):
        event = make_event("POST", f"/v1/actions/{action_id}/outcome", json.dumps(body))
        with patch.object(service, "authenticate", return_value=(self.auth, None)):
            return service.lambda_handler(event, None)

    # --- require_approval consumed-mismatch (line 4795) --------------------

    def test_require_approval_consumed_by_different_action(self):
        """Line 4795: approval consumed by a different action_id."""
        self._seed_evaluation(decision="require_approval")
        self._seed_approval(status="consumed", consumed_action_id="OTHER-action",
                            consumed_action_hash="hash123")
        result = self._post_outcome("act-1", {
            "status": "success", "action_hash": "hash123", "approval_id": "appr-1",
        })
        self.assertEqual(self._status(result), 409)
        self.assertEqual(self._body(result)["error"], "approval_already_consumed_or_revoked")

    # --- optional approval branches (lines 4799, 4802-4806) ----------------

    def test_optional_approval_not_found(self):
        """Line 4799: allow decision but supplied approval does not exist."""
        self._seed_evaluation(decision="allow")
        result = self._post_outcome("act-1", {
            "status": "success", "action_hash": "hash123", "approval_id": "missing-approval",
        })
        self.assertEqual(self._status(result), 403)
        self.assertEqual(self._body(result)["error"], "approval_not_found_or_tenant_mismatch")

    def test_optional_approval_consumed_by_different_action(self):
        """Lines 4802-4806: optional approval consumed by a different action."""
        self._seed_evaluation(decision="allow")
        self._seed_approval(status="consumed", consumed_action_id="OTHER-action",
                            consumed_action_hash="hash123")
        result = self._post_outcome("act-1", {
            "status": "success", "action_hash": "hash123", "approval_id": "appr-1",
        })
        self.assertEqual(self._status(result), 409)
        self.assertEqual(self._body(result)["error"], "approval_already_consumed_or_revoked")

    # --- consume_approval race fallback (lines 4840-4843) ------------------

    def test_consume_race_with_existing_outcome(self):
        """Lines 4840-4842: consume fails but a concurrent outcome appears -> idempotent 202."""
        self._seed_evaluation(decision="require_approval")
        self._seed_approval(status="approved")
        real_store = service.store()
        concurrent_outcome = {
            "event_type": "action.outcome", "tenant_id": "demo", "action_id": "act-1",
            "action_hash": "hash123", "status": "success", "approval_id": "appr-1",
        }
        # First get_action_outcome (pre-check at line 4772) sees nothing; the
        # second (race fallback at line 4840) sees a concurrently written outcome.
        with patch.object(service, "store", return_value=real_store), \
             patch.object(real_store, "consume_approval", return_value=None), \
             patch.object(real_store, "get_action_outcome",
                          side_effect=[None, concurrent_outcome]):
            result = self._post_outcome("act-1", {
                "status": "success", "action_hash": "hash123", "approval_id": "appr-1",
            })
        self.assertEqual(self._status(result), 202)
        self.assertTrue(self._body(result).get("idempotent"))

    def test_consume_race_without_existing_outcome(self):
        """Line 4843: consume fails and no outcome exists -> 409."""
        self._seed_evaluation(decision="require_approval")
        self._seed_approval(status="approved")
        real_store = service.store()
        with patch.object(service, "store", return_value=real_store), \
             patch.object(real_store, "consume_approval", return_value=None), \
             patch.object(real_store, "get_action_outcome",
                          side_effect=[None, None]):
            result = self._post_outcome("act-1", {
                "status": "success", "action_hash": "hash123", "approval_id": "appr-1",
            })
        self.assertEqual(self._status(result), 409)
        self.assertEqual(self._body(result)["error"], "approval_already_consumed_or_revoked")

    # --- put_event duplicate fallback (lines 4847-4849) --------------------

    def test_put_event_duplicate_with_existing_outcome(self):
        """Lines 4847-4849: put_event reports duplicate; existing outcome returned."""
        self._seed_evaluation(decision="allow")
        self._seed_outcome()
        result = self._post_outcome("act-1", {
            "status": "success", "action_hash": "hash123",
        })
        self.assertEqual(self._status(result), 202)
        self.assertTrue(self._body(result).get("idempotent"))


if __name__ == "__main__":
    unittest.main()
