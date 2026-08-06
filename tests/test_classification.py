"""Classification-aware action, policy, and audit coverage for #274."""

from __future__ import annotations

import json
import unittest
import urllib.error
import urllib.request
import uuid

from app.guard import evaluate, normalise_action
from app.policy import apply_policies, build_policy_record, rule_matches
from tests.local_api_harness import LocalApiFixture


class ClassificationUnitTests(unittest.TestCase):
    def test_action_defaults_and_normalises_classification(self):
        defaulted = normalise_action({"action": {"tool": "shell", "parameters": {"command": "ls"}}})
        normalised = normalise_action({"action": {"tool": "shell", "classification": " RESTRICTED ", "parameters": {"command": "ls"}}})

        self.assertEqual(defaulted["classification"], "unclassified")
        self.assertEqual(normalised["classification"], "restricted")
        self.assertEqual(evaluate(normalised)["action_classification"], "restricted")

    def test_invalid_classification_lists_allowed_values(self):
        with self.assertRaisesRegex(ValueError, "classification must be one of:.*secret"):
            normalise_action({"action": {"tool": "shell", "classification": "top-secret", "parameters": {}}})

    def test_classification_policy_uses_ordinal_threshold(self):
        policy = build_policy_record(
            {
                "policy_id": "classification-policy",
                "name": "Restricted data review",
                "rules": [
                    {
                        "rule_id": "restricted-review",
                        "decision": "require_approval",
                        "conditions": {"classification_at_least": "restricted"},
                    }
                ],
            },
            "demo",
            1,
        )
        below = normalise_action({"action": {"tool": "shell", "classification": "sensitive", "parameters": {}}})
        at_threshold = normalise_action({"action": {"tool": "shell", "classification": "restricted", "parameters": {}}})
        above = normalise_action({"action": {"tool": "shell", "classification": "secret", "parameters": {}}})

        self.assertFalse(rule_matches(policy["rules"][0], below))
        self.assertTrue(rule_matches(policy["rules"][0], at_threshold))
        self.assertTrue(rule_matches(policy["rules"][0], above))
        applied = apply_policies(evaluate(below), at_threshold, [policy])
        self.assertEqual(applied["decision"], "require_approval")
        self.assertEqual(applied["policy_matches"][0]["rule_id"], "restricted-review")

    def test_invalid_classification_policy_threshold_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "classification_at_least must be one of"):
            build_policy_record(
                {
                    "name": "Invalid classification policy",
                    "rules": [
                        {
                            "decision": "deny",
                            "conditions": {"classification_at_least": "top-secret"},
                        }
                    ],
                },
                "demo",
                1,
            )


class ClassificationApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = LocalApiFixture(tenant_id=f"classification-{uuid.uuid4().hex[:8]}")
        cls.state = cls.fixture.start()

    @classmethod
    def tearDownClass(cls):
        cls.fixture.stop()

    @classmethod
    def request(cls, path: str, method: str = "GET", payload: dict | None = None):
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(f"{cls.state['api_url']}{path}", data=data, method=method)
        request.add_header("Authorization", f"Bearer {cls.state['pat']}")
        request.add_header("Accept", "application/json")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read().decode("utf-8"))

    def test_evaluation_and_audit_export_include_classification(self):
        action_id = f"classification-action-{uuid.uuid4().hex[:10]}"
        status, result = self.request(
            "/v1/actions/evaluate",
            "POST",
            {
                "context": {
                    "tenant_id": self.state["tenant_id"],
                    "environment": "development",
                    "agent_id": "classification-test-agent",
                    "invoked_by": "classification-test",
                    "action_id": action_id,
                },
                "action": {"tool": "shell", "classification": "restricted", "parameters": {"command": "ls"}},
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(result["action_classification"], "restricted")
        self.assertEqual(result["action"]["classification"], "restricted")

        audit_status, audit = self.request(f"/v1/audit?tenant_id={self.state['tenant_id']}&limit=100")
        self.assertEqual(audit_status, 200)
        event = next(item for item in audit["events"] if item.get("action_id") == action_id)
        self.assertEqual(event["action_classification"], "restricted")

        export_status, export = self.request(f"/v1/audit/export?tenant_id={self.state['tenant_id']}&format=json&limit=100")
        self.assertEqual(export_status, 200)
        exported = next(item for item in export["events"] if item.get("action_id") == action_id)
        self.assertEqual(exported["action_classification"], "restricted")

    def test_invalid_classification_returns_bad_request(self):
        status, body = self.request(
            "/v1/actions/evaluate",
            "POST",
            {"action": {"tool": "shell", "classification": "top-secret", "parameters": {"command": "ls"}}},
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "invalid_request")
        self.assertIn("secret", body["message"])


if __name__ == "__main__":
    unittest.main()
