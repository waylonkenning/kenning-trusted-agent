"""Regression coverage for issue #323 Guard action and approval context."""

import unittest

from app import lambda_function as service
from app.guard import evaluate, normalise_action
from app.integration_adapters import normalise_integration_action
from tests.fixtures import FakeTable


class Bug323GuardContextTests(unittest.TestCase):
    def setUp(self):
        self.table = FakeTable()
        self.previous_table = service.table
        service.table = self.table
        self.store = service.AuditStore(self.table)
        self.auth = {
            "tenant_id": "demo",
            "token_id": "bug-323-test",
            "scopes": ["guard:evaluate", "audit:read", "approve:actions"],
        }

    def tearDown(self):
        service.table = self.previous_table

    def test_generic_cloud_shape_with_github_provider_is_normalised_before_detection(self):
        action = normalise_action(
            {
                "context": {"provider": "github"},
                "action": {
                    "tool": "cloud",
                    "operation": "update",
                    "target": "waylonkenning/kenning-trusted-agent/app/policy.py",
                    "parameters": {
                        "repository": "waylonkenning/kenning-trusted-agent",
                        "files": ["app/policy.py"],
                    },
                },
            }
        )
        result = evaluate(action)
        self.assertEqual(action["tool"], "github")
        self.assertEqual(action["provider"], "github")
        self.assertEqual(action["adapter"], "github")
        self.assertEqual(result["decision"], "allow")
        self.assertNotIn("PRIVILEGED_CLOUD_CHANGE", result["reason_codes"])
        self.assertNotIn("GITHUB_SCOPE_NOT_DECLARED", result["reason_codes"])

    def test_parameters_provider_also_selects_github_adapter(self):
        enriched = normalise_integration_action(
            {
                "tool": "cloud",
                "operation": "update_file",
                "target": "app/policy.py",
                "parameters": {
                    "provider": "github",
                    "repository": "acme/api",
                },
            }
        )
        self.assertEqual(enriched["tool"], "github")
        self.assertEqual(enriched["adapter"], "github")
        self.assertEqual(enriched["adapter_context"]["provider"], "github")

    def test_builtin_rule_and_supplied_agent_are_persisted_on_approval(self):
        payload = {
            "context": {
                "tenant_id": "demo",
                "environment": "development",
                "agent_id": "registered-file-agent",
                "invoked_by": "bug-323-test",
                "action_id": "bug-323-built-in-rule",
            },
            "action": {
                "tool": "shell",
                "parameters": {"command": "rm -rf /tmp/builtin-triggering-rule-test"},
            },
        }
        service.apply_tenant_runtime(payload, self.auth, self.store)
        decision = service.evaluate_and_record(payload, self.store)

        self.assertEqual(decision["decision"], "require_approval")
        approval = decision["approval"]
        self.assertEqual(approval["agent_id"], "registered-file-agent")
        triggering = approval["triggering_rule"]
        self.assertIsNotNone(triggering)
        self.assertEqual(triggering["rule_source"], "kenning")
        self.assertEqual(triggering["selected_rule"]["policy_id"], "kenning-starter-rules")
        self.assertEqual(triggering["selected_rule"]["rule_id"], "DESTRUCTIVE_FILESYSTEM_OPERATION")
        self.assertEqual(triggering["selected_rule"]["reason_code"], "DESTRUCTIVE_FILESYSTEM_OPERATION")
        self.assertTrue(any(match["rule_id"] == "DESTRUCTIVE_FILESYSTEM_OPERATION" for match in triggering["matched_rules"]))

    def test_missing_agent_identity_uses_explicit_unregistered_fallback(self):
        action = normalise_action(
            {
                "action": {
                    "tool": "shell",
                    "parameters": {"command": "rm -rf /tmp/unregistered-agent-test"},
                }
            }
        )
        self.assertEqual(action["agent_id"], "unregistered-agent")


if __name__ == "__main__":
    unittest.main()
