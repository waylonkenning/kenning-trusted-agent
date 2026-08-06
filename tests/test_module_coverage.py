"""Targeted tests to close remaining module coverage gaps (#270).

Covers: audit.py filter validation, integration_adapters.py email
normalisation, policy.py approval_chain validation, starter_rules.py
rule validation edge cases, tenant.py product validation.
"""

import unittest

from app import audit
from app import integration_adapters
from app import policy
from app import starter_rules
from app import tenant


class AuditFilterTests(unittest.TestCase):
    def test_normalise_filters_time_and_resource_fields(self):
        """Lines 37, 40-41: start_time, end_time, resource pass through."""
        filters = audit.normalise_filters({
            "start_time": "2026-01-01T00:00:00Z",
            "end_time": "2026-01-02T00:00:00Z",
            "resource": "agent-1",
        })
        self.assertEqual(filters["start_time"], "2026-01-01T00:00:00Z")
        self.assertEqual(filters["end_time"], "2026-01-02T00:00:00Z")
        self.assertEqual(filters["resource"], "agent-1")

    def test_normalise_filters_invalid_limit(self):
        """Lines 40-41: non-integer limit raises ValueError."""
        with self.assertRaises(ValueError):
            audit.normalise_filters({"limit": "abc"})

    def test_event_matches_receipt_id(self):
        """Lines 61, 63: receipt_id filter matches nested receipt dict."""
        event = {"receipt": {"receipt_id": "r-123"}, "agent_id": "a1"}
        self.assertTrue(audit.event_matches(event, {"receipt_id": "r-123"}))
        self.assertFalse(audit.event_matches(event, {"receipt_id": "wrong"}))

    def test_event_matches_time_range(self):
        """Lines 67-78: start_time and end_time filtering."""
        event = {"created_at": "2026-01-15T12:00:00Z", "agent_id": "a1"}
        self.assertTrue(audit.event_matches(event, {"start_time": "2026-01-01T00:00:00Z"}))
        self.assertFalse(audit.event_matches(event, {"start_time": "2026-02-01T00:00:00Z"}))
        self.assertTrue(audit.event_matches(event, {"end_time": "2026-02-01T00:00:00Z"}))
        self.assertFalse(audit.event_matches(event, {"end_time": "2026-01-01T00:00:00Z"}))

    def test_event_matches_resource_search(self):
        """Lines 67-78: resource filter searches action/target/resource JSON."""
        event = {"action": {"tool": "shell", "parameters": {"command": "rm -rf /data"}}, "agent_id": "a1"}
        self.assertTrue(audit.event_matches(event, {"resource": "shell"}))
        self.assertTrue(audit.event_matches(event, {"resource": "rm -rf"}))
        self.assertFalse(audit.event_matches(event, {"resource": "nonexistent"}))


class IntegrationAdapterTests(unittest.TestCase):
    def test_normalise_email_recipients_none(self):
        """Line 35: None returns empty list."""
        self.assertEqual(integration_adapters._normalise_email_recipients(None), [])

    def test_normalise_email_recipients_empty_string(self):
        """Line 35: empty string returns empty list."""
        self.assertEqual(integration_adapters._normalise_email_recipients(""), [])

    def test_normalise_email_recipients_non_string_non_list(self):
        """Line 40: non-string non-list wraps in list."""
        self.assertEqual(integration_adapters._normalise_email_recipients(42), [42])


class PolicyValidationTests(unittest.TestCase):
    def test_approval_chain_not_a_list(self):
        """Line 60: non-list raises ValueError."""
        with self.assertRaises(ValueError):
            policy.normalise_approval_chain("not-a-list")

    def test_approval_chain_too_many_steps(self):
        """Line 62: exceeding MAX_APPROVER_GROUPS (50) raises ValueError."""
        steps = [{"approver_groups": ["admin"]} for _ in range(51)]
        with self.assertRaises(ValueError):
            policy.normalise_approval_chain(steps)

    def test_approval_chain_step_not_dict(self):
        """Line 66: non-dict step raises ValueError."""
        with self.assertRaises(ValueError):
            policy.normalise_approval_chain(["not-a-dict"])

    def test_approval_chain_label_too_long(self):
        """Line 70: label exceeding max length raises ValueError."""
        with self.assertRaises(ValueError):
            policy.normalise_approval_chain([{"label": "x" * 300, "approver_groups": ["admin"]}])


class StarterRulesValidationTests(unittest.TestCase):
    def test_clean_text_too_long(self):
        """Line 94: text exceeding maximum raises ValueError."""
        with self.assertRaises(ValueError):
            starter_rules._clean_text("x" * 300, "test_field", 256)

    def test_groups_too_many(self):
        """Line 105: more than 50 groups raises ValueError."""
        with self.assertRaises(ValueError):
            starter_rules._groups([f"group-{i}" for i in range(51)])

    def test_normalise_not_a_list(self):
        """Line 114: non-list raises ValueError."""
        with self.assertRaises(ValueError):
            starter_rules.normalise_starter_rules("not-a-list")

    def test_normalise_too_many_rules(self):
        """Line 116: exceeding MAX_STARTER_RULES (100) raises ValueError."""
        rules = [{"rule_id": f"r{i}", "decision": "deny", "kind": "custom", "conditions": {"tool": "shell"}} for i in range(101)]
        with self.assertRaises(ValueError):
            starter_rules.normalise_starter_rules(rules)

    def test_normalise_rule_not_dict(self):
        """Line 123: non-dict rule raises ValueError."""
        with self.assertRaises(ValueError):
            starter_rules.normalise_starter_rules(["not-a-dict"])

    def test_normalise_missing_rule_id(self):
        """Line 126: missing rule_id raises ValueError."""
        with self.assertRaises(ValueError):
            starter_rules.normalise_starter_rules([{"decision": "deny"}])

    def test_normalise_duplicate_rule_id(self):
        """Line 128: duplicate rule_id raises ValueError."""
        with self.assertRaises(ValueError):
            starter_rules.normalise_starter_rules([
                {"rule_id": "r1", "decision": "deny", "kind": "custom", "conditions": {"tool": "shell"}},
                {"rule_id": "r1", "decision": "deny", "kind": "custom", "conditions": {"tool": "shell"}},
            ])

    def test_normalise_invalid_kind(self):
        """Line 134: invalid kind raises ValueError."""
        with self.assertRaises(ValueError):
            starter_rules.normalise_starter_rules([{"rule_id": "r1", "decision": "deny", "kind": "bogus"}])

    def test_normalise_builtin_unknown_reason_code(self):
        """Line 136: builtin with unknown reason_code raises ValueError."""
        with self.assertRaises(ValueError):
            starter_rules.normalise_starter_rules([{"rule_id": "r1", "decision": "deny", "kind": "builtin", "reason_code": "UNKNOWN_CODE"}])

    def test_normalise_invalid_decision(self):
        """Line 142: invalid decision raises ValueError."""
        with self.assertRaises(ValueError):
            starter_rules.normalise_starter_rules([{"rule_id": "r1", "decision": "bogus", "kind": "custom", "conditions": {"tool": "shell"}}])

    def test_normalise_enabled_not_boolean(self):
        """Line 145: enabled not a boolean raises ValueError."""
        with self.assertRaises(ValueError):
            starter_rules.normalise_starter_rules([{"rule_id": "r1", "decision": "deny", "kind": "custom", "conditions": {"tool": "shell"}, "enabled": "yes"}])

    def test_normalise_conditions_not_dict(self):
        """Line 134: non-dict conditions raises ValueError."""
        with self.assertRaises(ValueError):
            starter_rules.normalise_starter_rules([{"rule_id": "r1", "decision": "deny", "conditions": "bad"}])

    def test_normalise_rule_id_too_long(self):
        """Line 136: rule_id exceeding max raises ValueError."""
        with self.assertRaises(ValueError):
            starter_rules.normalise_starter_rules([{"rule_id": "x" * 200, "decision": "deny"}])

    def test_normalise_name_too_long(self):
        """Line 139: name exceeding max raises ValueError."""
        with self.assertRaises(ValueError):
            starter_rules.normalise_starter_rules([{"rule_id": "r1", "decision": "deny", "name": "x" * 300}])

    def test_normalise_reason_too_long(self):
        """Line 142: reason exceeding max raises ValueError."""
        with self.assertRaises(ValueError):
            starter_rules.normalise_starter_rules([{"rule_id": "r1", "decision": "deny", "reason": "x" * 600}])

    def test_normalise_description_too_long(self):
        """Line 145: description exceeding max raises ValueError."""
        with self.assertRaises(ValueError):
            starter_rules.normalise_starter_rules([{"rule_id": "r1", "decision": "deny", "description": "x" * 600}])

    def test_custom_starter_policy_with_groups_and_action(self):
        """Lines 184, 186: approver_groups and recommended_action propagated."""
        rules = [{
            "rule_id": "r1",
            "kind": "custom",
            "enabled": True,
            "decision": "require_approval",
            "conditions": {"tool": "shell"},
            "approver_groups": ["security"],
            "recommended_action": {"notify": "ops"},
        }]
        result = starter_rules.custom_starter_policy(rules, "demo", 1)
        self.assertIsNotNone(result)
        matched = result["rules"][0]
        self.assertEqual(matched["approver_groups"], ["security"])
        self.assertEqual(matched["recommended_action"], {"notify": "ops"})


class TenantValidationTests(unittest.TestCase):
    def test_enabled_products_not_a_list(self):
        """Line 99: non-list raises ValueError."""
        with self.assertRaises(ValueError):
            tenant.normalise_enabled_products("not-a-list")


if __name__ == "__main__":
    unittest.main()
