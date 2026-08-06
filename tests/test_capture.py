import unittest
from decimal import Decimal
from unittest.mock import patch

from app.capture import (
    _canonical_default,
    _string_list,
    apply_capture_policy,
    capture_action,
    capture_policy_summary,
    normalise_capture_policy,
)
from app.guard import build_receipt, normalise_action, verify_receipt
from app.proof import sha256_value


class CapturePolicyTests(unittest.TestCase):
    def action(self):
        return {
            "tool": "sql",
            "target": "customer-db",
            "parameters": {
                "statement": "SELECT * FROM customers WHERE email = 'person@example.org'",
                "command": "curl https://example.org --header 'X-Test-Header: raw-secret'",
            },
            "original_action": {
                "tool": "sql",
                "parameters": {
                    "statement": "SELECT * FROM customers WHERE email = 'person@example.org'",
                    "command": "curl https://example.org --header 'X-Test-Header: raw-secret'",
                },
            },
        }

    def test_fields_are_redacted_or_hashed_in_both_action_views(self):
        policy = normalise_capture_policy(
            {
                "store_original_action": True,
                "redact_fields": ["parameters.command"],
                "hash_fields": ["parameters.statement"],
            }
        )
        captured = capture_action(self.action(), policy)
        self.assertEqual(captured["parameters"]["command"], "[REDACTED_BY_TENANT_POLICY]")
        self.assertEqual(captured["original_action"]["parameters"]["command"], "[REDACTED_BY_TENANT_POLICY]")
        self.assertTrue(captured["parameters"]["statement"].startswith("sha256:"))
        self.assertEqual(captured["parameters"]["statement"], captured["original_action"]["parameters"]["statement"])
        self.assertNotIn("raw-secret", repr(captured))

    def test_original_action_can_be_removed_and_strings_are_bounded(self):
        captured = capture_action(
            {"parameters": {"note": "x" * 1000}, "original_action": {"note": "x" * 1000}},
            {"store_original_action": False, "max_field_length": 64},
        )
        self.assertNotIn("original_action", captured)
        self.assertTrue(captured["parameters"]["note"].endswith("...[TRUNCATED]"))
        self.assertLessEqual(len(captured["parameters"]["note"]), 78)

    def test_overlapping_fields_and_invalid_values_are_rejected(self):
        with self.assertRaises(ValueError):
            normalise_capture_policy({"redact_fields": ["parameters"], "hash_fields": ["parameters.statement"]})
        with self.assertRaises(ValueError):
            normalise_capture_policy({"redact_fields": ["parameters.command;drop"]})
        with self.assertRaises(ValueError):
            normalise_capture_policy({"max_field_length": 32})
        with self.assertRaises(ValueError):
            normalise_capture_policy({"redact_fields": {"field": "parameters.command"}})

    def test_captured_receipt_is_resealed(self):
        action = self.action()
        signed_receipt = build_receipt(
            normalise_action({"action": action}),
            "require_approval",
            approval={"action": action},
            signing_secret="capture-secret",
        )
        record = {
            "action": action,
            "trusted_action_receipt": signed_receipt,
        }
        with patch.dict("os.environ", {"RECEIPT_SIGNING_SECRET": "capture-secret"}, clear=False):
            captured = apply_capture_policy(record, {"store_original_action": False, "hash_fields": ["parameters.statement"]})
        receipt = captured["trusted_action_receipt"]
        unsigned = {key: value for key, value in receipt.items() if key not in {"integrity", "signature"}}
        self.assertEqual(receipt["integrity"]["record_hash"], sha256_value(unsigned))
        self.assertTrue(verify_receipt(receipt, signing_secret="capture-secret")["valid"])

    # --- _string_list edge cases ---

    def test_string_list_returns_empty_for_non_list(self):
        self.assertEqual(_string_list(123), [])
        self.assertEqual(_string_list(None), [])

    def test_string_list_wraps_string(self):
        self.assertEqual(_string_list("single"), ["single"])

    # --- _normalise_fields edge cases ---

    def test_normalise_fields_rejects_non_string_non_list(self):
        with self.assertRaises(ValueError):
            normalise_capture_policy({"redact_fields": 123})

    def test_normalise_fields_rejects_duplicates(self):
        with self.assertRaises(ValueError):
            normalise_capture_policy({"redact_fields": ["parameters.command", "parameters.command"]})

    def test_normalise_fields_rejects_invalid_pattern(self):
        with self.assertRaises(ValueError):
            normalise_capture_policy({"hash_fields": ["field-with-dash"]})

    def test_normalise_fields_rejects_too_many(self):
        with self.assertRaises(ValueError):
            normalise_capture_policy({"redact_fields": [f"field_{i}" for i in range(101)]})

    # --- normalise_capture_policy edge cases ---

    def test_normalise_rejects_non_bool_store_original(self):
        with self.assertRaises(ValueError):
            normalise_capture_policy({"store_original_action": "yes"})

    def test_normalise_rejects_bool_max_field_length(self):
        with self.assertRaises(ValueError):
            normalise_capture_policy({"max_field_length": True})

    def test_normalise_rejects_non_int_max_field_length(self):
        with self.assertRaises(ValueError):
            normalise_capture_policy({"max_field_length": "abc"})

    def test_normalise_rejects_non_dict(self):
        with self.assertRaises(ValueError):
            normalise_capture_policy("not-a-dict")

    def test_normalise_none_returns_default(self):
        policy = normalise_capture_policy(None)
        self.assertTrue(policy["store_original_action"])
        self.assertEqual(policy["redact_fields"], [])
        self.assertEqual(policy["hash_fields"], [])
        self.assertEqual(policy["max_field_length"], 4096)

    def test_normalise_fields_none_returns_empty(self):
        policy = normalise_capture_policy({"redact_fields": None, "hash_fields": None})
        self.assertEqual(policy["redact_fields"], [])
        self.assertEqual(policy["hash_fields"], [])

    def test_normalise_rejects_reverse_overlap(self):
        with self.assertRaises(ValueError):
            normalise_capture_policy({"redact_fields": ["parameters.statement"], "hash_fields": ["parameters"]})

    # --- capture_policy_summary ---

    def test_capture_policy_summary(self):
        summary = capture_policy_summary({"redact_fields": ["parameters.command"], "hash_fields": ["parameters.statement"]})
        self.assertTrue(summary["store_original_action"])
        self.assertEqual(summary["redact_fields"], ["parameters.command"])
        self.assertEqual(summary["hash_fields"], ["parameters.statement"])
        self.assertEqual(summary["max_field_length"], 4096)

    # --- _canonical_default ---

    def test_canonical_default_handles_decimal(self):
        self.assertEqual(_canonical_default(Decimal("19.99")), 19.99)

    def test_canonical_default_rejects_unknown_type(self):
        with self.assertRaises(TypeError):
            _canonical_default(object())

    # --- capture_action edge cases ---

    def test_capture_action_non_dict(self):
        self.assertEqual(capture_action("not-a-dict"), "not-a-dict")
        self.assertIsNone(capture_action(None))

    def test_hash_value_non_string(self):
        captured = capture_action(
            {"parameters": {"config": {"key": "value"}}},
            {"hash_fields": ["parameters.config"]},
        )
        self.assertTrue(captured["parameters"]["config"].startswith("sha256:"))

    def test_hash_value_with_decimal(self):
        captured = capture_action(
            {"parameters": {"amount": Decimal("19.99")}},
            {"hash_fields": ["parameters.amount"]},
        )
        self.assertTrue(captured["parameters"]["amount"].startswith("sha256:"))

    def test_hash_field_not_present_is_noop(self):
        captured = capture_action(
            {"parameters": {"command": "secret"}},
            {"hash_fields": ["nonexistent.field"]},
        )
        self.assertEqual(captured["parameters"]["command"], "secret")

    def test_truncate_list(self):
        captured = capture_action(
            {"parameters": {"items": ["x" * 100, "short"]}},
            {"max_field_length": 64},
        )
        self.assertTrue(captured["parameters"]["items"][0].endswith("...[TRUNCATED]"))
        self.assertEqual(captured["parameters"]["items"][1], "short")

    def test_truncate_nested_dict(self):
        captured = capture_action(
            {"parameters": {"nested": {"deep": "x" * 100}}},
            {"max_field_length": 64},
        )
        self.assertTrue(captured["parameters"]["nested"]["deep"].endswith("...[TRUNCATED]"))

    def test_apply_path_original_action_prefix(self):
        action = {
            "parameters": {"command": "secret"},
            "original_action": {"parameters": {"command": "secret"}},
        }
        captured = capture_action(action, {"redact_fields": ["original_action.parameters.command"]})
        self.assertEqual(captured["original_action"]["parameters"]["command"], "[REDACTED_BY_TENANT_POLICY]")
        self.assertEqual(captured["parameters"]["command"], "secret")

    def test_set_path_missing_intermediate_is_noop(self):
        captured = capture_action(
            {"parameters": {"command": "secret"}},
            {"redact_fields": ["nonexistent.deep.field"]},
        )
        self.assertEqual(captured["parameters"]["command"], "secret")

    # --- apply_capture_policy edge cases ---

    def test_apply_capture_policy_non_dict(self):
        self.assertEqual(apply_capture_policy("not-a-dict"), "not-a-dict")

    def test_apply_capture_policy_with_approvals(self):
        action = {"parameters": {"command": "secret"}}
        record = {
            "action": action,
            "approvals": [{"action": dict(action)}],
        }
        captured = apply_capture_policy(record, {"redact_fields": ["parameters.command"]})
        self.assertEqual(captured["action"]["parameters"]["command"], "[REDACTED_BY_TENANT_POLICY]")
        self.assertEqual(captured["approvals"][0]["action"]["parameters"]["command"], "[REDACTED_BY_TENANT_POLICY]")

    def test_apply_capture_policy_record_without_action(self):
        record = {"metadata": "info"}
        captured = apply_capture_policy(record, {"redact_fields": ["parameters.command"]})
        self.assertEqual(captured["metadata"], "info")
        self.assertIn("capture_policy", captured)


if __name__ == "__main__":
    unittest.main()
