import unittest

from app.guard import evaluate, normalise_action
from app.policy import (
    apply_policies,
    build_policy_record,
    normalise_approver_groups,
    normalise_test_cases,
    rule_matches,
)


class PolicyTests(unittest.TestCase):
    def action(self, **overrides):
        payload = {
            "context": {"tenant_id": "demo", "environment": "production", "agent_id": "ops-agent", "invoked_by": "user"},
            "action": {"tool": "shell", "operation": "execute", "target": "/srv/app", "parameters": {"command": "ls"}},
        }
        payload["context"].update(overrides)
        return normalise_action(payload)

    def test_policy_is_versioned_and_validates_decisions(self):
        record = build_policy_record(
            {
                "policy_id": "production-shell-policy",
                "name": "Production shell protection",
                "mode": "enforce",
                "rules": [{"rule_id": "block-shell", "tool": "shell", "environment": "production", "decision": "deny"}],
            },
            "demo",
            3,
        )
        self.assertEqual(record["version"], 3)
        self.assertEqual(record["status"], "draft")
        self.assertEqual(record["rules"][0]["rule_id"], "block-shell")
        with self.assertRaises(ValueError):
            build_policy_record({"rules": [{"decision": "unknown"}]}, "demo", 1)

    def test_matching_policy_overrides_baseline_and_explains_match(self):
        action = self.action()
        baseline = evaluate(action)
        policy = build_policy_record(
            {
                "policy_id": "production-shell-policy",
                "rules": [{"rule_id": "block-prod-shell", "tool": "shell", "environment": "production", "decision": "deny", "reason": "Production shell use is prohibited."}],
            },
            "demo",
            1,
        )
        policy["status"] = "published"
        result = apply_policies(baseline, action, [policy])
        self.assertEqual(result["decision"], "deny")
        self.assertEqual(result["policy_matches"][0]["policy_id"], "production-shell-policy")
        self.assertIn("POLICY_BLOCK-PROD-SHELL", result["reason_codes"])
        self.assertIn("Production shell use is prohibited.", [reason["message"] for reason in result["reasons"]])

    def test_multiple_policy_matches_explain_precedence_and_selected_rule(self):
        action = self.action(environment="development")
        baseline = evaluate(action)
        warn_policy = build_policy_record(
            {
                "policy_id": "a-shell-warning",
                "rules": [{"rule_id": "warn-shell", "tool": "shell", "decision": "warn"}],
            },
            "demo",
            1,
        )
        deny_policy = build_policy_record(
            {
                "policy_id": "z-shell-denial",
                "rules": [{"rule_id": "deny-shell", "tool": "shell", "decision": "deny"}],
            },
            "demo",
            1,
        )
        result = apply_policies(baseline, action, [deny_policy, warn_policy])
        resolution = result["policy_resolution"]
        self.assertEqual(result["decision"], "deny")
        self.assertEqual(resolution["strategy"], "most_restrictive_wins")
        self.assertEqual(resolution["decision_order"], ["allow", "warn", "rewrite", "require_approval", "deny"])
        self.assertEqual(resolution["baseline_decision"], "allow")
        self.assertEqual(resolution["selected_decision"], "deny")
        self.assertEqual(resolution["selected_match"]["rule_id"], "deny-shell")
        self.assertEqual(len(resolution["evaluated_matches"]), 2)
        self.assertTrue(all(item["applied"] for item in resolution["evaluated_matches"]))

    def test_lower_precedence_match_is_reported_without_overriding_baseline(self):
        action = normalise_action(
            {
                "context": {"environment": "production"},
                "action": {"tool": "sql", "parameters": {"statement": "UPDATE orders SET status = 'closed'"}},
            }
        )
        baseline = evaluate(action)
        warning_policy = build_policy_record(
            {
                "policy_id": "low-priority-warning",
                "rules": [{"rule_id": "warn-sql", "tool": "sql", "decision": "warn"}],
            },
            "demo",
            1,
        )
        result = apply_policies(baseline, action, [warning_policy])
        precedence = result["policy_resolution"]["evaluated_matches"][0]
        self.assertEqual(result["decision"], "require_approval")
        self.assertFalse(precedence["applied"])
        self.assertEqual(precedence["decision_before"], "require_approval")
        self.assertEqual(precedence["precedence_reason"], "lower_precedence_than_current_decision")

    def test_approval_policy_records_required_reviewer_groups(self):
        action = self.action()
        baseline = evaluate(action)
        policy = build_policy_record(
            {
                "policy_id": "production-review-policy",
                "rules": [
                    {
                        "rule_id": "security-review",
                        "tool": "shell",
                        "environment": "production",
                        "decision": "require_approval",
                        "approver_groups": ["security", "platform", "security"],
                    }
                ],
            },
            "demo",
            1,
        )
        result = apply_policies(baseline, action, [policy])
        self.assertEqual(result["decision"], "require_approval")
        self.assertEqual(result["approval_requirements"][0]["groups"], ["platform", "security"])
        self.assertEqual(result["policy_matches"][0]["approver_groups"], ["platform", "security"])

    def test_approval_groups_are_bounded(self):
        with self.assertRaises(ValueError):
            build_policy_record(
                {"rules": [{"decision": "require_approval", "approver_groups": ["security" * 129]}]},
                "demo",
                1,
            )

    def test_observe_policy_preserves_would_decision(self):
        action = self.action()
        baseline = evaluate(action)
        policy = build_policy_record(
            {
                "policy_id": "observe-shell-policy",
                "mode": "observe",
                "rules": [{"rule_id": "warn-shell", "tool": "shell", "decision": "deny"}],
            },
            "demo",
            1,
        )
        result = apply_policies(baseline, action, [policy])
        self.assertEqual(result["decision"], "observe")
        self.assertEqual(result["would_decision"], "deny")

    def test_rule_conditions_support_wildcards(self):
        action = self.action()
        self.assertTrue(rule_matches({"tool": "shell", "target": "/srv/*"}, action))
        self.assertFalse(rule_matches({"tool": "sql"}, action))

    def test_rule_conditions_match_structured_targets_and_resources(self):
        action = self.action()
        action["target"] = {"type": "s3-bucket", "id": "prod-bucket"}

        self.assertTrue(rule_matches({"target": {"type": "s3-bucket", "id": "prod-bucket"}}, action))
        self.assertTrue(rule_matches({"resource": {"type": "s3-bucket", "id": "prod-bucket"}}, action))
        self.assertFalse(rule_matches({"target": {"type": "s3-bucket", "id": "dev-bucket"}}, action))

    def test_rule_conditions_support_user_resource_time_and_scope(self):
        action = self.action(invoked_by="security-user")
        action["requested_at"] = "2026-07-16T12:00:00Z"
        action["parameters"]["requested_scope"] = ["/srv/app", "/srv/config"]
        self.assertTrue(
            rule_matches(
                {
                    "user": "security-*",
                    "resource": "/srv/app",
                    "start_time": "2026-07-16T00:00:00Z",
                    "end_time": "2026-07-16T23:59:59Z",
                    "maximum_scope": 1,
                },
                action,
            )
        )
        self.assertFalse(rule_matches({"end_time": "2026-07-15T23:59:59Z"}, action))

    def test_dry_run_required_rule_matches_only_before_preview(self):
        action = self.action()
        rule = {"conditions": {"dry_run_required": True}}
        self.assertTrue(rule_matches(rule, action))
        action["parameters"]["dry_run"] = True
        self.assertFalse(rule_matches(rule, action))

    def test_policy_test_cases_are_validated_and_redacted(self):
        record = build_policy_record(
            {
                "name": "Testable policy",
                "rules": [],
                "test_cases": [
                    {
                        "case_id": "safe-shell",
                        "action": {"tool": "shell", "parameters": {"command": "printf safe"}},
                        "expected_decision": "allow",
                        "expected_reason_codes": [],
                    }
                ],
            },
            "demo",
            1,
        )
        self.assertEqual(record["test_cases"][0]["case_id"], "safe-shell")
        with self.assertRaises(ValueError):
            normalise_test_cases([{"action": {"tool": "shell"}, "expected_decision": "unknown"}])
        with self.assertRaises(ValueError):
            normalise_test_cases([{"expected_decision": "allow"}])

    # --- Coverage: _list scalar, approver group edge cases ---

    def test_approver_groups_scalar_value_is_wrapped_in_list(self):
        """_list wraps a scalar value (line 28)."""
        groups = normalise_approver_groups("security")
        self.assertEqual(groups, ["security"])

    def test_approver_groups_exceeds_maximum_count(self):
        """More than 50 groups raises ValueError (line 36)."""
        with self.assertRaises(ValueError):
            normalise_approver_groups([f"group-{i}" for i in range(51)])

    def test_approver_groups_empty_string_is_skipped(self):
        """Empty or whitespace-only groups are silently dropped (line 41)."""
        groups = normalise_approver_groups(["", "  ", "security"])
        self.assertEqual(groups, ["security"])

    # --- Coverage: normalise_test_cases validation branches ---

    def test_test_cases_non_list_raises(self):
        with self.assertRaises(ValueError):
            normalise_test_cases("not-a-list")

    def test_test_cases_exceeds_maximum_count(self):
        valid_case = {"action": {"tool": "shell"}, "expected_decision": "allow"}
        with self.assertRaises(ValueError):
            normalise_test_cases([valid_case] * 101)

    def test_test_cases_non_dict_item_raises(self):
        with self.assertRaises(ValueError):
            normalise_test_cases(["not-a-dict"])

    def test_test_cases_string_expected_reason_codes_is_wrapped(self):
        """String expected_reason_codes is converted to list (line 72)."""
        cases = normalise_test_cases(
            [{"action": {"tool": "shell"}, "expected_decision": "allow", "expected_reason_codes": "CODE_A"}]
        )
        self.assertEqual(cases[0]["expected_reason_codes"], ["CODE_A"])

    def test_test_cases_non_list_expected_reason_codes_raises(self):
        with self.assertRaises(ValueError):
            normalise_test_cases(
                [{"action": {"tool": "shell"}, "expected_decision": "allow", "expected_reason_codes": 123}]
            )

    def test_test_cases_empty_case_id_raises(self):
        with self.assertRaises(ValueError):
            normalise_test_cases(
                [{"action": {"tool": "shell"}, "expected_decision": "allow", "case_id": "   "}]
            )

    # --- Coverage: build_policy_record validation ---

    def test_build_policy_record_non_dict_rule_raises(self):
        with self.assertRaises(ValueError):
            build_policy_record({"rules": ["not-a-dict"]}, "demo", 1)

    def test_build_policy_record_conditions_approver_groups(self):
        """Approver groups from conditions dict are normalised (lines 141-143)."""
        record = build_policy_record(
            {
                "rules": [
                    {
                        "decision": "require_approval",
                        "conditions": {"approver_groups": ["ops", "security"]},
                    }
                ]
            },
            "demo",
            1,
        )
        self.assertEqual(record["rules"][0]["approver_groups"], ["ops", "security"])

    # --- Coverage: _matches edge cases ---

    def test_matches_list_expected(self):
        """_matches with a list expected value (line 167)."""
        self.assertTrue(rule_matches({"tool": ["shell", "sql"]}, self.action()))
        self.assertFalse(rule_matches({"tool": ["sql", "python"]}, self.action()))

    def test_matches_dict_actual_substring(self):
        """_matches with dict/list actual uses substring match (line 172)."""
        action = self.action()
        action["parameters"]["query_scope"] = ["read", "write"]
        self.assertTrue(rule_matches({"query_scope": "read"}, action))
        self.assertFalse(rule_matches({"query_scope": "delete"}, action))

    # --- Coverage: rule_matches adapter_context, time_window, parameters ---

    def test_rule_matches_provider_region_adapter_context(self):
        """Provider and region conditions check adapter_context (lines 183-186)."""
        action = self.action()
        action["adapter_context"] = {"provider": "aws", "region": "us-east-1"}
        self.assertTrue(rule_matches({"provider": "aws"}, action))
        self.assertFalse(rule_matches({"provider": "gcp"}, action))
        self.assertTrue(rule_matches({"region": "us-east-1"}, action))
        self.assertFalse(rule_matches({"region": "eu-west-1"}, action))

    def test_rule_matches_time_window(self):
        """time_window dict conditions (lines 189, 191)."""
        action = self.action()
        action["requested_at"] = "2026-07-16T12:00:00Z"
        self.assertTrue(
            rule_matches({"time_window": {"start": "2026-07-16T00:00:00Z", "end": "2026-07-16T23:59:59Z"}}, action)
        )
        self.assertFalse(
            rule_matches({"time_window": {"start": "2026-07-17T00:00:00Z"}}, action)
        )
        self.assertFalse(
            rule_matches({"time_window": {"end": "2026-07-15T00:00:00Z"}}, action)
        )

    def test_rule_matches_reversible_and_query_scope(self):
        """reversible and query_scope conditions (lines 195-200)."""
        action = self.action()
        action["parameters"]["reversible"] = "true"
        self.assertTrue(rule_matches({"reversible": "true"}, action))
        self.assertFalse(rule_matches({"reversible": "false"}, action))
        action["parameters"]["query_scope"] = "read"
        self.assertTrue(rule_matches({"query_scope": "read"}, action))
        self.assertFalse(rule_matches({"query_scope": "write"}, action))

    def test_rule_matches_maximum_amount(self):
        """maximum_amount condition (lines 202-205)."""
        action = self.action()
        action["parameters"]["amount"] = 100
        self.assertTrue(rule_matches({"maximum_amount": 50}, action))
        self.assertFalse(rule_matches({"maximum_amount": 200}, action))

    def test_rule_matches_maximum_amount_invalid_value(self):
        """maximum_amount with non-numeric amount returns True (TypeError path)."""
        action = self.action()
        action["parameters"]["amount"] = "not-a-number"
        self.assertTrue(rule_matches({"maximum_amount": 50}, action))

    def test_rule_matches_minimum_amount(self):
        """minimum_amount condition (lines 207-210)."""
        action = self.action()
        action["parameters"]["amount"] = 100
        self.assertTrue(rule_matches({"minimum_amount": 50}, action))
        self.assertFalse(rule_matches({"minimum_amount": 200}, action))

    def test_rule_matches_minimum_amount_invalid_value(self):
        """minimum_amount with non-numeric amount returns False."""
        action = self.action()
        action["parameters"]["amount"] = "not-a-number"
        self.assertFalse(rule_matches({"minimum_amount": 50}, action))

    def test_rule_matches_maximum_scope_non_list(self):
        """maximum_scope with non-list scope (lines 211-212)."""
        action = self.action()
        action["parameters"]["requested_scope"] = "single-resource"
        self.assertFalse(rule_matches({"maximum_scope": 5}, action))
        self.assertTrue(rule_matches({"maximum_scope": 0}, action))

    def test_rule_matches_maximum_scope_invalid(self):
        """maximum_scope with non-numeric condition returns True."""
        action = self.action()
        action["parameters"]["requested_scope"] = ["a", "b"]
        self.assertTrue(rule_matches({"maximum_scope": "invalid"}, action))

    # --- Coverage: apply_policies edge cases ---

    def test_apply_policies_skips_non_dict_rule(self):
        """Non-dict rules in apply_policies are skipped (line 236)."""
        action = self.action()
        baseline = evaluate(action)
        result = apply_policies(baseline, action, [{"policy_id": "p", "version": 1, "rules": ["not-a-dict"]}])
        self.assertEqual(result["policy_matches"], [])

    def test_apply_policies_skips_invalid_decision(self):
        """Rules with decisions outside POLICY_DECISIONS are skipped (line 239)."""
        action = self.action()
        baseline = evaluate(action)
        result = apply_policies(
            baseline, action, [{"policy_id": "p", "version": 1, "rules": [{"decision": "invalid", "tool": "shell"}]}]
        )
        self.assertEqual(result["policy_matches"], [])

    def test_apply_policies_recommended_action(self):
        """recommended_action is redacted onto the decision (line 315)."""
        action = self.action()
        baseline = evaluate(action)
        policy = build_policy_record(
            {"rules": [{"decision": "deny", "tool": "shell", "recommended_action": "Use the web console."}]},
            "demo",
            1,
        )
        result = apply_policies(baseline, action, [policy])
        self.assertEqual(result["recommended_action"], "Use the web console.")

    def test_apply_policies_rewrite_decision(self):
        """Rewrite decision sets risk to high and score to 65."""
        action = self.action()
        baseline = evaluate(action)
        policy = build_policy_record(
            {"rules": [{"decision": "rewrite", "tool": "shell"}]},
            "demo",
            1,
        )
        result = apply_policies(baseline, action, [policy])
        self.assertEqual(result["decision"], "rewrite")
        self.assertEqual(result["risk"], "high")
        self.assertGreaterEqual(result["risk_score"], 65)

    def test_matches_none_expected_returns_true(self):
        """_matches with None expected returns True (line 136)."""
        self.assertTrue(rule_matches({"tool": None}, self.action()))

    def test_rule_matches_tools_condition_mismatch(self):
        """tools condition mismatch returns False (line 167)."""
        self.assertFalse(rule_matches({"tools": "sql"}, self.action()))

    def test_rule_matches_start_time_after_requested_at(self):
        """start_time after requested_at returns False (line 177)."""
        action = self.action()
        action["requested_at"] = "2026-07-15T00:00:00Z"
        self.assertFalse(rule_matches({"start_time": "2026-07-16T00:00:00Z"}, action))

    def test_apply_policies_approval_requirements_sorted(self):
        """Multiple approval requirements are sorted deterministically."""
        action = self.action()
        baseline = evaluate(action)
        policy_b = build_policy_record(
            {"policy_id": "b-policy", "rules": [{"rule_id": "r1", "decision": "require_approval", "tool": "shell", "approver_groups": ["ops"]}]},
            "demo",
            1,
        )
        policy_a = build_policy_record(
            {"policy_id": "a-policy", "rules": [{"rule_id": "r2", "decision": "require_approval", "tool": "shell", "approver_groups": ["security"]}]},
            "demo",
            1,
        )
        result = apply_policies(baseline, action, [policy_b, policy_a])
        ids = [req["policy_id"] for req in result["approval_requirements"]]
        self.assertEqual(ids, sorted(ids))


if __name__ == "__main__":
    unittest.main()
