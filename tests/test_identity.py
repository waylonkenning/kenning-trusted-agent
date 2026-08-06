import unittest

from app.identity import (
    authorize_action,
    build_agent_record,
    check_approval_separation,
    normalise_authority_level,
    normalise_delegation_chain,
    required_authority,
)


class AgentIdentityTests(unittest.TestCase):
    def action(self, **overrides):
        return {
            "tool": "sql",
            "operation": "execute",
            "target": "orders",
            "environment": "production",
            "parameters": {"statement": "UPDATE orders SET status = closed", "amount": 25},
            **overrides,
        }

    def test_registered_agent_can_use_delegated_tool_in_boundary(self):
        agent = build_agent_record(
            {
                "agent_id": "order-agent",
                "owner": "procurement@example.org",
                "purpose": "Process order updates",
                "allowed_environments": ["production"],
                "approved_tools": ["sql"],
                "may": ["sql:execute:orders"],
            },
            "demo",
        )
        result = authorize_action(agent, self.action())
        self.assertTrue(result["authorized"])
        self.assertEqual(result["decision"], "allow")

    def test_maximum_authority_ceiling_is_enforced(self):
        agent = build_agent_record(
            {
                "agent_id": "limited-order-agent",
                "maximum_authority": "standard",
                "allowed_environments": ["production"],
                "approved_tools": ["sql"],
                "may": ["sql:execute:orders"],
            },
            "demo",
        )
        self.assertEqual(required_authority(self.action()), "high")
        result = authorize_action(agent, self.action())
        self.assertFalse(result["authorized"])
        self.assertEqual(result["maximum_authority"], "standard")
        self.assertEqual(result["required_authority"], "high")
        self.assertIn("AUTHORITY_CEILING", {reason["code"] for reason in result["reasons"]})

    def test_read_action_can_run_at_read_authority(self):
        agent = build_agent_record(
            {
                "agent_id": "read-only-agent",
                "maximum_authority": "read",
                "approved_tools": ["sql"],
                "may": ["sql:execute:orders"],
            },
            "demo",
        )
        result = authorize_action(
            agent,
            self.action(
                environment="development",
                parameters={"statement": "SELECT id FROM orders LIMIT 10"},
            ),
        )
        self.assertTrue(result["authorized"])
        self.assertEqual(result["required_authority"], "read")

    def test_sql_query_with_privileged_statement_exceeds_read_authority(self):
        agent = build_agent_record(
            {
                "agent_id": "read-only-agent",
                "maximum_authority": "read",
                "approved_tools": ["sql"],
                "may": ["sql:query:orders"],
            },
            "demo",
        )
        action = self.action(
            operation="query",
            environment="development",
            parameters={"statement": "CREATE USER auditor; GRANT SELECT ON orders TO auditor"},
        )

        self.assertEqual(required_authority(action), "high")
        result = authorize_action(agent, action)

        self.assertFalse(result["authorized"])
        self.assertEqual(result["required_authority"], "high")
        self.assertIn("AUTHORITY_CEILING", {reason["code"] for reason in result["reasons"]})

    def test_show_create_table_is_read_only_metadata(self):
        action = self.action(
            operation="query",
            environment="development",
            parameters={"statement": "SHOW CREATE TABLE orders"},
        )
        self.assertEqual(required_authority(action), "read")

    def test_commented_select_query_keeps_read_authority(self):
        action = self.action(
            operation="query",
            environment="development",
            parameters={"statement": "/* trace_id=abc */ SELECT id FROM orders"},
        )
        self.assertEqual(required_authority(action), "read")

    def test_multi_statement_payload_cannot_use_read_fast_path(self):
        action = self.action(
            operation="query",
            environment="development",
            parameters={"statement": "SELECT 1; DROP TABLE users"},
        )
        self.assertEqual(required_authority(action), "high")

    def test_stacked_mutation_after_select_exceeds_read_authority(self):
        agent = build_agent_record(
            {
                "agent_id": "read-only-agent",
                "maximum_authority": "read",
                "approved_tools": ["sql"],
                "may": ["sql:execute:orders"],
            },
            "demo",
        )
        action = self.action(
            environment="development",
            parameters={"statement": "SELECT id FROM orders; DROP TABLE orders"},
        )

        self.assertEqual(required_authority(action), "high")
        result = authorize_action(agent, action)

        self.assertFalse(result["authorized"])
        self.assertIn("AUTHORITY_CEILING", {reason["code"] for reason in result["reasons"]})

    def test_agent_cannot_use_undelegated_tool_or_environment(self):
        agent = build_agent_record(
            {
                "agent_id": "order-agent",
                "allowed_environments": ["development"],
                "approved_tools": ["sql"],
            },
            "demo",
        )
        result = authorize_action(agent, self.action(tool="shell", environment="production"))
        self.assertFalse(result["authorized"])
        self.assertEqual(result["decision"], "deny")
        self.assertIn("ENVIRONMENT_BOUNDARY", {reason["code"] for reason in result["reasons"]})
        self.assertIn("TOOL_NOT_DELEGATED", {reason["code"] for reason in result["reasons"]})

    def test_human_approval_condition_is_returned(self):
        agent = build_agent_record(
            {
                "agent_id": "payment-agent",
                "allowed_environments": ["production"],
                "approved_tools": ["sql"],
                "conditions": {"human_approval_required": True, "maximum_payment": 100},
            },
            "demo",
        )
        result = authorize_action(agent, self.action())
        self.assertTrue(result["authorized"])
        self.assertEqual(result["decision"], "require_approval")

    def test_time_limited_delegation_is_enforced_at_action_time(self):
        agent = build_agent_record(
            {
                "agent_id": "time-limited-agent",
                "allowed_environments": ["production"],
                "approved_tools": ["sql"],
                "conditions": {
                    "not_before": "2026-07-17T10:00:00+12:00",
                    "not_after": "2026-07-17T12:00:00+12:00",
                },
            },
            "demo",
        )
        self.assertEqual(agent["conditions"]["not_before"], "2026-07-16T22:00:00Z")
        self.assertEqual(agent["conditions"]["not_after"], "2026-07-17T00:00:00Z")

        before = authorize_action(agent, self.action(requested_at="2026-07-16T21:59:59Z"))
        self.assertFalse(before["authorized"])
        self.assertIn("DELEGATION_NOT_YET_ACTIVE", {reason["code"] for reason in before["reasons"]})

        active = authorize_action(agent, self.action(requested_at="2026-07-16T23:00:00Z"))
        self.assertTrue(active["authorized"])
        self.assertEqual(active["delegation_window"]["not_after"], "2026-07-17T00:00:00Z")

        after = authorize_action(agent, self.action(requested_at="2026-07-17T00:00:01Z"))
        self.assertFalse(after["authorized"])
        self.assertIn("DELEGATION_EXPIRED", {reason["code"] for reason in after["reasons"]})

    def test_invalid_delegation_window_is_rejected(self):
        with self.assertRaises(ValueError):
            build_agent_record(
                {
                    "agent_id": "invalid-time-agent",
                    "approved_tools": ["sql"],
                    "conditions": {
                        "not_before": "2026-07-18T00:00:00Z",
                        "not_after": "2026-07-17T00:00:00Z",
                    },
                },
                "demo",
            )

    def test_revoked_agent_is_denied(self):
        agent = build_agent_record({"agent_id": "revoked-agent", "approved_tools": ["sql"]}, "demo")
        agent["status"] = "revoked"
        result = authorize_action(agent, self.action(environment="development"))
        self.assertFalse(result["authorized"])
        self.assertIn("AGENT_REVOKED", {reason["code"] for reason in result["reasons"]})

    def test_separation_of_duties_rejects_requester_and_agent_approval(self):
        agent = build_agent_record(
            {
                "agent_id": "payment-agent",
                "conditions": {
                    "separation_of_duties": {
                        "agent_cannot_approve": True,
                        "approver_must_differ_from_invoked_by": True,
                    }
                },
            },
            "demo",
        )
        approval = {"requested_by": "finance@example.org"}
        requester = check_approval_separation(agent, approval, "finance@example.org", {"token_type": "pat"})
        self.assertFalse(requester["allowed"])
        self.assertIn("APPROVER_EQUALS_REQUESTER", {reason["code"] for reason in requester["reasons"]})

        agent_token = check_approval_separation(agent, approval, "security@example.org", {"token_type": "agent"})
        self.assertFalse(agent_token["allowed"])
        self.assertIn("AGENT_CANNOT_APPROVE_OWN_ACTION", {reason["code"] for reason in agent_token["reasons"]})

    def test_separation_of_duties_checks_authenticated_principal(self):
        agent = {
            "conditions": {
                "separation_of_duties": {
                    "approver_must_differ_from_invoked_by": True,
                    "prohibited_approvers": ["user-123"],
                }
            }
        }
        approval = {"requested_by": "user-123"}
        result = check_approval_separation(
            agent,
            approval,
            "friendly-label",
            {"token_type": "pat"},
            approver_principal="user-123",
        )
        self.assertFalse(result["allowed"])
        self.assertEqual(
            {reason["code"] for reason in result["reasons"]},
            {"APPROVER_EQUALS_REQUESTER", "APPROVER_PROHIBITED"},
        )

    # --- normalise_authority_level edge cases ---

    def test_normalise_authority_level_rejects_invalid(self):
        with self.assertRaises(ValueError):
            normalise_authority_level("superuser")

    def test_normalise_authority_level_resolves_aliases(self):
        self.assertEqual(normalise_authority_level("low"), "read")
        self.assertEqual(normalise_authority_level("medium"), "standard")
        self.assertEqual(normalise_authority_level("elevated"), "high")
        self.assertEqual(normalise_authority_level("critical"), "admin")

    def test_normalise_authority_level_defaults_to_high(self):
        self.assertEqual(normalise_authority_level(None), "high")

    # --- normalise_delegation_chain edge cases ---

    def test_delegation_chain_rejects_non_list(self):
        with self.assertRaises(ValueError):
            normalise_delegation_chain("not-a-list")

    def test_delegation_chain_rejects_too_many_principals(self):
        with self.assertRaises(ValueError):
            normalise_delegation_chain([f"principal-{i}" for i in range(9)])

    def test_delegation_chain_rejects_duplicates(self):
        with self.assertRaises(ValueError):
            normalise_delegation_chain(["alice", "bob", "alice"])

    def test_delegation_chain_none_returns_empty(self):
        self.assertEqual(normalise_delegation_chain(None), [])

    def test_delegation_chain_normalises_list(self):
        self.assertEqual(normalise_delegation_chain(["alice", "bob"]), ["alice", "bob"])

    # --- required_authority edge cases ---

    def test_required_authority_cloud_iam_is_admin(self):
        action = {"tool": "aws", "operation": "execute", "target": "iam-role", "parameters": {}}
        self.assertEqual(required_authority(action), "admin")

    def test_required_authority_cloud_kms_is_admin(self):
        action = {"tool": "azure", "operation": "execute", "target": "key-vault", "parameters": {}}
        self.assertEqual(required_authority(action), "admin")

    def test_required_authority_irreversible_is_high(self):
        action = {
            "tool": "api",
            "operation": "execute",
            "target": "resource",
            "environment": "development",
            "parameters": {"reversible": False},
        }
        self.assertEqual(required_authority(action), "high")

    def test_required_authority_standard_for_reversible_non_production(self):
        action = {
            "tool": "api",
            "operation": "execute",
            "target": "resource",
            "environment": "development",
            "parameters": {"reversible": True},
        }
        self.assertEqual(required_authority(action), "standard")

    def test_required_authority_read_for_list_operation(self):
        action = {"tool": "api", "operation": "list", "target": "resources", "environment": "development", "parameters": {}}
        self.assertEqual(required_authority(action), "read")

    # --- _canonical_timestamp edge cases ---

    def test_canonical_timestamp_rejects_missing_timezone(self):
        with self.assertRaises(ValueError):
            build_agent_record(
                {"agent_id": "tz-agent", "approved_tools": ["sql"], "conditions": {"not_before": "2026-07-17T10:00:00"}},
                "demo",
            )

    def test_canonical_timestamp_rejects_invalid_format(self):
        with self.assertRaises(ValueError):
            build_agent_record(
                {"agent_id": "bad-ts-agent", "approved_tools": ["sql"], "conditions": {"not_before": "not-a-date"}},
                "demo",
            )

    def test_canonical_timestamp_rejects_whitespace_only(self):
        with self.assertRaises(ValueError):
            build_agent_record(
                {"agent_id": "ws-agent", "approved_tools": ["sql"], "conditions": {"not_before": "   "}},
                "demo",
            )

    def test_build_agent_record_requires_agent_id(self):
        with self.assertRaises(ValueError):
            build_agent_record({}, "demo")

    def test_delegation_window_accepts_alias_fields(self):
        agent = build_agent_record(
            {
                "agent_id": "alias-agent",
                "approved_tools": ["sql"],
                "conditions": {"valid_from": "2026-07-17T10:00:00Z", "expires_at": "2026-07-17T12:00:00Z"},
            },
            "demo",
        )
        self.assertEqual(agent["conditions"]["not_before"], "2026-07-17T10:00:00Z")
        self.assertEqual(agent["conditions"]["not_after"], "2026-07-17T12:00:00Z")

    def test_delegation_window_from_time_window_dict(self):
        agent = build_agent_record(
            {
                "agent_id": "tw-agent",
                "approved_tools": ["sql"],
                "conditions": {"time_window": {"start": "2026-07-17T10:00:00Z", "end": "2026-07-17T12:00:00Z"}},
            },
            "demo",
        )
        self.assertEqual(agent["conditions"]["not_before"], "2026-07-17T10:00:00Z")
        self.assertEqual(agent["conditions"]["not_after"], "2026-07-17T12:00:00Z")

    # --- authorize_action edge cases ---

    def test_authorize_no_approved_tools(self):
        agent = build_agent_record({"agent_id": "no-tools-agent"}, "demo")
        result = authorize_action(agent, self.action(environment="development", parameters={"statement": "SELECT 1"}))
        self.assertFalse(result["authorized"])
        self.assertIn("NO_APPROVED_TOOLS", {r["code"] for r in result["reasons"]})

    def test_authorize_action_not_delegated(self):
        agent = build_agent_record(
            {"agent_id": "may-agent", "approved_tools": ["sql"], "may": ["shell:*"]},
            "demo",
        )
        result = authorize_action(agent, self.action(environment="development", parameters={"statement": "SELECT 1"}))
        self.assertFalse(result["authorized"])
        self.assertIn("ACTION_NOT_DELEGATED", {r["code"] for r in result["reasons"]})

    def test_authorize_action_explicitly_prohibited(self):
        agent = build_agent_record(
            {"agent_id": "may-not-agent", "approved_tools": ["sql"], "may_not": ["sql:*"]},
            "demo",
        )
        result = authorize_action(agent, self.action(environment="development", parameters={"statement": "SELECT 1"}))
        self.assertFalse(result["authorized"])
        self.assertIn("ACTION_EXPLICITLY_PROHIBITED", {r["code"] for r in result["reasons"]})

    def test_authorize_invalid_action_timestamp(self):
        agent = build_agent_record(
            {"agent_id": "ts-agent", "approved_tools": ["sql"], "conditions": {"not_before": "2026-07-17T10:00:00Z"}},
            "demo",
        )
        result = authorize_action(
            agent,
            self.action(environment="development", requested_at="not-a-timestamp", parameters={"statement": "SELECT 1"}),
        )
        self.assertFalse(result["authorized"])
        self.assertIn("INVALID_ACTION_TIMESTAMP", {r["code"] for r in result["reasons"]})

    def test_authorize_unparseable_transaction_amount(self):
        agent = build_agent_record(
            {"agent_id": "amount-agent", "approved_tools": ["sql"], "conditions": {"maximum_payment": 100}},
            "demo",
        )
        result = authorize_action(
            agent,
            self.action(environment="development", parameters={"statement": "SELECT 1", "amount": "not-a-number"}),
        )
        self.assertFalse(result["authorized"])
        self.assertIn("UNPARSEABLE_TRANSACTION_AMOUNT", {r["code"] for r in result["reasons"]})

    def test_authorize_transaction_over_limit(self):
        agent = build_agent_record(
            {"agent_id": "limit-agent", "approved_tools": ["sql"], "conditions": {"maximum_payment": 50}},
            "demo",
        )
        result = authorize_action(
            agent,
            self.action(environment="development", parameters={"statement": "SELECT 1", "amount": 100}),
        )
        self.assertFalse(result["authorized"])
        self.assertIn("TRANSACTION_LIMIT", {r["code"] for r in result["reasons"]})

    # --- check_approval_separation edge cases ---

    def test_separation_of_duties_true_boolean(self):
        agent = {"conditions": {"separation_of_duties": True}}
        result = check_approval_separation(agent, {"requested_by": "user-a"}, "user-a")
        self.assertTrue(result["allowed"])

    def test_separation_of_duties_none_agent(self):
        result = check_approval_separation(None, {"requested_by": "user-a"}, "user-b")
        self.assertTrue(result["allowed"])

    def test_string_list_returns_empty_for_non_list(self):
        agent = build_agent_record({"agent_id": "test", "approved_tools": 123}, "demo")
        self.assertEqual(agent["approved_tools"], [])


if __name__ == "__main__":
    unittest.main()
