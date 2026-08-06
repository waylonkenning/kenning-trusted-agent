import unittest
from unittest.mock import Mock

from sdk.kenning_trusted_agent import GuardBlocked, GuardClient, before_tool_call


class SdkTests(unittest.TestCase):
    def test_before_tool_call_allows_low_risk_decision(self):
        client = Mock()
        client.evaluate.return_value = {"decision": "allow", "reason_codes": []}
        result = before_tool_call(client, {"tool": "shell", "parameters": {"command": "ls"}})
        self.assertEqual(result["decision"], "allow")
        client.evaluate.assert_called_once()

    def test_before_tool_call_raises_with_structured_block(self):
        client = Mock()
        client.evaluate.return_value = {"decision": "require_approval", "reason_codes": ["PRODUCTION_TARGET"]}
        with self.assertRaises(GuardBlocked) as raised:
            before_tool_call(client, {"tool": "sql", "parameters": {"statement": "DROP TABLE orders"}})
        self.assertEqual(raised.exception.decision["reason_codes"], ["PRODUCTION_TARGET"])

    def test_client_binds_tenant_and_passes_action_hash_to_outcome(self):
        client = GuardClient("https://example.invalid", "kta_pat_test", tenant_id="demo")
        client._request = Mock(return_value={"event_type": "action.outcome"})
        client.record_outcome(
            "action-1",
            status="success",
            action_hash="sha256:abc",
            approval_id="approval-1",
        )
        client._request.assert_called_once_with(
            "/v1/actions/action-1/outcome",
            "POST",
            {
                "context": {"tenant_id": "demo"},
                "status": "success",
                "action_hash": "sha256:abc",
                "approval_id": "approval-1",
            },
        )

    def test_ndjson_export_is_decoded_as_event_objects(self):
        client = GuardClient("https://example.invalid", "kta_pat_test")
        client._request = Mock(return_value=[{"event_type": "action.evaluated"}])
        result = client.export_audit(query={"decision": "deny"}, format="jsonl")
        self.assertEqual(result[0]["event_type"], "action.evaluated")
        client._request.assert_called_once()
        self.assertIn("format=jsonl", client._request.call_args.args[0])

    def test_ingest_audit_event(self):
        client = GuardClient("https://example.test", "pat", tenant_id="demo")
        client._request = Mock(return_value={"status": "accepted"})
        result = client.ingest_audit_event(
            "agent.run.completed",
            context={"run_id": "run-123"},
            idempotency_key="run-123",
            status="success",
        )
        self.assertEqual(result["status"], "accepted")
        client._request.assert_called_once_with(
            "/v1/audit/events",
            "POST",
            {
                "context": {"run_id": "run-123", "tenant_id": "demo"},
                "event_type": "agent.run.completed",
                "idempotency_key": "run-123",
                "status": "success",
            },
        )
        client._request.assert_called_once()

    def test_suite_workflows_preserve_tenant_context(self):
        client = GuardClient("https://example.test", "pat", tenant_id="demo")
        client._request = Mock(return_value={})

        client.verify_citations("A supported answer", citations=[{"url": "https://example.org", "claim": "A claim"}])
        self.assertEqual(client._request.call_args.args[0], "/v1/citations/verify")
        self.assertEqual(client._request.call_args.args[2]["context"], {"tenant_id": "demo"})

        client.create_proof(
            {"summary": "Recommend a supplier"},
            evidence=[{"claim": "Supplier A is lowest", "source": "pricing.xlsx"}],
            recommendation="Supplier A",
        )
        proof_payload = client._request.call_args.args[2]
        self.assertEqual(proof_payload["context"], {"tenant_id": "demo"})
        self.assertEqual(proof_payload["evidence"][0]["source"], "pricing.xlsx")

        client.list_approvals(status="pending", limit=10)
        self.assertIn("/v1/approvals?", client._request.call_args.args[0])
        self.assertIn("tenant_id=demo", client._request.call_args.args[0])

        client.list_tenants(limit=10)
        self.assertIn("tenant_id=demo", client._request.call_args.args[0])

    def test_identity_token_and_policy_helpers_build_expected_requests(self):
        client = GuardClient("https://example.test", "pat", tenant_id="demo")
        client._request = Mock(return_value={})

        client.register_agent({"agent_id": "invoice-agent", "approved_tools": ["sql"]})
        self.assertEqual(client._request.call_args.args[0], "/v1/agents")
        self.assertEqual(client._request.call_args.args[2]["context"], {"tenant_id": "demo"})

        client.issue_agent_credential("invoice-agent", expires_in_seconds=600, scopes=["guard:evaluate"])
        self.assertEqual(client._request.call_args.args[0], "/v1/agents/invoice-agent/credentials")
        self.assertEqual(client._request.call_args.args[2]["expires_in_seconds"], 600)

        client.create_token("child-token", scopes=["guard:evaluate"], groups=["security"], expires_in_days=7)
        self.assertEqual(client._request.call_args.args[0], "/v1/tokens")
        self.assertEqual(client._request.call_args.args[2]["tenant_id"], "demo")
        self.assertEqual(client._request.call_args.args[2]["groups"], ["security"])

        client.simulate_policy("production-sql", {"action": {"tool": "sql"}}, version=2)
        self.assertEqual(client._request.call_args.args[0], "/v1/policies/production-sql/simulate")
        self.assertEqual(client._request.call_args.args[2]["context"], {"tenant_id": "demo"})

        client.simulate_policy("production-sql", source_action_id="action-42", version=2)
        self.assertEqual(client._request.call_args.args[2]["source_action_id"], "action-42")
        with self.assertRaises(ValueError):
            client.simulate_policy("production-sql")

    def test_tenant_required_for_direct_configuration_helpers(self):
        client = GuardClient("https://example.test", "pat")
        with self.assertRaises(ValueError):
            client.get_tenant()

    def test_approval_decision_can_use_authenticated_principal(self):
        client = GuardClient("https://example.test", "pat", tenant_id="demo")
        client._request = Mock(return_value={})
        client.decide_approval("approval-1", "approve", action_hash="sha256:action")
        payload = client._request.call_args.args[2]
        self.assertNotIn("approver", payload)
        self.assertEqual(payload["context"], {"tenant_id": "demo"})


if __name__ == "__main__":
    unittest.main()
