"""Coverage for AI model registration, binding, and policy metadata."""

import json
import unittest
from unittest.mock import patch

from app import lambda_function as service
from app.model_registry import normalise_model_record
from app.policy import build_policy_record, rule_matches
from tests.test_federation import FakeTable, FakeTokenTable


class ModelRegistryTests(unittest.TestCase):
    def setUp(self):
        service.table = FakeTable()
        service.token_table = FakeTokenTable()
        self.store = service.AuditStore(service.table)
        self.auth = {
            "tenant_id": "demo",
            "token_id": "pat-model-admin",
            "subject": "model-admin@example.test",
            "scopes": [
                "model:read",
                "model:write",
                "identity:read",
                "identity:write",
                "guard:evaluate",
                "policy:read",
                "policy:write",
                "admin",
            ],
        }

    @staticmethod
    def body(result):
        return json.loads(result["body"])

    def _route(self, path, method="GET", body=None, auth=None):
        event = {
            "rawPath": path,
            "requestContext": {"http": {"method": method}},
            "headers": {},
        }
        if body is not None:
            event["body"] = json.dumps(body)
        with patch.object(service, "authenticate", return_value=(auth or self.auth, None)):
            return service.lambda_handler(event, None)

    def register_model(self, **overrides):
        payload = {
            "model_id": "invoice-model",
            "name": "Invoice classifier",
            "vendor": "Kenning Labs",
            "version": "2026.1",
            "risk_tier": "high",
            "bias_tested": True,
            "provenance": "Curated supplier invoice data.",
        }
        payload.update(overrides)
        return service.handle_register_model(payload, self.auth)

    def register_agent(self):
        return service.handle_register_agent(
            {
                "agent_id": "invoice-agent",
                "owner": "model-admin@example.test",
                "purpose": "Process invoices",
                "approved_tools": ["shell"],
                "allowed_environments": ["development"],
                "maximum_authority": "standard",
            },
            self.auth,
        )

    def test_model_record_validation_and_duplicate_version(self):
        with self.assertRaises(ValueError):
            normalise_model_record({"model_id": "bad id"}, "demo")
        created = self.register_model()
        self.assertEqual(created["statusCode"], 201)
        record = self.body(created)
        self.assertEqual(record["status"], "registered")
        self.assertEqual(record["risk_tier"], "high")
        duplicate = self.register_model()
        self.assertEqual(duplicate["statusCode"], 409)
        self.assertEqual(self.body(duplicate)["error"], "model_version_already_registered")
        invalid = self._route(
            "/v1/models",
            "POST",
            {"model_id": "bad id", "name": "Invalid", "vendor": "Kenning Labs", "version": "1", "risk_tier": "low"},
        )
        self.assertEqual(invalid["statusCode"], 400)

    def test_models_and_agent_binding_are_http_routes(self):
        model_payload = {"model_id": "route-model", "name": "Route model", "vendor": "Kenning Labs", "version": "1", "risk_tier": "low"}
        created = self._route("/v1/models", "POST", model_payload)
        self.assertEqual(created["statusCode"], 201)
        listed = self._route("/v1/models", "GET")
        self.assertEqual(self.body(listed)["models"][0]["model_id"], "route-model")
        self.register_agent()
        updated = self._route("/v1/agents/invoice-agent", "PUT", {"model_id": "route-model"})
        self.assertEqual(updated["statusCode"], 200)
        missing = self._route("/v1/agents/invoice-agent", "PUT", {"model_id": "missing-model"})
        self.assertEqual(missing["statusCode"], 404)

    def test_model_routes_enforce_read_and_write_scopes(self):
        read_limited = {**self.auth, "scopes": ["model:write"]}
        write_limited = {**self.auth, "scopes": ["model:read"]}
        self.assertEqual(self._route("/v1/models", "GET", auth=read_limited)["statusCode"], 403)
        self.assertEqual(self._route("/v1/models", "POST", {}, auth=write_limited)["statusCode"], 403)

    def test_agent_registration_rejects_unknown_model_binding(self):
        result = service.handle_register_agent(
            {
                "agent_id": "unknown-model-agent",
                "owner": "model-admin@example.test",
                "purpose": "Process invoices",
                "approved_tools": ["shell"],
                "model_id": "missing-model",
            },
            self.auth,
        )
        self.assertEqual(result["statusCode"], 404)
        self.assertEqual(self.body(result)["error"], "model_not_found")

    def test_list_is_tenant_scoped_and_reports_agent_binding_count(self):
        self.register_model()
        self.register_agent()
        bound = service.handle_update_agent(
            "invoice-agent",
            {"model_id": "invoice-model", "model_version": "2026.1"},
            self.auth,
        )
        self.assertEqual(bound["statusCode"], 200)
        listed = self.body(service.handle_list_models(self.auth))
        self.assertEqual(len(listed["models"]), 1)
        self.assertEqual(listed["models"][0]["bound_agent_count"], 1)
        other_auth = {**self.auth, "tenant_id": "other"}
        self.assertEqual(self.body(service.handle_list_models(other_auth))["models"], [])

    def test_model_risk_condition_and_evaluation_metadata(self):
        self.register_model()
        self.register_agent()
        service.handle_update_agent("invoice-agent", {"model_id": "invoice-model"}, self.auth)
        policy = build_policy_record(
            {
                "policy_id": "model-risk-policy",
                "name": "Model risk control",
                "rules": [
                    {
                        "rule_id": "high-risk-model-review",
                        "decision": "require_approval",
                        "conditions": {"model_risk_at_least": "high"},
                    }
                ],
            },
            "demo",
            1,
        )
        policy["status"] = "published"
        self.store.put_policy(policy)
        action = {
            "context": {
                "tenant_id": "demo",
                "agent_id": "invoice-agent",
                "invoked_by": "model-admin@example.test",
                "environment": "development",
            },
            "action": {"tool": "shell", "operation": "read", "target": "invoice.csv", "parameters": {}},
        }
        decision = service.evaluate_and_record(action, self.store)
        self.assertEqual(decision["decision"], "require_approval")
        self.assertEqual(decision["action"]["model_id"], "invoice-model")
        self.assertEqual(decision["action"]["model_version"], "2026.1")
        events = self.store.list_events("demo", filters={"event_type": "action.evaluated", "limit": 10})
        self.assertEqual(events[-1]["model_id"], "invoice-model")
        self.assertEqual(events[-1]["model_version"], "2026.1")
        self.assertTrue(rule_matches(policy["rules"][0], {"model_risk_tier": "high"}))
        self.assertFalse(rule_matches(policy["rules"][0], {"model_risk_tier": None}))

    def test_unbound_agent_records_null_model_fields(self):
        self.register_agent()
        decision = service.evaluate_and_record(
            {
                "context": {
                    "tenant_id": "demo",
                    "agent_id": "invoice-agent",
                    "invoked_by": "model-admin@example.test",
                    "environment": "development",
                },
                "action": {"tool": "shell", "operation": "read", "target": "invoice.csv", "parameters": {}},
            },
            self.store,
        )
        self.assertIsNone(decision["action"]["model_id"])
        self.assertIsNone(decision["action"]["model_version"])


if __name__ == "__main__":
    unittest.main()
