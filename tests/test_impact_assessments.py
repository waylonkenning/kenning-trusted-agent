import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from app import lambda_function as service
from app.guard import action_hash
from tests.test_lambda_routes import FakeTable, FakeTokenTable


class ImpactAssessmentTests(unittest.TestCase):
    def setUp(self):
        self.table = FakeTable()
        self.token_table = FakeTokenTable()
        service.table = self.table
        service.token_table = self.token_table
        self.auth = {
            "tenant_id": "demo",
            "token_id": "pat-impact-test",
            "subject": "assessor@example.org",
            "scopes": ["identity:read", "identity:write", "audit:read", "audit:write", "guard:evaluate"],
        }

    @staticmethod
    def body(result):
        return json.loads(result["body"])

    def register_agent(self, agent_id="impact-agent"):
        result = service.handle_register_agent(
            {"agent_id": agent_id, "owner": "assessor@example.org", "purpose": "Assess a governed AI system", "approved_tools": ["shell"]},
            self.auth,
        )
        self.assertEqual(result["statusCode"], 201)
        return self.body(result)

    @staticmethod
    def assessment_payload():
        return {
            "summary": "The agent reviews supplier proposals and recommends a preferred supplier.",
            "impacts_on_individuals": "Reviewers and supplier contacts may be affected by an incorrect recommendation.",
            "impacts_on_society": "Repeated recommendations may influence supplier access and market concentration.",
            "mitigations": "Use human review, record the evidence, and monitor outcomes for disparate impact.",
            "assessor": "assessor@example.org",
        }

    def _route(self, path, method="GET", body=None):
        event = {
            "rawPath": path,
            "requestContext": {"http": {"method": method}},
            "headers": {"authorization": "Bearer kta_pat_test"},
        }
        if body is not None:
            event["body"] = json.dumps(body)
        with patch.object(service, "authenticate", return_value=(self.auth, None)):
            return service.lambda_handler(event, None)

    def test_create_list_and_agent_status_are_auditable(self):
        agent = self.register_agent()
        created = self._route("/v1/agents/impact-agent/impact-assessments", "POST", self.assessment_payload())
        self.assertEqual(created["statusCode"], 201)
        record = self.body(created)
        self.assertEqual(record["agent_id"], agent["agent_id"])
        self.assertEqual(record["status"], "completed")
        listed = self._route("/v1/agents/impact-agent/impact-assessments")
        listed_body = self.body(listed)
        self.assertEqual(listed["statusCode"], 200)
        self.assertEqual(listed_body["assessment_status"], "assessed")
        self.assertEqual(listed_body["assessments"][0]["assessment_id"], record["assessment_id"])
        agents = self.body(service.handle_list_agents(self.auth))["agents"]
        listed_agent = next(item for item in agents if item["agent_id"] == "impact-agent")
        self.assertEqual(listed_agent["impact_assessment_status"], "assessed")
        self.assertEqual(listed_agent["impact_assessment_updated_at"], record["created_at"])
        events = service.store().list_events("demo", filters={"event_type": "impact_assessment.created", "agent_id": "impact-agent"})
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["source"], "internal")
        self.assertEqual(events[0]["assessment_id"], record["assessment_id"])

    def test_assessment_validation_and_tenant_scope(self):
        self.register_agent()
        with self.assertRaisesRegex(ValueError, "summary is required"):
            service.handle_create_impact_assessment("impact-agent", {**self.assessment_payload(), "summary": "  "}, self.auth)
        other_tenant = {**self.auth, "tenant_id": "other-tenant"}
        result = service.handle_list_impact_assessments("impact-agent", other_tenant)
        self.assertEqual(result["statusCode"], 404)
        self.assertEqual(self.body(result)["error"], "agent_not_found")

    def test_requires_impact_assessment_is_warn_only_and_ignores_external_events(self):
        self.register_agent()
        now = datetime.now(timezone.utc).replace(microsecond=0)
        self.table.put_item(Item={"pk": "TENANT#demo", "sk": f"EVENT#{now.isoformat()}Z#external", "event_id": "external-assessment", "event_type": "impact_assessment.created", "tenant_id": "demo", "agent_id": "impact-agent", "created_at": now.isoformat().replace("+00:00", "Z"), "source": "external", "summary": "Imported assessment"})
        policy = {"policy_id": "impact-reminder", "version": 1, "rules": [{"rule_id": "assessment-required", "decision": "deny", "conditions": {"requires_impact_assessment": True}}]}
        action = {"tenant_id": "demo", "agent_id": "impact-agent", "tool": "shell"}
        overdue = service._impact_assessment_policy_context({"decision": "allow", "would_decision": "allow"}, action, [policy], service.store())
        self.assertEqual(overdue["decision"], "warn")
        self.assertIn("ASSESSMENT_OVERDUE", overdue["reason_codes"])
        self.assertEqual(overdue["impact_assessment"]["status"], "assessment overdue")
        self.assertNotIn("_impact_assessment_current", action)
        flat_policy = {"policy_id": "flat-impact-reminder", "version": 1, "rules": [{"rule_id": "flat-assessment-required", "decision": "deny", "requires_impact_assessment": True}]}
        flat_overdue = service._impact_assessment_policy_context({"decision": "allow", "would_decision": "allow"}, action, [flat_policy], service.store())
        self.assertEqual(flat_overdue["decision"], "warn")
        self.assertIn("ASSESSMENT_OVERDUE", flat_overdue["reason_codes"])
        before_hash = action_hash(action)
        self.assertEqual(service.handle_create_impact_assessment("impact-agent", self.assessment_payload(), self.auth)["statusCode"], 201)
        current = service._impact_assessment_policy_context({"decision": "allow", "would_decision": "allow"}, action, [policy], service.store())
        self.assertEqual(current["decision"], "allow")
        self.assertEqual(current["impact_assessment"]["status"], "assessed")
        self.assertNotIn("ASSESSMENT_OVERDUE", current.get("reason_codes", []))
        self.assertEqual(action_hash(action), before_hash)

    def test_old_assessment_is_overdue(self):
        self.register_agent()
        old = (datetime.now(timezone.utc) - timedelta(days=366)).replace(microsecond=0)
        self.table.put_item(Item={"pk": "TENANT#demo", "sk": f"EVENT#{old.isoformat()}#old", "event_id": "old-assessment", "event_type": "impact_assessment.created", "tenant_id": "demo", "agent_id": "impact-agent", "created_at": old.isoformat().replace("+00:00", "Z"), "source": "internal", "assessment_id": "old-assessment", "status": "completed"})
        result = service.handle_list_impact_assessments("impact-agent", self.auth)
        self.assertEqual(self.body(result)["assessment_status"], "assessment overdue")


if __name__ == "__main__":
    unittest.main()
