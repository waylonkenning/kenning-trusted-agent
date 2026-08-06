"""API coverage for the ISO/IEC 42001 governance extensions."""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from app import lambda_function as service
from tests.test_lambda_routes import FakeTable, FakeTokenTable


class IsoGovernanceExtensionsTests(unittest.TestCase):
    def setUp(self):
        self.table = FakeTable()
        service.table = self.table
        service.token_table = FakeTokenTable()
        self.auth = {
            "tenant_id": "demo",
            "token_id": "iso-governance-test",
            "scopes": [
                "audit:read",
                "audit:write",
                "identity:read",
                "identity:write",
                "model:read",
                "model:write",
            ],
        }

    def route(self, path, method="GET", body=None, query=None, auth=None):
        event = {
            "rawPath": path,
            "requestContext": {"http": {"method": method}},
            "headers": {"authorization": "Bearer kta_pat_test"},
        }
        if body is not None:
            event["body"] = json.dumps(body)
        if query:
            event["queryStringParameters"] = query
        with patch.object(service, "authenticate", return_value=(auth or self.auth, None)):
            return service.lambda_handler(event, None)

    @staticmethod
    def body(result):
        return json.loads(result["body"])

    def test_nonconformity_lifecycle_and_anonymous_concern(self):
        created_result = self.route(
            "/v1/nonconformities",
            method="POST",
            body={
                "title": "Missing supplier evidence",
                "description": "The model review did not include supplier evidence.",
                "severity": "high",
                "source_event_id": "evt-review-1",
            },
        )
        self.assertEqual(created_result["statusCode"], 201)
        created = self.body(created_result)
        self.assertEqual(created["status"], "open")

        listed = self.body(self.route("/v1/nonconformities", query={"status": "open"}))
        self.assertEqual([item["nc_id"] for item in listed["nonconformities"]], [created["nc_id"]])

        resolved_result = self.route(
            f"/v1/nonconformities/{created['nc_id']}/resolve",
            method="POST",
            body={"corrective_action": "Add supplier evidence to the review checklist.", "resolved_by": "reviewer"},
        )
        self.assertEqual(resolved_result["statusCode"], 200)
        resolved = self.body(resolved_result)
        self.assertEqual(resolved["status"], "resolved")
        self.assertEqual(resolved["resolved_by"], "reviewer")

        idempotent = self.body(
            self.route(
                f"/v1/nonconformities/{created['nc_id']}/resolve",
                method="POST",
                body={"corrective_action": "A different action must not replace the first one."},
            )
        )
        self.assertEqual(idempotent["corrective_action"], resolved["corrective_action"])

        concern_result = self.route(
            "/v1/concerns",
            method="POST",
            body={"description": "Please review the supplier evidence process.", "anonymous": True},
        )
        self.assertEqual(concern_result["statusCode"], 201)
        concern = self.body(concern_result)
        self.assertTrue(concern["anonymous"])
        concern_events = service.store().list_events(
            "demo", filters={"event_type": "concern.reported", "limit": 10}
        )
        self.assertEqual(concern_events[0]["invoked_by"], "anonymous")

    def test_agent_documentation_is_durable_and_complete(self):
        registered_result = self.route(
            "/v1/agents",
            method="POST",
            body={"agent_id": "documented-agent", "owner": "owner@example.com", "purpose": "Review records"},
        )
        self.assertEqual(registered_result["statusCode"], 201)
        registered = self.body(registered_result)
        self.assertEqual(registered["documentation_completeness"], "0/4")

        updated_result = self.route(
            "/v1/agents/documented-agent",
            method="PUT",
            body={
                "documentation": {
                    "design": "The agent reviews records against approved rules.",
                    "resources": "It uses the registered model and tenant audit stream.",
                    "verification": "Verification runs include unit and end-to-end tests.",
                    "operational": "The owner reviews production changes each month.",
                }
            },
        )
        self.assertEqual(updated_result["statusCode"], 200)
        updated = self.body(updated_result)
        self.assertEqual(updated["documentation_completeness"], "4/4")
        self.assertEqual(updated["documentation_sections_completed"], 4)

        fetched = self.body(self.route("/v1/agents/documented-agent"))
        self.assertEqual(fetched["documentation"]["verification"], updated["documentation"]["verification"])
        events = service.store().list_events(
            "demo", filters={"event_type": "agent.documentation.updated", "limit": 10}
        )
        self.assertEqual(events[0]["agent_id"], "documented-agent")

    def test_supplier_model_and_data_resource_governance(self):
        supplier_result = self.route(
            "/v1/suppliers",
            method="POST",
            body={"name": "Trusted Data Co", "role": "data_provider", "risk_rating": "medium"},
        )
        self.assertEqual(supplier_result["statusCode"], 201)
        supplier = self.body(supplier_result)
        self.assertEqual(supplier["bound_model_count"], 0)

        model_result = self.route(
            "/v1/models",
            method="POST",
            body={
                "model_id": "invoice-model",
                "name": "Invoice classifier",
                "vendor": "Kenning Labs",
                "version": "2026.1",
                "risk_tier": "high",
                "supplier_id": supplier["supplier_id"],
            },
        )
        self.assertEqual(model_result["statusCode"], 201)
        model = self.body(model_result)
        self.assertEqual(model["supplier_name"], "Trusted Data Co")
        self.assertEqual(model["supplier_risk_rating"], "medium")

        resource_result = self.route(
            "/v1/models/invoice-model/data-resources",
            method="POST",
            body={
                "name": "Invoice training set",
                "source": "Customer-approved samples",
                "category": "training",
                "acquisition_date": "2026-01-15",
                "provenance": "Collected under the tenant data policy.",
                "preparation_notes": "Redacted and deduplicated.",
            },
        )
        self.assertEqual(resource_result["statusCode"], 201)
        resource = self.body(resource_result)
        self.assertEqual(resource["model_id"], "invoice-model")

        resources = self.body(self.route("/v1/models/invoice-model/data-resources"))
        self.assertEqual(resources["data_resources"][0]["data_resource_id"], resource["data_resource_id"])

        updated_model_result = self.route(
            "/v1/models/invoice-model",
            method="PUT",
            body={"version": "2026.1", "supplier_id": supplier["supplier_id"]},
        )
        self.assertEqual(updated_model_result["statusCode"], 200)
        self.assertEqual(self.body(updated_model_result)["supplier_name"], "Trusted Data Co")

        suppliers = self.body(self.route("/v1/suppliers"))
        self.assertEqual(suppliers["suppliers"][0]["bound_model_count"], 1)

    def test_governance_records_are_tenant_scoped(self):
        self.assertEqual(
            self.route("/v1/nonconformities", query={"tenant_id": "other"})["statusCode"],
            403,
        )
        self.assertEqual(
            self.route("/v1/models/not-in-demo/data-resources")["statusCode"],
            404,
        )


if __name__ == "__main__":
    unittest.main()
