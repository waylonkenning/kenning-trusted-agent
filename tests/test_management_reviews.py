"""Focused API coverage for ISO/IEC 42001 management reviews and policy review dates."""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from app import lambda_function as service
from tests.test_lambda_routes import FakeTable, FakeTokenTable


class ManagementReviewApiTests(unittest.TestCase):
    def setUp(self):
        self.table = FakeTable()
        self.tokens = FakeTokenTable()
        service.table = self.table
        service.token_table = self.tokens
        self.auth = {
            "tenant_id": "demo",
            "token_id": "management-review-test",
            "scopes": ["audit:read", "audit:write", "policy:read", "policy:write"],
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

    def test_management_review_records_metrics_history_and_audit_export(self):
        for event in (
            {
                "event_type": "action.evaluated",
                "decision": "require_approval",
                "created_at": "2026-01-10T10:00:00Z",
                "action_id": "action-approval",
            },
            {
                "event_type": "action.evaluated",
                "decision": "deny",
                "created_at": "2026-01-11T10:00:00Z",
                "action_id": "action-denied",
            },
            {
                "event_type": "policy.updated",
                "created_at": "2026-01-12T10:00:00Z",
                "policy_id": "policy-one",
            },
            {
                "event_type": "agent.registered",
                "created_at": "2026-01-13T10:00:00Z",
                "agent_id": "agent-one",
            },
            {
                "event_type": "nonconformity.raised",
                "created_at": "2026-01-14T10:00:00Z",
                "action_id": "nc-one",
            },
        ):
            service.store().put_event({"tenant_id": "demo", "run_id": "test", "agent_id": "test", **event})

        created_result = self.route(
            "/v1/management-reviews",
            method="POST",
            body={
                "context": {"tenant_id": "demo"},
                "period_start": "2026-01-01",
                "period_end": "2026-01-31",
                "attendees": "A. Reviewer; B. Owner",
                "decisions": "Continue human approval for production actions.",
                "action_items": "Review supplier evidence before the next meeting.",
            },
        )
        self.assertEqual(created_result["statusCode"], 201)
        created = self.body(created_result)
        self.assertTrue(created["review_id"].startswith("management-review-"))
        self.assertEqual(
            created["metrics"],
            {
                "total_actions": 2,
                "approvals_required": 1,
                "denials": 1,
                "policies_changed": 1,
                "agents_registered": 1,
                "nonconformities_open": 1,
            },
        )

        listed_result = self.route("/v1/management-reviews", query={"tenant_id": "demo"})
        self.assertEqual(listed_result["statusCode"], 200)
        listed = self.body(listed_result)
        self.assertEqual(len(listed["reviews"]), 1)
        self.assertEqual(listed["reviews"][0]["review_id"], created["review_id"])
        self.assertEqual(listed["reviews"][0]["action_items"], created["action_items"])

        export_result = self.route(
            "/v1/audit/export",
            query={"tenant_id": "demo", "format": "json", "limit": "100"},
        )
        self.assertEqual(export_result["statusCode"], 200)
        exported = self.body(export_result)
        self.assertTrue(
            any(event.get("event_type") == "management_review.created" for event in exported["events"])
        )

    def test_policy_review_date_is_durable_and_overdue_status_is_calculated(self):
        policy_id = "management-review-policy"
        created_result = self.route(
            "/v1/policies",
            method="POST",
            body={
                "context": {"tenant_id": "demo"},
                "policy_id": policy_id,
                "name": "Management review policy",
                "rules": [{"decision": "deny", "tool": "shell"}],
            },
        )
        self.assertEqual(created_result["statusCode"], 201)

        publish_result = self.route(
            f"/v1/policies/{policy_id}/publish",
            method="POST",
            body={"version": 1},
        )
        self.assertEqual(publish_result["statusCode"], 200)

        old_review_result = self.route(
            f"/v1/policies/{policy_id}",
            method="PUT",
            body={"version": 1, "last_reviewed_at": "2024-01-01T00:00:00Z"},
        )
        self.assertEqual(old_review_result["statusCode"], 200)
        self.assertTrue(self.body(old_review_result)["review_overdue"])

        current_review = service.utc_now()
        current_review_result = self.route(
            f"/v1/policies/{policy_id}",
            method="PUT",
            body={"version": 1, "last_reviewed_at": current_review},
        )
        self.assertEqual(current_review_result["statusCode"], 200)
        self.assertFalse(self.body(current_review_result)["review_overdue"])

        listed_result = self.route("/v1/policies")
        self.assertEqual(listed_result["statusCode"], 200)
        policy = next(item for item in self.body(listed_result)["policies"] if item["policy_id"] == policy_id)
        self.assertEqual(policy["last_reviewed_at"], current_review)
        self.assertFalse(policy["review_overdue"])

        reviewed_events = service.store().list_events(
            "demo",
            filters={"event_type": "policy.reviewed", "limit": 10},
        )
        self.assertEqual(len(reviewed_events), 2)


if __name__ == "__main__":
    unittest.main()
