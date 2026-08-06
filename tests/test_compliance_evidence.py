"""Compliance evidence exports over audit, policy, and consent records (#277)."""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from app import lambda_function as service
from app.policy import build_policy_record
from tests.test_lambda_routes import FakeTable, FakeTokenTable


class ComplianceEvidenceApiTests(unittest.TestCase):
    def setUp(self):
        service.table = FakeTable()
        service.token_table = FakeTokenTable()
        self.store = service.AuditStore(service.table)
        self.auth = {
            "tenant_id": "demo",
            "token_id": "compliance-evidence-test",
            "scopes": ["audit:read", "audit:write", "policy:read"],
        }

    @staticmethod
    def body(result):
        return json.loads(result["body"])

    def route(self, path, query=None, auth=None):
        event = {
            "rawPath": path,
            "requestContext": {"http": {"method": "GET"}},
            "headers": {"authorization": "Bearer kta_pat_test"},
            "queryStringParameters": query or {},
        }
        with patch.object(service, "authenticate", return_value=(auth or self.auth, None)):
            return service.lambda_handler(event, None)

    def test_action_evidence_contains_decisions_outcomes_and_summary(self):
        now = service.utc_now()
        self.store.put_event(
            {
                "event_type": "action.evaluated",
                "tenant_id": "demo",
                "created_at": now,
                "action_id": "action-review",
                "agent_id": "agent-1",
                "decision": "require_approval",
                "risk_score": 80,
                "action_classification": "sensitive",
                "approval_id": "approval-1",
            }
        )
        self.store.put_event(
            {
                "event_type": "action.outcome",
                "tenant_id": "demo",
                "created_at": now,
                "action_id": "action-review",
                "status": "success",
            }
        )
        self.store.put_event(
            {
                "event_type": "action.evaluated",
                "tenant_id": "demo",
                "created_at": now,
                "action_id": "action-deny",
                "agent_id": "agent-2",
                "decision": "deny",
                "risk_score": 100,
                "action": {"classification": "restricted"},
            }
        )
        self.store.put_event(
            {
                "event_type": "action.evaluated",
                "tenant_id": "demo",
                "created_at": now,
                "action_id": "action-auto",
                "agent_id": "agent-3",
                "decision": "allow",
                "risk_score": 10,
                "auto_approved": True,
            }
        )

        result = self.route(
            "/v1/compliance/evidence",
            query={"type": "actions", "period_days": "90"},
        )
        self.assertEqual(result["statusCode"], 200)
        body = self.body(result)
        self.assertEqual(body["type"], "actions")
        self.assertEqual(body["period"]["days"], 90)
        self.assertEqual(body["summary"], {
            "total_actions": 3,
            "approvals_required": 1,
            "denials": 1,
            "auto_approved": 1,
        })
        records = {item["action_id"]: item for item in body["actions"]}
        self.assertEqual(records["action-review"]["approval_id"], "approval-1")
        self.assertEqual(records["action-review"]["outcome_status"], "success")
        self.assertEqual(records["action-review"]["classification"], "sensitive")
        self.assertEqual(records["action-deny"]["classification"], "restricted")
        exported = self.store.list_events("demo", filters={"event_type": "compliance.evidence_exported"})
        self.assertEqual(len(exported), 1)
        self.assertEqual(exported[0]["exported_by"], "compliance-evidence-test")
        self.assertEqual(exported[0]["evidence_type"], "actions")
        self.assertEqual(exported[0]["record_count"], 3)

    def test_coverage_evidence_lists_untagged_policies(self):
        tagged = build_policy_record(
            {
                "policy_id": "tagged-policy",
                "name": "Tagged policy",
                "compliance_tags": ["Privacy Act 2020:IPP 5"],
                "rules": [],
            },
            "demo",
            1,
        )
        untagged = build_policy_record(
            {"policy_id": "untagged-policy", "name": "Untagged policy", "rules": []},
            "demo",
            1,
        )
        self.store.put_policy(tagged)
        self.store.put_policy(untagged)

        result = self.route("/v1/compliance/evidence", query={"type": "coverage"})
        self.assertEqual(result["statusCode"], 200)
        body = self.body(result)
        coverage = body["coverage"]
        self.assertEqual(coverage["total_policies"], 2)
        self.assertEqual(coverage["tagged_policies"], 1)
        self.assertEqual(coverage["untagged_policies"], 1)
        self.assertEqual(coverage["policies_without_compliance_tags"], ["untagged-policy"])
        self.assertEqual(body["summary"], coverage)

    def test_consent_evidence_reports_current_status_counts(self):
        self.store.put_event(
            {
                "event_type": "consent.granted",
                "tenant_id": "demo",
                "created_at": "2026-08-01T00:00:00Z",
                "consent_id": "consent-active",
                "subject": "subject-1",
                "purpose": "service-delivery",
                "data_scope": "contact",
                "granted_at": "2026-08-01T00:00:00Z",
                "expires_at": "2099-01-01T00:00:00Z",
            }
        )
        self.store.put_event(
            {
                "event_type": "consent.granted",
                "tenant_id": "demo",
                "created_at": "2026-07-01T00:00:00Z",
                "consent_id": "consent-expired",
                "subject": "subject-2",
                "purpose": "research",
                "data_scope": "profile",
                "granted_at": "2026-07-01T00:00:00Z",
                "expires_at": "2020-01-01T00:00:00Z",
            }
        )
        self.store.put_event(
            {
                "event_type": "consent.granted",
                "tenant_id": "demo",
                "created_at": "2026-06-01T00:00:00Z",
                "consent_id": "consent-revoked",
                "subject": "subject-3",
                "purpose": "service-delivery",
                "data_scope": "contact",
                "granted_at": "2026-06-01T00:00:00Z",
                "expires_at": "2099-01-01T00:00:00Z",
            }
        )
        self.store.put_event(
            {
                "event_type": "consent.revoked",
                "tenant_id": "demo",
                "created_at": "2026-06-02T00:00:00Z",
                "consent_id": "consent-revoked",
                "subject": "subject-3",
                "purpose": "service-delivery",
                "data_scope": "contact",
                "granted_at": "2026-06-01T00:00:00Z",
                "expires_at": "2099-01-01T00:00:00Z",
            }
        )

        result = self.route("/v1/compliance/evidence", query={"type": "consents"})
        self.assertEqual(result["statusCode"], 200)
        body = self.body(result)
        self.assertEqual(body["summary"], {"total_consents": 3, "active": 1, "expired": 1, "revoked": 1})
        records = {item["consent_id"]: item for item in body["consents"]}
        self.assertEqual(records["consent-revoked"]["granted_at"], "2026-06-01T00:00:00Z")
        self.assertEqual(records["consent-revoked"]["status"], "revoked")

    def test_evidence_type_and_scope_are_validated(self):
        invalid = self.route("/v1/compliance/evidence", query={"type": "unknown"})
        self.assertEqual(invalid["statusCode"], 400)
        limited = self.route(
            "/v1/compliance/evidence",
            query={"type": "actions"},
            auth={**self.auth, "scopes": ["policy:read"]},
        )
        self.assertEqual(limited["statusCode"], 403)
        self.assertEqual(self.body(limited)["required_scope"], "audit:read")


if __name__ == "__main__":
    unittest.main()
