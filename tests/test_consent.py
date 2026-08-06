"""Consent records and consent-aware policy coverage for #275."""

from __future__ import annotations

import json
import unittest
import urllib.error
import urllib.request
import uuid

from app.guard import evaluate, normalise_action
from app.policy import apply_policies, build_policy_record, rule_matches
from tests.local_api_harness import LocalApiFixture


class ConsentUnitTests(unittest.TestCase):
    def test_requires_consent_matches_without_active_record(self):
        policy = build_policy_record(
            {
                "policy_id": "consent-policy",
                "rules": [
                    {
                        "rule_id": "review-personal-data",
                        "decision": "require_approval",
                        "conditions": {
                            "requires_consent": {"purpose": "service-delivery", "data_scope": "contact"}
                        },
                    }
                ],
            },
            "demo",
            1,
        )
        action = normalise_action(
            {
                "action": {
                    "tool": "sql",
                    "purpose": "service-delivery",
                    "data_scope": "contact",
                    "parameters": {"statement": "SELECT email FROM people"},
                }
            }
        )
        self.assertTrue(rule_matches(policy["rules"][0], action))
        action["_active_consents"] = [{"purpose": "service-delivery", "data_scope": "contact", "status": "active"}]
        self.assertFalse(rule_matches(policy["rules"][0], action))
        applied = apply_policies(evaluate(action), action, [policy])
        self.assertEqual(applied["decision"], "allow")

    def test_requires_consent_does_not_match_a_different_action_purpose(self):
        policy = build_policy_record(
            {
                "rules": [
                    {
                        "decision": "deny",
                        "conditions": {"requires_consent": {"purpose": "service-delivery", "data_scope": "contact"}},
                    }
                ]
            },
            "demo",
            1,
        )
        action = normalise_action(
            {"action": {"tool": "sql", "purpose": "research", "data_scope": "contact", "parameters": {}}}
        )
        self.assertFalse(rule_matches(policy["rules"][0], action))

    def test_requires_consent_condition_is_validated(self):
        with self.assertRaisesRegex(ValueError, "requires_consent.*purpose is required"):
            build_policy_record(
                {"rules": [{"decision": "deny", "conditions": {"requires_consent": {"data_scope": "contact"}}}]},
                "demo",
                1,
            )


class ConsentApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = LocalApiFixture(tenant_id=f"consent-{uuid.uuid4().hex[:8]}")
        cls.state = cls.fixture.start()

    @classmethod
    def tearDownClass(cls):
        cls.fixture.stop()

    @classmethod
    def request(cls, path: str, method: str = "GET", payload: dict | None = None):
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(f"{cls.state['api_url']}{path}", data=data, method=method)
        request.add_header("Authorization", f"Bearer {cls.state['pat']}")
        request.add_header("Accept", "application/json")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read().decode("utf-8"))

    @classmethod
    def evaluate(cls, action: dict, action_id: str):
        return cls.request(
            "/v1/actions/evaluate",
            "POST",
            {
                "context": {
                    "tenant_id": cls.state["tenant_id"],
                    "environment": "development",
                    "agent_id": "consent-test-agent",
                    "invoked_by": "consent-test",
                    "action_id": action_id,
                },
                "action": action,
            },
        )

    def test_consent_lifecycle_filters_audit_and_policy_enforcement(self):
        purpose = "service-delivery"
        data_scope = "contact"
        policy_id = f"consent-policy-{uuid.uuid4().hex[:8]}"
        create_policy_status, _ = self.request(
            "/v1/policies",
            "POST",
            {
                "context": {"tenant_id": self.state["tenant_id"]},
                "policy_id": policy_id,
                "name": "Consent review policy",
                "rules": [
                    {
                        "rule_id": "consent-review",
                        "decision": "require_approval",
                        "conditions": {"requires_consent": {"purpose": purpose, "data_scope": data_scope}},
                    }
                ],
            },
        )
        self.assertEqual(create_policy_status, 201)
        publish_status, _ = self.request(f"/v1/policies/{policy_id}/publish", "POST", {"version": 1})
        self.assertEqual(publish_status, 200)

        no_consent_status, no_consent = self.evaluate(
            {"tool": "sql", "purpose": purpose, "data_scope": data_scope, "parameters": {"statement": "SELECT email"}},
            f"no-consent-{uuid.uuid4().hex[:8]}",
        )
        self.assertEqual(no_consent_status, 200)
        self.assertEqual(no_consent["decision"], "require_approval")

        create_status, consent = self.request(
            "/v1/consents",
            method="POST",
            payload={"subject": "citizen-001", "purpose": purpose, "data_scope": data_scope},
        )
        self.assertEqual(create_status, 201)
        self.assertEqual(consent["status"], "active")
        consent_id = consent["consent_id"]

        all_status, all_listed = self.request("/v1/consents")
        self.assertEqual(all_status, 200)
        self.assertTrue(any(item["consent_id"] == consent_id for item in all_listed["consents"]))
        list_status, listed = self.request("/v1/consents?subject=citizen-001&status=active")
        self.assertEqual(list_status, 200)
        self.assertEqual([item["consent_id"] for item in listed["consents"]], [consent_id])

        with_consent_status, with_consent = self.evaluate(
            {"tool": "sql", "purpose": purpose, "data_scope": data_scope, "parameters": {"statement": "SELECT email"}},
            f"with-consent-{uuid.uuid4().hex[:8]}",
        )
        self.assertEqual(with_consent_status, 200)
        self.assertEqual(with_consent["decision"], "allow")

        audit_status, audit = self.request(f"/v1/audit?event_type=consent.granted&tenant_id={self.state['tenant_id']}")
        self.assertEqual(audit_status, 200)
        self.assertTrue(any(event.get("consent_id") == consent_id for event in audit["events"]))

        revoke_status, revoked = self.request(f"/v1/consents/{consent_id}/revoke", method="POST", payload={})
        self.assertEqual(revoke_status, 200)
        self.assertEqual(revoked["status"], "revoked")
        self.assertFalse(revoked["idempotent"])
        repeat_status, repeated = self.request(f"/v1/consents/{consent_id}/revoke", method="POST", payload={})
        self.assertEqual(repeat_status, 200)
        self.assertTrue(repeated["idempotent"])

        after_revoke_status, after_revoke = self.evaluate(
            {"tool": "sql", "purpose": purpose, "data_scope": data_scope, "parameters": {"statement": "SELECT email"}},
            f"after-revoke-{uuid.uuid4().hex[:8]}",
        )
        self.assertEqual(after_revoke_status, 200)
        self.assertEqual(after_revoke["decision"], "require_approval")

        revoked_list_status, revoked_list = self.request("/v1/consents?status=revoked")
        self.assertEqual(revoked_list_status, 200)
        self.assertEqual(len([item for item in revoked_list["consents"] if item["consent_id"] == consent_id]), 1)

    def test_expired_consent_is_not_active(self):
        status, consent = self.request(
            "/v1/consents",
            method="POST",
            payload={
                "subject": "citizen-expired",
                "purpose": "service-delivery",
                "data_scope": "contact",
                "expires_at": "2020-01-01T00:00:00Z",
            },
        )
        self.assertEqual(status, 201)
        self.assertEqual(consent["status"], "expired")
        list_status, listed = self.request("/v1/consents?subject=citizen-expired&status=expired")
        self.assertEqual(list_status, 200)
        self.assertEqual(len(listed["consents"]), 1)

    def test_invalid_consent_and_status_are_rejected(self):
        status, body = self.request("/v1/consents", method="POST", payload={"subject": "citizen-001", "purpose": "service-delivery"})
        self.assertEqual(status, 400)
        self.assertIn("data_scope", body["message"])
        status, body = self.request("/v1/consents?status=unknown")
        self.assertEqual(status, 400)
        self.assertIn("active", body["allowed_statuses"])


if __name__ == "__main__":
    unittest.main()
