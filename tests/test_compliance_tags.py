"""Coverage for tenant compliance labels and policy coverage summaries (#273)."""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from app import lambda_function as service
from app.policy import normalise_compliance_tags
from app.starter_rules import default_starter_rules
from tests.test_lambda_routes import FakeTable, FakeTokenTable


class ComplianceTagsApiTests(unittest.TestCase):
    def setUp(self):
        service.table = FakeTable()
        service.token_table = FakeTokenTable()
        self.auth = {
            "tenant_id": "demo",
            "token_id": "compliance-test",
            "scopes": ["policy:read", "policy:write", "tenant:read", "tenant:write"],
        }

    @staticmethod
    def body(result):
        return json.loads(result["body"])

    def route(self, path, method="GET", body=None, auth=None):
        event = {
            "rawPath": path,
            "requestContext": {"http": {"method": method}},
            "headers": {"authorization": "Bearer kta_pat_test"},
        }
        if body is not None:
            event["body"] = json.dumps(body)
        with patch.object(service, "authenticate", return_value=(auth or self.auth, None)):
            return service.lambda_handler(event, None)

    def test_compliance_tags_are_bounded_deduplicated_and_sorted(self):
        self.assertEqual(
            normalise_compliance_tags([" Privacy Act 2020:IPP 5 ", "privacy act 2020:ipp 5", "NZ Algorithm Charter:Transparency"]),
            ["NZ Algorithm Charter:Transparency", "Privacy Act 2020:IPP 5"],
        )
        with self.assertRaises(ValueError):
            normalise_compliance_tags("Privacy Act 2020:IPP 5")
        with self.assertRaises(ValueError):
            normalise_compliance_tags(["tag"] * 51)

    def test_policy_tags_are_created_updated_and_returned_in_coverage(self):
        first = self.route(
            "/v1/policies",
            method="POST",
            body={
                "context": {"tenant_id": "demo"},
                "policy_id": "privacy-policy",
                "name": "Privacy policy",
                "compliance_tags": ["Privacy Act 2020:IPP 5", "NZ Algorithm Charter:Transparency"],
                "rules": [],
            },
        )
        self.assertEqual(first["statusCode"], 201)
        self.assertEqual(
            self.body(first)["compliance_tags"],
            ["NZ Algorithm Charter:Transparency", "Privacy Act 2020:IPP 5"],
        )

        updated = self.route(
            "/v1/policies/privacy-policy",
            method="PUT",
            body={"version": 1, "compliance_tags": ["Privacy Act 2020:IPP 8"]},
        )
        self.assertEqual(updated["statusCode"], 200)
        self.assertEqual(self.body(updated)["compliance_tags"], ["Privacy Act 2020:IPP 8"])

        second = self.route(
            "/v1/policies",
            method="POST",
            body={
                "context": {"tenant_id": "demo"},
                "policy_id": "algorithm-policy",
                "name": "Algorithm policy",
                "compliance_tags": ["Privacy Act 2020:IPP 8", "NZ Algorithm Charter:Accountability"],
                "rules": [],
            },
        )
        self.assertEqual(second["statusCode"], 201)

        coverage = self.route("/v1/compliance/coverage")
        self.assertEqual(coverage["statusCode"], 200)
        summary = self.body(coverage)
        self.assertEqual(summary["total_policies"], 2)
        self.assertEqual(summary["tagged_policies"], 2)
        self.assertEqual(summary["untagged_policies"], 0)
        by_tag = {item["tag"]: item for item in summary["tags"]}
        self.assertEqual(by_tag["Privacy Act 2020:IPP 8"]["policy_count"], 2)
        self.assertEqual(by_tag["Privacy Act 2020:IPP 8"]["policy_ids"], ["algorithm-policy", "privacy-policy"])

    def test_compliance_coverage_requires_policy_read(self):
        limited = {**self.auth, "scopes": ["tenant:read"]}
        result = self.route("/v1/compliance/coverage", auth=limited)
        self.assertEqual(result["statusCode"], 403)
        self.assertEqual(self.body(result)["required_scope"], "policy:read")

    def test_starter_defaults_have_editable_compliance_tags(self):
        defaults = default_starter_rules()
        self.assertTrue(all(rule["compliance_tags"] for rule in defaults))
        self.assertTrue(any("Privacy Act 2020:IPP 5" in rule["compliance_tags"] for rule in defaults))
        self.assertTrue(any("NZ Algorithm Charter:Transparency" in rule["compliance_tags"] for rule in defaults))

        selected = next(rule for rule in defaults if rule["rule_id"] == "CREDENTIAL_EXPOSURE")
        selected["compliance_tags"] = []
        saved = service.handle_put_starter_rules("demo", {"rules": defaults}, self.auth)
        self.assertEqual(saved["statusCode"], 201)
        listed = service.handle_get_starter_rules("demo", self.auth)
        self.assertEqual(listed["statusCode"], 200)
        stored = next(rule for rule in self.body(listed)["rules"] if rule["rule_id"] == "CREDENTIAL_EXPOSURE")
        self.assertEqual(stored["compliance_tags"], [])

    def test_policy_tags_must_be_an_array(self):
        result = self.route(
            "/v1/policies",
            method="POST",
            body={"name": "Invalid tags", "compliance_tags": "Privacy Act 2020:IPP 5", "rules": []},
        )
        self.assertEqual(result["statusCode"], 400)
        self.assertIn("compliance_tags", self.body(result)["message"])


if __name__ == "__main__":
    unittest.main()
