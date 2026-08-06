"""Targeted tests for starter rules, environment, and retention branches (#271).

Covers: handle_put_starter_rules, handle_simulate_starter_rule,
handle_list_environments, handle_put_environment, handle_retention_run.
"""

import unittest
from unittest.mock import patch

from app import lambda_function as service
from tests.test_federation import FakeTable, FakeTokenTable


def make_event(method, path, body=None, query=None, headers=None):
    event = {
        "rawPath": path,
        "requestContext": {"http": {"method": method}},
        "headers": headers or {},
    }
    if body is not None:
        event["body"] = body
    if query:
        event["queryStringParameters"] = query
    return event


class StarterRulesTests(unittest.TestCase):
    def setUp(self):
        self.table = FakeTable()
        service.table = self.table
        self.token_table = FakeTokenTable()
        service.token_table = self.token_table
        self.admin_auth = {"tenant_id": "demo", "token_id": "t1", "role": "admin", "subject": "admin@example.com", "scopes": ["admin"]}

    def _status(self, result):
        return result.get("statusCode", 200)

    def _body(self, result):
        import json
        raw = result.get("body", "{}")
        return json.loads(raw) if isinstance(raw, str) else raw

    # ------------------------------------------------------------------
    # handle_put_starter_rules (lines 3273, 3275)
    # ------------------------------------------------------------------

    def test_put_starter_rules_target_error(self):
        """Line 3273: tenant_target error propagates."""
        with patch.object(service, "tenant_target", return_value=(None, {"statusCode": 403, "body": "{}"})):
            result = service.handle_put_starter_rules("demo", {"rules": []}, self.admin_auth)
        self.assertEqual(self._status(result), 403)

    def test_put_starter_rules_missing_rules(self):
        """Line 3275: missing rules key returns 400."""
        with patch.object(service, "tenant_target", return_value=("demo", None)):
            result = service.handle_put_starter_rules("demo", {}, self.admin_auth)
        self.assertEqual(self._status(result), 400)
        self.assertEqual(self._body(result).get("error"), "starter_rules_required")

    # ------------------------------------------------------------------
    # handle_simulate_starter_rule (lines 3305, 3311)
    # ------------------------------------------------------------------

    def test_simulate_starter_rule_target_error(self):
        """Line 3305: tenant_target error propagates."""
        with patch.object(service, "tenant_target", return_value=(None, {"statusCode": 403, "body": "{}"})):
            result = service.handle_simulate_starter_rule("demo", {"rule_id": "r1"}, self.admin_auth)
        self.assertEqual(self._status(result), 403)

    def test_simulate_starter_rule_not_found(self):
        """Line 3311: rule not found returns 404."""
        with patch.object(service, "tenant_target", return_value=("demo", None)):
            result = service.handle_simulate_starter_rule("demo", {"rule_id": "missing"}, self.admin_auth)
        self.assertEqual(self._status(result), 404)
        self.assertEqual(self._body(result).get("error"), "starter_rule_not_found")


class EnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.table = FakeTable()
        service.table = self.table
        self.token_table = FakeTokenTable()
        service.token_table = self.token_table
        self.admin_auth = {"tenant_id": "demo", "token_id": "t1", "role": "admin", "subject": "admin@example.com", "scopes": ["admin"]}

    def _status(self, result):
        return result.get("statusCode", 200)

    def _body(self, result):
        import json
        raw = result.get("body", "{}")
        return json.loads(raw) if isinstance(raw, str) else raw

    # ------------------------------------------------------------------
    # handle_list_environments (line 3349)
    # ------------------------------------------------------------------

    def test_list_environments_target_error(self):
        """Line 3349: tenant_target error propagates."""
        with patch.object(service, "tenant_target", return_value=(None, {"statusCode": 403, "body": "{}"})):
            result = service.handle_list_environments("demo", self.admin_auth)
        self.assertEqual(self._status(result), 403)

    # ------------------------------------------------------------------
    # handle_put_environment (line 3365)
    # ------------------------------------------------------------------

    def test_put_environment_target_error(self):
        """Line 3365: tenant_target error propagates."""
        with patch.object(service, "tenant_target", return_value=(None, {"statusCode": 403, "body": "{}"})):
            result = service.handle_put_environment("demo", "dev", {}, self.admin_auth)
        self.assertEqual(self._status(result), 403)


class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.table = FakeTable()
        service.table = self.table
        self.token_table = FakeTokenTable()
        service.token_table = self.token_table
        self.admin_auth = {"tenant_id": "demo", "token_id": "t1", "role": "admin", "subject": "admin@example.com", "scopes": ["admin"]}

    def _status(self, result):
        return result.get("statusCode", 200)

    def _body(self, result):
        import json
        raw = result.get("body", "{}")
        return json.loads(raw) if isinstance(raw, str) else raw

    # ------------------------------------------------------------------
    # handle_retention_run (line 3411)
    # ------------------------------------------------------------------

    def test_retention_run_target_error(self):
        """Line 3411: tenant_target error propagates."""
        with patch.object(service, "tenant_target", return_value=(None, {"statusCode": 403, "body": "{}"})):
            result = service.handle_retention_run("demo", {}, self.admin_auth)
        self.assertEqual(self._status(result), 403)


if __name__ == "__main__":
    unittest.main()
