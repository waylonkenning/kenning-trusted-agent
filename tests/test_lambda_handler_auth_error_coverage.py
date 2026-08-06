"""Targeted branch coverage for lambda_handler auth-config error paths in
app/lambda_function.py (#271).

Covers the except-ValueError branches for /auth/login, /auth/reauth, and
/auth/logout, which return 400 invalid_auth_configuration when the OIDC
configuration is invalid.
"""

import json
import unittest
from unittest.mock import patch

from app import lambda_function as service


def make_event(method, path, query=None, headers=None):
    event = {
        "rawPath": path,
        "requestContext": {"http": {"method": method}},
        "headers": headers or {},
    }
    if query:
        event["queryStringParameters"] = query
    return event


class LambdaHandlerAuthErrorCoverageTests(unittest.TestCase):
    def _status(self, result):
        return result.get("statusCode", 200)

    def _body(self, result):
        raw = result.get("body", "{}")
        return json.loads(raw) if isinstance(raw, str) else raw

    def test_auth_login_invalid_configuration(self):
        """Lines 5725-5726: /auth/login ValueError -> 400."""
        with patch.object(service, "handle_auth_login", side_effect=ValueError("bad oidc")):
            result = service.lambda_handler(make_event("GET", "/auth/login"), None)
        self.assertEqual(self._status(result), 400)
        self.assertEqual(self._body(result)["error"], "invalid_auth_configuration")

    def test_auth_reauth_invalid_configuration(self):
        """Lines 5730-5731: /auth/reauth ValueError -> 400."""
        with patch.object(service, "handle_auth_login", side_effect=ValueError("bad oidc")):
            result = service.lambda_handler(make_event("GET", "/auth/reauth"), None)
        self.assertEqual(self._status(result), 400)
        self.assertEqual(self._body(result)["error"], "invalid_auth_configuration")

    def test_auth_logout_invalid_configuration(self):
        """Lines 5735-5736: /auth/logout ValueError -> 400."""
        with patch.object(service, "handle_auth_logout_redirect", side_effect=ValueError("bad oidc")):
            result = service.lambda_handler(make_event("GET", "/auth/logout"), None)
        self.assertEqual(self._status(result), 400)
        self.assertEqual(self._body(result)["error"], "invalid_auth_configuration")


if __name__ == "__main__":
    unittest.main()
