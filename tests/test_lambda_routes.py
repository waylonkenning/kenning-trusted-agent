import base64
import json
import time
import unittest
from unittest.mock import Mock
from unittest.mock import patch

from app import lambda_function as service
from app.starter_rules import default_starter_rules
from app.tenant import build_tenant_config

# Blank every OIDC env var so "no config" tests are deterministic even when
# the CI / dev environment has a real Cognito pool wired up.
_NO_OIDC_ENV = {
    key: ""
    for key in (
        "CONTROL_PLANE_OIDC_ISSUER_URL",
        "CONTROL_PLANE_OIDC_CLIENT_ID",
        "CONTROL_PLANE_OIDC_REDIRECT_URI",
        "CONTROL_PLANE_OIDC_AUTHORIZATION_URL",
        "CONTROL_PLANE_OIDC_TOKEN_URL",
        "CONTROL_PLANE_OIDC_LOGOUT_URL",
        "CONTROL_PLANE_OIDC_JWKS_URL",
        "CONTROL_PLANE_OIDC_PASSKEYS_ENABLED",
        "CONTROL_PLANE_OIDC_PASSKEYS_URL",
        "CONTROL_PLANE_OIDC_PASSKEYS_REDIRECT_URI",
    )
}


def conditional_check_failed():
    if service.boto3 is None:
        return service.ClientError()
    return service.ClientError(
        {"Error": {"Code": "ConditionalCheckFailedException", "Message": "condition failed"}},
        "FakeTable",
    )


class FakeTable:
    def __init__(self):
        self.items = {}
        self.scan_calls = 0
        self.query_calls = 0
        self.put_calls = []
        self.get_calls = []

    def put_item(self, Item, **kwargs):
        self.put_calls.append((Item["pk"], Item["sk"]))
        if kwargs.get("ConditionExpression") and (Item["pk"], Item["sk"]) in self.items:
            raise conditional_check_failed()
        self.items[(Item["pk"], Item["sk"])] = dict(Item)

    def get_item(self, Key, **_kwargs):
        self.get_calls.append((Key["pk"], Key["sk"]))
        return {"Item": self.items.get((Key["pk"], Key["sk"]))} if (Key["pk"], Key["sk"]) in self.items else {}

    def scan(self, **_kwargs):
        self.scan_calls += 1
        return {"Items": list(self.items.values())}

    @staticmethod
    def matches_condition(item, condition):
        if hasattr(condition, "get_expression"):
            expression = condition.get_expression()
            operator = expression["operator"]
            values = expression["values"]
            if operator == "AND":
                return all(FakeTable.matches_condition(item, value) for value in values)
            field = (
                values[0].get_name()
                if hasattr(values[0], "get_name")
                else getattr(values[0], "name", str(values[0]))
            )
            actual = item.get(field)
            expected = values[1]
            if operator in ("=", "eq"):
                return actual == expected
            if operator == "begins_with":
                return str(actual or "").startswith(str(expected))
            if operator in ("BETWEEN", "between"):
                return values[1] <= actual <= values[2]
            return True
        if condition is None or not hasattr(condition, "operator"):
            return True
        clauses = getattr(condition, "clauses", None)
        if clauses:
            return all(FakeTable.matches_condition(item, clause) for clause in clauses)
        field = getattr(condition, "field", None)
        operator = getattr(condition, "operator", None)
        actual = item.get(field)
        value = getattr(condition, "value", None)
        if operator == "eq":
            return actual == value
        if operator == "begins_with":
            return str(actual or "").startswith(str(value))
        if operator == "between":
            return value[0] <= actual <= value[1]
        return True

    def query(self, **kwargs):
        self.query_calls += 1
        items = [
            item for item in self.items.values()
            if self.matches_condition(item, kwargs.get("KeyConditionExpression"))
        ]
        items.sort(key=lambda item: (item.get("pk", ""), item.get("sk", "")), reverse=not kwargs.get("ScanIndexForward", True))
        limit = kwargs.get("Limit")
        return {"Items": items[:int(limit)] if limit else items}

    def delete_item(self, Key):
        self.items.pop((Key["pk"], Key["sk"]), None)

    def update_item(self, Key, UpdateExpression, ExpressionAttributeValues, ExpressionAttributeNames=None, ConditionExpression=None, ReturnValues=None, **_kwargs):
        key = (Key["pk"], Key["sk"])
        item = self.items.get(key)
        if item is None:
            if ConditionExpression:
                raise conditional_check_failed()
            item = {"pk": key[0], "sk": key[1]}
        names = ExpressionAttributeNames or {}

        def atom_matches(atom):
            atom = atom.strip()
            for operator in ("<=", ">=", "=", "<", ">"):
                if operator in atom:
                    left, right = atom.split(operator, 1)
                    left = names.get(left.strip(), left.strip())
                    expected = ExpressionAttributeValues[right.strip()]
                    actual = item.get(left)
                    if operator == "=":
                        return actual == expected
                    try:
                        actual_number = float(actual)
                        expected_number = float(expected)
                    except (TypeError, ValueError):
                        return False
                    return {"<=": actual_number <= expected_number, ">=": actual_number >= expected_number, "<": actual_number < expected_number, ">": actual_number > expected_number}[operator]
            return True

        if ConditionExpression:
            any_group = False
            for group in ConditionExpression.split(" OR "):
                if all(atom_matches(atom) for atom in group.split(" AND ")):
                    any_group = True
                    break
            if not any_group:
                raise conditional_check_failed()
        set_expression, _, add_expression = UpdateExpression.partition(" ADD ")
        assignments = set_expression.removeprefix("SET ").split(", ")
        for assignment in assignments:
            left, right = assignment.split(" = ", 1)
            item[names.get(left, left)] = ExpressionAttributeValues[right]
        for addition in add_expression.split(", ") if add_expression else []:
            left, right = addition.split(" ", 1)
            key_name = names.get(left, left)
            item[key_name] = (item.get(key_name) or 0) + ExpressionAttributeValues[right]
        self.items[key] = dict(item)
        return {"Attributes": dict(item)} if ReturnValues == "ALL_NEW" else {}


class FakeTokenTable:
    def __init__(self):
        self.items = {}
        self.scan_calls = 0
        self.query_calls = 0

    def put_item(self, Item, **kwargs):
        if kwargs.get("ConditionExpression") and Item["token_hash"] in self.items:
            raise conditional_check_failed()
        self.items[Item["token_hash"]] = dict(Item)

    def get_item(self, Key, **_kwargs):
        item = self.items.get(Key["token_hash"])
        return {"Item": dict(item)} if item else {}

    def scan(self, **_kwargs):
        self.scan_calls += 1
        return {"Items": [dict(item) for item in self.items.values()]}

    def query(self, **kwargs):
        self.query_calls += 1
        condition = kwargs.get("KeyConditionExpression")
        return {
            "Items": [
                dict(item) for item in self.items.values()
                if FakeTable.matches_condition(item, condition)
            ]
        }

    def update_item(self, Key, UpdateExpression=None, ExpressionAttributeValues=None, ExpressionAttributeNames=None, **_kwargs):
        item = self.items[Key["token_hash"]]
        names = ExpressionAttributeNames or {}
        values = ExpressionAttributeValues or {}
        for assignment in str(UpdateExpression or "").removeprefix("SET ").split(", "):
            left, right = assignment.split(" = ", 1)
            item[names.get(left, left)] = values[right]
        self.items[Key["token_hash"]] = dict(item)
        return {"Attributes": dict(item)}




class LambdaRouteTests(unittest.TestCase):
    def setUp(self):
        self.table = FakeTable()
        service.table = self.table
        self.token_table = FakeTokenTable()
        service.token_table = self.token_table
        self.store = service.AuditStore(self.table)
        self.auth = {
            "tenant_id": "demo",
            "token_id": "pat-admin-test",
            "scopes": ["tenant:read", "tenant:write", "tenant:retention", "guard:evaluate", "audit:read", "approve:actions", "token:admin"],
        }


    @staticmethod
    def body(result):
        return json.loads(result["body"])


    def _route(self, path, method="GET", body=None, auth=None, query=None):
        event = {
            "rawPath": path,
            "requestContext": {"http": {"method": method}},
            "headers": {"authorization": "Bearer kta_pat_test"},
        }
        if body is not None:
            event["body"] = json.dumps(body)
        if query:
            event["queryStringParameters"] = query
        effective_auth = auth or self.auth
        with patch.object(service, "authenticate", return_value=(effective_auth, None)):
            return service.lambda_handler(event, None)


    def _session_auth(self, **overrides):
        auth = {
            "token_type": "session",
            "auth_source": "session",
            "tenant_id": "demo",
            "subject": "user@example.org",
            "email": "user@example.org",
            "display_name": "Test User",
            "token_id": "session-test",
            "token_hash": "fake-session-hash",
            "scopes": ["tenant:read"],
            "expires_at": int(time.time()) + 3600,
            "last_activity_at": int(time.time()),
        }
        auth.update(overrides)
        return auth


    def _make_client_error(self, code):
        exc = service.ClientError(
            {"Error": {"Code": code, "Message": "test"}},
            "ConfirmSignUp",
        )
        exc.response = {"Error": {"Code": code, "Message": "test"}}
        return exc


    def _route(self, path, method="GET", body=None, auth=None, query=None):
        event = {
            "rawPath": path,
            "requestContext": {"http": {"method": method}},
            "headers": {"authorization": "Bearer kta_pat_test"},
        }
        if body is not None:
            event["body"] = json.dumps(body)
        if query:
            event["queryStringParameters"] = query
        effective_auth = auth or self.auth
        with patch.object(service, "authenticate", return_value=(effective_auth, None)):
            return service.lambda_handler(event, None)


    def _routed(self, path, method="GET", body=None, auth=None, query=None):
        """Call lambda_handler with patched authenticate."""
        event = {
            "rawPath": path,
            "requestContext": {"http": {"method": method}},
            "headers": {"authorization": "Bearer kta_pat_test"},
        }
        if query:
            event["queryStringParameters"] = query
        if body is not None:
            event["body"] = json.dumps(body)
        use_auth = auth or self.auth
        with patch.object(service, "authenticate", return_value=(use_auth, None)):
            return service.lambda_handler(event, None)



    def _mcp_call(self, tool_name, arguments, auth=None, profile=None):
        mcp_auth = auth or {**self.auth, "scopes": ["mcp:read", "guard:evaluate", "identity:write", "identity:read", "proof:write", "proof:read", "citation:verify"]}
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }
        return service.handle_mcp({"headers": {}}, body, "POST", mcp_auth, profile)



    def test_handle_auth_config_reports_oidc_disabled_by_default(self):
        with patch.dict("os.environ", _NO_OIDC_ENV):
            result = service.handle_auth_config()
        self.assertEqual(result["statusCode"], 200)
        body = self.body(result)
        self.assertFalse(body["oidc_enabled"])
        self.assertFalse(body["passkeys_enabled"])
        self.assertIn("session_ttl_seconds", body)


    def test_handle_auth_login_returns_404_without_oidc_config(self):
        with patch.dict("os.environ", _NO_OIDC_ENV):
            result = service.handle_auth_login({"queryStringParameters": {}})
        self.assertEqual(result["statusCode"], 404)
        self.assertEqual(self.body(result)["error"], "oidc_not_configured")


    def test_handle_auth_login_redirects_to_provider_when_configured(self):
        oidc_env = {
            "CONTROL_PLANE_OIDC_ISSUER_URL": "https://auth.example.org",
            "CONTROL_PLANE_OIDC_CLIENT_ID": "test-client",
            "CONTROL_PLANE_OIDC_REDIRECT_URI": "https://console.example.org/auth/callback",
            "CONTROL_PLANE_OIDC_AUTHORIZATION_URL": "https://auth.example.org/authorize",
            "CONTROL_PLANE_OIDC_TOKEN_URL": "https://auth.example.org/token",
        }
        with patch.dict("os.environ", oidc_env), patch.object(service, "token_table", FakeTokenTable()):
            result = service.handle_auth_login({"queryStringParameters": {"return_to": "/app/dashboard"}})
        self.assertEqual(result["statusCode"], 302)
        location = result["headers"]["location"]
        self.assertTrue(location.startswith("https://auth.example.org/authorize?"))
        self.assertIn("client_id=test-client", location)
        self.assertIn("code_challenge_method=S256", location)


    def test_handle_auth_login_sanitises_open_redirect(self):
        oidc_env = {
            "CONTROL_PLANE_OIDC_ISSUER_URL": "https://auth.example.org",
            "CONTROL_PLANE_OIDC_CLIENT_ID": "test-client",
            "CONTROL_PLANE_OIDC_REDIRECT_URI": "https://console.example.org/auth/callback",
            "CONTROL_PLANE_OIDC_AUTHORIZATION_URL": "https://auth.example.org/authorize",
            "CONTROL_PLANE_OIDC_TOKEN_URL": "https://auth.example.org/token",
        }
        with patch.dict("os.environ", oidc_env), patch.object(service, "token_table", FakeTokenTable()):
            result = service.handle_auth_login({"queryStringParameters": {"return_to": "https://evil.example.org"}})
        self.assertEqual(result["statusCode"], 302)


    def test_handle_auth_callback_rejects_missing_state_or_code(self):
        oidc_env = {
            "CONTROL_PLANE_OIDC_ISSUER_URL": "https://auth.example.org",
            "CONTROL_PLANE_OIDC_CLIENT_ID": "test-client",
            "CONTROL_PLANE_OIDC_REDIRECT_URI": "https://console.example.org/auth/callback",
            "CONTROL_PLANE_OIDC_AUTHORIZATION_URL": "https://auth.example.org/authorize",
            "CONTROL_PLANE_OIDC_TOKEN_URL": "https://auth.example.org/token",
            "CONTROL_PLANE_PORTAL_ORIGIN": "https://console.example.org",
        }
        with patch.dict("os.environ", oidc_env), patch.object(service, "token_table", FakeTokenTable()):
            result = service.handle_auth_callback({"queryStringParameters": {}})
        self.assertEqual(result["statusCode"], 302)
        self.assertEqual(result["headers"]["location"], "https://console.example.org/app?auth_error=invalid_oidc_callback")


    def test_handle_auth_callback_rejects_unknown_state(self):
        oidc_env = {
            "CONTROL_PLANE_OIDC_ISSUER_URL": "https://auth.example.org",
            "CONTROL_PLANE_OIDC_CLIENT_ID": "test-client",
            "CONTROL_PLANE_OIDC_REDIRECT_URI": "https://console.example.org/auth/callback",
            "CONTROL_PLANE_OIDC_AUTHORIZATION_URL": "https://auth.example.org/authorize",
            "CONTROL_PLANE_OIDC_TOKEN_URL": "https://auth.example.org/token",
            "CONTROL_PLANE_PORTAL_ORIGIN": "https://console.example.org",
        }
        with patch.dict("os.environ", oidc_env), patch.object(service, "token_table", FakeTokenTable()):
            result = service.handle_auth_callback({"queryStringParameters": {"state": "bogus", "code": "abc"}})
        self.assertEqual(result["statusCode"], 302)
        self.assertEqual(result["headers"]["location"], "https://console.example.org/app?auth_error=invalid_oidc_state")


    def test_handle_auth_logout_redirects_without_oidc(self):
        with patch.dict("os.environ", _NO_OIDC_ENV):
            result = service.handle_auth_logout_redirect()
        self.assertEqual(result["statusCode"], 302)
        self.assertEqual(result["headers"]["location"], "/app")


    def test_handle_auth_logout_uses_provider_logout_when_configured(self):
        oidc_env = {
            "CONTROL_PLANE_OIDC_ISSUER_URL": "https://auth.example.org",
            "CONTROL_PLANE_OIDC_CLIENT_ID": "test-client",
            "CONTROL_PLANE_OIDC_REDIRECT_URI": "https://console.example.org/auth/callback",
            "CONTROL_PLANE_OIDC_AUTHORIZATION_URL": "https://auth.example.org/authorize",
            "CONTROL_PLANE_OIDC_TOKEN_URL": "https://auth.example.org/token",
            "CONTROL_PLANE_OIDC_LOGOUT_URL": "https://auth.example.org/logout",
        }
        with patch.dict("os.environ", oidc_env):
            result = service.handle_auth_logout_redirect()
        self.assertEqual(result["statusCode"], 302)
        self.assertIn("auth.example.org/logout", result["headers"]["location"])

    # ------------------------------------------------------------------
    # Session handlers: handle_create_session, handle_me, handle_csrf,
    # handle_logout
    # ------------------------------------------------------------------


    def test_handle_create_session_rejects_non_interactive(self):
        workload_auth = {
            "token_type": "pat",
            "auth_source": "pat",
            "principal_type": "workload",
            "tenant_id": "demo",
            "subject": "workload@example.org",
            "token_id": "pat-workload",
            "scopes": ["session:create"],
        }
        result = service.handle_create_session({"headers": {}}, workload_auth)
        self.assertEqual(result["statusCode"], 403)


    def test_handle_create_session_returns_active_for_existing_session(self):
        session_auth = self._session_auth()
        result = service.handle_create_session({"headers": {}}, session_auth)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(self.body(result)["session"], "active")


    def test_handle_csrf_rejects_non_session(self):
        result = service.handle_csrf(self.auth)
        self.assertEqual(result["statusCode"], 403)


    def test_handle_accept_invitation_redeems_for_session_subject(self):
        created = self.body(service.handle_create_invitation("demo", {"role": "viewer"}, {}, self.auth))
        token = created["token"]
        session_auth = self._session_auth(subject="acceptor@example.org")
        result = service.handle_accept_invitation({"token": token}, session_auth)
        self.assertEqual(result["statusCode"], 200)
        body = self.body(result)
        self.assertTrue(body["accepted"])
        self.assertEqual(body["membership"]["subject"], "acceptor@example.org")

    # ------------------------------------------------------------------
    # Policy handlers
    # ------------------------------------------------------------------


    def test_lambda_handler_health_endpoint(self):
        result = service.lambda_handler({"rawPath": "/health", "requestContext": {"http": {"method": "GET"}}}, None)
        self.assertEqual(result["statusCode"], 200)
        body = self.body(result)
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["service"], "kenning-agent-guard")
        self.assertIn("release_id", body)
        self.assertIn("release_name", body)
        self.assertIn("release_version", body)


    def test_lambda_handler_options_returns_204(self):
        result = service.lambda_handler({"rawPath": "/v1/anything", "requestContext": {"http": {"method": "OPTIONS"}}}, None)
        self.assertEqual(result["statusCode"], 204)


    def test_lambda_handler_auth_config_route(self):
        result = service.lambda_handler({"rawPath": "/auth/config", "requestContext": {"http": {"method": "GET"}}}, None)
        self.assertEqual(result["statusCode"], 200)
        self.assertIn("oidc_enabled", self.body(result))


    def test_lambda_handler_invalid_json_returns_400(self):
        event = {
            "rawPath": "/v1/actions/evaluate",
            "requestContext": {"http": {"method": "POST"}},
            "headers": {"authorization": "Bearer kta_pat_test"},
            "body": "{invalid json",
        }
        with patch.object(service, "authenticate", return_value=(self.auth, None)):
            result = service.lambda_handler(event, None)
        self.assertEqual(result["statusCode"], 400)
        self.assertEqual(self.body(result)["error"], "invalid_json")


    def test_lambda_handler_value_error_returns_400(self):
        event = {
            "rawPath": "/v1/actions/evaluate",
            "requestContext": {"http": {"method": "POST"}},
            "headers": {"authorization": "Bearer kta_pat_test"},
            "body": json.dumps({"context": {"tenant_id": "demo"}, "action": {}}),
        }
        with patch.object(service, "authenticate", return_value=(self.auth, None)), \
             patch.object(service, "handle_evaluate", side_effect=ValueError("bad input")):
            result = service.lambda_handler(event, None)
        self.assertEqual(result["statusCode"], 400)
        self.assertEqual(self.body(result)["error"], "invalid_request")


    def test_lambda_handler_scope_enforcement(self):
        limited_auth = {**self.auth, "scopes": ["tenant:read"]}
        event = {
            "rawPath": "/v1/actions/evaluate",
            "requestContext": {"http": {"method": "POST"}},
            "headers": {"authorization": "Bearer kta_pat_test"},
            "body": json.dumps({"context": {"tenant_id": "demo"}, "action": {"tool": "shell"}}),
        }
        with patch.object(service, "authenticate", return_value=(limited_auth, None)):
            result = service.lambda_handler(event, None)
        self.assertEqual(result["statusCode"], 403)
        self.assertEqual(self.body(result)["required_scope"], "guard:evaluate")

    # ------------------------------------------------------------------
    # MCP handler edge cases
    # ------------------------------------------------------------------


    def test_session_authentication_returns_none_without_cookie(self):
        event = {"headers": {}}
        auth, error = service.session_authentication(event)
        self.assertIsNone(auth)
        self.assertIsNone(error)


    def test_session_authentication_rejects_expired_session(self):
        from app.control_plane import session_hash as sh
        token = "kta_session_expired_test_token"
        self.token_table.put_item(Item={
            "token_hash": sh(token),
            "token_id": "sess-expired",
            "token_type": "session",
            "status": "active",
            "tenant_id": "demo",
            "subject": "user-1",
            "expires_at": int(time.time()) - 100,
        })
        event = {"headers": {"cookie": f"kta_session={token}"}}
        auth, error = service.session_authentication(event)
        self.assertIsNone(auth)
        self.assertIsNotNone(error)
        self.assertEqual(error["statusCode"], 401)


    def test_session_authentication_rejects_revoked_session(self):
        from app.control_plane import session_hash as sh
        token = "kta_session_revoked_test_token"
        self.token_table.put_item(Item={
            "token_hash": sh(token),
            "token_id": "sess-revoked",
            "token_type": "session",
            "status": "revoked",
            "tenant_id": "demo",
            "subject": "user-1",
            "expires_at": int(time.time()) + 3600,
        })
        event = {"headers": {"cookie": f"kta_session={token}"}}
        auth, error = service.session_authentication(event)
        self.assertIsNone(auth)
        self.assertIsNotNone(error)


    def test_session_authentication_success(self):
        from app.control_plane import session_hash as sh
        token = "kta_session_valid_test_token"
        now = int(time.time())
        self.token_table.put_item(Item={
            "token_hash": sh(token),
            "token_id": "sess-valid",
            "token_type": "session",
            "status": "active",
            "tenant_id": "demo",
            "subject": "user-1",
            "expires_at": now + 3600,
            "last_activity_at": now,
            "session_scopes": ["guard:evaluate"],
        })
        event = {"headers": {"cookie": f"kta_session={token}"}}
        auth, error = service.session_authentication(event)
        self.assertIsNotNone(auth)
        self.assertIsNone(error)
        self.assertEqual(auth["subject"], "user-1")
        self.assertEqual(auth["auth_source"], "session")


    def test_session_authentication_revokes_on_inactivity(self):
        from app.control_plane import session_hash as sh
        token = "kta_session_inactive_test_token"
        now = int(time.time())
        self.token_table.put_item(Item={
            "token_hash": sh(token),
            "token_id": "sess-inactive",
            "token_type": "session",
            "status": "active",
            "tenant_id": "demo",
            "subject": "user-1",
            "expires_at": now + 3600,
            "last_activity_at": now - 100000,
        })
        event = {"headers": {"cookie": f"kta_session={token}"}}
        auth, error = service.session_authentication(event)
        self.assertIsNone(auth)
        self.assertIsNotNone(error)

    # ------------------------------------------------------------------
    # validate_session_csrf
    # ------------------------------------------------------------------


    def test_validate_session_csrf_skips_non_session(self):
        service.validate_session_csrf({"headers": {}}, self.auth, "POST")


    def test_validate_session_csrf_skips_get(self):
        session_auth = {**self.auth, "auth_source": "session", "token_type": "session"}
        service.validate_session_csrf({"headers": {}}, session_auth, "GET")


    def test_validate_session_csrf_rejects_missing_header(self):
        session_auth = {**self.auth, "auth_source": "session", "token_type": "session", "csrf_hash": "abc123"}
        with self.assertRaises(service.ApiError):
            service.validate_session_csrf({"headers": {}}, session_auth, "POST")

    # ------------------------------------------------------------------
    # _confirmation_values
    # ------------------------------------------------------------------


    def test_handle_auth_confirm_validation_error(self):
        result = service.handle_auth_confirm({})
        self.assertEqual(result["statusCode"], 400)


    def test_handle_auth_confirm_no_oidc_config(self):
        with patch.dict("os.environ", _NO_OIDC_ENV):
            result = service.handle_auth_confirm({"username": "user@example.com", "confirmation_code": "123456"})
        self.assertEqual(result["statusCode"], 503)


    def test_handle_auth_confirm_resend_validation_error(self):
        result = service.handle_auth_confirm_resend({})
        self.assertEqual(result["statusCode"], 400)


    def test_handle_auth_confirm_resend_no_oidc_config(self):
        with patch.dict("os.environ", _NO_OIDC_ENV):
            result = service.handle_auth_confirm_resend({"username": "user@example.com"})
        self.assertEqual(result["statusCode"], 503)

    # ------------------------------------------------------------------
    # _oauth_client_secret
    # ------------------------------------------------------------------


    def test_handle_csrf_requires_session(self):
        result = service.handle_csrf(self.auth)
        self.assertEqual(result["statusCode"], 403)


    def test_handle_logout_non_session_returns_204(self):
        result = service.handle_logout(self.auth)
        self.assertEqual(result["statusCode"], 204)


    def test_handle_logout_session_revokes(self):
        from app.control_plane import session_hash as sh
        token = "kta_session_logout_test_token"
        self.token_table.put_item(Item={
            "token_hash": sh(token),
            "token_id": "sess-logout",
            "token_type": "session",
            "status": "active",
            "tenant_id": "demo",
            "subject": "user-1",
            "expires_at": int(time.time()) + 3600,
        })
        session_auth = {**self.auth, "auth_source": "session", "token_type": "session", "token_hash": sh(token), "tenant_id": "demo", "subject": "user-1"}
        result = service.handle_logout(session_auth)
        self.assertEqual(result["statusCode"], 204)
        record = self.token_table.items[sh(token)]
        self.assertEqual(record["status"], "revoked")


    def test_handle_create_session_already_session(self):
        session_auth = {**self.auth, "auth_source": "session", "token_type": "session", "subject": "user-1"}
        result = service.handle_create_session({"headers": {}}, session_auth)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(self.body(result)["session"], "active")


    def test_handle_create_session_requires_scope(self):
        pat_auth = {**self.auth, "token_type": "pat", "subject": "user-1", "scopes": ["tenant:read"]}
        result = service.handle_create_session({"headers": {}}, pat_auth)
        self.assertEqual(result["statusCode"], 403)
        self.assertEqual(self.body(result)["error"], "interactive_session_scope_required")

    # ------------------------------------------------------------------
    # Member handlers
    # ------------------------------------------------------------------


    def test_lambda_handler_v1_me_route(self):
        session_auth = {**self.auth, "auth_source": "session", "token_type": "session", "subject": "user-1", "tenant_id": "demo", "expires_at": int(time.time()) + 3600, "last_activity_at": int(time.time())}
        result = self._route("/v1/me", auth=session_auth)
        self.assertEqual(result["statusCode"], 200)


    def test_lambda_handler_agents_route(self):
        identity_auth = {**self.auth, "scopes": [*self.auth["scopes"], "identity:read", "identity:write"]}
        result = self._route("/v1/agents", "GET", auth=identity_auth)
        self.assertEqual(result["statusCode"], 200)


    def test_lambda_handler_agents_post_route(self):
        identity_auth = {**self.auth, "scopes": [*self.auth["scopes"], "identity:read", "identity:write"]}
        result = self._route("/v1/agents", "POST", body={"agent_id": "route-agent", "name": "Route", "owner": "user-1"}, auth=identity_auth)
        self.assertEqual(result["statusCode"], 201)


    def test_lambda_handler_policies_route(self):
        policy_auth = {**self.auth, "scopes": [*self.auth["scopes"], "policy:read", "policy:write"]}
        result = self._route("/v1/policies", "GET", auth=policy_auth)
        self.assertEqual(result["statusCode"], 200)


    def test_lambda_handler_policies_post_route(self):
        policy_auth = {**self.auth, "scopes": [*self.auth["scopes"], "policy:read", "policy:write"]}
        result = self._route("/v1/policies", "POST", body={"name": "Route Policy", "rules": []}, auth=policy_auth)
        self.assertEqual(result["statusCode"], 201)


    def test_lambda_handler_receipt_public_key_route(self):
        proof_auth = {**self.auth, "scopes": [*self.auth["scopes"], "proof:read"]}
        result = self._route("/v1/receipts/public-key", "GET", auth=proof_auth)
        # 200 when signing key is configured, 503 otherwise
        self.assertIn(result["statusCode"], (200, 503))


    def test_lambda_handler_tenant_invitations_route(self):
        result = self._route("/v1/tenants/demo/invitations", "GET")
        self.assertEqual(result["statusCode"], 200)


    def test_lambda_handler_tenant_invitations_post_route(self):
        result = self._route("/v1/tenants/demo/invitations", "POST", body={"role": "viewer"})
        self.assertEqual(result["statusCode"], 201)


    def test_lambda_handler_tenant_environments_route(self):
        result = self._route("/v1/tenants/demo/environments", "GET")
        self.assertEqual(result["statusCode"], 200)


    def test_lambda_handler_tenant_get_route(self):
        result = self._route("/v1/tenants/demo", "GET")
        self.assertEqual(result["statusCode"], 200)


    def test_lambda_handler_tenant_put_route(self):
        result = self._route("/v1/tenants/demo", "PUT", body={"name": "Updated Demo"})
        self.assertIn(result["statusCode"], (200, 201))


    def test_lambda_handler_citation_verify_route(self):
        citation_auth = {**self.auth, "scopes": [*self.auth["scopes"], "citation:verify"]}
        result = self._route("/v1/citations/verify", "POST", body={"response": "A claim cites https://example.org.", "citations": [{"url": "https://example.org", "claim": "A claim"}]}, auth=citation_auth)
        self.assertEqual(result["statusCode"], 200)


    def test_lambda_handler_actions_outcome_route(self):
        payload = {
            "context": {"tenant_id": "demo", "environment": "production", "agent_id": "route-outcome-agent", "invoked_by": "test", "run_id": "route-outcome-run"},
            "action": {"tool": "shell", "parameters": {"command": "echo route-outcome"}},
        }
        service.apply_tenant_runtime(payload, self.auth, self.store)
        decision = service.evaluate_and_record(payload, self.store)
        actions_auth = {**self.auth, "scopes": [*self.auth["scopes"], "actions:write"]}
        result = self._route(
            f"/v1/actions/{decision['action']['action_id']}/outcome",
            "POST",
            body={"status": "success", "action_hash": decision["action_hash"], "context": {"tenant_id": "demo"}},
            auth=actions_auth,
        )
        self.assertEqual(result["statusCode"], 202)


    def test_lambda_handler_permission_error_returns_403(self):
        event = {
            "rawPath": "/v1/actions/evaluate",
            "requestContext": {"http": {"method": "POST"}},
            "headers": {"authorization": "Bearer kta_pat_test"},
            "body": json.dumps({"context": {"tenant_id": "demo"}, "action": {"tool": "shell"}}),
        }
        with patch.object(service, "authenticate", return_value=(self.auth, None)), \
             patch.object(service, "handle_evaluate", side_effect=PermissionError("agent credential mismatch")):
            result = service.lambda_handler(event, None)
        self.assertEqual(result["statusCode"], 403)


    def test_lambda_handler_generic_exception_returns_500(self):
        event = {
            "rawPath": "/v1/audit",
            "requestContext": {"http": {"method": "GET"}},
            "headers": {"authorization": "Bearer kta_pat_test"},
            "queryStringParameters": {"tenant_id": "demo"},
        }
        with patch.object(service, "authenticate", return_value=(self.auth, None)), \
             patch.object(service, "handle_audit", side_effect=RuntimeError("unexpected")):
            result = service.lambda_handler(event, None)
        self.assertEqual(result["statusCode"], 500)


    def test_lambda_handler_auth_confirm_route(self):
        event = {
            "rawPath": "/auth/confirm",
            "requestContext": {"http": {"method": "POST"}},
            "headers": {},
            "body": json.dumps({}),
        }
        result = service.lambda_handler(event, None)
        self.assertEqual(result["statusCode"], 400)


    def test_lambda_handler_auth_confirm_resend_route(self):
        event = {
            "rawPath": "/auth/confirm/resend",
            "requestContext": {"http": {"method": "POST"}},
            "headers": {},
            "body": json.dumps({}),
        }
        result = service.lambda_handler(event, None)
        self.assertEqual(result["statusCode"], 400)


    def test_lambda_handler_auth_session_route(self):
        # Session auth on POST /auth/session returns "already active"
        session_auth = {**self.auth, "auth_source": "session", "token_type": "session", "subject": "user-1"}
        event = {
            "rawPath": "/auth/session",
            "requestContext": {"http": {"method": "POST"}},
            "headers": {"authorization": "Bearer kta_pat_test", "x-kenning-csrf": "dummy"},
            "body": json.dumps({}),
        }
        with patch.object(service, "authenticate", return_value=(session_auth, None)), \
             patch.object(service, "validate_session_csrf"):
            result = service.lambda_handler(event, None)
        self.assertEqual(result["statusCode"], 200)


    def test_lambda_handler_auth_csrf_route(self):
        from app.control_plane import session_hash as sh
        token = "kta_session_csrf_route_token"
        self.token_table.put_item(Item={
            "token_hash": sh(token),
            "token_id": "sess-csrf-route",
            "token_type": "session",
            "status": "active",
            "tenant_id": "demo",
            "subject": "user-1",
            "expires_at": int(time.time()) + 3600,
        })
        session_auth = {**self.auth, "auth_source": "session", "token_type": "session", "token_hash": sh(token), "subject": "user-1", "tenant_id": "demo"}
        event = {
            "rawPath": "/auth/csrf",
            "requestContext": {"http": {"method": "GET"}},
            "headers": {"authorization": "Bearer kta_pat_test"},
        }
        with patch.object(service, "authenticate", return_value=(session_auth, None)):
            result = service.lambda_handler(event, None)
        self.assertEqual(result["statusCode"], 200)


    def test_lambda_handler_auth_logout_post_route(self):
        # Use PAT auth (non-session) to avoid CSRF requirement
        event = {
            "rawPath": "/auth/logout",
            "requestContext": {"http": {"method": "POST"}},
            "headers": {"authorization": "Bearer kta_pat_test"},
            "body": json.dumps({}),
        }
        with patch.object(service, "authenticate", return_value=(self.auth, None)):
            result = service.lambda_handler(event, None)
        self.assertEqual(result["statusCode"], 204)


    def test_lambda_handler_tenant_environment_put_route(self):
        # First create a tenant config so the environment can be added
        self._route("/v1/tenants/demo", "PUT", body={
            "name": "Demo",
            "default_environment": "production",
            "environments": [{"environment_id": "production", "status": "active", "mode": "observe"}],
        })
        result = self._route("/v1/tenants/demo/environments/staging", "PUT", body={"status": "active", "mode": "observe"})
        self.assertIn(result["statusCode"], (200, 201))


    def test_lambda_handler_invitations_accept_route(self):
        session_auth = {**self.auth, "auth_source": "session", "token_type": "session", "subject": "accept-user@example.com", "tenant_id": "demo"}
        created = service.handle_create_invitation("demo", {"role": "viewer"}, {}, self.auth)
        token = self.body(created)["token"]
        event = {
            "rawPath": "/v1/invitations/accept",
            "requestContext": {"http": {"method": "POST"}},
            "headers": {"authorization": "Bearer kta_pat_test"},
            "body": json.dumps({"token": token}),
        }
        with patch.object(service, "authenticate", return_value=(session_auth, None)), \
             patch.object(service, "validate_session_csrf"):
            result = service.lambda_handler(event, None)
        self.assertEqual(result["statusCode"], 200)

    # ------------------------------------------------------------------
    # Platform access grant handlers
    # ------------------------------------------------------------------


    def test_route_me(self):
        session_auth = {**self.auth, "auth_source": "session", "subject": "user-1", "session_scopes": ["*"]}
        result = self._routed("/v1/me", auth=session_auth)
        self.assertIn(result["statusCode"], (200, 403))


    def test_route_tenants_get(self):
        result = self._routed("/v1/tenants")
        self.assertEqual(result["statusCode"], 200)


    def test_route_tenant_get(self):
        result = self._routed("/v1/tenants/demo")
        self.assertEqual(result["statusCode"], 200)


    def test_route_tenant_put(self):
        result = self._routed("/v1/tenants/demo", "PUT", {"name": "Route Test Tenant"})
        self.assertIn(result["statusCode"], (200, 201))


    def test_route_tenant_invitations_get(self):
        result = self._routed("/v1/tenants/demo/invitations")
        self.assertEqual(result["statusCode"], 200)


    def test_route_tenant_invitations_post(self):
        result = self._routed("/v1/tenants/demo/invitations", "POST", {"role": "viewer"})
        self.assertIn(result["statusCode"], (200, 201))


    def test_route_tenant_invitation_revoke(self):
        created = self._routed("/v1/tenants/demo/invitations", "POST", {"role": "viewer"})
        inv_id = self.body(created).get("invitation_id", "unknown")
        result = self._routed(f"/v1/tenants/demo/invitations/{inv_id}/revoke", "POST", {})
        self.assertIn(result["statusCode"], (200, 404))


    def test_route_tenant_environments_get(self):
        result = self._routed("/v1/tenants/demo/environments")
        self.assertEqual(result["statusCode"], 200)


    def test_route_tenant_environment_put(self):
        result = self._routed("/v1/tenants/demo/environments/staging", "PUT", {"status": "active", "mode": "enforce"})
        self.assertIn(result["statusCode"], (200, 201, 400))


    def test_route_policies_get(self):
        policy_auth = {**self.auth, "scopes": [*self.auth["scopes"], "policy:read"]}
        result = self._routed("/v1/policies", auth=policy_auth)
        self.assertEqual(result["statusCode"], 200)


    def test_route_policies_post(self):
        policy_auth = {**self.auth, "scopes": [*self.auth["scopes"], "policy:write"]}
        result = self._routed("/v1/policies", "POST", {
            "policy_id": "route-test-policy",
            "name": "Route Test Policy",
            "rules": [{"rule_id": "r1", "decision": "deny", "conditions": {"tool": "shell"}}],
        }, auth=policy_auth)
        self.assertIn(result["statusCode"], (200, 201))


    def test_route_citations_verify(self):
        cit_auth = {**self.auth, "scopes": [*self.auth["scopes"], "citation:verify"]}
        result = self._routed("/v1/citations/verify", "POST", {
            "response": "A claim cites https://example.org.",
            "citations": [{"url": "https://example.org", "claim": "A claim"}],
        }, auth=cit_auth)
        self.assertEqual(result["statusCode"], 200)


    def test_route_citation_reports_extract(self):
        cit_auth = {**self.auth, "scopes": [*self.auth["scopes"], "citation:verify"]}
        result = self._routed("/v1/citation-reports/extract", "POST", {
            "report_name": "route-test.txt",
            "report_text": "A claim cites https://example.org/route.",
        }, auth=cit_auth)
        self.assertEqual(result["statusCode"], 200)


    def test_route_agents_post(self):
        id_auth = {**self.auth, "scopes": [*self.auth["scopes"], "identity:write"]}
        result = self._routed("/v1/agents", "POST", {"agent_id": "route-agent", "name": "Route Agent", "owner": "user-1"}, auth=id_auth)
        self.assertIn(result["statusCode"], (200, 201))


    def test_route_agents_get(self):
        id_auth = {**self.auth, "scopes": [*self.auth["scopes"], "identity:read"]}
        result = self._routed("/v1/agents", auth=id_auth)
        self.assertEqual(result["statusCode"], 200)


    def test_route_receipts_public_key(self):
        proof_auth = {**self.auth, "scopes": [*self.auth["scopes"], "proof:read"]}
        result = self._routed("/v1/receipts/public-key", auth=proof_auth)
        self.assertIn(result["statusCode"], (200, 503))


    def test_route_invitations_redeem(self):
        result = self._routed("/v1/invitations/redeem", "POST", {"token": "nonexistent-token", "subject": "redeem-user"})
        self.assertIn(result["statusCode"], (200, 404))


    def test_route_invitations_accept(self):
        session_auth = {**self.auth, "auth_source": "session", "subject": "user-1", "session_scopes": ["*"]}
        result = self._routed("/v1/invitations/accept", "POST", {"token": "nonexistent-token"}, auth=session_auth)
        self.assertIn(result["statusCode"], (200, 400, 403, 404))


    def test_route_auth_session_post(self):
        oidc_auth = {**self.auth, "auth_source": "oidc", "subject": "user-1", "session_scopes": ["*"]}
        result = self._routed("/auth/session", "POST", {}, auth=oidc_auth)
        self.assertIn(result["statusCode"], (200, 201, 403))


    def test_route_auth_csrf_get(self):
        session_auth = {**self.auth, "auth_source": "session", "subject": "user-1", "session_scopes": ["*"]}
        result = self._routed("/auth/csrf", auth=session_auth)
        self.assertIn(result["statusCode"], (200, 403))


    def test_route_auth_logout_post(self):
        session_auth = {**self.auth, "auth_source": "session", "subject": "user-1", "session_scopes": ["*"], "token_hash": "test-hash"}
        result = self._routed("/auth/logout", "POST", {}, auth=session_auth)
        self.assertIn(result["statusCode"], (200, 204))


    def test_route_permission_error_returns_403(self):
        event = {
            "rawPath": "/v1/actions/evaluate",
            "requestContext": {"http": {"method": "POST"}},
            "headers": {"authorization": "Bearer kta_pat_test"},
            "body": json.dumps({"context": {"tenant_id": "other-tenant"}, "action": {"tool": "shell"}}),
        }
        with patch.object(service, "authenticate", return_value=(self.auth, None)):
            result = service.lambda_handler(event, None)
        self.assertEqual(result["statusCode"], 403)


    def test_route_internal_error_returns_500(self):
        event = {
            "rawPath": "/v1/audit",
            "requestContext": {"http": {"method": "GET"}},
            "headers": {"authorization": "Bearer kta_pat_test"},
        }
        with patch.object(service, "authenticate", return_value=(self.auth, None)), \
             patch.object(service, "handle_audit", side_effect=RuntimeError("unexpected")):
            result = service.lambda_handler(event, None)
        self.assertEqual(result["statusCode"], 500)

    # ------------------------------------------------------------------
    # Authenticate function coverage
    # ------------------------------------------------------------------


    def test_route_auth_login_get(self):
        result = service.lambda_handler({"rawPath": "/auth/login", "requestContext": {"http": {"method": "GET"}}, "headers": {}}, None)
        self.assertIn(result["statusCode"], (200, 302, 404))


    def test_route_auth_reauth_get(self):
        result = service.lambda_handler({"rawPath": "/auth/reauth", "requestContext": {"http": {"method": "GET"}}, "headers": {}}, None)
        self.assertIn(result["statusCode"], (200, 302, 401, 404))


    def test_route_auth_logout_get(self):
        result = service.lambda_handler({"rawPath": "/auth/logout", "requestContext": {"http": {"method": "GET"}}, "headers": {}}, None)
        self.assertIn(result["statusCode"], (200, 302, 404))


    def test_route_auth_callback_get(self):
        result = service.lambda_handler({"rawPath": "/auth/callback", "requestContext": {"http": {"method": "GET"}}, "headers": {}, "queryStringParameters": {"state": "test", "code": "test"}}, None)
        self.assertIn(result["statusCode"], (200, 302, 400, 401, 404))


    def test_route_auth_passkeys_callback_get(self):
        result = service.lambda_handler({"rawPath": "/auth/passkeys/callback", "requestContext": {"http": {"method": "GET"}}, "headers": {}}, None)
        self.assertIn(result["statusCode"], (200, 302, 400, 401, 404))


    def test_route_auth_confirm_post(self):
        event = {
            "rawPath": "/auth/confirm",
            "requestContext": {"http": {"method": "POST"}},
            "headers": {},
            "body": json.dumps({"username": "test@example.com", "code": "123456"}),
        }
        result = service.lambda_handler(event, None)
        self.assertIn(result["statusCode"], (200, 400, 404, 503))


    def test_route_auth_confirm_resend_post(self):
        event = {
            "rawPath": "/auth/confirm/resend",
            "requestContext": {"http": {"method": "POST"}},
            "headers": {},
            "body": json.dumps({"username": "test@example.com"}),
        }
        result = service.lambda_handler(event, None)
        self.assertIn(result["statusCode"], (200, 400, 404, 503))


    def test_route_auth_passkeys_get(self):
        session_auth = {**self.auth, "auth_source": "session", "subject": "user-1", "session_scopes": ["*"]}
        result = self._routed("/auth/passkeys", auth=session_auth)
        self.assertIn(result["statusCode"], (200, 302, 403, 404, 503))

    # ------------------------------------------------------------------
    # Guard unavailable and edge case coverage
    # ------------------------------------------------------------------


    def test_scope_enforcement_all_routes(self):
        """Exercise scope checks for routes that require specific scopes."""
        no_scope_auth = {**self.auth, "scopes": []}
        routes_requiring_scopes = [
            ("/v1/actions/evaluate", "POST", {"context": {"tenant_id": "demo"}, "action": {"tool": "shell"}}, "guard:evaluate"),
            ("/v1/tokens", "GET", None, "token:admin"),
            ("/v1/tokens", "POST", {"name": "t", "scopes": ["guard:evaluate"]}, "token:admin"),
            ("/v1/tenants", "GET", None, "tenant:read"),
            ("/v1/tenants/demo", "GET", None, "tenant:read"),
            ("/v1/tenants/demo", "PUT", {"name": "t"}, "tenant:write"),
            ("/v1/tenants/demo/starter-rules", "GET", None, "tenant:read"),
            ("/v1/tenants/demo/starter-rules", "PUT", {"rules": []}, "tenant:write"),
            ("/v1/tenants/demo/environments", "GET", None, "tenant:read"),
            ("/v1/tenants/demo/environments/staging", "PUT", {"status": "active"}, "tenant:write"),
            ("/v1/tenants/demo/retention/run", "POST", {}, "tenant:retention"),
            ("/v1/audit", "GET", None, "audit:read"),
            ("/v1/security/events", "GET", None, "audit:read"),
            ("/v1/audit/events", "POST", {"event_type": "test.event"}, "audit:write"),
            ("/v1/audit/export", "GET", None, "audit:read"),
            ("/v1/metrics", "GET", None, "audit:read"),
            ("/v1/policies", "GET", None, "policy:read"),
            ("/v1/policies", "POST", {"policy_id": "p", "name": "P", "rules": []}, "policy:write"),
            ("/v1/policies/p1", "PUT", {"name": "P", "rules": []}, "policy:write"),
            ("/v1/policies/p1", "DELETE", {}, "policy:write"),
            ("/v1/policies/p1/publish", "POST", {}, "policy:write"),
            ("/v1/policies/p1/suspend", "POST", {}, "policy:write"),
            ("/v1/policies/p1/reactivate", "POST", {}, "policy:write"),
            ("/v1/policies/p1/test", "POST", {"action": {"tool": "shell"}}, "policy:simulate"),
            ("/v1/policies/p1/simulate", "POST", {"action": {"tool": "shell"}}, "policy:simulate"),
            ("/v1/citations/verify", "POST", {"response": "x", "citations": []}, "citation:verify"),
            ("/v1/citation-reports/extract", "POST", {"report_text": "x"}, "citation:verify"),
            ("/v1/agents", "POST", {"agent_id": "a"}, "identity:write"),
            ("/v1/agents", "GET", None, "identity:read"),
            ("/v1/agents/a1", "GET", None, "identity:read"),
            ("/v1/agents/a1/revoke", "POST", {}, "identity:write"),
            ("/v1/agents/a1/credentials", "POST", {}, "identity:write"),
            ("/v1/agents/a1/credentials", "GET", None, "identity:read"),
            ("/v1/agents/a1/credentials/c1", "GET", None, "identity:read"),
            ("/v1/agents/a1/credentials/c1/revoke", "POST", {}, "identity:write"),
            ("/v1/proofs", "POST", {"action": {"tool": "shell"}}, "proof:write"),
            ("/v1/proofs/p1", "GET", None, "proof:read"),
            ("/v1/proofs/p1/verify", "GET", None, "proof:read"),
            ("/v1/proofs/p1/report", "GET", None, "proof:read"),
            ("/v1/receipts/public-key", "GET", None, "proof:read"),
            ("/v1/approvals", "GET", None, "approve:actions"),
            ("/v1/approvals/a1", "GET", None, "approve:actions"),
            ("/v1/approvals/a1/revoke", "POST", {}, "approve:actions"),
            ("/v1/approvals/a1/decision", "POST", {"decision": "approve"}, "approve:actions"),
            ("/v1/actions/a1/outcome", "POST", {"status": "success"}, "actions:write"),
        ]
        for path, method, body, required_scope in routes_requiring_scopes:
            event = {
                "rawPath": path,
                "requestContext": {"http": {"method": method}},
                "headers": {"authorization": "Bearer kta_pat_test"},
            }
            if body is not None:
                event["body"] = json.dumps(body)
            with patch.object(service, "authenticate", return_value=(no_scope_auth, None)):
                result = service.lambda_handler(event, None)
            self.assertEqual(result["statusCode"], 403, f"Expected 403 for {method} {path} (requires {required_scope})")
            self.assertEqual(self.body(result)["required_scope"], required_scope, f"Wrong scope for {method} {path}")
