import json
import os
import time
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlparse

from app import lambda_function as service
from app.control_plane import (
    DEFAULT_SESSION_INACTIVITY_SECONDS,
    DEFAULT_SESSION_TTL_SECONDS,
    MAX_SESSION_INACTIVITY_SECONDS,
    MAX_SESSION_TTL_SECONDS,
    SESSION_COOKIE_NAME,
    SESSION_TOKEN_PREFIX,
    membership_record,
    normalise_email,
    normalise_subject,
    parse_cookie,
    role_allows,
    role_scopes,
    session_hash,
    session_inactivity_ttl,
    session_ttl,
)
from tests.fixtures import FakeTable, FakeTokenTable


class ControlPlaneTests(unittest.TestCase):
    def setUp(self):
        self.original_table = service.table
        self.original_token_table = service.token_table
        service.table = FakeTable()
        service.token_table = FakeTokenTable()

    def tearDown(self):
        service.table = self.original_table
        service.token_table = self.original_token_table

    @staticmethod
    def body(result):
        return json.loads(result["body"]) if result.get("body") else None

    def user_auth(self):
        return {
            "token_type": "pat",
            "auth_source": "pat",
            "token_id": "pat-user",
            "subject": "user@example.org",
            "tenant_id": "demo",
            "principal_type": "user",
            "scopes": ["tenant:read", "tenant:write", "session:create"],
        }

    def test_roles_map_to_least_privilege_scopes(self):
        self.assertIn("tenant:read", role_scopes("viewer"))
        self.assertNotIn("tenant:write", role_scopes("viewer"))
        self.assertIn("policy:write", role_scopes("policy_admin"))
        self.assertTrue(role_allows("owner", "admin"))
        self.assertFalse(role_allows("auditor", "admin"))

    def test_approver_can_connect_agent_without_admin_delegation(self):
        approver_scopes = role_scopes("approver")
        self.assertIn("approve:actions", approver_scopes)
        self.assertIn("token:admin", approver_scopes)
        self.assertIn("guard:evaluate", approver_scopes)
        self.assertIn("mcp:read", approver_scopes)
        self.assertNotIn("tenant:write", approver_scopes)

        created = service.handle_create_token(
            {
                "name": "approver-agent-connection",
                "scopes": ["guard:evaluate", "mcp:read"],
                "expires_in_days": 90,
            },
            {
                "tenant_id": "demo",
                "token_id": "pat-approver",
                "subject": "approver@example.org",
                "scopes": approver_scopes,
            },
        )
        self.assertEqual(created["statusCode"], 201)
        created_body = self.body(created)
        self.assertEqual(created_body["token_metadata"]["scopes"], ["guard:evaluate", "mcp:read"])

        escalated = service.handle_create_token(
            {"name": "approver-admin-connection", "scopes": ["tenant:write"]},
            {
                "tenant_id": "demo",
                "token_id": "pat-approver",
                "subject": "approver@example.org",
                "scopes": approver_scopes,
            },
        )
        self.assertEqual(escalated["statusCode"], 403)
        self.assertEqual(self.body(escalated)["error"], "token_scope_escalation")

        membership_escalation = service.handle_create_member(
            "demo",
            {"subject": "approver@example.org", "role": "admin"},
            {},
            {
                "tenant_id": "demo",
                "token_id": "pat-approver-delegated",
                "subject": "approver@example.org",
                "scopes": ["token:admin"],
            },
        )
        self.assertEqual(membership_escalation["statusCode"], 403)
        self.assertEqual(self.body(membership_escalation)["error"], "membership_role_required")

    def test_session_exchange_sets_httponly_cookie_without_returning_secret(self):
        result = service.handle_create_session({"headers": {"user-agent": "test"}}, self.user_auth())
        self.assertEqual(result["statusCode"], 201)
        self.assertIn("HttpOnly", result["headers"]["set-cookie"])
        self.assertIn("SameSite=None", result["headers"]["set-cookie"])
        self.assertEqual(result["cookies"], [result["headers"]["set-cookie"]])
        self.assertNotIn("kta_session_", result["body"])
        self.assertEqual(len(service.token_table.items), 1)

    def test_low_scope_pat_cannot_bootstrap_creator_browser_session(self):
        leaked_pat = {
            "token_type": "pat",
            "auth_source": "pat",
            "token_id": "pat-low-scope",
            "created_by": "owner@example.org",
            "tenant_id": "demo",
            "principal_type": "user",
            "scopes": ["guard:evaluate"],
        }

        result = service.handle_create_session({"headers": {"user-agent": "test"}}, leaked_pat)

        self.assertEqual(result["statusCode"], 403)
        self.assertEqual(self.body(result)["error"], "interactive_session_scope_required")
        self.assertEqual(service.token_table.items, {})

    def test_human_oidc_session_omits_missing_tenant_index_key(self):
        auth = {**self.user_auth(), "auth_source": "oidc", "token_type": "federated", "tenant_id": None}
        session_token, _ = service.create_browser_session(auth, {"headers": {"user-agent": "test"}})
        self.assertTrue(session_token.startswith("kta_session_"))
        stored = next(iter(service.token_table.items.values()))
        self.assertNotIn("tenant_id", stored)

    def test_configured_oidc_group_grants_platform_admin_session(self):
        auth = {
            **self.user_auth(),
            "auth_source": "oidc",
            "token_type": "federated",
            "tenant_id": None,
            "groups": ["platform-admin"],
        }
        with patch.dict("os.environ", {"CONTROL_PLANE_PLATFORM_ADMIN_GROUPS": "platform-admin"}, clear=False):
            _, session = service.create_browser_session(auth, {"headers": {"user-agent": "test"}})
        self.assertTrue(session["platform_admin"])
        self.assertEqual(session["session_scopes"], ["admin"])

    def test_unconfigured_oidc_group_cannot_grant_platform_admin_session(self):
        auth = {
            **self.user_auth(),
            "auth_source": "oidc",
            "token_type": "federated",
            "tenant_id": None,
            "groups": ["platform-admin"],
        }
        with patch.dict("os.environ", {"CONTROL_PLANE_PLATFORM_ADMIN_GROUPS": ""}, clear=False):
            _, session = service.create_browser_session(auth, {"headers": {"user-agent": "test"}})
        self.assertFalse(session["platform_admin"])
        self.assertEqual(session["session_scopes"], [])

    def test_session_membership_controls_tenant_selection_and_api_role(self):
        membership = membership_record("demo", "user@example.org", {"role": "owner"}, actor="bootstrap")
        service.AuditStore(service.table).put_membership(membership)
        session = service.handle_create_session({"headers": {"user-agent": "test"}}, self.user_auth())
        cookie = session["headers"]["set-cookie"].split(";", 1)[0]

        me = service.lambda_handler({"rawPath": "/v1/me", "requestContext": {"http": {"method": "GET"}}, "headers": {"cookie": cookie}}, None)
        self.assertEqual(me["statusCode"], 200)
        self.assertEqual(self.body(me)["memberships"][0]["tenant_id"], "demo")

        tenant = service.lambda_handler({"rawPath": "/v1/tenants/demo", "requestContext": {"http": {"method": "GET"}}, "headers": {"cookie": cookie}}, None)
        self.assertEqual(tenant["statusCode"], 200)
        self.assertEqual(self.body(tenant)["tenant_id"], "demo")

        cross_tenant = service.lambda_handler(
            {
                "rawPath": "/v1/tenants/other",
                "requestContext": {"http": {"method": "GET"}},
                "headers": {"cookie": cookie, "x-kenning-tenant-id": "other"},
            },
            None,
        )
        self.assertEqual(cross_tenant["statusCode"], 403)
        self.assertEqual(self.body(cross_tenant)["error"], "membership_required")

    def test_api_gateway_v2_cookie_array_authenticates_session(self):
        membership = membership_record("demo", "user@example.org", {"role": "owner"}, actor="bootstrap")
        service.AuditStore(service.table).put_membership(membership)
        session = service.handle_create_session({"headers": {"user-agent": "test"}}, self.user_auth())
        cookie = session["headers"]["set-cookie"].split(";", 1)[0]

        me = service.lambda_handler(
            {
                "rawPath": "/v1/me",
                "requestContext": {"http": {"method": "GET"}},
                "headers": {},
                "cookies": [cookie],
            },
            None,
        )
        self.assertEqual(me["statusCode"], 200)
        self.assertEqual(self.body(me)["memberships"][0]["tenant_id"], "demo")

    def test_viewer_cannot_update_tenant(self):
        membership = membership_record("demo", "user@example.org", {"role": "viewer"}, actor="bootstrap")
        service.AuditStore(service.table).put_membership(membership)
        session = service.handle_create_session({"headers": {"user-agent": "test"}}, self.user_auth())
        cookie = session["headers"]["set-cookie"].split(";", 1)[0]
        csrf_response = service.lambda_handler({"rawPath": "/auth/csrf", "requestContext": {"http": {"method": "GET"}}, "headers": {"cookie": cookie}}, None)
        csrf = self.body(csrf_response)["csrf_token"]
        result = service.lambda_handler(
            {
                "rawPath": "/v1/tenants/demo",
                "requestContext": {"http": {"method": "PUT"}},
                "headers": {"cookie": cookie, "x-kenning-csrf": csrf, "content-type": "application/json"},
                "body": json.dumps({"name": "Not allowed"}),
            },
            None,
        )
        self.assertEqual(result["statusCode"], 403)
        self.assertEqual(self.body(result)["required_scope"], "tenant:write")

    def test_session_mutations_require_csrf_token(self):
        membership = membership_record("demo", "user@example.org", {"role": "owner"}, actor="bootstrap")
        service.AuditStore(service.table).put_membership(membership)
        session = service.handle_create_session({"headers": {"user-agent": "test"}}, self.user_auth())
        cookie = session["headers"]["set-cookie"].split(";", 1)[0]
        result = service.lambda_handler(
            {
                "rawPath": "/v1/tenants/demo",
                "requestContext": {"http": {"method": "PUT"}},
                "headers": {"cookie": cookie, "content-type": "application/json"},
                "body": json.dumps({"name": "Not allowed"}),
            },
            None,
        )
        self.assertEqual(result["statusCode"], 403)
        self.assertEqual(self.body(result)["error"], "csrf_required")

    def test_membership_admin_can_provision_and_revoke_users(self):
        owner = membership_record("demo", "user@example.org", {"role": "owner"}, actor="bootstrap")
        store = service.AuditStore(service.table)
        store.put_membership(owner)
        created = service.handle_create_member(
            "demo",
            {"subject": "reviewer@example.org", "email": "reviewer@example.org", "role": "auditor"},
            {"headers": {}},
            {**self.user_auth(), "role": "owner"},
        )
        self.assertEqual(created["statusCode"], 201)
        listed = service.handle_list_members("demo", {"headers": {}}, {**self.user_auth(), "role": "owner"})
        self.assertEqual(self.body(listed)["count"], 2)
        revoked = service.handle_update_member(
            "demo", "reviewer@example.org", {"status": "revoked"}, {"headers": {}}, {**self.user_auth(), "role": "owner"}
        )
        self.assertEqual(revoked["statusCode"], 200)
        self.assertEqual(self.body(revoked)["status"], "revoked")

    def test_cookie_parser_rejects_non_session_values(self):
        self.assertIsNone(parse_cookie("kta_session=not-a-session"))
        self.assertEqual(parse_cookie("kta_session=kta_session_abc"), "kta_session_abc")
        self.assertEqual(session_hash("kta_session_abc"), session_hash("kta_session_abc"))

    def _create_session_and_event(self):
        session_token, _ = service.create_browser_session(self.user_auth(), {"headers": {"user-agent": "test"}})
        return {"headers": {"cookie": f"kta_session={session_token}"}}

    def test_session_absolute_expiry_rejects_after_ttl(self):
        """Regression for #138: a session past its absolute TTL is rejected."""
        event = self._create_session_and_event()
        record = next(iter(service.token_table.items.values()))
        record["expires_at"] = int(time.time()) - 1
        auth, error = service.session_authentication(event)
        self.assertIsNone(auth)
        self.assertIsNotNone(error)

    def test_session_inactivity_expiry_revokes_and_rejects(self):
        """Regression for #138: a session idle beyond the inactivity window is
        revoked and rejected."""
        event = self._create_session_and_event()
        record = next(iter(service.token_table.items.values()))
        record["last_activity_at"] = int(time.time()) - 3600
        auth, error = service.session_authentication(event)
        self.assertIsNone(auth)
        self.assertIsNotNone(error)
        updated = next(iter(service.token_table.items.values()))
        self.assertEqual(updated["status"], "revoked")
        self.assertEqual(updated["revoke_reason"], "inactivity_timeout")

    def test_session_sliding_window_keeps_active_session_alive(self):
        """Regression for #138: normal activity resets the inactivity clock."""
        event = self._create_session_and_event()
        record = next(iter(service.token_table.items.values()))
        record["last_activity_at"] = int(time.time()) - 60
        auth, error = service.session_authentication(event)
        self.assertIsNotNone(auth)
        self.assertIsNone(error)
        updated = next(iter(service.token_table.items.values()))
        self.assertEqual(updated["status"], "active")
        self.assertGreaterEqual(int(updated["last_activity_at"]), int(time.time()) - 2)

    def test_platform_support_grant_is_separate_reason_bound_and_audited(self):
        result = service.handle_platform_access_grant(
            {"tenant_id": "demo", "reason": "Investigate a customer-reported policy incident", "operation": "support", "expires_in_seconds": 900},
            {"auth_source": "aws_iam", "subject": "operator@example.org", "scopes": ["admin"]},
        )
        self.assertEqual(result["statusCode"], 201)
        grant = self.body(result)
        self.assertEqual(grant["tenant_id"], "demo")
        self.assertEqual(len(grant["grant_hash"]), 64)
        self.assertEqual(service.table.get_item(Key={"pk": f"PLATFORM_ACCESS#{grant['grant_id']}", "sk": "METADATA"})["Item"]["status"], "active")
        events = service.AuditStore(service.table).list_events("demo", filters={"event_type": "platform.support.access_granted"})
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["grant_hash"], grant["grant_hash"])

    def test_platform_support_read_requires_active_grant_and_is_audited(self):
        operator = {"auth_source": "aws_iam", "subject": "operator@example.org", "scopes": ["admin"]}
        created = self.body(service.handle_platform_access_grant(
            {"tenant_id": "demo", "reason": "Investigate a customer-reported policy incident", "operation": "support", "expires_in_seconds": 900},
            operator,
        ))
        read = service.handle_platform_support_read(
            {"grant_id": created["grant_id"], "tenant_id": "demo", "resource": "tenant"},
            operator,
        )
        self.assertEqual(read["statusCode"], 200)
        self.assertEqual(self.body(read)["tenant_id"], "demo")
        events = service.AuditStore(service.table).list_events("demo", filters={"event_type": "platform.support.operation"})
        self.assertEqual(len(events), 1)
        revoked = service.handle_revoke_platform_access_grant(created["grant_id"], {"reason": "Support investigation is complete"}, operator)
        self.assertEqual(revoked["statusCode"], 200)
        denied = service.handle_platform_support_read(
            {"grant_id": created["grant_id"], "tenant_id": "demo", "resource": "tenant"},
            operator,
        )
        self.assertEqual(denied["statusCode"], 403)

    def test_platform_support_grant_listing_handles_iso_timestamps(self):
        store = service.AuditStore(service.table)
        store.put_platform_access_grant({
            "item_type": "platform_access_grant",
            "grant_id": "support-grant-listing",
            "tenant_id": "demo",
            "operation": "support",
            "reason": "Validate grant listing",
            "status": "active",
            "created_at": "2026-07-17T00:00:00Z",
        })
        listed = store.list_platform_access_grants(tenant_id="demo")
        self.assertEqual([item["grant_id"] for item in listed], ["support-grant-listing"])

    def test_oidc_reauthentication_is_bound_to_current_session_and_forces_login(self):
        session = service.handle_create_session({"headers": {"user-agent": "test"}}, self.user_auth())
        cookie = session["headers"]["set-cookie"].split(";", 1)[0]
        with patch.dict("os.environ", {
            "CONTROL_PLANE_OIDC_ISSUER_URL": "https://idp.example.org",
            "CONTROL_PLANE_OIDC_CLIENT_ID": "client-id",
            "CONTROL_PLANE_OIDC_REDIRECT_URI": "https://portal.example.org/auth/callback",
            "CONTROL_PLANE_OIDC_AUTHORIZATION_URL": "https://idp.example.org/authorize",
            "CONTROL_PLANE_OIDC_TOKEN_URL": "https://idp.example.org/token",
        }, clear=False):
            result = service.lambda_handler(
                {"rawPath": "/auth/reauth", "requestContext": {"http": {"method": "GET"}}, "headers": {"cookie": cookie}},
                None,
            )
        self.assertEqual(result["statusCode"], 302)
        self.assertIn("prompt=login", result["headers"]["location"])
        self.assertIn("max_age=0", result["headers"]["location"])
        state = next(item for item in service.token_table.items.values() if item.get("token_type") == "oidc_state")
        self.assertTrue(state.get("reauth_session_hash"))

    def test_oidc_config_rejects_a_jwks_url_with_a_command_line_fragment(self):
        with patch.dict("os.environ", {
            "CONTROL_PLANE_OIDC_ISSUER_URL": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example",
            "CONTROL_PLANE_OIDC_CLIENT_ID": "client-id",
            "CONTROL_PLANE_OIDC_REDIRECT_URI": "https://portal.example.org/auth/callback",
            "CONTROL_PLANE_OIDC_AUTHORIZATION_URL": "https://login.example.org/oauth2/authorize",
            "CONTROL_PLANE_OIDC_TOKEN_URL": "https://login.example.org/oauth2/token",
            "CONTROL_PLANE_OIDC_JWKS_URL": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example/.well-known/jwks.json ProductionFunctionName=broken",
        }, clear=False):
            with self.assertRaisesRegex(ValueError, "CONTROL_PLANE_OIDC_JWKS_URL"):
                service.control_plane_oidc_config()

    def test_oidc_callback_returns_a_safe_configuration_error_for_invalid_oidc_config(self):
        with patch.dict("os.environ", {
            "CONTROL_PLANE_OIDC_ISSUER_URL": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example",
            "CONTROL_PLANE_OIDC_CLIENT_ID": "client-id",
            "CONTROL_PLANE_OIDC_REDIRECT_URI": "https://portal.example.org/auth/callback",
            "CONTROL_PLANE_OIDC_AUTHORIZATION_URL": "https://login.example.org/oauth2/authorize",
            "CONTROL_PLANE_OIDC_TOKEN_URL": "https://login.example.org/oauth2/token",
            "CONTROL_PLANE_OIDC_JWKS_URL": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example/.well-known/jwks.json invalid",
            "CONTROL_PLANE_PORTAL_ORIGIN": "",
        }, clear=False):
            result = service.handle_auth_callback({"queryStringParameters": {"state": "state", "code": "code"}})
        self.assertEqual(result["statusCode"], 503)
        self.assertEqual(self.body(result), {"error": "invalid_auth_configuration"})

    def test_oidc_logout_redirect_clears_cookie_and_uses_managed_login_endpoint(self):
        with patch.dict("os.environ", {
            "CONTROL_PLANE_OIDC_ISSUER_URL": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example",
            "CONTROL_PLANE_OIDC_CLIENT_ID": "client-id",
            "CONTROL_PLANE_OIDC_REDIRECT_URI": "https://portal.example.org/auth/callback",
            "CONTROL_PLANE_OIDC_AUTHORIZATION_URL": "https://login.example.org/oauth2/authorize",
            "CONTROL_PLANE_OIDC_TOKEN_URL": "https://login.example.org/oauth2/token",
            "CONTROL_PLANE_PORTAL_ORIGIN": "https://portal.example.org",
        }, clear=False):
            result = service.lambda_handler(
                {"rawPath": "/auth/logout", "requestContext": {"http": {"method": "GET"}}, "headers": {}},
                None,
            )
        self.assertEqual(result["statusCode"], 302)
        location = urlparse(result["headers"]["location"])
        self.assertEqual(f"{location.scheme}://{location.netloc}{location.path}", "https://login.example.org/logout")
        query = parse_qs(location.query)
        self.assertEqual(query["client_id"], ["client-id"])
        self.assertEqual(query["logout_uri"], ["https://portal.example.org/app"])
        self.assertIn("kta_session=;", result["headers"]["set-cookie"])
        self.assertEqual(result["cookies"], [result["headers"]["set-cookie"]])

    def test_oidc_logout_supports_an_explicit_provider_logout_endpoint(self):
        with patch.dict("os.environ", {
            "CONTROL_PLANE_OIDC_ISSUER_URL": "https://idp.example.org",
            "CONTROL_PLANE_OIDC_CLIENT_ID": "client-id",
            "CONTROL_PLANE_OIDC_REDIRECT_URI": "https://portal.example.org/auth/callback",
            "CONTROL_PLANE_OIDC_AUTHORIZATION_URL": "https://idp.example.org/authorize",
            "CONTROL_PLANE_OIDC_TOKEN_URL": "https://idp.example.org/token",
            "CONTROL_PLANE_OIDC_LOGOUT_URL": "https://idp.example.org/oidc/logout?tenant=kenning",
            "CONTROL_PLANE_PORTAL_ORIGIN": "https://portal.example.org",
        }, clear=False):
            result = service.lambda_handler(
                {"rawPath": "/auth/logout", "requestContext": {"http": {"method": "GET"}}, "headers": {}},
                None,
            )
        self.assertEqual(result["statusCode"], 302)
        location = urlparse(result["headers"]["location"])
        query = parse_qs(location.query)
        self.assertEqual(query["tenant"], ["kenning"])
        self.assertEqual(query["client_id"], ["client-id"])
        self.assertEqual(query["logout_uri"], ["https://portal.example.org/app"])

    def test_oidc_callback_returns_to_configured_portal_origin(self):
        state = "oidc-state-test"
        service.token_table.items[service.session_hash(state)] = {
            "token_hash": service.session_hash(state),
            "token_id": "oidc-state-test",
            "token_type": "oidc_state",
            "status": "active",
            "state": state,
            "nonce": "nonce-test",
            "code_verifier": "verifier-test",
            "return_to": "/app",
            "expires_at": int(service.time.time()) + 600,
        }
        upstream = Mock()
        upstream.__enter__ = Mock(return_value=upstream)
        upstream.__exit__ = Mock(return_value=False)
        upstream.read.return_value = b'{"id_token":"id-token-test"}'
        verified = {
            "token_type": "federated",
            "auth_source": "oidc",
            "token_id": "oidc:https://idp.example.org:user@example.org",
            "subject": "user@example.org",
            "tenant_id": "demo",
            "principal_type": "user",
            "scopes": [],
        }
        with patch.dict("os.environ", {
            "CONTROL_PLANE_OIDC_ISSUER_URL": "https://idp.example.org",
            "CONTROL_PLANE_OIDC_CLIENT_ID": "client-id",
            "CONTROL_PLANE_OIDC_REDIRECT_URI": "https://api.example.org/auth/callback",
            "CONTROL_PLANE_OIDC_AUTHORIZATION_URL": "https://idp.example.org/authorize",
            "CONTROL_PLANE_OIDC_TOKEN_URL": "https://idp.example.org/token",
            "CONTROL_PLANE_PORTAL_ORIGIN": "https://portal.example.org",
        }, clear=False), patch.object(service, "urlopen", return_value=upstream), patch.object(
            service, "verify_federated_token", return_value=verified
        ), patch.object(service, "decode_unverified", return_value=({}, {"nonce": "nonce-test"}, b"", b"") ):
            result = service.handle_auth_callback(
                {"queryStringParameters": {"state": state, "code": "code-test"}, "headers": {"user-agent": "test"}}
            )
        self.assertEqual(result["statusCode"], 302)
        self.assertEqual(result["headers"]["location"], "https://portal.example.org/app")
        self.assertTrue(result.get("cookies"))

    def test_oidc_callback_preserves_invitation_token_for_actionable_fallback(self):
        state = "oidc-state-invite-test"
        service.token_table.items[service.session_hash(state)] = {
            "token_hash": service.session_hash(state),
            "token_id": state,
            "token_type": "oidc_state",
            "status": "active",
            "state": state,
            "nonce": "nonce-invite-test",
            "code_verifier": "verifier-test",
            "return_to": "/app",
            "invite_token": "kta_invite_example",
            "expires_at": int(service.time.time()) + 3600,
        }
        upstream = Mock()
        upstream.__enter__ = Mock(return_value=upstream)
        upstream.__exit__ = Mock(return_value=False)
        upstream.read.return_value = b'{"id_token":"id-token-test"}'
        verified = {
            "token_type": "federated",
            "auth_source": "oidc",
            "token_id": "oidc:https://idp.example.org:user@example.org",
            "subject": "user@example.org",
            "tenant_id": "demo",
            "principal_type": "user",
            "scopes": [],
        }
        with patch.dict("os.environ", {
            "CONTROL_PLANE_OIDC_ISSUER_URL": "https://idp.example.org",
            "CONTROL_PLANE_OIDC_CLIENT_ID": "client-id",
            "CONTROL_PLANE_OIDC_REDIRECT_URI": "https://api.example.org/auth/callback",
            "CONTROL_PLANE_OIDC_AUTHORIZATION_URL": "https://idp.example.org/authorize",
            "CONTROL_PLANE_OIDC_TOKEN_URL": "https://idp.example.org/token",
            "CONTROL_PLANE_PORTAL_ORIGIN": "https://portal.example.org",
        }, clear=False), patch.object(service, "urlopen", return_value=upstream), patch.object(
            service, "verify_federated_token", return_value=verified
        ), patch.object(service, "decode_unverified", return_value=({}, {"nonce": "nonce-invite-test"}, b"", b"")):
            result = service.handle_auth_callback(
                {"queryStringParameters": {"state": state, "code": "code-test"}, "headers": {"user-agent": "test"}}
            )
        self.assertEqual(result["statusCode"], 302)
        self.assertEqual(result["headers"]["location"], "https://portal.example.org/app?invite=kta_invite_example")

    def test_oidc_callback_redeems_invitation_for_verified_new_user(self):
        invitation_result = service.handle_create_invitation(
            "demo",
            {"role": "viewer", "expires_in_days": 7, "max_uses": 1},
            {},
            self.user_auth(),
        )
        self.assertEqual(invitation_result["statusCode"], 201)
        invitation = self.body(invitation_result)
        state = "oidc-state-enrollment-test"
        service.token_table.items[service.session_hash(state)] = {
            "token_hash": service.session_hash(state),
            "token_id": state,
            "token_type": "oidc_state",
            "status": "active",
            "state": state,
            "nonce": "nonce-enrollment-test",
            "code_verifier": "verifier-test",
            "return_to": "/app",
            "invite_token": invitation["token"],
            "expires_at": int(service.time.time()) + 3600,
        }
        upstream = Mock()
        upstream.__enter__ = Mock(return_value=upstream)
        upstream.__exit__ = Mock(return_value=False)
        upstream.read.return_value = b'{"id_token":"id-token-test"}'
        verified = {
            "token_type": "federated",
            "auth_source": "oidc",
            "token_id": "oidc:https://idp.example.org:user@example.org",
            "subject": "user@example.org",
            "tenant_id": None,
            "principal_type": "user",
            "scopes": [],
        }
        with patch.dict("os.environ", {
            "CONTROL_PLANE_OIDC_ISSUER_URL": "https://idp.example.org",
            "CONTROL_PLANE_OIDC_CLIENT_ID": "client-id",
            "CONTROL_PLANE_OIDC_REDIRECT_URI": "https://api.example.org/auth/callback",
            "CONTROL_PLANE_OIDC_AUTHORIZATION_URL": "https://idp.example.org/authorize",
            "CONTROL_PLANE_OIDC_TOKEN_URL": "https://idp.example.org/token",
            "CONTROL_PLANE_PORTAL_ORIGIN": "https://portal.example.org",
        }, clear=False), patch.object(service, "urlopen", return_value=upstream), patch.object(
            service, "verify_federated_token", return_value=verified
        ), patch.object(service, "decode_unverified", return_value=({}, {"nonce": "nonce-enrollment-test"}, b"", b"")):
            result = service.handle_auth_callback(
                {"queryStringParameters": {"state": state, "code": "code-test"}, "headers": {"user-agent": "test"}}
            )

        self.assertEqual(result["statusCode"], 302)
        self.assertEqual(result["headers"]["location"], f"https://portal.example.org/app?invite={invitation['token']}")
        membership = service.AuditStore(service.table).get_membership("user@example.org", "demo")
        self.assertIsNotNone(membership)
        self.assertEqual(membership["role"], "viewer")
        self.assertEqual(membership["status"], "active")
        token_hash = service.hashlib.sha256(invitation["token"].encode("utf-8")).hexdigest()
        stored_invitation = service.AuditStore(service.table).get_invitation_by_token_hash(token_hash)
        self.assertEqual(stored_invitation["status"], "redeemed")

    def test_control_plane_oidc_provider_uses_configured_claim_names(self):
        with patch.dict("os.environ", {
            "CONTROL_PLANE_OIDC_ISSUER_URL": "https://idp.example.org",
            "CONTROL_PLANE_OIDC_CLIENT_ID": "client-id",
            "CONTROL_PLANE_OIDC_REDIRECT_URI": "https://api.example.org/auth/callback",
            "CONTROL_PLANE_OIDC_AUTHORIZATION_URL": "https://idp.example.org/authorize",
            "CONTROL_PLANE_OIDC_TOKEN_URL": "https://idp.example.org/token",
            "CONTROL_PLANE_OIDC_TENANT_CLAIM": "custom:tenant_id",
            "CONTROL_PLANE_OIDC_GROUPS_CLAIM": "cognito:groups",
        }, clear=False):
            config = service.control_plane_oidc_config()
            provider = service.control_plane_provider(config)
        self.assertEqual(provider["tenant_claim"], "custom:tenant_id")
        self.assertEqual(provider["groups_claim"], "cognito:groups")

    def test_control_plane_provider_resolves_tenant_from_membership(self):
        with patch.dict("os.environ", {
            "CONTROL_PLANE_OIDC_ISSUER_URL": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example",
            "CONTROL_PLANE_OIDC_CLIENT_ID": "client-id",
            "CONTROL_PLANE_OIDC_REDIRECT_URI": "https://portal.example.org/auth/callback",
            "CONTROL_PLANE_OIDC_AUTHORIZATION_URL": "https://login.example.org/oauth2/authorize",
            "CONTROL_PLANE_OIDC_TOKEN_URL": "https://login.example.org/oauth2/token",
        }, clear=False):
            provider = service.control_plane_provider(service.control_plane_oidc_config())
        self.assertTrue(provider["allow_missing_tenant_claim"])
        self.assertNotIn("tenant_id", provider)

    def test_auth_config_advertises_passkeys_only_when_explicitly_enabled(self):
        with patch.dict("os.environ", {
            "CONTROL_PLANE_OIDC_ISSUER_URL": "https://idp.example.org",
            "CONTROL_PLANE_OIDC_CLIENT_ID": "client-id",
            "CONTROL_PLANE_OIDC_REDIRECT_URI": "https://portal.example.org/auth/callback",
            "CONTROL_PLANE_OIDC_AUTHORIZATION_URL": "https://idp.example.org/authorize",
            "CONTROL_PLANE_OIDC_TOKEN_URL": "https://idp.example.org/token",
            "CONTROL_PLANE_OIDC_PASSKEYS_ENABLED": "true",
        }, clear=False):
            config = self.body(service.handle_auth_config())
        self.assertTrue(config["oidc_enabled"])
        self.assertTrue(config["passkeys_enabled"])

    def test_auth_config_returns_safe_error_for_invalid_oidc_url(self):
        """Regression for #200: an invalid OIDC URL must not raise an unhandled
        API failure or leak internal configuration details."""
        with patch.dict("os.environ", {
            "CONTROL_PLANE_OIDC_ISSUER_URL": "https://idp.example.org",
            "CONTROL_PLANE_OIDC_CLIENT_ID": "client-id",
            "CONTROL_PLANE_OIDC_REDIRECT_URI": "https://portal.example.org/auth/callback",
            "CONTROL_PLANE_OIDC_AUTHORIZATION_URL": "https://user:pass@idp.example.org/authorize",
            "CONTROL_PLANE_OIDC_TOKEN_URL": "https://idp.example.org/token",
        }, clear=False):
            result = service.handle_auth_config()
        self.assertEqual(result["statusCode"], 500)
        body = self.body(result)
        self.assertEqual(body["error"], "auth_configuration_unavailable")
        self.assertIn("message", body)
        # No internal configuration details (env var names, URLs) may leak.
        serialized = json.dumps(body)
        self.assertNotIn("CONTROL_PLANE_OIDC", serialized)
        self.assertNotIn("user:pass", serialized)
        self.assertNotIn("idp.example.org", serialized)

    def test_auth_config_route_returns_safe_error_for_invalid_oidc_url(self):
        """The /auth/config route must return a controlled JSON error rather
        than an unhandled API Gateway failure for invalid configuration."""
        with patch.dict("os.environ", {
            "CONTROL_PLANE_OIDC_ISSUER_URL": "https://idp.example.org",
            "CONTROL_PLANE_OIDC_CLIENT_ID": "client-id",
            "CONTROL_PLANE_OIDC_REDIRECT_URI": "https://portal.example.org/auth/callback",
            "CONTROL_PLANE_OIDC_AUTHORIZATION_URL": "https://user:pass@idp.example.org/authorize",
            "CONTROL_PLANE_OIDC_TOKEN_URL": "https://idp.example.org/token",
        }, clear=False):
            result = service.lambda_handler(
                {"rawPath": "/auth/config", "requestContext": {"http": {"method": "GET"}}}, None
            )
        self.assertEqual(result["statusCode"], 500)
        self.assertEqual(self.body(result)["error"], "auth_configuration_unavailable")

    def test_auth_config_valid_configuration_is_unchanged(self):
        """A valid OIDC configuration must keep returning the normal payload."""
        with patch.dict("os.environ", {
            "CONTROL_PLANE_OIDC_ISSUER_URL": "https://idp.example.org",
            "CONTROL_PLANE_OIDC_CLIENT_ID": "client-id",
            "CONTROL_PLANE_OIDC_REDIRECT_URI": "https://portal.example.org/auth/callback",
            "CONTROL_PLANE_OIDC_AUTHORIZATION_URL": "https://idp.example.org/authorize",
            "CONTROL_PLANE_OIDC_TOKEN_URL": "https://idp.example.org/token",
        }, clear=False):
            result = service.handle_auth_config()
        self.assertEqual(result["statusCode"], 200)
        body = self.body(result)
        self.assertTrue(body["oidc_enabled"])
        self.assertIn("session_cookie", body)

    def test_auth_config_disables_pat_bootstrap_by_default(self):
        """Regression for #131: the human sign-in boundary must not expose PAT
        bootstrap unless explicitly enabled, regardless of deployment mode."""
        with patch.dict("os.environ", {
            "CONTROL_PLANE_OIDC_ISSUER_URL": "https://idp.example.org",
            "CONTROL_PLANE_OIDC_CLIENT_ID": "client-id",
            "CONTROL_PLANE_OIDC_REDIRECT_URI": "https://portal.example.org/auth/callback",
            "CONTROL_PLANE_OIDC_AUTHORIZATION_URL": "https://idp.example.org/authorize",
            "CONTROL_PLANE_OIDC_TOKEN_URL": "https://idp.example.org/token",
        }, clear=False):
            env = os.environ.pop("CONTROL_PLANE_ALLOW_PAT_BOOTSTRAP", None)
            try:
                config = self.body(service.handle_auth_config())
            finally:
                if env is not None:
                    os.environ["CONTROL_PLANE_ALLOW_PAT_BOOTSTRAP"] = env
        self.assertFalse(config["pat_bootstrap_enabled"])

    def test_passkey_management_redirect_requires_a_browser_session(self):
        with patch.dict("os.environ", {
            "CONTROL_PLANE_OIDC_ISSUER_URL": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example",
            "CONTROL_PLANE_OIDC_CLIENT_ID": "client-id",
            "CONTROL_PLANE_OIDC_REDIRECT_URI": "https://portal.example.org/auth/callback",
            "CONTROL_PLANE_OIDC_AUTHORIZATION_URL": "https://login.example.org/oauth2/authorize",
            "CONTROL_PLANE_OIDC_TOKEN_URL": "https://login.example.org/oauth2/token",
            "CONTROL_PLANE_OIDC_PASSKEYS_ENABLED": "true",
        }, clear=False):
            result = service.lambda_handler(
                {"rawPath": "/auth/passkeys", "requestContext": {"http": {"method": "GET"}}, "headers": {}},
                None,
            )
        self.assertEqual(result["statusCode"], 401)

    def test_passkey_management_redirect_uses_dedicated_completion_callback(self):
        with patch.dict("os.environ", {
            "CONTROL_PLANE_OIDC_ISSUER_URL": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example",
            "CONTROL_PLANE_OIDC_CLIENT_ID": "client-id",
            "CONTROL_PLANE_OIDC_REDIRECT_URI": "https://portal.example.org/auth/callback",
            "CONTROL_PLANE_OIDC_AUTHORIZATION_URL": "https://login.example.org/oauth2/authorize",
            "CONTROL_PLANE_OIDC_TOKEN_URL": "https://login.example.org/token",
            "CONTROL_PLANE_OIDC_PASSKEYS_ENABLED": "true",
            "CONTROL_PLANE_PORTAL_ORIGIN": "https://portal.example.org",
        }, clear=False):
            session = service.handle_create_session({"headers": {"user-agent": "test"}}, self.user_auth())
            cookie = session["headers"]["set-cookie"].split(";", 1)[0]
            result = service.lambda_handler(
                {"rawPath": "/auth/passkeys", "requestContext": {"http": {"method": "GET"}}, "headers": {"cookie": cookie}},
                None,
            )
        self.assertEqual(result["statusCode"], 302)
        location = result["headers"]["location"]
        self.assertTrue(location.startswith("https://login.example.org/passkeys/add?"))
        query = parse_qs(urlparse(location).query)
        self.assertEqual(query["client_id"], ["client-id"])
        self.assertEqual(query["redirect_uri"], ["https://portal.example.org/auth/passkeys/callback"])
        self.assertNotIn("code_challenge", query)
        flow_cookie = result["headers"]["set-cookie"].split(";", 1)[0]
        flow_id = flow_cookie.split("=", 1)[1]
        stored = service.token_table.get_item(Key={"token_hash": session_hash(f"passkey-flow:{flow_id}")})["Item"]
        self.assertEqual(stored["flow"], "passkey_add")
        self.assertEqual(stored["session_hash"], service.session_hash(cookie.split("=", 1)[1]))

        with patch.dict("os.environ", {"CONTROL_PLANE_PORTAL_ORIGIN": "https://portal.example.org"}, clear=False):
            callback = service.lambda_handler(
                {
                    "rawPath": "/auth/passkeys/callback",
                    "requestContext": {"http": {"method": "GET"}},
                    "headers": {"cookie": f"{cookie}; {flow_cookie}"},
                },
                None,
            )
        self.assertEqual(callback["statusCode"], 302)
        self.assertEqual(callback["headers"]["location"], "https://portal.example.org/app?passkey=added")
        self.assertIn("Max-Age=0", callback["headers"]["set-cookie"])
        self.assertEqual(service.token_table.items[stored["token_hash"]]["status"], "consumed")

    def test_passkey_callback_does_not_turn_provider_failure_into_success(self):
        with patch.dict("os.environ", {
            "CONTROL_PLANE_OIDC_ISSUER_URL": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example",
            "CONTROL_PLANE_OIDC_CLIENT_ID": "client-id",
            "CONTROL_PLANE_OIDC_REDIRECT_URI": "https://portal.example.org/auth/callback",
            "CONTROL_PLANE_OIDC_AUTHORIZATION_URL": "https://login.example.org/oauth2/authorize",
            "CONTROL_PLANE_OIDC_TOKEN_URL": "https://login.example.org/token",
        }, clear=False):
            callback = service.lambda_handler(
                {
                    "rawPath": "/auth/passkeys/callback",
                    "rawQueryString": "result=invalid_session",
                    "queryStringParameters": {"result": "invalid_session"},
                    "requestContext": {"http": {"method": "GET"}},
                    "headers": {},
                },
                None,
            )
        self.assertEqual(callback["statusCode"], 400)
        self.assertEqual(self.body(callback), {"error": "passkey_registration_failed", "result": "invalid_session"})

    def test_unconfirmed_account_can_be_confirmed_without_a_session(self):
        cognito = Mock()
        with patch.object(service, "cognito_idp", cognito), patch.dict("os.environ", {
            "CONTROL_PLANE_OIDC_ISSUER_URL": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example",
            "CONTROL_PLANE_OIDC_CLIENT_ID": "client-id",
            "CONTROL_PLANE_OIDC_REDIRECT_URI": "https://portal.example.org/auth/callback",
            "CONTROL_PLANE_OIDC_AUTHORIZATION_URL": "https://login.example.org/oauth2/authorize",
            "CONTROL_PLANE_OIDC_TOKEN_URL": "https://login.example.org/oauth2/token",
        }, clear=False):
            result = service.lambda_handler(
                {
                    "rawPath": "/auth/confirm",
                    "requestContext": {"http": {"method": "POST"}},
                    "headers": {"content-type": "application/json"},
                    "body": json.dumps({"username": "user@example.org", "confirmation_code": "123456"}),
                },
                None,
            )
        self.assertEqual(result["statusCode"], 200)
        self.assertTrue(self.body(result)["confirmed"])
        cognito.confirm_sign_up.assert_called_once_with(ClientId="client-id", Username="user@example.org", ConfirmationCode="123456")

    def test_confirmation_recovery_resends_a_code_and_returns_only_masked_delivery(self):
        cognito = Mock()
        cognito.resend_confirmation_code.return_value = {
            "CodeDeliveryDetails": {"DeliveryMedium": "EMAIL", "Destination": "u***@e***.org", "AttributeName": "email"}
        }
        with patch.object(service, "cognito_idp", cognito), patch.dict("os.environ", {
            "CONTROL_PLANE_OIDC_ISSUER_URL": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example",
            "CONTROL_PLANE_OIDC_CLIENT_ID": "client-id",
            "CONTROL_PLANE_OIDC_REDIRECT_URI": "https://portal.example.org/auth/callback",
            "CONTROL_PLANE_OIDC_AUTHORIZATION_URL": "https://login.example.org/oauth2/authorize",
            "CONTROL_PLANE_OIDC_TOKEN_URL": "https://login.example.org/oauth2/token",
        }, clear=False):
            result = service.handle_auth_confirm_resend({"username": "user@example.org"})
        self.assertEqual(result["statusCode"], 200)
        payload = self.body(result)
        self.assertEqual(payload["code_delivery_details"], {"delivery_medium": "EMAIL", "destination": "u***@e***.org"})
        cognito.resend_confirmation_code.assert_called_once_with(ClientId="client-id", Username="user@example.org")

    def test_confirmation_rejects_invalid_codes_before_calling_identity_provider(self):
        cognito = Mock()
        with patch.object(service, "cognito_idp", cognito), patch.dict("os.environ", {
            "CONTROL_PLANE_OIDC_ISSUER_URL": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example",
            "CONTROL_PLANE_OIDC_CLIENT_ID": "client-id",
            "CONTROL_PLANE_OIDC_REDIRECT_URI": "https://portal.example.org/auth/callback",
            "CONTROL_PLANE_OIDC_AUTHORIZATION_URL": "https://login.example.org/oauth2/authorize",
            "CONTROL_PLANE_OIDC_TOKEN_URL": "https://login.example.org/oauth2/token",
        }, clear=False):
            result = service.handle_auth_confirm({"username": "user@example.org", "confirmation_code": "not-a-code"})
        self.assertEqual(result["statusCode"], 400)
        self.assertEqual(self.body(result)["error"], "invalid_confirmation_code")
        cognito.confirm_sign_up.assert_not_called()

    def test_security_events_are_filtered_to_tenant_administration_records(self):
        auth = {**self.user_auth(), "scopes": ["admin"]}
        service.AuditStore(service.table).put_event({
            "event_type": "tenant.config.updated", "tenant_id": "demo", "environment": "administration",
            "run_id": "tenant-management", "action_id": "demo", "agent_id": "platform-administrator",
            "invoked_by": "operator@example.org", "created_at": service.utc_now(), "status": "accepted",
        })
        service.AuditStore(service.table).put_event({
            "event_type": "action.evaluated", "tenant_id": "demo", "environment": "production",
            "run_id": "run-1", "action_id": "action-1", "agent_id": "agent", "invoked_by": "user",
            "created_at": service.utc_now(), "status": "accepted",
        })
        result = service.handle_security_events({"queryStringParameters": {"tenant_id": "demo", "limit": "50"}}, auth)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual([item["event_type"] for item in self.body(result)["events"]], ["tenant.config.updated"])

    def test_session_inactivity_revokes_browser_session(self):
        session = service.handle_create_session({"headers": {"user-agent": "test"}}, self.user_auth())
        cookie = session["headers"]["set-cookie"].split(";", 1)[0]
        token_record = next(iter(service.token_table.items.values()))
        token_record["last_activity_at"] = int(service.time.time()) - 3601
        with patch.dict("os.environ", {"CONTROL_PLANE_SESSION_INACTIVITY_SECONDS": "300"}):
            result = service.lambda_handler({"rawPath": "/v1/me", "requestContext": {"http": {"method": "GET"}}, "headers": {"cookie": cookie}}, None)
        self.assertEqual(result["statusCode"], 401)
        self.assertEqual(token_record["status"], "revoked")

    def test_normalise_subject_rejects_empty_and_control_characters(self):
        with self.assertRaises(ValueError):
            normalise_subject("")
        with self.assertRaises(ValueError):
            normalise_subject(None)
        with self.assertRaises(ValueError):
            normalise_subject("has\x00null")
        with self.assertRaises(ValueError):
            normalise_subject("x" * 257)

    def test_normalise_email_validates_and_rejects(self):
        self.assertIsNone(normalise_email(""))
        self.assertIsNone(normalise_email(None))
        self.assertEqual(normalise_email("User@Example.ORG"), "user@example.org")
        with self.assertRaises(ValueError):
            normalise_email("not-an-email")
        with self.assertRaises(ValueError):
            normalise_email("x" * 321 + "@a.com")

    def test_membership_record_rejects_invalid_tenant_id(self):
        with self.assertRaises(ValueError):
            membership_record("", "user@example.org")
        with self.assertRaises(ValueError):
            membership_record("x" * 65, "user@example.org")

    def test_membership_record_rejects_invalid_status(self):
        with self.assertRaises(ValueError):
            membership_record("demo", "user@example.org", {"status": "unknown"})

    def test_membership_record_rejects_oversized_display_name(self):
        with self.assertRaises(ValueError):
            membership_record("demo", "user@example.org", {"display_name": "x" * 257})

    def test_session_ttl_clamps_to_bounds(self):
        with patch.dict("os.environ", {"CONTROL_PLANE_SESSION_TTL_SECONDS": "100"}):
            self.assertEqual(session_ttl(), 900)
        with patch.dict("os.environ", {"CONTROL_PLANE_SESSION_TTL_SECONDS": "999999"}):
            self.assertEqual(session_ttl(), MAX_SESSION_TTL_SECONDS)
        with patch.dict("os.environ", {"CONTROL_PLANE_SESSION_TTL_SECONDS": "not-a-number"}):
            self.assertEqual(session_ttl(), DEFAULT_SESSION_TTL_SECONDS)

    def test_session_inactivity_ttl_clamps_to_bounds(self):
        with patch.dict("os.environ", {"CONTROL_PLANE_SESSION_INACTIVITY_SECONDS": "10"}):
            self.assertEqual(session_inactivity_ttl(), 300)
        with patch.dict("os.environ", {"CONTROL_PLANE_SESSION_INACTIVITY_SECONDS": "999999"}):
            self.assertEqual(session_inactivity_ttl(), MAX_SESSION_INACTIVITY_SECONDS)
        with patch.dict("os.environ", {"CONTROL_PLANE_SESSION_INACTIVITY_SECONDS": "bad"}):
            self.assertEqual(session_inactivity_ttl(), DEFAULT_SESSION_INACTIVITY_SECONDS)

    def test_parse_cookie_handles_none_empty_and_oversized_values(self):
        self.assertIsNone(parse_cookie(None))
        self.assertIsNone(parse_cookie(""))
        long_value = SESSION_TOKEN_PREFIX + "x" * 250
        self.assertIsNone(parse_cookie(f"{SESSION_COOKIE_NAME}={long_value}"))

    def test_parse_cookie_with_custom_cookie_name(self):
        self.assertEqual(parse_cookie("other=value", "other"), "value")
        self.assertIsNone(parse_cookie("other=", "other"))

    def test_portal_origin_rejects_path_query_and_fragment(self):
        with patch.dict("os.environ", {"CONTROL_PLANE_PORTAL_ORIGIN": "https://example.org/app"}, clear=False):
            with self.assertRaises(ValueError):
                service.portal_origin()
        with patch.dict("os.environ", {"CONTROL_PLANE_PORTAL_ORIGIN": "https://example.org?q=1"}, clear=False):
            with self.assertRaises(ValueError):
                service.portal_origin()

    def test_parse_cookie_returns_none_on_malformed_header(self):
        self.assertIsNone(parse_cookie("kta_session=\x00invalid"))


if __name__ == "__main__":
    unittest.main()
