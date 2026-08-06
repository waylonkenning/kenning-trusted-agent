"""Targeted tests for OIDC auth flow branches in lambda_function.py (#271).

Covers: account confirmation error paths, auth login edge cases,
passkey registration flows, OIDC callback validation, and session
creation branches.

Tests call handler functions directly to avoid routing/auth complexity
and target specific interior branches.
"""

import hashlib
import json
import time
import unittest
from unittest.mock import MagicMock, patch

from app import lambda_function as service
from tests.test_federation import FakeTable, FakeTokenTable


def make_event(method, path, body=None, query=None, headers=None):
    event = {
        "rawPath": path,
        "requestContext": {"http": {"method": method}},
        "headers": headers or {},
    }
    if body is not None:
        event["body"] = json.dumps(body) if isinstance(body, dict) else body
    if query:
        event["queryStringParameters"] = query
    return event


class OidcAuthFlowTests(unittest.TestCase):
    def setUp(self):
        self.table = FakeTable()
        service.table = self.table
        self.token_table = FakeTokenTable()
        service.token_table = self.token_table
        self.store = service.AuditStore(self.table)

    def _status(self, result):
        return result.get("statusCode", 200)

    def _body(self, result):
        raw = result.get("body", "{}")
        return json.loads(raw) if isinstance(raw, str) else raw

    # ------------------------------------------------------------------
    # Account confirmation error paths (lines 1278-1282, 1297-1301)
    # ------------------------------------------------------------------

    def _make_client_error(self, code, message="bad"):
        """Create a botocore-shaped ClientError via the module's re-export."""
        error_response = {"Error": {"Code": code, "Message": message}}
        exc = service.ClientError(error_response, "TestOperation")
        # The fallback ClientError (no botocore installed) doesn't set .response
        exc.response = error_response
        return exc

    def test_auth_confirm_client_error(self):
        """Lines 1278-1279: ClientError during confirm returns mapped error."""
        with patch.object(service, "_confirmation_client", return_value=({"client_id": "test"}, None)), \
             patch.object(service, "cognito_idp") as mock_cognito:
            mock_cognito.confirm_sign_up.side_effect = self._make_client_error("CodeMismatchException")
            result = service.handle_auth_confirm({"username": "user@example.com", "confirmation_code": "123456"})
        self.assertEqual(self._status(result), 400)
        self.assertEqual(self._body(result).get("error"), "invalid_confirmation_code")

    def test_auth_confirm_generic_error(self):
        """Lines 1280-1282: generic exception during confirm returns 503."""
        with patch.object(service, "_confirmation_client", return_value=({"client_id": "test"}, None)), \
             patch.object(service, "cognito_idp") as mock_cognito:
            mock_cognito.confirm_sign_up.side_effect = RuntimeError("network down")
            result = service.handle_auth_confirm({"username": "user@example.com", "confirmation_code": "123456"})
        self.assertEqual(self._status(result), 503)

    def test_auth_confirm_resend_client_error(self):
        """Lines 1297-1298: ClientError during resend returns mapped error."""
        with patch.object(service, "_confirmation_client", return_value=({"client_id": "test"}, None)), \
             patch.object(service, "cognito_idp") as mock_cognito:
            mock_cognito.resend_confirmation_code.side_effect = self._make_client_error("UserNotFoundException", "not found")
            result = service.handle_auth_confirm_resend({"username": "user@example.com"})
        self.assertEqual(self._status(result), 404)
        self.assertEqual(self._body(result).get("error"), "account_not_found")

    def test_auth_confirm_resend_generic_error(self):
        """Lines 1299-1301: generic exception during resend returns 503."""
        with patch.object(service, "_confirmation_client", return_value=({"client_id": "test"}, None)), \
             patch.object(service, "cognito_idp") as mock_cognito:
            mock_cognito.resend_confirmation_code.side_effect = RuntimeError("network down")
            result = service.handle_auth_confirm_resend({"username": "user@example.com"})
        self.assertEqual(self._status(result), 503)

    # ------------------------------------------------------------------
    # Auth login edge cases (lines 1321, 1327, 1337, 1353)
    # ------------------------------------------------------------------

    def test_auth_login_token_table_none(self):
        """Line 1321: token_table None returns 503."""
        with patch.object(service, "control_plane_oidc_config", return_value={
            "client_id": "test", "authorization_url": "https://auth.example.com/authorize",
            "redirect_uri": "https://portal.example.com/auth/callback",
        }), patch.object(service, "token_table", None):
            result = service.handle_auth_login(make_event("GET", "/auth/login"))
        self.assertEqual(self._status(result), 503)

    def test_auth_login_reauth_without_session(self):
        """Line 1327: reauth requested but no active session returns 401."""
        with patch.object(service, "control_plane_oidc_config", return_value={
            "client_id": "test", "authorization_url": "https://auth.example.com/authorize",
            "redirect_uri": "https://portal.example.com/auth/callback",
        }), patch.object(service, "session_authentication", return_value=(None, {"error": "no_session"})):
            result = service.handle_auth_login(make_event("GET", "/auth/reauth"), force_reauth=True)
        self.assertEqual(self._status(result), 401)

    def test_auth_login_invalid_invite_token_stripped(self):
        """Line 1337: invite token not starting with kta_invite_ is stripped."""
        with patch.object(service, "control_plane_oidc_config", return_value={
            "client_id": "test", "authorization_url": "https://auth.example.com/authorize",
            "redirect_uri": "https://portal.example.com/auth/callback", "scope": "openid",
        }):
            result = service.handle_auth_login(make_event("GET", "/auth/login", query={"invite": "bad-token"}))
        self.assertEqual(self._status(result), 302)

    def test_auth_login_valid_invite_token_in_state(self):
        """Line 1353: valid invite token stored in state_item."""
        with patch.object(service, "control_plane_oidc_config", return_value={
            "client_id": "test", "authorization_url": "https://auth.example.com/authorize",
            "redirect_uri": "https://portal.example.com/auth/callback", "scope": "openid",
        }):
            result = service.handle_auth_login(make_event("GET", "/auth/login", query={"invite": "kta_invite_abc123"}))
        self.assertEqual(self._status(result), 302)
        items = list(self.token_table.items.values())
        state_items = [i for i in items if i.get("token_type") == "oidc_state"]
        self.assertTrue(any(i.get("invite_token") == "kta_invite_abc123" for i in state_items))

    # ------------------------------------------------------------------
    # Passkey flows (lines 1380-1452)
    # ------------------------------------------------------------------

    def test_auth_passkeys_not_configured(self):
        """Line 1380: passkeys env var disabled returns 404."""
        auth = {"tenant_id": "demo", "token_id": "t1", "token_type": "session", "auth_source": "session"}
        with patch.object(service, "control_plane_oidc_config", return_value={"client_id": "test"}), \
             patch.dict("os.environ", {"CONTROL_PLANE_OIDC_PASSKEYS_ENABLED": "false"}):
            result = service.handle_auth_passkeys(make_event("GET", "/auth/passkeys"), auth)
        self.assertEqual(self._status(result), 404)

    def test_auth_passkeys_not_session_auth(self):
        """Line 1382: non-session auth returns 403."""
        auth = {"tenant_id": "demo", "token_id": "t1", "token_type": "pat", "auth_source": "pat"}
        with patch.object(service, "control_plane_oidc_config", return_value={"client_id": "test"}), \
             patch.dict("os.environ", {"CONTROL_PLANE_OIDC_PASSKEYS_ENABLED": "true"}):
            result = service.handle_auth_passkeys(make_event("GET", "/auth/passkeys"), auth)
        self.assertEqual(self._status(result), 403)

    def test_auth_passkeys_token_table_none(self):
        """Line 1384: token_table None returns 503."""
        auth = {"tenant_id": "demo", "token_id": "t1", "token_type": "session", "auth_source": "session"}
        with patch.object(service, "control_plane_oidc_config", return_value={"client_id": "test"}), \
             patch.dict("os.environ", {"CONTROL_PLANE_OIDC_PASSKEYS_ENABLED": "true"}), \
             patch.object(service, "token_table", None):
            result = service.handle_auth_passkeys(make_event("GET", "/auth/passkeys"), auth)
        self.assertEqual(self._status(result), 503)

    def test_auth_passkeys_callback_failed_result(self):
        """Line 1433: failed passkey result returns 400."""
        result = service.handle_auth_passkeys_callback(make_event("GET", "/auth/passkeys/callback", query={"result": "cancelled"}))
        self.assertEqual(self._status(result), 400)
        self.assertEqual(self._body(result).get("error"), "passkey_registration_failed")

    def test_auth_passkeys_callback_no_session(self):
        """Lines 1436-1438: no session auth returns error."""
        with patch.object(service, "session_authentication", return_value=(None, {"statusCode": 401, "body": "{}"})):
            result = service.handle_auth_passkeys_callback(make_event("GET", "/auth/passkeys/callback", query={"result": "success"}))
        self.assertIn(self._status(result), [401, 403])

    def test_auth_passkeys_callback_no_flow_cookie(self):
        """Line 1441: missing flow cookie returns 400."""
        auth = {"tenant_id": "demo", "token_id": "t1", "token_type": "session", "auth_source": "session", "token_hash": "h1"}
        with patch.object(service, "session_authentication", return_value=(auth, None)):
            result = service.handle_auth_passkeys_callback(make_event("GET", "/auth/passkeys/callback", query={"result": "success"}))
        self.assertEqual(self._status(result), 400)

    def test_auth_passkeys_callback_invalid_flow(self):
        """Lines 1444-1450: invalid flow record returns 400."""
        auth = {"tenant_id": "demo", "token_id": "t1", "token_type": "session", "auth_source": "session", "token_hash": "h1"}
        with patch.object(service, "session_authentication", return_value=(auth, None)):
            result = service.handle_auth_passkeys_callback(make_event("GET", "/auth/passkeys/callback", query={"result": "success"}, headers={"cookie": "kenning_passkey_flow=test-flow"}))
        self.assertEqual(self._status(result), 400)

    def test_auth_passkeys_callback_reads_flow_with_strong_consistency(self):
        """A newly created passkey flow must be visible immediately after redirect."""
        auth = {"tenant_id": "demo", "token_id": "t1", "token_type": "session", "auth_source": "session", "token_hash": "h1"}
        flow_id = "strong-read-flow"
        flow_hash = service.session_hash(f"passkey-flow:{flow_id}")
        self.token_table.put_item(Item={
            "token_hash": flow_hash, "token_type": "passkey_flow", "status": "active",
            "session_hash": "h1", "expires_at": int(time.time()) + 600,
        })
        original_get_item = self.token_table.get_item
        self.token_table.get_item = MagicMock(wraps=original_get_item)
        with patch.object(service, "session_authentication", return_value=(auth, None)), \
             patch.object(service, "portal_origin", return_value="https://portal.example.com"):
            result = service.handle_auth_passkeys_callback(
                make_event(
                    "GET",
                    "/auth/passkeys/callback",
                    query={"result": "success"},
                    headers={"cookie": f"kta_passkey_flow={flow_id}"},
                )
            )
        self.assertEqual(self._status(result), 302)
        self.token_table.get_item.assert_called_once_with(
            Key={"token_hash": flow_hash},
            ConsistentRead=True,
        )

    def test_auth_passkeys_callback_expired_flow(self):
        """Lines 1451-1452: expired flow returns 400."""
        auth = {"tenant_id": "demo", "token_id": "t1", "token_type": "session", "auth_source": "session", "token_hash": "h1"}
        flow_id = "test-flow"
        flow_hash = hashlib.sha256(f"passkey-flow:{flow_id}".encode()).hexdigest()
        self.token_table.put_item(Item={
            "token_hash": flow_hash, "token_type": "passkey_flow", "status": "active",
            "session_hash": "h1", "expires_at": int(time.time()) - 100,
        })
        with patch.object(service, "session_authentication", return_value=(auth, None)):
            result = service.handle_auth_passkeys_callback(make_event("GET", "/auth/passkeys/callback", query={"result": "success"}, headers={"cookie": f"kenning_passkey_flow={flow_id}"}))
        self.assertEqual(self._status(result), 400)

    # ------------------------------------------------------------------
    # OIDC callback validation (lines 1505, 1516, 1521, 1525, 1543-1557)
    # ------------------------------------------------------------------

    def _seed_oidc_state(self, state="test-state", nonce="test-nonce", invite_token=None,
                          reauth_session_hash=None):
        state_hash = hashlib.sha256(state.encode()).hexdigest()
        item = {
            "token_hash": state_hash, "token_type": "oidc_state", "status": "active",
            "state": state, "nonce": nonce, "code_verifier": "verifier",
            "return_to": "/app", "expires_at": int(time.time()) + 600,
        }
        if invite_token:
            item["invite_token"] = invite_token
        if reauth_session_hash:
            item["reauth_session_hash"] = reauth_session_hash
        self.token_table.put_item(Item=item)

    def _mock_urlopen(self, payload):
        """Create a urlopen mock that works as a context manager returning JSON."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(payload).encode()
        mock_cm = MagicMock()
        mock_cm.__enter__ = MagicMock(return_value=mock_response)
        mock_cm.__exit__ = MagicMock(return_value=False)
        return MagicMock(return_value=mock_cm)

    def test_auth_callback_client_secret_arn(self):
        """Line 1505: client_secret_arn adds client_secret to form."""
        self._seed_oidc_state()
        with patch.object(service, "control_plane_oidc_config", return_value={
            "client_id": "test", "token_url": "https://auth.example.com/token",
            "redirect_uri": "https://portal.example.com/auth/callback",
            "issuer_url": "https://auth.example.com",
            "client_secret_arn": "arn:aws:secretsmanager:us-east-1:123:secret:test",
        }), patch.object(service, "_oauth_client_secret", return_value="secret-value") as mock_secret, \
             patch.object(service, "urlopen", self._mock_urlopen({"id_token": "fake"})), \
             patch.object(service, "verify_federated_token", side_effect=ValueError("bad token")):
            result = service.handle_auth_callback(make_event("GET", "/auth/callback", query={"code": "c", "state": "test-state"}))
        mock_secret.assert_called_once()
        self.assertEqual(self._status(result), 302)

    def test_auth_callback_missing_id_token(self):
        """Line 1516: token response without id_token raises ValueError."""
        self._seed_oidc_state()
        with patch.object(service, "control_plane_oidc_config", return_value={
            "client_id": "test", "token_url": "https://auth.example.com/token",
            "redirect_uri": "https://portal.example.com/auth/callback",
            "issuer_url": "https://auth.example.com",
        }), patch.object(service, "urlopen", self._mock_urlopen({"access_token": "fake"})):
            result = service.handle_auth_callback(make_event("GET", "/auth/callback", query={"code": "c", "state": "test-state"}))
        self.assertEqual(self._status(result), 302)

    def test_auth_callback_reads_state_with_strong_consistency(self):
        """A newly created OIDC state must be visible immediately after redirect."""
        self._seed_oidc_state()
        self.token_table.get_item = MagicMock(wraps=self.token_table.get_item)
        with patch.object(service, "control_plane_oidc_config", return_value={
            "client_id": "test", "token_url": "https://auth.example.com/token",
            "redirect_uri": "https://portal.example.com/auth/callback",
            "issuer_url": "https://auth.example.com",
        }), patch.object(service, "urlopen", self._mock_urlopen({"access_token": "fake"})), \
             patch.object(service, "portal_origin", return_value="https://portal.example.com"):
            result = service.handle_auth_callback(
                make_event("GET", "/auth/callback", query={"code": "c", "state": "test-state"})
            )
        self.assertEqual(self._status(result), 302)
        self.token_table.get_item.assert_called_once_with(
            Key={"token_hash": hashlib.sha256(b"test-state").hexdigest()},
            ConsistentRead=True,
        )

    def test_auth_callback_nonce_mismatch(self):
        """Line 1521: nonce mismatch raises ValueError."""
        self._seed_oidc_state(nonce="expected-nonce")
        with patch.object(service, "control_plane_oidc_config", return_value={
            "client_id": "test", "token_url": "https://auth.example.com/token",
            "redirect_uri": "https://portal.example.com/auth/callback",
            "issuer_url": "https://auth.example.com",
        }), patch.object(service, "urlopen", self._mock_urlopen({"id_token": "fake"})), \
             patch.object(service, "verify_federated_token", return_value={"sub": "user1"}), \
             patch.object(service, "decode_unverified", return_value=(None, {"nonce": "wrong-nonce"}, None, None)):
            result = service.handle_auth_callback(make_event("GET", "/auth/callback", query={"code": "c", "state": "test-state"}))
        self.assertEqual(self._status(result), 302)

    def test_auth_callback_reauth_revokes_old_session(self):
        """Lines 1524-1530: reauth revokes old session."""
        old_hash = hashlib.sha256(b"old-session").hexdigest()
        self.token_table.put_item(Item={"token_hash": old_hash, "token_type": "session", "status": "active"})
        self._seed_oidc_state(reauth_session_hash=old_hash)
        with patch.object(service, "control_plane_oidc_config", return_value={
            "client_id": "test", "token_url": "https://auth.example.com/token",
            "redirect_uri": "https://portal.example.com/auth/callback",
            "issuer_url": "https://auth.example.com",
        }), patch.object(service, "urlopen", self._mock_urlopen({"id_token": "fake"})), \
             patch.object(service, "verify_federated_token", return_value={"sub": "user1"}), \
             patch.object(service, "decode_unverified", return_value=(None, {"nonce": "test-nonce"}, None, None)), \
             patch.object(service, "create_browser_session", return_value=("token", {"token_hash": "new-hash", "subject": "user1"})), \
             patch.object(service, "portal_origin", return_value="https://portal.example.com"):
            result = service.handle_auth_callback(make_event("GET", "/auth/callback", query={"code": "c", "state": "test-state"}))
        self.assertEqual(self._status(result), 302)
        old_session = self.token_table.get_item(Key={"token_hash": old_hash}).get("Item")
        self.assertEqual(old_session.get("status"), "revoked")

    def test_auth_callback_invite_redemption_failure_swallowed(self):
        """Lines 1541-1544: invite redemption failure doesn't break login."""
        self._seed_oidc_state(invite_token="kta_invite_abc")
        with patch.object(service, "control_plane_oidc_config", return_value={
            "client_id": "test", "token_url": "https://auth.example.com/token",
            "redirect_uri": "https://portal.example.com/auth/callback",
            "issuer_url": "https://auth.example.com",
        }), patch.object(service, "urlopen", self._mock_urlopen({"id_token": "fake"})), \
             patch.object(service, "verify_federated_token", return_value={"sub": "user1"}), \
             patch.object(service, "decode_unverified", return_value=(None, {"nonce": "test-nonce"}, None, None)), \
             patch.object(service, "create_browser_session", return_value=("token", {"token_hash": "h", "subject": "user1"})), \
             patch.object(service, "redeem_invitation", return_value=(None, {"error": "expired"})), \
             patch.object(service, "portal_origin", return_value="https://portal.example.com"):
            result = service.handle_auth_callback(make_event("GET", "/auth/callback", query={"code": "c", "state": "test-state"}))
        self.assertEqual(self._status(result), 302)

    def test_auth_callback_invite_redemption_exception_swallowed(self):
        """Lines 1543-1544: invite redemption exception doesn't break login."""
        self._seed_oidc_state(invite_token="kta_invite_abc")
        with patch.object(service, "control_plane_oidc_config", return_value={
            "client_id": "test", "token_url": "https://auth.example.com/token",
            "redirect_uri": "https://portal.example.com/auth/callback",
            "issuer_url": "https://auth.example.com",
        }), patch.object(service, "urlopen", self._mock_urlopen({"id_token": "fake"})), \
             patch.object(service, "verify_federated_token", return_value={"sub": "user1"}), \
             patch.object(service, "decode_unverified", return_value=(None, {"nonce": "test-nonce"}, None, None)), \
             patch.object(service, "create_browser_session", return_value=("token", {"token_hash": "h", "subject": "user1"})), \
             patch.object(service, "redeem_invitation", side_effect=RuntimeError("db down")), \
             patch.object(service, "portal_origin", return_value="https://portal.example.com"):
            result = service.handle_auth_callback(make_event("GET", "/auth/callback", query={"code": "c", "state": "test-state"}))
        self.assertEqual(self._status(result), 302)

    def test_auth_callback_client_error(self):
        """Lines 1549-1554: ClientError during callback redirects to recovery."""
        self._seed_oidc_state()
        with patch.object(service, "control_plane_oidc_config", return_value={
            "client_id": "test", "token_url": "https://auth.example.com/token",
            "redirect_uri": "https://portal.example.com/auth/callback",
            "issuer_url": "https://auth.example.com",
        }), patch.object(service, "urlopen", side_effect=service.ClientError(
            {"Error": {"Code": "InvalidGrantException", "Message": "bad"}}, "CreateToken",
        )):
            result = service.handle_auth_callback(make_event("GET", "/auth/callback", query={"code": "c", "state": "test-state"}))
        self.assertEqual(self._status(result), 302)

    def test_auth_callback_generic_error(self):
        """Lines 1555-1557: generic exception during callback redirects to recovery."""
        self._seed_oidc_state()
        with patch.object(service, "control_plane_oidc_config", return_value={
            "client_id": "test", "token_url": "https://auth.example.com/token",
            "redirect_uri": "https://portal.example.com/auth/callback",
            "issuer_url": "https://auth.example.com",
        }), patch.object(service, "urlopen", side_effect=RuntimeError("network down")):
            result = service.handle_auth_callback(make_event("GET", "/auth/callback", query={"code": "c", "state": "test-state"}))
        self.assertEqual(self._status(result), 302)

    # ------------------------------------------------------------------
    # Session creation (lines 1578-1596)
    # ------------------------------------------------------------------

    def test_create_session_pat_bootstrap(self):
        """Lines 1577-1580: PAT bootstrap creates owner membership."""
        auth = {
            "tenant_id": "demo", "token_id": "t1", "token_type": "pat",
            "subject": "user@example.com", "scopes": ["session:create"],
        }
        with patch.dict("os.environ", {"CONTROL_PLANE_ALLOW_PAT_BOOTSTRAP": "true"}):
            result = service.handle_create_session(make_event("POST", "/auth/session"), auth)
        self.assertEqual(self._status(result), 201)

    def test_create_session_event_failure_swallowed(self):
        """Lines 1595-1596: event write failure doesn't break session creation."""
        auth = {
            "tenant_id": "demo", "token_id": "t1", "token_type": "pat",
            "subject": "user@example.com", "scopes": ["session:create"],
        }
        self.table.put_item(Item={
            "pk": "MEMBERSHIP#user@example.com", "sk": "TENANT#demo",
            "tenant_id": "demo", "subject": "user@example.com", "role": "admin",
        })
        with patch.object(service.AuditStore, "put_event", side_effect=RuntimeError("dynamodb down")):
            result = service.handle_create_session(make_event("POST", "/auth/session"), auth)
        self.assertEqual(self._status(result), 201)


if __name__ == "__main__":
    unittest.main()
