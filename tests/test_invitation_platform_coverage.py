"""Targeted tests for invitation redemption and platform access grant branches (#271).

Covers: redeem_invitation validation, handle_redeem_invitation admin gate,
handle_accept_invitation session gate, handle_platform_access_grant validation.
"""

import hashlib
import time
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


class InvitationRedemptionTests(unittest.TestCase):
    def setUp(self):
        self.table = FakeTable()
        service.table = self.table
        self.token_table = FakeTokenTable()
        service.token_table = self.token_table
        self.store = service.AuditStore(self.table)

    def _status(self, result):
        return result.get("statusCode", 200)

    def _body(self, result):
        import json
        raw = result.get("body", "{}")
        return json.loads(raw) if isinstance(raw, str) else raw

    def _seed_invitation(self, token="kta_invite_test123", status="active", expires_at=None, max_uses=1, use_count=0):
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        record = {
            "pk": f"INVITATION#{token_hash}",
            "sk": "METADATA",
            "item_type": "tenant_invitation",
            "invitation_id": "inv-test1",
            "tenant_id": "demo",
            "role": "viewer",
            "status": status,
            "token_hash": token_hash,
            "max_uses": max_uses,
            "use_count": use_count,
            "created_by": "admin@example.com",
            "created_at": "2026-01-01T00:00:00Z",
        }
        if expires_at is not None:
            record["expires_at"] = expires_at
        self.table.put_item(Item=record)
        return token

    # ------------------------------------------------------------------
    # redeem_invitation (lines 1831, 1839, 1843, 1847-1848)
    # ------------------------------------------------------------------

    def test_redeem_invitation_empty_token(self):
        """Line 1831: empty token returns 400."""
        membership, error = service.redeem_invitation("", "user@example.com")
        self.assertIsNone(membership)
        self.assertEqual(error["statusCode"], 400)
        self.assertEqual(self._body(error).get("error"), "invitation_token_required")

    def test_redeem_invitation_expired(self):
        """Line 1839: expired invitation returns 410."""
        token = self._seed_invitation(expires_at=int(time.time()) - 100)
        membership, error = service.redeem_invitation(token, "user@example.com")
        self.assertIsNone(membership)
        self.assertEqual(error["statusCode"], 410)
        self.assertEqual(self._body(error).get("error"), "invitation_expired")

    def test_redeem_invitation_fully_used(self):
        """Line 1843: exhausted invitation returns 409."""
        token = self._seed_invitation(max_uses=1, use_count=1)
        membership, error = service.redeem_invitation(token, "user@example.com")
        self.assertIsNone(membership)
        self.assertEqual(error["statusCode"], 409)
        self.assertEqual(self._body(error).get("error"), "invitation_fully_used")

    def test_redeem_invitation_invalid_subject(self):
        """Lines 1847-1848: invalid subject returns 400."""
        token = self._seed_invitation()
        membership, error = service.redeem_invitation(token, "\x00invalid")
        self.assertIsNone(membership)
        self.assertEqual(error["statusCode"], 400)
        self.assertEqual(self._body(error).get("error"), "invalid_subject")

    def test_redeem_invitation_success(self):
        """Happy path: valid invitation creates membership."""
        token = self._seed_invitation()
        membership, error = service.redeem_invitation(token, "user@example.com")
        self.assertIsNotNone(membership)
        self.assertIsNone(error)
        self.assertEqual(membership["subject"], "user@example.com")
        self.assertEqual(membership["tenant_id"], "demo")

    # ------------------------------------------------------------------
    # handle_redeem_invitation (lines 1870, 1873)
    # ------------------------------------------------------------------

    def test_handle_redeem_invitation_admin_error(self):
        """Line 1870: control_plane_admin error propagates."""
        token = self._seed_invitation()
        auth = {"tenant_id": "demo", "token_id": "t1", "role": "viewer", "subject": "viewer@example.com"}
        with patch.object(service, "control_plane_admin", return_value={"statusCode": 403, "body": "{}"}):
            result = service.handle_redeem_invitation({"token": token, "subject": "user@example.com"}, make_event("POST", "/v1/invitations/redeem"), auth)
        self.assertEqual(result["statusCode"], 403)

    def test_handle_redeem_invitation_subject_required(self):
        """Line 1873: missing subject returns 400."""
        token = self._seed_invitation()
        auth = {"tenant_id": "demo", "token_id": "t1", "role": "admin", "subject": "admin@example.com"}
        with patch.object(service, "control_plane_admin", return_value=None):
            result = service.handle_redeem_invitation({"token": token}, make_event("POST", "/v1/invitations/redeem"), auth)
        self.assertEqual(result["statusCode"], 400)
        self.assertEqual(self._body(result).get("error"), "subject_required")

    # ------------------------------------------------------------------
    # handle_accept_invitation (lines 1896, 1899)
    # ------------------------------------------------------------------

    def test_accept_invitation_subject_required(self):
        """Line 1896: session without subject returns 400."""
        token = self._seed_invitation()
        auth = {"tenant_id": "demo", "token_id": "t1", "token_type": "session", "auth_source": "session", "subject": ""}
        result = service.handle_accept_invitation({"token": token}, auth)
        self.assertEqual(result["statusCode"], 400)
        self.assertEqual(self._body(result).get("error"), "subject_required")

    def test_accept_invitation_redeem_error(self):
        """Line 1899: redeem error propagates."""
        auth = {"tenant_id": "demo", "token_id": "t1", "token_type": "session", "auth_source": "session", "subject": "user@example.com"}
        result = service.handle_accept_invitation({"token": "kta_invite_nonexistent"}, auth)
        self.assertEqual(result["statusCode"], 404)
        self.assertEqual(self._body(result).get("error"), "invitation_not_found")


class PlatformAccessGrantTests(unittest.TestCase):
    def setUp(self):
        self.table = FakeTable()
        service.table = self.table
        self.token_table = FakeTokenTable()
        service.token_table = self.token_table

    def _status(self, result):
        return result.get("statusCode", 200)

    def _body(self, result):
        import json
        raw = result.get("body", "{}")
        return json.loads(raw) if isinstance(raw, str) else raw

    # ------------------------------------------------------------------
    # handle_platform_access_grant (lines 1914, 1917, 1926-1927, 1929)
    # ------------------------------------------------------------------

    def test_platform_access_grant_not_operator(self):
        """Line 1914: non-operator returns error."""
        auth = {"tenant_id": "demo", "token_id": "t1", "role": "viewer", "subject": "viewer@example.com"}
        result = service.handle_platform_access_grant({"tenant_id": "demo", "reason": "Testing support access grant"}, auth)
        self.assertIn(result["statusCode"], (401, 403))

    def test_platform_access_grant_invalid_tenant_id(self):
        """Line 1917: invalid tenant_id raises ValueError."""
        auth = {"tenant_id": "demo", "token_id": "t1", "role": "admin", "subject": "admin@example.com", "platform_admin": True, "scopes": ["admin"]}
        with patch.object(service, "require_platform_operator", return_value=None):
            with self.assertRaises(ValueError):
                service.handle_platform_access_grant({"tenant_id": "", "reason": "Testing support access grant"}, auth)

    def test_platform_access_grant_invalid_expires_in_seconds(self):
        """Lines 1926-1927: non-integer expires_in_seconds raises ValueError."""
        auth = {"tenant_id": "demo", "token_id": "t1", "role": "admin", "subject": "admin@example.com", "platform_admin": True, "scopes": ["admin"]}
        with patch.object(service, "require_platform_operator", return_value=None):
            with self.assertRaises(ValueError):
                service.handle_platform_access_grant({"tenant_id": "demo", "reason": "Testing support access grant", "expires_in_seconds": "abc"}, auth)

    def test_platform_access_grant_expires_out_of_range(self):
        """Line 1929: expires_in_seconds out of range raises ValueError."""
        auth = {"tenant_id": "demo", "token_id": "t1", "role": "admin", "subject": "admin@example.com", "platform_admin": True, "scopes": ["admin"]}
        with patch.object(service, "require_platform_operator", return_value=None):
            with self.assertRaises(ValueError):
                service.handle_platform_access_grant({"tenant_id": "demo", "reason": "Testing support access grant", "expires_in_seconds": 10}, auth)


if __name__ == "__main__":
    unittest.main()
