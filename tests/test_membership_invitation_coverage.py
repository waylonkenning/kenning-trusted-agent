"""Targeted tests for membership and invitation branches in lambda_function.py (#271).

Covers: member creation/update validation, owner role restrictions,
last-owner protection, invitation creation validation, and revocation.
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


class MembershipInvitationTests(unittest.TestCase):
    def setUp(self):
        self.table = FakeTable()
        service.table = self.table
        self.token_table = FakeTokenTable()
        service.token_table = self.token_table
        self.store = service.AuditStore(self.table)
        self.admin_auth = {"tenant_id": "demo", "token_id": "t1", "role": "admin", "subject": "admin@example.com"}

    def _status(self, result):
        return result.get("statusCode", 200)

    def _body(self, result):
        import json
        raw = result.get("body", "{}")
        return json.loads(raw) if isinstance(raw, str) else raw

    # ------------------------------------------------------------------
    # Member creation (lines 1691-1692)
    # ------------------------------------------------------------------

    def test_create_member_owner_role_requires_owner(self):
        """Lines 1691-1692: non-owner cannot create owner role."""
        auth = {"tenant_id": "demo", "token_id": "t1", "role": "admin", "subject": "admin@example.com"}
        with patch.object(service, "control_plane_admin", return_value=None):
            result = service.handle_create_member("demo", {"subject": "user@example.com", "role": "owner"}, make_event("POST", "/v1/tenants/demo/members"), auth)
        self.assertEqual(self._status(result), 403)
        self.assertEqual(self._body(result).get("error"), "owner_role_requires_owner")

    # ------------------------------------------------------------------
    # Member update (lines 1703, 1709, 1711, 1714-1716)
    # ------------------------------------------------------------------

    def test_update_member_not_found(self):
        """Line 1703: updating non-existent member returns 404."""
        with patch.object(service, "control_plane_admin", return_value=None):
            result = service.handle_update_member("demo", "missing@example.com", {"role": "viewer"}, make_event("PUT", "/v1/tenants/demo/members/missing"), self.admin_auth)
        self.assertEqual(self._status(result), 404)

    def test_update_member_promote_to_owner_requires_owner(self):
        """Line 1709: non-owner cannot promote to owner."""
        self.table.put_item(Item={"pk": "USER#user@example.com", "sk": "MEMBERSHIP#demo", "tenant_id": "demo", "subject": "user@example.com", "role": "viewer", "status": "active"})
        auth = {"tenant_id": "demo", "token_id": "t1", "role": "admin", "subject": "admin@example.com"}
        with patch.object(service, "control_plane_admin", return_value=None):
            result = service.handle_update_member("demo", "user@example.com", {"role": "owner"}, make_event("PUT", "/v1/tenants/demo/members/user"), auth)
        self.assertEqual(self._status(result), 403)
        self.assertEqual(self._body(result).get("error"), "owner_role_requires_owner")

    def test_update_member_demote_owner_requires_owner(self):
        """Line 1711: non-owner cannot demote owner."""
        self.table.put_item(Item={"pk": "USER#owner@example.com", "sk": "MEMBERSHIP#demo", "tenant_id": "demo", "subject": "owner@example.com", "role": "owner", "status": "active"})
        auth = {"tenant_id": "demo", "token_id": "t1", "role": "admin", "subject": "admin@example.com"}
        with patch.object(service, "control_plane_admin", return_value=None):
            result = service.handle_update_member("demo", "owner@example.com", {"role": "viewer"}, make_event("PUT", "/v1/tenants/demo/members/owner"), auth)
        self.assertEqual(self._status(result), 403)
        self.assertEqual(self._body(result).get("error"), "owner_role_requires_owner")

    def test_update_member_last_owner_cannot_be_removed(self):
        """Lines 1714-1716: last active owner cannot be deactivated."""
        self.table.put_item(Item={"pk": "USER#owner@example.com", "sk": "MEMBERSHIP#demo", "tenant_id": "demo", "subject": "owner@example.com", "role": "owner", "status": "active"})
        auth = {"tenant_id": "demo", "token_id": "t1", "role": "owner", "subject": "owner@example.com"}
        with patch.object(service, "control_plane_admin", return_value=None):
            result = service.handle_update_member("demo", "owner@example.com", {"status": "suspended"}, make_event("PUT", "/v1/tenants/demo/members/owner"), auth)
        self.assertEqual(self._status(result), 409)
        self.assertEqual(self._body(result).get("error"), "last_owner_cannot_be_removed")

    # ------------------------------------------------------------------
    # Invitation creation (lines 1743, 1749, 1756-1757, 1766-1767)
    # ------------------------------------------------------------------

    def test_create_invitation_admin_error(self):
        """Line 1743: control_plane_admin error propagates."""
        with patch.object(service, "control_plane_admin", return_value={"statusCode": 403, "body": "{}"}):
            result = service.handle_create_invitation("demo", {"role": "viewer"}, make_event("POST", "/v1/tenants/demo/invitations"), self.admin_auth)
        self.assertEqual(self._status(result), 403)

    def test_create_invitation_owner_role_requires_owner(self):
        """Line 1749: non-owner cannot create owner invitation."""
        auth = {"tenant_id": "demo", "token_id": "t1", "role": "admin", "subject": "admin@example.com"}
        with patch.object(service, "control_plane_admin", return_value=None):
            result = service.handle_create_invitation("demo", {"role": "owner"}, make_event("POST", "/v1/tenants/demo/invitations"), auth)
        self.assertEqual(self._status(result), 403)
        self.assertEqual(self._body(result).get("error"), "owner_role_requires_owner")

    def test_create_invitation_invalid_expires_in_days(self):
        """Lines 1756-1757: non-integer expires_in_days returns 400."""
        with patch.object(service, "control_plane_admin", return_value=None):
            result = service.handle_create_invitation("demo", {"role": "viewer", "expires_in_days": "abc"}, make_event("POST", "/v1/tenants/demo/invitations"), self.admin_auth)
        self.assertEqual(self._status(result), 400)
        self.assertEqual(self._body(result).get("error"), "invalid_expires_in_days")

    def test_create_invitation_invalid_max_uses(self):
        """Lines 1766-1767: non-integer max_uses returns 400."""
        with patch.object(service, "control_plane_admin", return_value=None):
            result = service.handle_create_invitation("demo", {"role": "viewer", "max_uses": "abc"}, make_event("POST", "/v1/tenants/demo/invitations"), self.admin_auth)
        self.assertEqual(self._status(result), 400)
        self.assertEqual(self._body(result).get("error"), "invalid_max_uses")

    # ------------------------------------------------------------------
    # Invitation listing and revocation (lines 1795, 1803, 1809, 1811)
    # ------------------------------------------------------------------

    def test_list_invitations_admin_error(self):
        """Line 1795: control_plane_admin error propagates."""
        with patch.object(service, "control_plane_admin", return_value={"statusCode": 403, "body": "{}"}):
            result = service.handle_list_invitations("demo", make_event("GET", "/v1/tenants/demo/invitations"), self.admin_auth)
        self.assertEqual(self._status(result), 403)

    def test_revoke_invitation_admin_error(self):
        """Line 1803: control_plane_admin error propagates."""
        with patch.object(service, "control_plane_admin", return_value={"statusCode": 403, "body": "{}"}):
            result = service.handle_revoke_invitation("demo", "inv-123", {}, make_event("POST", "/v1/tenants/demo/invitations/inv-123/revoke"), self.admin_auth)
        self.assertEqual(self._status(result), 403)

    def test_revoke_invitation_index_not_found(self):
        """Line 1809: invitation index not found returns 404."""
        with patch.object(service, "control_plane_admin", return_value=None):
            result = service.handle_revoke_invitation("demo", "inv-missing", {}, make_event("POST", "/v1/tenants/demo/invitations/inv-missing/revoke"), self.admin_auth)
        self.assertEqual(self._status(result), 404)

    def test_revoke_invitation_record_not_found(self):
        """Line 1809: invitation record not found returns 404."""
        self.table.put_item(Item={"pk": "TENANT#demo", "sk": "INVITATION#inv-123", "item_type": "invitation_index", "invitation_id": "inv-123", "tenant_id": "demo", "token_hash": "hash123"})
        with patch.object(service, "control_plane_admin", return_value=None):
            result = service.handle_revoke_invitation("demo", "inv-123", {}, make_event("POST", "/v1/tenants/demo/invitations/inv-123/revoke"), self.admin_auth)
        self.assertEqual(self._status(result), 404)

    def test_revoke_invitation_already_revoked(self):
        """Line 1811: revoking already-revoked invitation returns 200."""
        self.table.put_item(Item={"pk": "TENANT#demo", "sk": "INVITATION#inv-123", "item_type": "invitation_index", "invitation_id": "inv-123", "tenant_id": "demo", "token_hash": "hash123"})
        self.table.put_item(Item={"pk": "INVITATION#hash123", "sk": "METADATA", "item_type": "tenant_invitation", "invitation_id": "inv-123", "tenant_id": "demo", "status": "revoked", "role": "viewer"})
        with patch.object(service, "control_plane_admin", return_value=None):
            result = service.handle_revoke_invitation("demo", "inv-123", {}, make_event("POST", "/v1/tenants/demo/invitations/inv-123/revoke"), self.admin_auth)
        self.assertEqual(self._status(result), 200)


if __name__ == "__main__":
    unittest.main()
