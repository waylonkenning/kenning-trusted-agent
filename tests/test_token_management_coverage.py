"""Targeted tests for PAT/token management branches in lambda_function.py (#271).

Covers: _query_token_index pagination/error, list_pat_records scan fallback,
handle_create_token scope/group validation, handle_list_tokens, handle_revoke_token.
"""

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
        event["body"] = body
    if query:
        event["queryStringParameters"] = query
    return event


class TokenManagementTests(unittest.TestCase):
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
    # _query_token_index (lines 2154, 2156-2157)
    # ------------------------------------------------------------------

    def test_query_token_index_pagination(self):
        """Line 2154: LastEvaluatedKey triggers pagination."""
        mock_table = MagicMock()
        mock_table.query.side_effect = [
            {"Items": [{"token_id": "pat-1"}], "LastEvaluatedKey": {"token_hash": "h1"}},
            {"Items": [{"token_id": "pat-2"}]},
        ]
        with patch.object(service, "token_table", mock_table):
            records, indexed = service._query_token_index("tenant-index", "tenant_id", "demo")
        self.assertTrue(indexed)
        self.assertEqual(len(records), 2)

    def test_query_token_index_exception(self):
        """Lines 2156-2157: query exception returns ([], False)."""
        mock_table = MagicMock()
        mock_table.query.side_effect = Exception("boom")
        with patch.object(service, "token_table", mock_table):
            records, indexed = service._query_token_index("tenant-index", "tenant_id", "demo")
        self.assertFalse(indexed)
        self.assertEqual(records, [])

    def test_query_token_index_no_table(self):
        """Line 2137: missing token table raises RuntimeError."""
        with patch.object(service, "token_table", None):
            with self.assertRaises(RuntimeError):
                service._query_token_index("tenant-index", "tenant_id", "demo")

    # ------------------------------------------------------------------
    # list_pat_records (lines 2162, 2196)
    # ------------------------------------------------------------------

    def test_list_pat_records_no_table(self):
        """Line 2162: missing token table raises RuntimeError."""
        with patch.object(service, "token_table", None):
            with self.assertRaises(RuntimeError):
                service.list_pat_records("demo")

    def test_list_pat_records_scan_fallback(self):
        """Line 2196: scan pagination when GSI empty."""
        mock_table = MagicMock()
        # GSI returns nothing
        mock_table.query.return_value = {"Items": []}
        # Scan returns one page with a continuation then stops
        mock_table.scan.side_effect = [
            {"Items": [{"token_id": "pat-1", "tenant_id": "demo", "token_type": "pat"}], "LastEvaluatedKey": {"token_hash": "h1"}},
            {"Items": []},
        ]
        with patch.object(service, "token_table", mock_table):
            with patch("time.sleep"):
                records = service.list_pat_records("demo")
        self.assertEqual(len(records), 1)

    # ------------------------------------------------------------------
    # handle_create_token (lines 2204, 2207, 2210-2211, 2213, 2222, 2233, 2235)
    # ------------------------------------------------------------------

    def test_create_token_target_error(self):
        """Line 2204: token_target error propagates."""
        with patch.object(service, "token_target", return_value=(None, {"statusCode": 403, "body": "{}"})):
            result = service.handle_create_token({"name": "test"}, self.admin_auth)
        self.assertEqual(self._status(result), 403)

    def test_create_token_name_required(self):
        """Line 2207: empty name raises ValueError."""
        with patch.object(service, "token_target", return_value=("demo", None)):
            with self.assertRaises(ValueError):
                service.handle_create_token({"name": ""}, self.admin_auth)

    def test_create_token_invalid_expires_in_days(self):
        """Lines 2210-2211: non-integer expires_in_days raises ValueError."""
        with patch.object(service, "token_target", return_value=("demo", None)):
            with self.assertRaises(ValueError):
                service.handle_create_token({"name": "test", "expires_in_days": "abc"}, self.admin_auth)

    def test_create_token_expires_out_of_range(self):
        """Line 2213: out-of-range expires_in_days raises ValueError."""
        with patch.object(service, "token_target", return_value=("demo", None)):
            with self.assertRaises(ValueError):
                service.handle_create_token({"name": "test", "expires_in_days": 99999}, self.admin_auth)

    def test_create_token_unsupported_scope(self):
        """Line 2222: unsupported scope returns 400."""
        with patch.object(service, "token_target", return_value=("demo", None)):
            result = service.handle_create_token({"name": "test", "scopes": ["bogus_scope"]}, self.admin_auth)
        self.assertEqual(self._status(result), 400)
        self.assertEqual(self._body(result).get("error"), "unsupported_token_scope")

    def test_create_token_invalid_groups_type(self):
        """Line 2233: non-list groups returns 400."""
        with patch.object(service, "token_target", return_value=("demo", None)):
            result = service.handle_create_token({"name": "test", "groups": "not-a-list"}, self.admin_auth)
        self.assertEqual(self._status(result), 400)
        self.assertEqual(self._body(result).get("error"), "invalid_token_groups")

    def test_create_token_too_many_groups(self):
        """Line 2235: >50 groups returns 400."""
        with patch.object(service, "token_target", return_value=("demo", None)):
            result = service.handle_create_token({"name": "test", "groups": [f"g{i}" for i in range(51)]}, self.admin_auth)
        self.assertEqual(self._status(result), 400)
        self.assertEqual(self._body(result).get("error"), "invalid_token_groups")

    def test_create_token_scope_escalation(self):
        """Line 2224: non-admin cannot escalate scopes."""
        auth = {"tenant_id": "demo", "token_id": "t1", "role": "viewer", "subject": "v@example.com", "scopes": ["audit:read"]}
        with patch.object(service, "token_target", return_value=("demo", None)):
            result = service.handle_create_token({"name": "test", "scopes": ["audit:write"]}, auth)
        self.assertEqual(self._status(result), 403)
        self.assertEqual(self._body(result).get("error"), "token_scope_escalation")

    # ------------------------------------------------------------------
    # handle_list_tokens (line 2284)
    # ------------------------------------------------------------------

    def test_list_tokens_target_error(self):
        """Line 2284: tenant_target error propagates."""
        with patch.object(service, "tenant_target", return_value=(None, {"statusCode": 403, "body": "{}"})):
            result = service.handle_list_tokens(make_event("GET", "/v1/tokens"), self.admin_auth)
        self.assertEqual(self._status(result), 403)

    # ------------------------------------------------------------------
    # handle_revoke_token (lines 2292, 2298)
    # ------------------------------------------------------------------

    def test_revoke_token_target_error(self):
        """Line 2292: token_target error propagates."""
        with patch.object(service, "token_target", return_value=(None, {"statusCode": 403, "body": "{}"})):
            result = service.handle_revoke_token("pat-1", {}, self.admin_auth)
        self.assertEqual(self._status(result), 403)

    def test_revoke_token_already_revoked(self):
        """Line 2298: revoking already-revoked token returns 200."""
        revoked_record = {"token_id": "pat-1", "tenant_id": "demo", "token_type": "pat", "status": "revoked", "token_hash": "h1", "name": "test"}
        with patch.object(service, "token_target", return_value=("demo", None)):
            with patch.object(service, "list_pat_records", return_value=[revoked_record]):
                result = service.handle_revoke_token("pat-1", {}, self.admin_auth)
        self.assertEqual(self._status(result), 200)


if __name__ == "__main__":
    unittest.main()
