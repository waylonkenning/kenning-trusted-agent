import json
import unittest
from unittest.mock import patch

from app import lambda_function as service


class StaleTokenIndex:
    """Return an old token from the GSI while the base table has a new one."""

    def __init__(self, items):
        self.items = {item["token_hash"]: dict(item) for item in items}
        self.query_calls = 0
        self.scan_calls = 0

    def query(self, **_kwargs):
        self.query_calls += 1
        return {"Items": [dict(item) for item in self.items.values() if item["token_id"] == "old-token"]}

    def scan(self, **_kwargs):
        self.scan_calls += 1
        return {"Items": [dict(item) for item in self.items.values()]}

    def update_item(self, Key, **_kwargs):
        item = self.items[Key["token_hash"]]
        item["status"] = "revoked"


class PaginatedTokenTable:
    """Put the requested PAT after the old 5,000-record scan boundary."""

    def __init__(self):
        self.query_calls = 0
        self.scan_calls = 0
        self.items = [
            {
                "token_hash": f"old-hash-{index}",
                "token_id": f"old-token-{index}",
                "tenant_id": "demo",
                "token_type": "pat",
                "status": "active",
                "name": "Old token",
            }
            for index in range(5000)
        ]
        self.items.append(
            {
                "token_hash": "new-hash",
                "token_id": "new-token",
                "tenant_id": "demo",
                "token_type": "pat",
                "status": "active",
                "name": "New token",
            }
        )

    def query(self, **_kwargs):
        self.query_calls += 1
        return {"Items": []}

    def scan(self, **kwargs):
        self.scan_calls += 1
        start = int((kwargs.get("ExclusiveStartKey") or {}).get("offset", 0))
        limit = int(kwargs.get("Limit") or 100)
        end = min(start + limit, len(self.items))
        result = {"Items": self.items[start:end]}
        if end < len(self.items):
            result["LastEvaluatedKey"] = {"offset": end}
        return result


class StaleStatusTokenIndex:
    """Return an old GSI status while the base table has the current status."""

    def __init__(self, item):
        self.base_item = dict(item)
        self.index_item = dict(item)
        self.get_item_calls = 0
        self.query_calls = 0

    def query(self, **_kwargs):
        self.query_calls += 1
        return {"Items": [dict(self.index_item)]}

    def get_item(self, Key, **_kwargs):
        self.get_item_calls += 1
        if Key["token_hash"] != self.base_item["token_hash"]:
            return {}
        return {"Item": dict(self.base_item)}

    def update_item(self, Key, **_kwargs):
        self.base_item["status"] = "revoked"


class TokenVisibilityTests(unittest.TestCase):
    def setUp(self):
        self.old_table = service.token_table
        self.old_audit_table = service.table
        self.old_store = service.store
        self.items = [
            {"token_hash": "old-hash", "token_id": "old-token", "tenant_id": "demo", "token_type": "pat", "status": "active", "name": "Old token"},
            {"token_hash": "new-hash", "token_id": "new-token", "tenant_id": "demo", "token_type": "pat", "status": "active", "name": "New token"},
        ]
        self.table = StaleTokenIndex(self.items)
        service.token_table = self.table
        service.table = None

    def tearDown(self):
        service.token_table = self.old_table
        service.table = self.old_audit_table
        service.store = self.old_store

    @staticmethod
    def auth():
        return {"tenant_id": "demo", "subject": "admin", "scopes": ["token:admin"]}

    @staticmethod
    def body(result):
        return json.loads(result["body"])

    def test_list_uses_strong_read_for_recent_token_when_gsi_is_stale(self):
        result = service.handle_list_tokens(
            {"queryStringParameters": {"tenant_id": "demo", "token_id": "new-token"}},
            self.auth(),
        )

        self.assertEqual(result["statusCode"], 200)
        self.assertEqual({item["token_id"] for item in self.body(result)["tokens"]}, {"old-token", "new-token"})
        self.assertEqual(self.table.query_calls, 1)
        self.assertEqual(self.table.scan_calls, 1)

    def test_revoke_uses_strong_read_for_recent_token_when_gsi_is_stale(self):
        audit_store = type("AuditStoreStub", (), {"put_event": lambda _self, _event: None})()
        with patch.object(service, "store", return_value=audit_store):
            result = service.handle_revoke_token("new-token", {"tenant_id": "demo"}, self.auth())

        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(self.table.items["new-hash"]["status"], "revoked")
        self.assertEqual(self.table.scan_calls, 1)

    def test_list_reconciles_status_when_gsi_contains_stale_token(self):
        table = StaleStatusTokenIndex({
            "token_hash": "token-hash",
            "token_id": "token-id",
            "tenant_id": "demo",
            "token_type": "pat",
            "status": "revoked",
            "name": "Revoked token",
        })
        table.index_item["status"] = "active"
        previous_table = service.token_table
        service.token_table = table
        try:
            result = service.handle_list_tokens(
                {"queryStringParameters": {"tenant_id": "demo", "token_id": "token-id"}},
                self.auth(),
            )
        finally:
            service.token_table = previous_table

        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(self.body(result)["tokens"][0]["status"], "revoked")
        self.assertEqual(table.query_calls, 1)
        self.assertEqual(table.get_item_calls, 1)

    def test_list_finds_recent_token_after_large_table_prefix(self):
        table = PaginatedTokenTable()
        previous_table = service.token_table
        service.token_table = table
        try:
            result = service.handle_list_tokens(
                {"queryStringParameters": {"tenant_id": "demo", "token_id": "new-token"}},
                self.auth(),
            )
        finally:
            service.token_table = previous_table

        self.assertEqual(result["statusCode"], 200)
        self.assertEqual([item["token_id"] for item in self.body(result)["tokens"]], ["new-token"])
        self.assertEqual(table.query_calls, 1)
        self.assertEqual(table.scan_calls, 6)


if __name__ == "__main__":
    unittest.main()
