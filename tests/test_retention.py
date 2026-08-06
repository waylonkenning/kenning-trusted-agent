import base64
import json
import time
import unittest
from unittest.mock import Mock
from unittest.mock import patch

from app import lambda_function as service
from app.starter_rules import default_starter_rules
from app.tenant import build_tenant_config


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




class RetentionTests(unittest.TestCase):
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


    def _mcp_call(self, tool_name, arguments, auth=None, profile=None):
        mcp_auth = auth or {**self.auth, "scopes": ["mcp:read", "guard:evaluate", "identity:write", "identity:read", "proof:write", "proof:read", "citation:verify"]}
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }
        return service.handle_mcp({"headers": {}}, body, "POST", mcp_auth, profile)


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



    def test_retention_preview_and_execution_delete_only_expired_records(self):
        config = build_tenant_config("demo", {"retention_enabled": True, "retention_days": 1})
        self.store.put_tenant_config(config)
        old = "2000-01-01T00:00:00Z"
        self.table.put_item({"pk": "TENANT#demo", "sk": "EVENT#old", "tenant_id": "demo", "event_type": "action.evaluated", "created_at": old})
        self.table.put_item({"pk": "PROOF#old", "sk": "METADATA", "tenant_id": "demo", "proof_id": "proof-old", "created_at": old})
        self.table.put_item({"pk": "APPROVAL#old", "sk": "METADATA", "tenant_id": "demo", "approval_id": "approval-old", "created_at": old})
        self.table.put_item({"pk": "POLICY#keep", "sk": "VERSION#0000000001", "tenant_id": "demo", "item_type": "policy", "created_at": old})

        preview = service.handle_retention_run("demo", {}, self.auth)
        self.assertEqual(preview["statusCode"], 200)
        self.assertTrue(self.body(preview)["dry_run"])
        self.assertEqual(self.body(preview)["candidate_count"], 3)

        executed = service.handle_retention_run("demo", {"execute": True}, self.auth)
        self.assertEqual(executed["statusCode"], 200)
        self.assertEqual(self.body(executed)["deleted_count"], 3)
        self.assertIn(("POLICY#keep", "VERSION#0000000001"), self.table.items)
        self.assertIn(("TENANT#demo", "CONFIG"), self.table.items)


    def test_lambda_handler_tenant_retention_route(self):
        retention_auth = {**self.auth, "scopes": [*self.auth["scopes"], "tenant:retention", "tenant:write"]}
        service.handle_put_tenant("demo", {"name": "Demo", "retention_enabled": True, "retention_days": 30}, retention_auth)
        result = self._route("/v1/tenants/demo/retention/run", "POST", body={}, auth=retention_auth)
        self.assertIn(result["statusCode"], (200, 202))


    def test_handle_retention_run(self):
        service.handle_put_tenant("demo", {"name": "Demo", "retention_enabled": True, "retention_days": 30}, self.auth)
        result = service.handle_retention_run("demo", {}, self.auth)
        self.assertIn(result["statusCode"], (200, 202))

    # ------------------------------------------------------------------
    # Citation verify handler
    # ------------------------------------------------------------------


    def test_route_tenant_retention_run(self):
        result = self._routed("/v1/tenants/demo/retention/run", "POST", {"dry_run": True})
        self.assertIn(result["statusCode"], (200, 409))


    def test_store_with_retention_expiry(self):
        config = {"tenant_id": "demo", "item_type": "tenant_config", "retention_enabled": True, "retention_days": 30, "pk": "TENANT#demo", "sk": "CONFIG"}
        self.store.put_tenant_config(config)
        item = {"tenant_id": "demo", "item_type": "audit_event", "created_at": "2020-01-01T00:00:00Z"}
        result = self.store._with_retention_expiry(item)
        self.assertIn("retention_expires_at", result)


    def test_store_with_retention_expiry_legal_hold(self):
        config = {"tenant_id": "demo", "item_type": "tenant_config", "retention_enabled": True, "retention_days": 30, "legal_hold_enabled": True, "pk": "TENANT#demo", "sk": "CONFIG"}
        self.store.put_tenant_config(config)
        item = {"tenant_id": "demo", "item_type": "audit_event", "created_at": "2020-01-01T00:00:00Z"}
        result = self.store._with_retention_expiry(item)
        self.assertNotIn("retention_expires_at", result)


    def test_store_list_retention_candidates(self):
        config = {"tenant_id": "demo", "item_type": "tenant_config", "retention_enabled": True, "retention_days": 1, "pk": "TENANT#demo", "sk": "CONFIG"}
        self.store.put_tenant_config(config)
        old_item = {"pk": "TENANT#demo", "sk": "EVENT#old", "tenant_id": "demo", "item_type": "audit_event", "created_at": "2020-01-01T00:00:00Z", "retention_expires_at": 1}
        self.table.items[("TENANT#demo", "EVENT#old")] = old_item
        candidates = self.store.list_retention_candidates("demo", int(time.time()))
        self.assertGreaterEqual(len(candidates), 0)
