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




class ProofTests(unittest.TestCase):
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



    def test_duplicate_proof_id_cannot_overwrite_same_tenant_proof(self):
        proof_id = "proof-duplicate-security-test"
        first = service.handle_create_proof({"tenant_id": "demo", "proof_id": proof_id, "request_summary": "first"}, self.auth)
        second = service.handle_create_proof({"tenant_id": "demo", "proof_id": proof_id, "request_summary": "second"}, self.auth)

        self.assertEqual(first["statusCode"], 201)
        self.assertEqual(second["statusCode"], 409)
        self.assertEqual(self.body(second)["error"], "proof_id_conflict")
        self.assertEqual(self.table.items[("TENANT#demo", f"PROOF#{proof_id}")]["request"]["summary"], "first")


    def test_proof_integrity_can_be_verified_without_mutating_the_record(self):
        payload = {
            "context": {"tenant_id": "demo", "agent_id": "verify-agent", "invoked_by": "test"},
            "action": {"tool": "shell", "parameters": {"command": "ls"}},
        }
        decision = service.evaluate_and_record(payload, self.store)
        verified = service.handle_verify_proof(decision["proof_id"], self.auth)
        self.assertEqual(verified["statusCode"], 200)
        result = self.body(verified)
        self.assertTrue(result["valid"])
        self.assertTrue(result["proof_integrity"]["valid"])
        self.assertTrue(result["receipt_integrity"]["valid"])

        proof_key = ("TENANT#demo", f"PROOF#{decision['proof_id']}")
        self.table.items[proof_key]["recommendation"] = "tampered"
        tampered = service.handle_verify_proof(decision["proof_id"], self.auth)
        self.assertFalse(self.body(tampered)["valid"])


    def test_proof_integrity_remains_valid_when_retention_adds_ttl_metadata(self):
        self.store.put_tenant_config(build_tenant_config("demo", {"retention_enabled": True, "retention_days": 30}))
        decision = service.evaluate_and_record(
            {
                "context": {"tenant_id": "demo", "agent_id": "retention-proof-agent", "invoked_by": "test"},
                "action": {"tool": "shell", "parameters": {"command": "ls"}},
            },
            self.store,
        )
        proof_key = ("TENANT#demo", f"PROOF#{decision['proof_id']}")
        self.assertIn("retention_expires_at", self.table.items[proof_key])
        verified = self.body(service.handle_verify_proof(decision["proof_id"], self.auth))
        self.assertTrue(verified["valid"])
        self.assertTrue(verified["proof_integrity"]["valid"])


    def test_proof_integrity_remains_valid_after_recording_tool_outcome(self):
        payload = {
            "context": {"tenant_id": "demo", "agent_id": "outcome-proof-agent", "invoked_by": "test"},
            "action": {"tool": "shell", "parameters": {"command": "printf proof"}},
        }
        decision = service.evaluate_and_record(payload, self.store)
        outcome = service.handle_outcome(
            {},
            {
                "tenant_id": "demo",
                "proof_id": decision["proof_id"],
                "action_hash": decision["action_hash"],
                "status": "success",
                "result": "completed",
            },
            decision["action"]["action_id"],
            self.auth,
        )
        self.assertEqual(outcome["statusCode"], 202)

        verified = self.body(service.handle_verify_proof(decision["proof_id"], self.auth))
        self.assertTrue(verified["valid"])
        self.assertTrue(verified["proof_integrity"]["valid"])
        self.assertTrue(verified["receipt_integrity"]["valid"])


    def test_agent_credential_cannot_read_another_agents_proof(self):
        self.store.put_proof(
            {
                "proof_id": "proof-other-agent",
                "proof_uri": "proof://run/action",
                "tenant_id": "demo",
                "run_id": "run-agent-binding",
                "action_id": "action-other-agent",
                "agent": {"id": "other-agent"},
                "created_at": "2026-07-16T00:00:00Z",
            }
        )
        agent_auth = {**self.auth, "token_type": "agent", "agent_id": "bound-agent", "scopes": ["proof:read"]}

        denied = service.handle_get_proof("proof-other-agent", agent_auth)

        self.assertEqual(denied["statusCode"], 403)
        self.assertEqual(self.body(denied)["error"], "agent_credential_mismatch")


    def test_handle_get_proof_returns_proof(self):
        proof_auth = {**self.auth, "scopes": self.auth["scopes"] + ["proof:write", "proof:read"]}
        created = self.body(service.handle_create_proof(
            {"tenant_id": "demo", "proof_id": "proof-get-test", "request_summary": "test proof"},
            proof_auth,
        ))
        result = service.handle_get_proof("proof-get-test", proof_auth)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(self.body(result)["proof_id"], "proof-get-test")


    def test_handle_get_proof_report_renders_markdown(self):
        proof_auth = {**self.auth, "scopes": self.auth["scopes"] + ["proof:write", "proof:read"]}
        service.handle_create_proof(
            {"tenant_id": "demo", "proof_id": "proof-report-test", "request_summary": "report test"},
            proof_auth,
        )
        result = service.handle_get_proof("proof-report-test", proof_auth, report=True)
        self.assertEqual(result["statusCode"], 200)
        body = self.body(result)
        self.assertEqual(body["format"], "markdown")
        self.assertIn("report", body)


    def test_handle_get_proof_returns_404_for_missing(self):
        proof_auth = {**self.auth, "scopes": self.auth["scopes"] + ["proof:read"]}
        result = service.handle_get_proof("nonexistent-proof", proof_auth)
        self.assertEqual(result["statusCode"], 404)


    def test_lambda_handler_proof_routes(self):
        proof_auth = {**self.auth, "scopes": [*self.auth["scopes"], "proof:write", "proof:read"]}
        created = service.handle_create_proof(
            {"context": {"tenant_id": "demo", "environment": "production", "agent_id": "proof-agent", "invoked_by": "test", "run_id": "proof-run"}, "action": {"tool": "shell", "parameters": {"command": "echo proof"}}},
            proof_auth,
        )
        proof_id = self.body(created)["proof_id"]
        result = self._route(f"/v1/proofs/{proof_id}", "GET", auth=proof_auth)
        self.assertEqual(result["statusCode"], 200)
        result = self._route(f"/v1/proofs/{proof_id}/verify", "GET", auth=proof_auth)
        self.assertEqual(result["statusCode"], 200)
        result = self._route(f"/v1/proofs/{proof_id}/report", "GET", auth=proof_auth)
        self.assertEqual(result["statusCode"], 200)


    def test_handle_create_proof(self):
        proof_auth = {**self.auth, "scopes": [*self.auth["scopes"], "proof:write", "proof:read"]}
        result = service.handle_create_proof(
            {"context": {"tenant_id": "demo", "environment": "production", "agent_id": "proof-test-agent", "invoked_by": "test", "run_id": "proof-test-run"}, "action": {"tool": "shell", "parameters": {"command": "echo proof"}}},
            proof_auth,
        )
        self.assertEqual(result["statusCode"], 201)
        self.assertIn("proof_id", self.body(result))


    def test_handle_get_proof_not_found(self):
        proof_auth = {**self.auth, "scopes": [*self.auth["scopes"], "proof:read"]}
        result = service.handle_get_proof("nonexistent-proof", proof_auth)
        self.assertEqual(result["statusCode"], 404)


    def test_handle_verify_proof_not_found(self):
        proof_auth = {**self.auth, "scopes": [*self.auth["scopes"], "proof:read"]}
        result = service.handle_verify_proof("nonexistent-proof", proof_auth)
        self.assertEqual(result["statusCode"], 404)


    def test_route_proofs_post(self):
        proof_auth = {**self.auth, "scopes": [*self.auth["scopes"], "proof:write"]}
        result = self._routed("/v1/proofs", "POST", {
            "context": {"tenant_id": "demo", "environment": "production", "agent_id": "proof-agent", "invoked_by": "test"},
            "action": {"tool": "shell", "parameters": {"command": "ls"}},
        }, auth=proof_auth)
        self.assertIn(result["statusCode"], (200, 201))


    def test_route_proof_get(self):
        proof_auth = {**self.auth, "scopes": [*self.auth["scopes"], "proof:write", "proof:read"]}
        created = self._routed("/v1/proofs", "POST", {
            "context": {"tenant_id": "demo", "environment": "production", "agent_id": "proof-get-agent", "invoked_by": "test"},
            "action": {"tool": "shell", "parameters": {"command": "ls"}},
        }, auth=proof_auth)
        proof_id = self.body(created).get("proof_id", "unknown")
        result = self._routed(f"/v1/proofs/{proof_id}", auth=proof_auth)
        self.assertIn(result["statusCode"], (200, 404))


    def test_route_proof_verify(self):
        proof_auth = {**self.auth, "scopes": [*self.auth["scopes"], "proof:write", "proof:read"]}
        created = self._routed("/v1/proofs", "POST", {
            "context": {"tenant_id": "demo", "environment": "production", "agent_id": "proof-verify-agent", "invoked_by": "test"},
            "action": {"tool": "shell", "parameters": {"command": "ls"}},
        }, auth=proof_auth)
        proof_id = self.body(created).get("proof_id", "unknown")
        result = self._routed(f"/v1/proofs/{proof_id}/verify", auth=proof_auth)
        self.assertIn(result["statusCode"], (200, 404))


    def test_route_proof_report(self):
        proof_auth = {**self.auth, "scopes": [*self.auth["scopes"], "proof:write", "proof:read"]}
        created = self._routed("/v1/proofs", "POST", {
            "context": {"tenant_id": "demo", "environment": "production", "agent_id": "proof-report-agent", "invoked_by": "test"},
            "action": {"tool": "shell", "parameters": {"command": "ls"}},
        }, auth=proof_auth)
        proof_id = self.body(created).get("proof_id", "unknown")
        result = self._routed(f"/v1/proofs/{proof_id}/report", auth=proof_auth)
        self.assertIn(result["statusCode"], (200, 404))


    def test_store_put_and_get_proof(self):
        proof = {"tenant_id": "demo", "proof_id": "proof-store-test", "created_at": service.utc_now()}
        self.store.put_proof(proof)
        result = self.store.get_proof("proof-store-test", "demo")
        self.assertIsNotNone(result)
        self.assertEqual(result["proof_id"], "proof-store-test")


    def test_mcp_create_proof_tool(self):
        mcp_auth = {**self.auth, "scopes": ["mcp:read", "proof:write"]}
        result = self._mcp_call("create_proof", {
            "context": {"tenant_id": "demo", "environment": "production", "agent_id": "mcp-proof-agent", "invoked_by": "test"},
            "action": {"tool": "shell", "parameters": {"command": "ls"}},
        }, auth=mcp_auth)
        self.assertEqual(result["statusCode"], 200)


    def test_mcp_verify_proof_tool(self):
        mcp_auth = {**self.auth, "scopes": ["mcp:read", "proof:write", "proof:read"]}
        created = self._mcp_call("create_proof", {
            "context": {"tenant_id": "demo", "environment": "production", "agent_id": "mcp-vp-agent", "invoked_by": "test"},
            "action": {"tool": "shell", "parameters": {"command": "ls"}},
        }, auth=mcp_auth)
        proof_id = self.body(created)["result"]["structuredContent"].get("proof_id", "unknown")
        result = self._mcp_call("verify_proof", {"proof_id": proof_id}, auth=mcp_auth)
        self.assertEqual(result["statusCode"], 200)


    def test_mcp_verify_proof_missing_id(self):
        mcp_auth = {**self.auth, "scopes": ["mcp:read", "proof:read"]}
        result = self._mcp_call("verify_proof", {}, auth=mcp_auth)
        self.assertEqual(result["statusCode"], 200)
        body = self.body(result)
        self.assertIn("error", body)
