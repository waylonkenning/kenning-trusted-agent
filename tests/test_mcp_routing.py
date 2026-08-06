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




class McpRoutingTests(unittest.TestCase):
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



    def test_product_mcp_profiles_isolate_tools_and_bind_citation_tenant(self):
        profile_expectations = {
            "/mcp/agent-guard": ({"evaluate_action"}, ["mcp:read", "guard:evaluate"]),
            "/mcp/citation-trust": ({"verify_citations"}, ["mcp:read", "citation:verify"]),
            "/mcp/agent-proof": ({"create_proof", "verify_proof", "get_receipt_public_key"}, ["mcp:read", "proof:read", "proof:write"]),
            "/mcp/agent-identity": (
                {"register_agent", "list_agents", "get_agent", "revoke_agent", "issue_agent_credential", "list_agent_credentials", "get_agent_credential", "revoke_agent_credential"},
                ["mcp:read", "identity:read", "identity:write"],
            ),
        }
        for path, (expected_tools, scopes) in profile_expectations.items():
            profile_auth = {**self.auth, "scopes": scopes}
            profile_event = {"requestContext": {"http": {"method": "POST"}}, "rawPath": path, "headers": {"MCP-Protocol-Version": "2025-06-18"}}
            with patch.object(service, "authenticate", return_value=(profile_auth, None)):
                listed = service.lambda_handler(
                    {
                        **profile_event,
                        "body": json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
                    },
                    None,
                )
            self.assertEqual(listed["statusCode"], 200)
            self.assertEqual({tool["name"] for tool in self.body(listed)["result"]["tools"]}, expected_tools)

        citation_auth = {
            **self.auth,
            "scopes": ["mcp:read", "citation:verify"],
        }
        event = {
            "requestContext": {"http": {"method": "POST"}},
            "rawPath": "/mcp/citation-trust",
            "headers": {"MCP-Protocol-Version": "2025-06-18"},
        }
        with patch.object(service, "authenticate", return_value=(citation_auth, None)):
            initialized = service.lambda_handler(
                {
                    **event,
                    "body": json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "initialize",
                            "params": {"protocolVersion": "2025-06-18"},
                        }
                    ),
                },
                None,
            )
            self.assertEqual(initialized["statusCode"], 200)
            initialize_body = self.body(initialized)
            self.assertEqual(initialize_body["result"]["serverInfo"]["name"], "kenning-citation-trust")
            self.assertIn("tenant is derived from the PAT", initialize_body["result"]["instructions"])

            listed = service.lambda_handler(
                {
                    **event,
                    "body": json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
                },
                None,
            )
            listed_body = self.body(listed)
            self.assertEqual({tool["name"] for tool in listed_body["result"]["tools"]}, {"verify_citations"})
            citation_tool = listed_body["result"]["tools"][0]
            self.assertFalse(citation_tool["inputSchema"]["additionalProperties"])

            verified = service.lambda_handler(
                {
                    **event,
                    "body": json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": 3,
                            "method": "tools/call",
                            "params": {
                                "name": "verify_citations",
                                "arguments": {
                                    "response": "Example Domain",
                                    "citations": [{"url": "https://example.com", "claim": "Example Domain", "source_text": "Example Domain"}],
                                },
                            },
                        }
                    ),
                },
                None,
            )
            verified_body = self.body(verified)
            self.assertEqual(verified_body["result"]["structuredContent"]["tenant_id"], "demo")
            self.assertEqual(verified_body["result"]["structuredContent"]["status"], "pass")

            wrong_product = service.lambda_handler(
                {
                    **event,
                    "body": json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": 4,
                            "method": "tools/call",
                            "params": {"name": "evaluate_action", "arguments": {}},
                        }
                    ),
                },
                None,
            )
            self.assertEqual(self.body(wrong_product)["error"]["code"], -32601)

            tenant_override = service.lambda_handler(
                {
                    **event,
                    "body": json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": 5,
                            "method": "tools/call",
                            "params": {
                                "name": "verify_citations",
                                "arguments": {"tenant_id": "another-tenant", "response": "Example Domain"},
                            },
                        }
                    ),
                },
                None,
            )
            self.assertEqual(self.body(tenant_override)["error"]["code"], -32602)


    def test_mcp_route_requires_mcp_scope(self):
        auth = {**self.auth, "scopes": ["guard:evaluate"]}
        event = {
            "requestContext": {"http": {"method": "POST"}},
            "rawPath": "/mcp",
            "body": json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
            "headers": {"authorization": "Bearer kta_pat_test"},
        }
        with patch.object(service, "authenticate", return_value=(auth, None)):
            result = service.lambda_handler(event, None)
        self.assertEqual(result["statusCode"], 403)
        self.assertEqual(self.body(result)["required_scope"], "mcp:read")


    def test_disabled_product_blocks_api_access_and_mcp_exposure(self):
        self.store.put_tenant_config(build_tenant_config("demo", {"enabled_products": ["agent-guard"]}))
        proof_auth = {**self.auth, "scopes": self.auth["scopes"] + ["proof:read", "mcp:read", "proof:write"]}
        proof_event = {
            "rawPath": "/v1/proofs/proof-disabled",
            "requestContext": {"http": {"method": "GET"}},
        }
        with patch.object(service, "authenticate", return_value=(proof_auth, None)):
            blocked = service.lambda_handler(proof_event, None)
        self.assertEqual(blocked["statusCode"], 403)
        self.assertEqual(self.body(blocked)["error"], "product_disabled")
        listed = service.handle_mcp(
            {"headers": {"MCP-Protocol-Version": "2025-06-18"}},
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            "POST",
            proof_auth,
        )
        self.assertEqual({tool["name"] for tool in self.body(listed)["result"]["tools"]}, {"evaluate_action"})
        blocked_tool = service.handle_mcp(
            {"headers": {"MCP-Protocol-Version": "2025-06-18"}},
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "create_proof", "arguments": {}},
            },
            "POST",
            proof_auth,
        )
        blocked_body = self.body(blocked_tool)
        self.assertEqual(blocked_body["error"]["code"], -32003)
        self.assertEqual(blocked_body["error"]["data"]["product_id"], "agent-proof")


    def test_product_access_lookup_failure_fails_closed_for_http_and_mcp(self):
        proof_auth = {**self.auth, "scopes": self.auth["scopes"] + ["proof:read", "mcp:read"]}
        with patch.object(service, "store", side_effect=RuntimeError("tenant config unavailable")):
            blocked = self._route("/v1/receipts/public-key", auth=proof_auth)
            self.assertEqual(blocked["statusCode"], 503)
            blocked_body = self.body(blocked)
            self.assertEqual(blocked_body["error"], "product_access_unavailable")
            self.assertTrue(blocked_body["retryable"])

            blocked_tool = service.handle_mcp(
                {"headers": {"MCP-Protocol-Version": "2025-06-18"}},
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "get_receipt_public_key", "arguments": {}},
                },
                "POST",
                proof_auth,
            )
        self.assertEqual(blocked_tool["statusCode"], 200)
        blocked_tool_body = self.body(blocked_tool)
        self.assertEqual(blocked_tool_body["error"]["code"], -32003)
        self.assertEqual(blocked_tool_body["error"]["data"]["error"], "product_access_unavailable")


    def test_mcp_initialize_negotiates_protocol_version(self):
        mcp_auth = {**self.auth, "scopes": ["mcp:read"]}
        event = {"headers": {"MCP-Protocol-Version": "2025-06-18"}}
        result = service.handle_mcp(
            event,
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
            "POST",
            mcp_auth,
        )
        self.assertEqual(result["statusCode"], 200)
        body = self.body(result)
        self.assertEqual(body["result"]["protocolVersion"], "2025-06-18")
        self.assertEqual(body["result"]["serverInfo"]["name"], "kenning-trusted-agent")


    def test_mcp_ping_returns_empty_result(self):
        mcp_auth = {**self.auth, "scopes": ["mcp:read"]}
        event = {"headers": {}}
        result = service.handle_mcp(event, {"jsonrpc": "2.0", "id": 99, "method": "ping"}, "POST", mcp_auth)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(self.body(result)["result"], {})


    def test_mcp_rejects_get_method(self):
        mcp_auth = {**self.auth, "scopes": ["mcp:read"]}
        result = service.handle_mcp({"headers": {}}, {}, "GET", mcp_auth)
        self.assertEqual(result["statusCode"], 405)


    def test_mcp_rejects_invalid_jsonrpc_version(self):
        mcp_auth = {**self.auth, "scopes": ["mcp:read"]}
        result = service.handle_mcp({"headers": {}}, {"jsonrpc": "1.0", "id": 1, "method": "ping"}, "POST", mcp_auth)
        self.assertEqual(result["statusCode"], 400)


    def test_mcp_rejects_unsupported_protocol_version_header(self):
        mcp_auth = {**self.auth, "scopes": ["mcp:read"]}
        result = service.handle_mcp(
            {"headers": {"MCP-Protocol-Version": "1999-01-01"}},
            {"jsonrpc": "2.0", "id": 1, "method": "ping"},
            "POST",
            mcp_auth,
        )
        self.assertEqual(result["statusCode"], 400)


    def test_mcp_notifications_return_202(self):
        mcp_auth = {**self.auth, "scopes": ["mcp:read"]}
        result = service.handle_mcp(
            {"headers": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            "POST",
            mcp_auth,
        )
        self.assertEqual(result["statusCode"], 202)


    def test_mcp_unknown_method_returns_error(self):
        mcp_auth = {**self.auth, "scopes": ["mcp:read"]}
        result = service.handle_mcp(
            {"headers": {}},
            {"jsonrpc": "2.0", "id": 1, "method": "resources/list"},
            "POST",
            mcp_auth,
        )
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(self.body(result)["error"]["code"], -32601)

    # ------------------------------------------------------------------
    # Approval get handler
    # ------------------------------------------------------------------


    def test_mcp_tools_list(self):
        mcp_auth = {**self.auth, "scopes": ["mcp:read"]}
        result = service.handle_mcp(
            {"headers": {}},
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            "POST",
            mcp_auth,
        )
        self.assertEqual(result["statusCode"], 200)
        tools = self.body(result)["result"]["tools"]
        self.assertGreaterEqual(len(tools), 1)


    def test_mcp_tool_not_in_profile(self):
        mcp_auth = {**self.auth, "scopes": ["mcp:read", "guard:evaluate"]}
        profile = service.MCP_PROFILES["agent-guard"]
        result = self._mcp_call("verify_citations", {"response": "test"}, mcp_auth, profile)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(self.body(result)["error"]["code"], -32601)


    def test_mcp_register_agent(self):
        profile = service.MCP_PROFILES["agent-identity"]
        result = self._mcp_call("register_agent", {"agent_id": "mcp-reg-agent", "name": "MCP Agent", "owner": "user-1"}, profile=profile)
        self.assertEqual(result["statusCode"], 200)
        content = self.body(result)["result"]["structuredContent"]
        self.assertEqual(content["agent_id"], "mcp-reg-agent")


    def test_mcp_list_agents(self):
        profile = service.MCP_PROFILES["agent-identity"]
        self._mcp_call("register_agent", {"agent_id": "mcp-list-agent", "name": "MCP List", "owner": "user-1"}, profile=profile)
        result = self._mcp_call("list_agents", {}, profile=profile)
        self.assertEqual(result["statusCode"], 200)
        content = self.body(result)["result"]["structuredContent"]
        self.assertIn("agents", content)


    def test_mcp_get_agent(self):
        profile = service.MCP_PROFILES["agent-identity"]
        self._mcp_call("register_agent", {"agent_id": "mcp-get-agent", "name": "MCP Get", "owner": "user-1"}, profile=profile)
        result = self._mcp_call("get_agent", {"agent_id": "mcp-get-agent"}, profile=profile)
        self.assertEqual(result["statusCode"], 200)
        content = self.body(result)["result"]["structuredContent"]
        self.assertEqual(content["agent_id"], "mcp-get-agent")


    def test_mcp_revoke_agent(self):
        profile = service.MCP_PROFILES["agent-identity"]
        self._mcp_call("register_agent", {"agent_id": "mcp-revoke-agent", "name": "MCP Revoke", "owner": "user-1"}, profile=profile)
        result = self._mcp_call("revoke_agent", {"agent_id": "mcp-revoke-agent"}, profile=profile)
        self.assertEqual(result["statusCode"], 200)
        content = self.body(result)["result"]["structuredContent"]
        self.assertEqual(content["status"], "revoked")


    def test_mcp_get_receipt_public_key(self):
        result = self._mcp_call("get_receipt_public_key", {})
        self.assertEqual(result["statusCode"], 200)


    def test_mcp_scope_enforcement(self):
        mcp_auth = {**self.auth, "scopes": ["mcp:read"]}
        result = self._mcp_call("evaluate_action", {
            "context": {"tenant_id": "demo"},
            "action": {"tool": "shell"},
        }, auth=mcp_auth)
        self.assertEqual(result["statusCode"], 403)

    # ------------------------------------------------------------------
    # Scope enforcement coverage for all routes
    # ------------------------------------------------------------------


    def test_mcp_approved_retry_not_found(self):
        result = self._mcp_call("evaluate_action", {
            "context": {"tenant_id": "demo", "environment": "production", "agent_id": "retry-agent", "invoked_by": "test"},
            "action": {"tool": "shell", "parameters": {"command": "ls"}},
            "approval_id": "nonexistent-approval",
        })
        self.assertEqual(result["statusCode"], 200)
        content = self.body(result)["result"]["structuredContent"]
        self.assertEqual(content["error"], "approval_not_found")
        self.assertTrue(self.body(result)["result"]["isError"])


    def test_mcp_approved_retry_not_approved(self):
        self.store.put_approval({
            "approval_id": "approval-mcp-pending",
            "tenant_id": "demo",
            "status": "pending",
            "agent_id": "retry-agent",
            "run_id": "run-retry",
            "action_id": "action-retry",
            "action_hash": "sha256:retry",
            "requested_by": "test",
            "expires_at": 4_000_000_000,
            "created_at": "2026-07-16T00:00:00Z",
        })
        result = self._mcp_call("evaluate_action", {
            "context": {"tenant_id": "demo", "environment": "production", "agent_id": "retry-agent", "invoked_by": "test"},
            "action": {"tool": "shell", "parameters": {"command": "ls"}},
            "approval_id": "approval-mcp-pending",
        })
        self.assertEqual(result["statusCode"], 200)
        content = self.body(result)["result"]["structuredContent"]
        self.assertEqual(content["error"], "approval_not_approved")

    # ------------------------------------------------------------------
    # mcp_approval_reference
    # ------------------------------------------------------------------


    def test_lambda_handler_mcp_route(self):
        mcp_auth = {**self.auth, "scopes": ["mcp:read"]}
        event = {
            "rawPath": "/mcp",
            "requestContext": {"http": {"method": "POST"}},
            "headers": {"authorization": "Bearer kta_pat_test"},
            "body": json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
        }
        with patch.object(service, "authenticate", return_value=(mcp_auth, None)):
            result = service.lambda_handler(event, None)
        self.assertEqual(result["statusCode"], 200)


    def test_mcp_error_shape(self):
        error = service.mcp_error(1, -32600, "test error", data={"extra": True})
        self.assertEqual(error["error"]["code"], -32600)
        self.assertEqual(error["error"]["data"]["extra"], True)


    def test_mcp_tool_response_shape(self):
        result = service.mcp_tool_response(42, {"key": "value"}, is_error=True)
        body = json.loads(result["body"])
        self.assertEqual(body["id"], 42)
        self.assertTrue(body["result"]["isError"])
        self.assertEqual(body["result"]["structuredContent"]["key"], "value")

    # ------------------------------------------------------------------
    # Lambda handler routing coverage
    # ------------------------------------------------------------------


    def test_route_mcp_post(self):
        mcp_auth = {**self.auth, "scopes": [*self.auth["scopes"], "mcp:read"]}
        result = self._routed("/mcp", "POST", {"jsonrpc": "2.0", "id": 1, "method": "ping"}, auth=mcp_auth)
        self.assertEqual(result["statusCode"], 200)


    def test_mcp_get_receipt_public_key_tool(self):
        mcp_auth = {**self.auth, "scopes": ["mcp:read", "proof:read"]}
        result = self._mcp_call("get_receipt_public_key", {}, auth=mcp_auth)
        self.assertIn(result["statusCode"], (200, 503))


    def test_mcp_list_agents_tool(self):
        mcp_auth = {**self.auth, "scopes": ["mcp:read", "identity:read"]}
        result = self._mcp_call("list_agents", {}, auth=mcp_auth)
        self.assertEqual(result["statusCode"], 200)


    def test_mcp_verify_citations_tool(self):
        mcp_auth = {**self.auth, "scopes": ["mcp:read", "citation:verify"]}
        result = self._mcp_call("verify_citations", {
            "response": "A claim cites https://example.org.",
            "citations": [{"url": "https://example.org", "claim": "A claim"}],
        }, auth=mcp_auth)
        self.assertEqual(result["statusCode"], 200)


    def test_route_mcp_scope_enforcement(self):
        no_scope_auth = {**self.auth, "scopes": []}
        result = self._routed("/mcp", "POST", {"jsonrpc": "2.0", "id": 1, "method": "ping"}, auth=no_scope_auth)
        self.assertEqual(result["statusCode"], 403)
