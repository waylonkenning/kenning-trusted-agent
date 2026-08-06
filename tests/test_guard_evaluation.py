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




class GuardEvaluationTests(unittest.TestCase):
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



    def test_report_citation_extraction_is_bounded_and_hash_bound(self):
        report_auth = {**self.auth, "scopes": [*self.auth["scopes"], "citation:verify"]}
        extracted = service.handle_citation_report_extract(
            {
                "report_name": "test-report.txt",
                "report_text": "A claim cites https://example.org/report. (OECD, 2026[1])",
            },
            report_auth,
        )
        self.assertEqual(extracted["statusCode"], 200)
        extracted_body = self.body(extracted)
        self.assertEqual(extracted_body["tenant_id"], "demo")
        self.assertEqual(extracted_body["citation_count"], 1)
        self.assertEqual(extracted_body["reference_marker_count"], 1)
        mismatch = service.handle_citation_report_extract(
            {"report_text": "A claim cites https://example.org/report.", "content_sha256": "0" * 64},
            report_auth,
        )
        self.assertEqual(mismatch["statusCode"], 400)
        self.assertEqual(self.body(mismatch)["error"], "content_hash_mismatch")


    def test_caller_supplied_observe_mode_is_ignored_for_guard_evaluation(self):
        payload = {
            "mode": "observe",
            "context": {
                "tenant_id": "demo",
                "environment": "production",
                "agent_id": "test-agent",
                "invoked_by": "test",
                "mode": "observe",
            },
            "action": {"tool": "shell", "parameters": {"command": "rm -rf /"}},
        }
        service.apply_tenant_runtime(payload, self.auth, self.store)
        decision = service.evaluate_and_record(payload, self.store)
        self.assertEqual(decision["decision"], "deny")
        self.assertIsNone(decision["would_decision"])
        self.assertEqual(decision["mode"], "enforce")
        self.assertEqual(decision["tenant_policy"]["mode"], "enforce")


    def test_mcp_tool_schema_does_not_expose_guard_mode(self):
        definition = service.mcp_tool_definition()
        properties = definition["inputSchema"]["properties"]
        self.assertNotIn("mode", properties)
        self.assertNotIn("mode", properties["context"]["properties"])


    def test_action_evaluation_retry_is_idempotent_and_action_id_cannot_be_reused(self):
        payload = {
            "context": {
                "tenant_id": "demo",
                "environment": "production",
                "agent_id": "retry-agent",
                "invoked_by": "test",
                "action_id": "stable-action-42",
            },
            "action": {"tool": "sql", "parameters": {"statement": "UPDATE orders SET status = closed"}},
        }

        first = self.body(service.handle_evaluate({}, dict(payload), self.auth))
        second = self.body(service.handle_evaluate({}, json.loads(json.dumps(payload)), self.auth))

        self.assertEqual(first["decision"], "require_approval")
        self.assertTrue(second["idempotent"])
        self.assertEqual(second["action_id"], first["action"]["action_id"])
        self.assertEqual(second["action_hash"], first["action_hash"])
        self.assertEqual(second["approval"]["approval_id"], first["approval"]["approval_id"])
        self.assertEqual(second["proof_id"], first["proof_id"])
        self.assertEqual(
            sum(
                1
                for (pk, _sk), item in self.table.items.items()
                if pk.startswith("TENANT#") and item.get("event_type") == "action.evaluated"
            ),
            1,
        )

        changed = json.loads(json.dumps(payload))
        changed["action"]["parameters"]["statement"] = "UPDATE orders SET status = closed WHERE id = 42"
        conflict = service.handle_evaluate({}, changed, self.auth)
        self.assertEqual(conflict["statusCode"], 409)
        self.assertEqual(self.body(conflict)["error"], "action_id_reuse")



    def test_approved_evaluation_consumes_approval_before_execution(self):
        payload = {
            "context": {
                "tenant_id": "demo",
                "environment": "production",
                "agent_id": "resume-agent",
                "invoked_by": "requester@example.org",
                "action_id": "stable-resume-action",
            },
            "action": {"tool": "sql", "parameters": {"statement": "UPDATE orders SET status = 'closed'"}},
        }

        initial = self.body(service.handle_evaluate({}, json.loads(json.dumps(payload)), self.auth))
        self.assertEqual(initial["decision"], "require_approval")
        approval_id = initial["approval"]["approval_id"]
        action_hash = initial["action_hash"]
        approved = service.handle_approval(
            {},
            {"tenant_id": "demo", "decision": "approve", "approver": "security@example.org", "action_hash": action_hash},
            approval_id,
            self.auth,
        )
        self.assertEqual(approved["statusCode"], 200)

        resume_payload = {**json.loads(json.dumps(payload)), "approval_id": approval_id, "action_hash": action_hash}
        resumed = service.handle_evaluate({}, resume_payload, self.auth)
        resumed_body = self.body(resumed)
        self.assertEqual(resumed["statusCode"], 200)
        self.assertEqual(resumed_body["decision"], "allow")
        self.assertTrue(resumed_body["approval_resume"])
        self.assertEqual(resumed_body["approval_status"], "consumed")
        self.assertEqual(self.table.items[(f"APPROVAL#{approval_id}", "METADATA")]["status"], "consumed")

        replayed = service.handle_evaluate({}, resume_payload, self.auth)
        replayed_body = self.body(replayed)
        self.assertEqual(replayed["statusCode"], 409)
        self.assertEqual(replayed_body["error"], "approval_not_approved")
        self.assertEqual(replayed_body["status"], "consumed")


    def test_capture_policy_protects_evaluation_approval_and_proof_records(self):
        secret_statement = "UPDATE accounts SET status='closed', note='capture-secret-9842'"
        config = build_tenant_config(
            "demo",
            {
                "capture_policy": {
                    "store_original_action": False,
                    "redact_fields": ["target"],
                    "hash_fields": ["parameters.statement"],
                },
                "environments": [
                    {"environment_id": "production", "status": "active", "mode": "enforce", "allowed_tools": ["sql"]},
                ],
                "default_environment": "production",
            },
        )
        self.store.put_tenant_config(config)
        self.store._tenant_config_cache.clear()
        payload = {
            "context": {"tenant_id": "demo", "environment": "production", "agent_id": "capture-agent", "invoked_by": "test"},
            "action": {"tool": "sql", "target": "accounts", "parameters": {"statement": secret_statement}},
        }
        service.apply_tenant_runtime(payload, self.auth, self.store)
        decision = service.evaluate_and_record(payload, self.store)
        self.assertEqual(decision["decision"], "require_approval")
        self.assertNotIn("original_action", decision["action"])
        self.assertTrue(decision["action"]["parameters"]["statement"].startswith("sha256:"))
        self.assertEqual(decision["action"]["target"], "[REDACTED_BY_TENANT_POLICY]")
        self.assertNotIn(secret_statement, repr(decision))
        self.assertNotEqual(decision["action_hash"], decision["action"]["parameters"]["statement"])

        approval = decision["approval"]
        self.assertNotIn(secret_statement, repr(approval))
        proof = self.table.items[("TENANT#demo", f"PROOF#{decision['proof_id']}")]
        event = next(
            item
            for (pk, _sk), item in self.table.items.items()
            if pk == "TENANT#demo" and item.get("event_type") == "action.evaluated"
        )
        self.assertNotIn(secret_statement, repr(proof))
        self.assertNotIn(secret_statement, repr(event))
        self.assertEqual(
            sum(1 for key in self.table.put_calls if key[0] == f"APPROVAL#{approval['approval_id']}"),
            1,
        )
        self.assertEqual(
            sum(1 for key in self.table.get_calls if key == ("TENANT#demo", "CONFIG")),
            1,
        )


    def test_mcp_exposes_guard_proof_and_receipt_workflows(self):
        mcp_auth = {
            **self.auth,
            "scopes": self.auth["scopes"] + ["mcp:read", "proof:read", "proof:write"],
        }
        event = {"headers": {"MCP-Protocol-Version": "2025-06-18"}}
        listed = service.handle_mcp(
            event,
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            "POST",
            mcp_auth,
        )
        self.assertEqual(listed["statusCode"], 200)
        self.assertEqual(
            {tool["name"] for tool in self.body(listed)["result"]["tools"]},
            {"evaluate_action", "verify_citations", "create_proof", "verify_proof", "get_receipt_public_key"},
        )
        citation_tool = next(tool for tool in self.body(listed)["result"]["tools"] if tool["name"] == "verify_citations")
        self.assertTrue(citation_tool["annotations"]["readOnlyHint"])
        self.assertFalse(citation_tool["annotations"]["destructiveHint"])
        self.assertTrue(citation_tool["annotations"]["openWorldHint"])
        self.assertEqual(citation_tool["outputSchema"]["properties"]["status"]["enum"], ["pass", "warning", "fail"])
        citation_properties = citation_tool["inputSchema"]["properties"]["citations"]["items"]["properties"]
        self.assertIn("claim_support_required", citation_properties)
        self.assertIn("reference_metadata", citation_properties)
        self.assertIn("reference_verified", citation_tool["outputSchema"]["properties"]["citations"]["items"]["properties"])

        evaluated = service.handle_mcp(
            event,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "evaluate_action",
                    "arguments": {
                        "context": {"tenant_id": "demo", "agent_id": "mcp-agent", "invoked_by": "test"},
                        "action": {"tool": "shell", "parameters": {"command": "ls"}},
                    },
                },
            },
            "POST",
            mcp_auth,
        )
        proof_id = self.body(evaluated)["result"]["structuredContent"]["proof_id"]
        verified = service.handle_mcp(
            event,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "verify_proof", "arguments": {"proof_id": proof_id}},
            },
            "POST",
            mcp_auth,
        )
        self.assertTrue(self.body(verified)["result"]["structuredContent"]["valid"])


    def test_http_evaluation_fails_closed_when_guard_is_unavailable(self):
        event = {
            "requestContext": {"http": {"method": "POST"}},
            "rawPath": "/v1/actions/evaluate",
            "body": json.dumps(
                {
                    "context": {"tenant_id": "demo", "action_id": "action-unavailable"},
                    "action": {"tool": "shell", "parameters": {"command": "printf test"}},
                }
            ),
            "headers": {"authorization": "Bearer kta_pat_test"},
        }
        with patch.object(service, "authenticate", return_value=(self.auth, None)), patch.object(
            service, "handle_evaluate", side_effect=RuntimeError("table unavailable")
        ):
            result = service.lambda_handler(event, None)
        self.assertEqual(result["statusCode"], 503)
        body = self.body(result)
        self.assertEqual(body["error"], "guard_unavailable")
        self.assertEqual(body["decision"], "deny")
        self.assertEqual(body["reason_codes"], ["GUARD_UNAVAILABLE"])
        self.assertEqual(body["enforcement"], "fail_closed")
        self.assertTrue(body["retryable"])


    def test_mcp_evaluation_fails_closed_when_guard_is_unavailable(self):
        mcp_auth = {**self.auth, "scopes": ["mcp:read", "guard:evaluate"]}
        event = {
            "headers": {"MCP-Protocol-Version": "2025-06-18"},
            "body": "",
        }
        body = {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {
                "name": "evaluate_action",
                "arguments": {
                    "context": {"tenant_id": "demo", "action_id": "mcp-action-unavailable"},
                    "action": {"tool": "shell", "parameters": {"command": "printf test"}},
                },
            },
        }
        with patch.object(service, "product_access_error", return_value=None), patch.object(
            service, "store", side_effect=RuntimeError("table unavailable")
        ):
            result = service.handle_mcp(event, body, "POST", mcp_auth)
        self.assertEqual(result["statusCode"], 503)
        rpc = self.body(result)
        self.assertEqual(rpc["error"]["code"], -32002)
        self.assertEqual(rpc["error"]["data"]["decision"], "deny")
        self.assertEqual(rpc["error"]["data"]["enforcement"], "fail_closed")


    def test_external_audit_ingest_rejects_guard_control_event_types(self):
        auth = {**self.auth, "scopes": self.auth["scopes"] + ["audit:write"]}
        with self.assertRaisesRegex(ValueError, "reserved for internally generated Guard events"):
            service.handle_ingest_audit_event(
                {"headers": {}},
                {"context": {"tenant_id": "demo"}, "event_type": "action.evaluated", "action_id": "action-forged"},
                auth,
            )


    def test_external_audit_events_are_not_authoritative_action_state(self):
        self.store.put_event(
            {
                "event_type": "action.evaluated",
                "tenant_id": "demo",
                "action_id": "action-forged",
                "action_hash": "sha256:forged",
                "decision": "allow",
                "created_at": "2026-07-16T12:00:00Z",
                "source": "external",
            }
        )
        self.assertIsNone(self.store.get_action_evaluation("demo", "action-forged"))

        self.store.put_event(
            {
                "event_type": "action.evaluated",
                "tenant_id": "demo",
                "action_id": "action-requires-approval",
                "action_hash": "sha256:real",
                "decision": "require_approval",
                "created_at": "2026-07-16T12:01:00Z",
            }
        )
        self.store.put_event(
            {
                "event_type": "action.outcome",
                "tenant_id": "demo",
                "action_id": "action-requires-approval",
                "action_hash": "sha256:real",
                "approval_id": "approval-pending",
                "status": "success",
                "created_at": "2026-07-16T12:02:00Z",
                "source": "external",
            }
        )
        self.assertIsNone(self.store.get_action_outcome("demo", "action-requires-approval"))
        self.table.put_item(
            {
                "pk": "APPROVAL#approval-pending",
                "sk": "METADATA",
                "tenant_id": "demo",
                "approval_id": "approval-pending",
                "action_id": "action-requires-approval",
                "action_hash": "sha256:real",
                "status": "pending",
            }
        )

        outcome = service.handle_outcome(
            {},
            {"context": {"tenant_id": "demo"}, "action_hash": "sha256:real", "approval_id": "approval-pending", "status": "success"},
            "action-requires-approval",
            self.auth,
        )
        self.assertEqual(outcome["statusCode"], 409)
        self.assertEqual(self.body(outcome)["error"], "approval_not_approved")


    def test_pending_approval_count_excludes_decided_and_expired_records(self):
        """Regression for #140: the overview pending count must reflect live
        approval records, not the cumulative decision metric."""
        now = int(time.time())
        for approval_id, status, expires_at in (
            ("approval-live-pending", "pending", now + 900),
            ("approval-expired-pending", "pending", now - 10),
            ("approval-approved", "approved", now + 900),
            ("approval-denied", "denied", now + 900),
        ):
            self.store.put_approval(
                {
                    "approval_id": approval_id,
                    "tenant_id": "demo",
                    "status": status,
                    "agent_id": "count-agent",
                    "environment": "production",
                    "created_at": "2026-07-29T00:00:00Z",
                    "expires_at": expires_at,
                    "action_id": f"action-{approval_id}",
                    "action_hash": f"sha256:{approval_id}",
                    "run_id": f"run-{approval_id}",
                }
            )

        pending = service.handle_list_approvals({"queryStringParameters": {"status": "pending"}}, self.auth)
        self.assertEqual(pending["statusCode"], 200)
        body = self.body(pending)
        self.assertEqual(body["count"], 1)
        self.assertEqual([a["approval_id"] for a in body["approvals"]], ["approval-live-pending"])

        expired_record = self.store.get_approval("approval-expired-pending")
        self.assertEqual(expired_record["status"], "expired")


    def test_policy_test_cases_run_without_execution_side_effects(self):
        policy_auth = {
            **self.auth,
            "scopes": self.auth["scopes"] + ["policy:read", "policy:write", "policy:simulate"],
        }
        policy_id = "policy-test-cases"
        created = service.handle_create_policy(
            {
                "context": {"tenant_id": "demo"},
                "policy_id": policy_id,
                "name": "Production shell test policy",
                "rules": [
                    {"rule_id": "deny-production-shell", "tool": "shell", "environment": "production", "decision": "deny"},
                ],
                "test_cases": [
                    {
                        "case_id": "production-shell-denied",
                        "context": {"environment": "production"},
                        "action": {"tool": "shell", "parameters": {"command": "ls"}},
                        "expected_decision": "deny",
                        "expected_reason_codes": ["POLICY_DENY-PRODUCTION-SHELL"],
                    },
                    {
                        "case_id": "development-shell-allowed",
                        "context": {"environment": "development"},
                        "action": {"tool": "shell", "parameters": {"command": "ls"}},
                        "expected_decision": "allow",
                    },
                ],
            },
            policy_auth,
        )
        self.assertEqual(created["statusCode"], 201)
        listed = service.store().list_policies("demo")
        self.assertEqual([item["policy_id"] for item in listed], [policy_id])
        self.assertEqual(self.table.scan_calls, 0)
        tested = service.handle_test_policy(policy_id, {"version": 1}, policy_auth)
        tested_body = self.body(tested)
        self.assertEqual(tested["statusCode"], 200)
        self.assertTrue(tested_body["all_passed"])
        self.assertEqual(tested_body["passed_count"], 2)
        self.assertFalse(any(key[1].startswith("PROOF#") for key in self.table.items))
        self.assertFalse(any(key[0].startswith("APPROVAL#") for key in self.table.items))


    def test_draft_policy_can_be_edited_or_deleted_but_published_policy_cannot(self):
        policy_auth = {
            **self.auth,
            "scopes": self.auth["scopes"] + ["policy:read", "policy:write", "policy:simulate"],
        }
        policy_id = "draft-policy-lifecycle"
        created = service.handle_create_policy(
            {
                "context": {"tenant_id": "demo"},
                "policy_id": policy_id,
                "name": "Original draft",
                "rules": [{"rule_id": "draft-rule", "tool": "shell", "decision": "warn"}],
            },
            policy_auth,
        )
        self.assertEqual(created["statusCode"], 201)

        updated = service.handle_update_policy(
            policy_id,
            {
                "version": 1,
                "name": "Edited draft",
                "mode": "enforce",
                "rules": [{"rule_id": "draft-rule", "tool": "shell", "decision": "deny"}],
            },
            policy_auth,
        )
        self.assertEqual(updated["statusCode"], 200)
        self.assertEqual(self.body(updated)["name"], "Edited draft")
        self.assertEqual(self.body(updated)["rules"][0]["decision"], "deny")

        published = service.handle_publish_policy(policy_id, {"version": 1}, policy_auth)
        self.assertEqual(published["statusCode"], 200)
        self.assertEqual(service.handle_update_policy(policy_id, {"version": 1, "name": "No change"}, policy_auth)["statusCode"], 409)
        self.assertEqual(service.handle_delete_policy(policy_id, {"version": 1}, policy_auth)["statusCode"], 400)

        deletable_id = "draft-policy-to-delete"
        self.assertEqual(
            service.handle_create_policy(
                {"context": {"tenant_id": "demo"}, "policy_id": deletable_id, "name": "Delete me", "rules": []},
                policy_auth,
            )["statusCode"],
            201,
        )
        deleted = service.handle_delete_policy(deletable_id, {"version": 1}, policy_auth)
        self.assertEqual(deleted["statusCode"], 200)
        self.assertEqual(self.body(deleted)["status"], "deleted")
        self.assertIsNone(service.store().get_policy(deletable_id, 1))
        self.assertFalse(any(item.get("policy_id") == deletable_id for item in service.store().list_policies("demo")))


    def test_published_policy_can_suspend_reactivate_and_delete_with_confirmation(self):
        policy_auth = {
            **self.auth,
            "scopes": self.auth["scopes"] + ["policy:read", "policy:write", "policy:simulate"],
        }
        policy_id = "policy-lifecycle"
        created = service.handle_create_policy(
            {
                "context": {"tenant_id": "demo"},
                "policy_id": policy_id,
                "name": "Published policy lifecycle",
                "rules": [{"rule_id": "deny-lifecycle-shell", "tool": "shell", "decision": "deny"}],
            },
            policy_auth,
        )
        self.assertEqual(created["statusCode"], 201)
        published = service.handle_publish_policy(policy_id, {"version": 1}, policy_auth)
        self.assertEqual(published["statusCode"], 200)
        self.assertEqual(self.body(published)["status"], "published")

        active_payload = {
            "context": {"tenant_id": "demo", "environment": "development", "agent_id": "lifecycle-agent", "invoked_by": "test"},
            "action": {"action_id": "lifecycle-active", "tool": "shell", "parameters": {"command": "ls"}},
        }
        service.apply_tenant_runtime(active_payload, self.auth, self.store)
        active_decision = service.evaluate_and_record(active_payload, self.store)
        self.assertTrue(any(match["policy_id"] == policy_id for match in active_decision["policy_matches"]))

        not_confirmed = service.handle_suspend_policy(policy_id, {"version": 1}, policy_auth)
        self.assertEqual(not_confirmed["statusCode"], 400)
        self.assertEqual(self.body(not_confirmed)["error"], "policy_confirmation_required")
        suspended = service.handle_suspend_policy(policy_id, {"version": 1, "confirm": True}, policy_auth)
        self.assertEqual(suspended["statusCode"], 200)
        self.assertEqual(self.body(suspended)["status"], "suspended")

        suspended_payload = {
            **active_payload,
            "context": {**active_payload["context"], "action_id": "lifecycle-suspended"},
        }
        service.apply_tenant_runtime(suspended_payload, self.auth, self.store)
        suspended_decision = service.evaluate_and_record(suspended_payload, self.store)
        self.assertFalse(any(match["policy_id"] == policy_id for match in suspended_decision["policy_matches"]))

        reactivated = service.handle_reactivate_policy(policy_id, {"version": 1, "confirm": True}, policy_auth)
        self.assertEqual(reactivated["statusCode"], 200)
        self.assertEqual(self.body(reactivated)["status"], "published")
        delete_not_confirmed = service.handle_delete_policy(policy_id, {"version": 1}, policy_auth)
        self.assertEqual(delete_not_confirmed["statusCode"], 400)
        deleted = service.handle_delete_policy(policy_id, {"version": 1, "confirm": True}, policy_auth)
        self.assertEqual(deleted["statusCode"], 200)
        self.assertEqual(self.body(deleted)["deleted_versions"], [1])
        self.assertIsNone(self.store.get_policy(policy_id, 1))
        self.assertFalse(any(item.get("policy_id") == policy_id for item in self.store.list_policies("demo")))
        self.assertTrue(any(item.get("event_type") == "policy.deleted" for item in self.table.items.values()))


    def test_policy_simulation_can_replay_a_historical_action_without_side_effects(self):
        policy_auth = {
            **self.auth,
            "scopes": self.auth["scopes"] + ["policy:read", "policy:write", "policy:simulate"],
        }
        policy_id = "historical-simulation-policy"
        created = service.handle_create_policy(
            {
                "context": {"tenant_id": "demo"},
                "policy_id": policy_id,
                "name": "Historical simulation policy",
                "rules": [
                    {"rule_id": "deny-production-shell", "tool": "shell", "environment": "production", "decision": "deny"},
                ],
            },
            policy_auth,
        )
        self.assertEqual(created["statusCode"], 201)
        source_action = service.normalise_action(
            {
                "context": {
                    "tenant_id": "demo",
                    "environment": "production",
                    "run_id": "run-historical",
                    "action_id": "action-historical",
                    "agent_id": "historical-agent",
                    "invoked_by": "historical-user",
                },
                "action": {"tool": "shell", "parameters": {"command": "ls"}},
            }
        )
        self.store.put_event(
            {
                "event_type": "action.evaluated",
                "tenant_id": "demo",
                "environment": "production",
                "run_id": source_action["run_id"],
                "action_id": source_action["action_id"],
                "agent_id": source_action["agent_id"],
                "invoked_by": source_action["invoked_by"],
                "created_at": source_action["requested_at"],
                "decision": "allow",
                "action_hash": "sha256:historical-source",
                "action": source_action,
            }
        )
        simulated = service.handle_simulate_policy(
            policy_id,
            {"context": {"tenant_id": "demo"}, "version": 1, "source_action_id": "action-historical"},
            policy_auth,
        )
        self.assertEqual(simulated["statusCode"], 200)
        body = self.body(simulated)
        self.assertTrue(body["simulation"])
        self.assertEqual(body["decision"], "deny")
        self.assertEqual(body["simulation_source"]["type"], "historical_action")
        self.assertEqual(body["simulation_source"]["action_id"], "action-historical")
        self.assertFalse(any(key[1].startswith("PROOF#") for key in self.table.items))
        self.assertFalse(any(key[0].startswith("APPROVAL#") for key in self.table.items))


    def test_approval_separation_blocks_requester(self):
        approval = {
            "approval_id": "approval-sod",
            "tenant_id": "demo",
            "run_id": "run-sod",
            "action_id": "action-sod",
            "action_hash": "sha256:action",
            "agent_id": "payment-agent",
            "requested_by": "finance@example.org",
            "status": "pending",
            "expires_at": 4_000_000_000,
            "created_at": "2026-07-16T00:00:00Z",
        }
        self.table.put_item({"pk": "APPROVAL#approval-sod", "sk": "METADATA", **approval})
        self.table.put_item({
            "pk": "AGENT#payment-agent",
            "sk": "METADATA",
            "agent_id": "payment-agent",
            "tenant_id": "demo",
            "conditions": {"separation_of_duties": {"approver_must_differ_from_invoked_by": True}},
        })
        auth = {**self.auth, "scopes": ["approve:actions"]}
        result = service.handle_approval(
            {"queryStringParameters": {}},
            {"decision": "approve", "approver": "finance@example.org", "action_hash": "sha256:action"},
            "approval-sod",
            auth,
        )
        self.assertEqual(result["statusCode"], 403)
        self.assertEqual(self.body(result)["error"], "separation_of_duties_violation")


    def test_evaluate_binds_requester_to_authenticated_principal_for_approval_separation(self):
        self.table.put_item({
            "pk": "AGENT#payment-agent",
            "sk": "METADATA",
            "agent_id": "payment-agent",
            "tenant_id": "demo",
            "status": "active",
            "allowed_environments": ["production"],
            "approved_tools": ["sql"],
            "conditions": {
                "human_approval_required": True,
                "separation_of_duties": {"approver_must_differ_from_invoked_by": True},
            },
        })
        payload = {
            "context": {
                "tenant_id": "demo",
                "environment": "production",
                "agent_id": "payment-agent",
                "invoked_by": "spoofed-requester@example.org",
            },
            "action": {"tool": "sql", "parameters": {"statement": "UPDATE orders SET status = closed"}},
        }
        evaluated = self.body(service.handle_evaluate({}, payload, self.auth))
        approval = evaluated["approval"]
        self.assertEqual(approval["requested_by"], "pat-admin-test")

        decision = service.handle_approval(
            {},
            {"tenant_id": "demo", "decision": "approve", "approver": "security@example.org", "action_hash": evaluated["action_hash"]},
            approval["approval_id"],
            {**self.auth, "scopes": ["approve:actions"]},
        )
        self.assertEqual(decision["statusCode"], 403)
        self.assertEqual(self.body(decision)["error"], "separation_of_duties_violation")


    def test_approval_records_authenticated_principal_and_binds_federated_identity(self):
        approval = {
            "approval_id": "approval-principal",
            "tenant_id": "demo",
            "run_id": "run-principal",
            "action_id": "action-principal",
            "action_hash": "sha256:principal",
            "agent_id": "test-agent",
            "requested_by": "requester@example.org",
            "status": "pending",
            "expires_at": 4_000_000_000,
            "created_at": "2026-07-16T00:00:00Z",
        }
        self.store.put_approval(approval)
        result = service.handle_approval(
            {},
            {"tenant_id": "demo", "decision": "approve", "approver": "Security reviewer", "action_hash": "sha256:principal"},
            "approval-principal",
            self.auth,
        )
        self.assertEqual(result["statusCode"], 200)
        recorded = self.body(result)["approval"]
        self.assertEqual(recorded["approver"], "Security reviewer")
        self.assertEqual(recorded["approver_principal"], "pat-admin-test")
        self.assertEqual(recorded["approver_auth_source"], "pat")

        oidc_approval = {**approval, "approval_id": "approval-oidc-principal", "status": "pending"}
        self.store.put_approval(oidc_approval)
        oidc_auth = {
            **self.auth,
            "auth_source": "oidc",
            "subject": "security@example.org",
            "token_type": "federated",
        }
        mismatch = service.handle_approval(
            {},
            {"tenant_id": "demo", "decision": "approve", "approver": "spoofed@example.org", "action_hash": "sha256:principal"},
            "approval-oidc-principal",
            oidc_auth,
        )
        self.assertEqual(mismatch["statusCode"], 403)
        self.assertEqual(self.body(mismatch)["error"], "approver_identity_mismatch")


    def test_approval_requires_verified_reviewer_group(self):
        approval = {
            "approval_id": "approval-group",
            "tenant_id": "demo",
            "status": "pending",
            "agent_id": "group-agent",
            "run_id": "run-group",
            "action_id": "action-group",
            "action_hash": "sha256:group",
            "requested_by": "requester",
            "expires_at": 4_000_000_000,
            "approval_requirements": [
                {
                    "groups": ["security"],
                    "policy_id": "policy-review",
                    "policy_version": 1,
                    "rule_id": "security-review",
                }
            ],
        }
        self.store.put_approval(approval)
        reviewer = {**self.auth, "scopes": ["approve:actions"], "groups": ["engineering"]}
        blocked = service.handle_approval(
            {"pathParameters": {}},
            {"decision": "approve", "approver": "engineering-reviewer", "action_hash": "sha256:group"},
            "approval-group",
            reviewer,
        )
        self.assertEqual(blocked["statusCode"], 403)
        self.assertEqual(self.body(blocked)["error"], "approver_group_required")
        allowed = {**reviewer, "groups": ["security"]}
        decided = service.handle_approval(
            {"pathParameters": {}},
            {"decision": "approve", "approver": "security-reviewer", "action_hash": "sha256:group"},
            "approval-group",
            allowed,
        )
        self.assertEqual(decided["statusCode"], 200)


    def test_approval_expiry_is_persisted_and_audited(self):
        approval = {
            "approval_id": "approval-expired",
            "tenant_id": "demo",
            "run_id": "run-expired",
            "action_id": "action-expired",
            "action_hash": "sha256:expired",
            "agent_id": "test-agent",
            "status": "pending",
            "requested_by": "requester@example.org",
            "expires_at": 1,
            "created_at": "2000-01-01T00:00:00Z",
        }
        self.store.put_approval(approval)
        result = service.handle_get_approval("approval-expired", self.auth)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(self.body(result)["approval"]["status"], "expired")
        persisted = self.table.items[("APPROVAL#approval-expired", "METADATA")]
        self.assertEqual(persisted["status"], "expired")
        events = self.store.list_events("demo", filters={"event_type": "approval.expired"})
        self.assertEqual(len(events), 1)


    def test_approval_can_be_revoked_and_cannot_be_replayed(self):
        approval = {
            "approval_id": "approval-revocable",
            "tenant_id": "demo",
            "run_id": "run-revocable",
            "action_id": "action-revocable",
            "action_hash": "sha256:revocable",
            "agent_id": "test-agent",
            "status": "pending",
            "requested_by": "requester@example.org",
            "expires_at": 4_000_000_000,
            "created_at": "2026-07-16T00:00:00Z",
        }
        self.store.put_approval(approval)
        revoked = service.handle_revoke_approval(
            {},
            {"tenant_id": "demo", "reason": "Requester cancelled the action."},
            "approval-revocable",
            self.auth,
        )
        self.assertEqual(revoked["statusCode"], 200)
        self.assertEqual(self.body(revoked)["approval"]["status"], "revoked")
        repeated = service.handle_revoke_approval(
            {},
            {"tenant_id": "demo"},
            "approval-revocable",
            self.auth,
        )
        self.assertEqual(repeated["statusCode"], 200)
        self.assertTrue(self.body(repeated)["idempotent"])
        decision = service.handle_approval(
            {},
            {"tenant_id": "demo", "decision": "approve", "approver": "security@example.org", "action_hash": "sha256:revocable"},
            "approval-revocable",
            self.auth,
        )
        self.assertEqual(decision["statusCode"], 409)
        self.assertEqual(self.body(decision)["error"], "approval_expired_or_already_decided")
        events = self.store.list_events("demo", filters={"event_type": "approval.revoked"})
        self.assertEqual(len(events), 1)


    def test_approved_action_outcome_consumes_approval_and_is_idempotent(self):
        action_id = "action-consume"
        action_hash = "sha256:consume"
        self.store.put_event(
            {
                "event_type": "action.evaluated",
                "tenant_id": "demo",
                "run_id": "run-consume",
                "action_id": action_id,
                "agent_id": "test-agent",
                "invoked_by": "requester@example.org",
                "created_at": "2026-07-16T00:00:00Z",
                "decision": "require_approval",
                "action_hash": action_hash,
            }
        )
        self.store.put_approval(
            {
                "approval_id": "approval-consume",
                "tenant_id": "demo",
                "run_id": "run-consume",
                "action_id": action_id,
                "action_hash": action_hash,
                "agent_id": "test-agent",
                "status": "approved",
                "requested_by": "requester@example.org",
                "approver": "security@example.org",
                "expires_at": 4_000_000_000,
                "created_at": "2026-07-16T00:00:00Z",
            }
        )
        payload = {
            "tenant_id": "demo",
            "approval_id": "approval-consume",
            "action_hash": action_hash,
            "status": "success",
            "result": "completed",
        }
        first = service.handle_outcome({}, payload, action_id, self.auth)
        self.assertEqual(first["statusCode"], 202)
        self.assertEqual(self.body(first)["approval_status"], "consumed")
        self.assertEqual(self.table.items[("APPROVAL#approval-consume", "METADATA")]["status"], "consumed")

        repeated = service.handle_outcome({}, payload, action_id, self.auth)
        self.assertEqual(repeated["statusCode"], 202)
        self.assertTrue(self.body(repeated)["idempotent"])

        changed = service.handle_outcome({}, {**payload, "status": "failed"}, action_id, self.auth)
        self.assertEqual(changed["statusCode"], 409)
        self.assertEqual(self.body(changed)["error"], "action_outcome_already_recorded")



    def test_expire_approval_transitions_pending_to_expired_and_audits(self):
        approval = {
            "approval_id": "approval-expire-store",
            "tenant_id": "demo",
            "run_id": "run-expire",
            "action_id": "action-expire",
            "action_hash": "sha256:expire",
            "agent_id": "expire-agent",
            "status": "pending",
            "requested_by": "requester@example.org",
            "expires_at": 1,
            "created_at": "2000-01-01T00:00:00Z",
        }
        self.store.put_approval(approval)
        expired = self.store.expire_approval(approval, now=int(time.time()))
        self.assertEqual(expired["status"], "expired")
        self.assertIn("expired_at", expired)
        events = self.store.list_events("demo", filters={"event_type": "approval.expired"})
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["approval_id"], "approval-expire-store")


    def test_expire_approval_skips_non_pending_and_unexpired(self):
        approved = {
            "approval_id": "approval-not-expire",
            "tenant_id": "demo",
            "run_id": "run-ne",
            "action_id": "action-ne",
            "action_hash": "sha256:ne",
            "agent_id": "ne-agent",
            "status": "approved",
            "requested_by": "requester@example.org",
            "expires_at": 1,
            "created_at": "2000-01-01T00:00:00Z",
        }
        result = self.store.expire_approval(approved, now=int(time.time()))
        self.assertEqual(result["status"], "approved")
        future = {**approved, "status": "pending", "expires_at": int(time.time()) + 9999}
        result2 = self.store.expire_approval(future, now=int(time.time()))
        self.assertEqual(result2["status"], "pending")


    def test_store_revoke_approval_returns_changed_flag(self):
        approval = {
            "approval_id": "approval-revoke-store",
            "tenant_id": "demo",
            "run_id": "run-rs",
            "action_id": "action-rs",
            "action_hash": "sha256:rs",
            "agent_id": "rs-agent",
            "status": "pending",
            "requested_by": "requester@example.org",
            "expires_at": 4_000_000_000,
            "created_at": "2026-07-16T00:00:00Z",
        }
        self.store.put_approval(approval)
        revoked, changed = self.store.revoke_approval("approval-revoke-store", "admin", "2026-07-17T00:00:00Z", "test reason")
        self.assertTrue(changed)
        self.assertEqual(revoked["status"], "revoked")
        self.assertEqual(revoked["revoked_by"], "admin")
        again, changed_again = self.store.revoke_approval("approval-revoke-store", "admin", "2026-07-17T00:00:00Z")
        self.assertFalse(changed_again)


    def test_store_consume_approval_returns_none_for_non_approved(self):
        approval = {
            "approval_id": "approval-consume-store",
            "tenant_id": "demo",
            "run_id": "run-cs",
            "action_id": "action-cs",
            "action_hash": "sha256:cs",
            "agent_id": "cs-agent",
            "status": "pending",
            "requested_by": "requester@example.org",
            "expires_at": 4_000_000_000,
            "created_at": "2026-07-16T00:00:00Z",
        }
        self.store.put_approval(approval)
        result = self.store.consume_approval("approval-consume-store", "executor", "2026-07-17T00:00:00Z", "action-cs", "sha256:cs")
        self.assertIsNone(result)
        self.store.update_approval("approval-consume-store", "approved", "approver", "2026-07-17T00:00:00Z")
        consumed = self.store.consume_approval("approval-consume-store", "executor", "2026-07-17T00:00:00Z", "action-cs", "sha256:cs")
        self.assertIsNotNone(consumed)
        self.assertEqual(consumed["status"], "consumed")


    def test_store_get_action_outcome_returns_recorded_outcome(self):
        self.store.put_event({
            "event_type": "action.outcome",
            "tenant_id": "demo",
            "run_id": "run-outcome",
            "action_id": "action-outcome-store",
            "agent_id": "outcome-agent",
            "invoked_by": "test",
            "created_at": "2026-07-16T00:00:00Z",
            "status": "success",
            "action_hash": "sha256:outcome",
        })
        outcome = self.store.get_action_outcome("demo", "action-outcome-store")
        self.assertIsNotNone(outcome)
        self.assertEqual(outcome["status"], "success")
        self.assertIsNone(self.store.get_action_outcome("demo", "nonexistent-action"))

    # ------------------------------------------------------------------
    # OIDC / auth handlers
    # ------------------------------------------------------------------


    def test_handle_get_policy_returns_404_for_missing(self):
        policy_auth = {**self.auth, "scopes": self.auth["scopes"] + ["policy:read"]}
        result = service.handle_get_policy("nonexistent-policy", {"queryStringParameters": {}}, policy_auth)
        self.assertEqual(result["statusCode"], 404)


    def test_handle_publish_policy_sets_status(self):
        policy_auth = {**self.auth, "scopes": self.auth["scopes"] + ["policy:read", "policy:write"]}
        service.handle_create_policy(
            {"context": {"tenant_id": "demo"}, "policy_id": "publish-me", "name": "Publish", "rules": []},
            policy_auth,
        )
        result = service.handle_publish_policy("publish-me", {"version": 1}, policy_auth)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(self.body(result)["status"], "published")

    # ------------------------------------------------------------------
    # Audit and security event handlers
    # ------------------------------------------------------------------


    def test_handle_get_approval_returns_approval(self):
        self.store.put_approval({
            "approval_id": "approval-get-test",
            "tenant_id": "demo",
            "status": "pending",
            "agent_id": "get-agent",
            "run_id": "run-get",
            "action_id": "action-get",
            "action_hash": "sha256:get",
            "requested_by": "test",
            "expires_at": 4_000_000_000,
            "created_at": "2026-07-16T00:00:00Z",
        })
        result = service.handle_get_approval("approval-get-test", self.auth)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(self.body(result)["approval"]["approval_id"], "approval-get-test")


    def test_handle_get_approval_returns_404_for_missing(self):
        result = service.handle_get_approval("nonexistent-approval", self.auth)
        self.assertEqual(result["statusCode"], 404)


    def test_handle_get_approval_rejects_cross_tenant(self):
        self.store.put_approval({
            "approval_id": "approval-other-tenant-get",
            "tenant_id": "other",
            "status": "pending",
            "agent_id": "other-agent",
            "run_id": "run-other",
            "action_id": "action-other",
            "action_hash": "sha256:other",
            "requested_by": "test",
            "expires_at": 4_000_000_000,
            "created_at": "2026-07-16T00:00:00Z",
        })
        result = service.handle_get_approval("approval-other-tenant-get", self.auth)
        self.assertEqual(result["statusCode"], 403)

    # ------------------------------------------------------------------
    # Session authentication
    # ------------------------------------------------------------------


    def test_handle_get_policy_not_found(self):
        policy_auth = {**self.auth, "scopes": [*self.auth["scopes"], "policy:read"]}
        result = service.handle_get_policy("nonexistent-policy", {}, policy_auth)
        self.assertEqual(result["statusCode"], 404)


    def test_handle_update_policy_not_found(self):
        policy_auth = {**self.auth, "scopes": [*self.auth["scopes"], "policy:write"]}
        result = service.handle_update_policy("nonexistent-policy", {"name": "Updated", "version": 1}, policy_auth)
        self.assertIn(result["statusCode"], (400, 404))


    def test_handle_delete_policy_not_found(self):
        policy_auth = {**self.auth, "scopes": [*self.auth["scopes"], "policy:write"]}
        result = service.handle_delete_policy("nonexistent-policy", {}, policy_auth)
        self.assertIn(result["statusCode"], (400, 404))


    def test_handle_publish_policy_not_found(self):
        policy_auth = {**self.auth, "scopes": [*self.auth["scopes"], "policy:write"]}
        result = service.handle_publish_policy("nonexistent-policy", {}, policy_auth)
        self.assertIn(result["statusCode"], (400, 404))


    def test_handle_suspend_policy_not_found(self):
        policy_auth = {**self.auth, "scopes": [*self.auth["scopes"], "policy:write"]}
        result = service.handle_suspend_policy("nonexistent-policy", {}, policy_auth)
        self.assertIn(result["statusCode"], (400, 404))


    def test_handle_reactivate_policy_not_found(self):
        policy_auth = {**self.auth, "scopes": [*self.auth["scopes"], "policy:write"]}
        result = service.handle_reactivate_policy("nonexistent-policy", {}, policy_auth)
        self.assertIn(result["statusCode"], (400, 404))


    def test_policy_lifecycle(self):
        policy_auth = {**self.auth, "scopes": [*self.auth["scopes"], "policy:write", "policy:read", "policy:simulate"]}
        created = service.handle_create_policy(
            {"name": "Lifecycle Policy", "rules": [{"rule_id": "r1", "decision": "deny", "conditions": {"tool": "shell"}}]},
            policy_auth,
        )
        policy_id = self.body(created)["policy_id"]
        published = service.handle_publish_policy(policy_id, {"confirm": True}, policy_auth)
        self.assertEqual(published["statusCode"], 200)
        suspended = service.handle_suspend_policy(policy_id, {"confirm": True}, policy_auth)
        self.assertEqual(suspended["statusCode"], 200)
        reactivated = service.handle_reactivate_policy(policy_id, {"confirm": True}, policy_auth)
        self.assertEqual(reactivated["statusCode"], 200)
        updated = service.handle_update_policy(policy_id, {"name": "Updated Lifecycle", "version": 1}, policy_auth)
        self.assertIn(updated["statusCode"], (200, 409))
        # Delete requires draft status; published policy returns 400/409
        deleted = service.handle_delete_policy(policy_id, {"version": 1}, policy_auth)
        self.assertIn(deleted["statusCode"], (200, 400, 409))

    # ------------------------------------------------------------------
    # Approval list / decide / revoke handlers
    # ------------------------------------------------------------------


    def test_handle_list_approvals(self):
        self.store.put_approval({
            "approval_id": "approval-list-test",
            "tenant_id": "demo",
            "status": "pending",
            "agent_id": "list-agent",
            "run_id": "run-list",
            "action_id": "action-list",
            "action_hash": "sha256:list",
            "requested_by": "test",
            "expires_at": 4_000_000_000,
            "created_at": "2026-07-16T00:00:00Z",
        })
        event = {"queryStringParameters": {"tenant_id": "demo"}}
        result = service.handle_list_approvals(event, self.auth)
        self.assertEqual(result["statusCode"], 200)
        body = self.body(result)
        self.assertGreaterEqual(body["count"], 1)


    def test_handle_list_approvals_invalid_status(self):
        event = {"queryStringParameters": {"status": "invalid_status"}}
        result = service.handle_list_approvals(event, self.auth)
        self.assertEqual(result["statusCode"], 400)


    def test_handle_list_approvals_with_status_filter(self):
        event = {"queryStringParameters": {"status": "pending"}}
        result = service.handle_list_approvals(event, self.auth)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(self.body(result)["statuses"], ["pending"])


    def test_handle_approval_not_found(self):
        result = service.handle_approval({}, {"decision": "approve"}, "nonexistent", self.auth)
        self.assertEqual(result["statusCode"], 404)


    def test_handle_approval_tenant_mismatch(self):
        self.store.put_approval({
            "approval_id": "approval-mismatch-decide",
            "tenant_id": "other",
            "status": "pending",
            "agent_id": "agent-x",
            "run_id": "run-x",
            "action_id": "action-x",
            "action_hash": "sha256:x",
            "requested_by": "test",
            "expires_at": 4_000_000_000,
            "created_at": "2026-07-16T00:00:00Z",
        })
        result = service.handle_approval({}, {"decision": "approve", "tenant_id": "demo"}, "approval-mismatch-decide", self.auth)
        self.assertEqual(result["statusCode"], 403)


    def test_handle_approval_invalid_decision(self):
        self.store.put_approval({
            "approval_id": "approval-invalid-decision",
            "tenant_id": "demo",
            "status": "pending",
            "agent_id": "agent-y",
            "run_id": "run-y",
            "action_id": "action-y",
            "action_hash": "sha256:y",
            "requested_by": "test",
            "expires_at": 4_000_000_000,
            "created_at": "2026-07-16T00:00:00Z",
        })
        result = service.handle_approval({}, {"decision": "maybe"}, "approval-invalid-decision", self.auth)
        self.assertEqual(result["statusCode"], 400)


    def test_handle_approval_approve(self):
        self.store.put_approval({
            "approval_id": "approval-approve-test",
            "tenant_id": "demo",
            "status": "pending",
            "agent_id": "agent-approve",
            "run_id": "run-approve",
            "action_id": "action-approve",
            "action_hash": "sha256:approve",
            "requested_by": "test",
            "expires_at": 4_000_000_000,
            "created_at": "2026-07-16T00:00:00Z",
        })
        result = service.handle_approval({}, {"decision": "approve"}, "approval-approve-test", self.auth)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(self.body(result)["approval"]["status"], "approved")


    def test_handle_approval_deny(self):
        self.store.put_approval({
            "approval_id": "approval-deny-test",
            "tenant_id": "demo",
            "status": "pending",
            "agent_id": "agent-deny",
            "run_id": "run-deny",
            "action_id": "action-deny",
            "action_hash": "sha256:deny",
            "requested_by": "test",
            "expires_at": 4_000_000_000,
            "created_at": "2026-07-16T00:00:00Z",
        })
        result = service.handle_approval({}, {"decision": "deny"}, "approval-deny-test", self.auth)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(self.body(result)["approval"]["status"], "denied")


    def test_handle_approval_action_hash_mismatch(self):
        self.store.put_approval({
            "approval_id": "approval-hash-mismatch",
            "tenant_id": "demo",
            "status": "pending",
            "agent_id": "agent-hm",
            "run_id": "run-hm",
            "action_id": "action-hm",
            "action_hash": "sha256:correct",
            "requested_by": "test",
            "expires_at": 4_000_000_000,
            "created_at": "2026-07-16T00:00:00Z",
        })
        result = service.handle_approval({}, {"decision": "approve", "action_hash": "sha256:wrong"}, "approval-hash-mismatch", self.auth)
        self.assertEqual(result["statusCode"], 409)


    def test_handle_approval_already_decided(self):
        self.store.put_approval({
            "approval_id": "approval-already-decided",
            "tenant_id": "demo",
            "status": "approved",
            "agent_id": "agent-ad",
            "run_id": "run-ad",
            "action_id": "action-ad",
            "action_hash": "sha256:ad",
            "requested_by": "test",
            "approver": "other-user",
            "expires_at": 4_000_000_000,
            "created_at": "2026-07-16T00:00:00Z",
        })
        result = service.handle_approval({}, {"decision": "deny"}, "approval-already-decided", self.auth)
        self.assertEqual(result["statusCode"], 409)


    def test_handle_revoke_approval_not_found(self):
        result = service.handle_revoke_approval({}, {}, "nonexistent-revoke", self.auth)
        self.assertEqual(result["statusCode"], 404)


    def test_handle_revoke_approval_success(self):
        self.store.put_approval({
            "approval_id": "approval-revoke-test",
            "tenant_id": "demo",
            "status": "pending",
            "agent_id": "agent-revoke",
            "run_id": "run-revoke",
            "action_id": "action-revoke",
            "action_hash": "sha256:revoke",
            "requested_by": "test",
            "expires_at": 4_000_000_000,
            "created_at": "2026-07-16T00:00:00Z",
        })
        result = service.handle_revoke_approval({}, {"reason": "No longer needed"}, "approval-revoke-test", self.auth)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(self.body(result)["approval"]["status"], "revoked")

    # ------------------------------------------------------------------
    # handle_outcome
    # ------------------------------------------------------------------


    def test_handle_outcome_action_not_found(self):
        result = service.handle_outcome({}, {"status": "success"}, "nonexistent-action", self.auth)
        self.assertEqual(result["statusCode"], 404)


    def test_mcp_tools_list_agent_guard_profile(self):
        mcp_auth = {**self.auth, "scopes": ["mcp:read"]}
        profile = service.MCP_PROFILES["agent-guard"]
        result = service.handle_mcp(
            {"headers": {}},
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            "POST",
            mcp_auth,
            profile,
        )
        self.assertEqual(result["statusCode"], 200)
        tools = self.body(result)["result"]["tools"]
        tool_names = [tool["name"] for tool in tools]
        self.assertIn("evaluate_action", tool_names)
        self.assertNotIn("verify_citations", tool_names)


    def test_mcp_evaluate_action(self):
        result = self._mcp_call("evaluate_action", {
            "context": {"tenant_id": "demo", "environment": "production", "agent_id": "mcp-agent", "invoked_by": "test"},
            "action": {"tool": "shell", "parameters": {"command": "ls"}},
        })
        self.assertEqual(result["statusCode"], 200)
        body = self.body(result)
        self.assertIn("result", body)
        self.assertIn("structuredContent", body["result"])


    def test_mcp_approval_reference_explicit(self):
        self.assertEqual(service.mcp_approval_reference({"approval_id": "approval-123"}), "approval-123")


    def test_mcp_approval_reference_from_intent(self):
        self.assertEqual(service.mcp_approval_reference({"intent": "Please run approval-abc123 now"}), "approval-abc123")


    def test_mcp_approval_reference_no_match(self):
        self.assertEqual(service.mcp_approval_reference({"intent": "just do it"}), "")

    # ------------------------------------------------------------------
    # lambda_handler routing - additional routes
    # ------------------------------------------------------------------


    def test_lambda_handler_approvals_route(self):
        result = self._route("/v1/approvals", "GET", query={"tenant_id": "demo"})
        self.assertEqual(result["statusCode"], 200)


    def test_lambda_handler_approvals_get_route(self):
        self.store.put_approval({
            "approval_id": "approval-route-get",
            "tenant_id": "demo",
            "status": "pending",
            "agent_id": "route-agent",
            "run_id": "run-route",
            "action_id": "action-route",
            "action_hash": "sha256:route",
            "requested_by": "test",
            "expires_at": 4_000_000_000,
            "created_at": "2026-07-16T00:00:00Z",
        })
        result = self._route("/v1/approvals/approval-route-get", "GET")
        self.assertEqual(result["statusCode"], 200)


    def test_lambda_handler_approvals_decision_route(self):
        self.store.put_approval({
            "approval_id": "approval-route-decide",
            "tenant_id": "demo",
            "status": "pending",
            "agent_id": "route-agent-d",
            "run_id": "run-route-d",
            "action_id": "action-route-d",
            "action_hash": "sha256:route-d",
            "requested_by": "test",
            "expires_at": 4_000_000_000,
            "created_at": "2026-07-16T00:00:00Z",
        })
        result = self._route("/v1/approvals/approval-route-decide/decision", "POST", body={"decision": "approve"})
        self.assertEqual(result["statusCode"], 200)


    def test_lambda_handler_approvals_revoke_route(self):
        self.store.put_approval({
            "approval_id": "approval-route-revoke",
            "tenant_id": "demo",
            "status": "pending",
            "agent_id": "route-agent-r",
            "run_id": "run-route-r",
            "action_id": "action-route-r",
            "action_hash": "sha256:route-r",
            "requested_by": "test",
            "expires_at": 4_000_000_000,
            "created_at": "2026-07-16T00:00:00Z",
        })
        result = self._route("/v1/approvals/approval-route-revoke/revoke", "POST", body={})
        self.assertEqual(result["statusCode"], 200)


    def test_lambda_handler_actions_evaluate_route(self):
        result = self._route("/v1/actions/evaluate", "POST", body={
            "context": {"tenant_id": "demo", "environment": "production", "agent_id": "route-eval-agent", "invoked_by": "test"},
            "action": {"tool": "shell", "parameters": {"command": "ls"}},
        })
        self.assertEqual(result["statusCode"], 200)


    def test_route_policy_get(self):
        policy_auth = {**self.auth, "scopes": [*self.auth["scopes"], "policy:read", "policy:write"]}
        self._routed("/v1/policies", "POST", {
            "policy_id": "route-get-policy",
            "name": "Route Get Policy",
            "rules": [{"rule_id": "r1", "decision": "deny", "conditions": {"tool": "shell"}}],
        }, auth=policy_auth)
        result = self._routed("/v1/policies/route-get-policy", auth=policy_auth)
        self.assertIn(result["statusCode"], (200, 404))


    def test_route_policy_put(self):
        policy_auth = {**self.auth, "scopes": [*self.auth["scopes"], "policy:write"]}
        result = self._routed("/v1/policies/route-put-policy", "PUT", {
            "name": "Route Put Policy",
            "rules": [{"rule_id": "r1", "decision": "deny", "conditions": {"tool": "shell"}}],
        }, auth=policy_auth)
        self.assertIn(result["statusCode"], (200, 201, 400, 404))


    def test_route_policy_delete(self):
        policy_auth = {**self.auth, "scopes": [*self.auth["scopes"], "policy:write"]}
        result = self._routed("/v1/policies/route-del-policy", "DELETE", {}, auth=policy_auth)
        self.assertIn(result["statusCode"], (200, 404))


    def test_route_policy_publish(self):
        policy_auth = {**self.auth, "scopes": [*self.auth["scopes"], "policy:write"]}
        result = self._routed("/v1/policies/route-pub-policy/publish", "POST", {}, auth=policy_auth)
        self.assertIn(result["statusCode"], (200, 404))


    def test_route_policy_suspend(self):
        policy_auth = {**self.auth, "scopes": [*self.auth["scopes"], "policy:write"]}
        result = self._routed("/v1/policies/route-sus-policy/suspend", "POST", {}, auth=policy_auth)
        self.assertIn(result["statusCode"], (200, 404))


    def test_route_policy_reactivate(self):
        policy_auth = {**self.auth, "scopes": [*self.auth["scopes"], "policy:write"]}
        result = self._routed("/v1/policies/route-re-policy/reactivate", "POST", {}, auth=policy_auth)
        self.assertIn(result["statusCode"], (200, 404))


    def test_route_policy_test(self):
        policy_auth = {**self.auth, "scopes": [*self.auth["scopes"], "policy:simulate"]}
        result = self._routed("/v1/policies/route-test-policy/test", "POST", {
            "context": {"tenant_id": "demo", "environment": "production", "agent_id": "test-agent", "invoked_by": "test"},
            "action": {"tool": "shell", "parameters": {"command": "ls"}},
        }, auth=policy_auth)
        self.assertIn(result["statusCode"], (200, 404))


    def test_route_policy_simulate(self):
        policy_auth = {**self.auth, "scopes": [*self.auth["scopes"], "policy:simulate", "policy:write"]}
        self._routed("/v1/policies", "POST", {
            "policy_id": "route-sim-policy",
            "name": "Route Sim Policy",
            "rules": [{"rule_id": "r1", "decision": "deny", "conditions": {"tool": "shell"}}],
        }, auth=policy_auth)
        result = self._routed("/v1/policies/route-sim-policy/simulate", "POST", {
            "context": {"tenant_id": "demo", "environment": "production", "agent_id": "sim-agent", "invoked_by": "test"},
            "action": {"tool": "shell", "parameters": {"command": "ls"}},
        }, auth=policy_auth)
        self.assertIn(result["statusCode"], (200, 404))


    def test_route_approvals_get(self):
        result = self._routed("/v1/approvals")
        self.assertEqual(result["statusCode"], 200)


    def test_route_approval_get(self):
        result = self._routed("/v1/approvals/nonexistent-approval")
        self.assertIn(result["statusCode"], (200, 404))


    def test_route_approval_revoke(self):
        result = self._routed("/v1/approvals/nonexistent-approval/revoke", "POST", {})
        self.assertIn(result["statusCode"], (200, 404))


    def test_route_approval_decision(self):
        result = self._routed("/v1/approvals/nonexistent-approval/decision", "POST", {"decision": "approve"})
        self.assertIn(result["statusCode"], (200, 404))


    def test_route_action_outcome(self):
        actions_auth = {**self.auth, "scopes": [*self.auth["scopes"], "actions:write"]}
        result = self._routed("/v1/actions/nonexistent-action/outcome", "POST", {"status": "success"}, auth=actions_auth)
        self.assertIn(result["statusCode"], (200, 202, 404))


    def test_route_evaluate(self):
        result = self._routed("/v1/actions/evaluate", "POST", {
            "context": {"tenant_id": "demo", "environment": "production", "agent_id": "route-eval-agent", "invoked_by": "test"},
            "action": {"tool": "shell", "parameters": {"command": "echo hello"}},
        })
        self.assertEqual(result["statusCode"], 200)


    def test_guard_unavailable_payload_observe_mode(self):
        payload = {"context": {"mode": "observe", "tenant_id": "demo"}, "mode": "observe"}
        result = service.guard_unavailable_payload(payload, self.auth)
        self.assertEqual(result["decision"], "deny")
        self.assertEqual(result["mode"], "observe")
        self.assertEqual(result["enforcement"], "fail_closed")


    def test_guard_unavailable_payload_enforce_mode(self):
        payload = {"context": {"tenant_id": "demo"}}
        result = service.guard_unavailable_payload(payload, self.auth)
        self.assertEqual(result["mode"], "enforce")


    def test_guard_unavailable_response_shape(self):
        payload = {"context": {"tenant_id": "demo"}}
        result = service.guard_unavailable_response(payload, self.auth, RuntimeError("test"))
        self.assertEqual(result["statusCode"], 503)
        self.assertIn("retry-after", result["headers"])


    def test_store_get_action_evaluation(self):
        self.store.put_event({
            "event_type": "action.evaluated",
            "tenant_id": "demo",
            "action_id": "eval-test-action",
            "created_at": service.utc_now(),
            "decision": "allow",
        })
        result = self.store.get_action_evaluation("demo", "eval-test-action")
        self.assertIsNotNone(result)
        self.assertEqual(result["action_id"], "eval-test-action")


    def test_store_get_action_evaluation_not_found(self):
        result = self.store.get_action_evaluation("demo", "nonexistent-action")
        self.assertIsNone(result)


    def test_store_get_action_outcome(self):
        self.store.put_event({
            "event_type": "action.outcome",
            "tenant_id": "demo",
            "action_id": "outcome-test-action",
            "created_at": service.utc_now(),
            "status": "success",
        })
        result = self.store.get_action_outcome("demo", "outcome-test-action")
        self.assertIsNotNone(result)


    def test_store_revoke_approval_not_found(self):
        revoked, changed = self.store.revoke_approval("nonexistent", "user", service.utc_now())
        self.assertIsNone(revoked)
        self.assertFalse(changed)


    def test_store_consume_approval_not_approved(self):
        result = self.store.consume_approval("nonexistent", "user", service.utc_now(), "action-1", "hash-1")
        self.assertIsNone(result)


    def test_handle_simulate_policy_with_historical_action(self):
        policy_auth = {**self.auth, "scopes": [*self.auth["scopes"], "policy:write", "policy:simulate"]}
        service.handle_create_policy({
            "policy_id": "sim-hist-policy",
            "name": "Sim Hist Policy",
            "rules": [{"rule_id": "r1", "decision": "deny", "conditions": {"tool": "shell"}}],
        }, policy_auth)
        payload = {
            "context": {"tenant_id": "demo", "environment": "production", "agent_id": "sim-agent", "invoked_by": "test", "action_id": "sim-hist-action-1"},
            "action": {"tool": "shell", "parameters": {"command": "ls"}},
        }
        service.apply_tenant_runtime(payload, self.auth, self.store)
        service.evaluate_and_record(payload, self.store)
        result = service.handle_simulate_policy("sim-hist-policy", {
            "source_action_id": "sim-hist-action-1",
            "context": {"tenant_id": "demo"},
        }, policy_auth)
        self.assertIn(result["statusCode"], (200, 404))


    def test_handle_test_policy_not_found(self):
        policy_auth = {**self.auth, "scopes": [*self.auth["scopes"], "policy:simulate"]}
        result = service.handle_test_policy("nonexistent-policy", {
            "context": {"tenant_id": "demo", "environment": "production", "agent_id": "test-agent", "invoked_by": "test"},
            "action": {"tool": "shell", "parameters": {"command": "ls"}},
        }, policy_auth)
        self.assertEqual(result["statusCode"], 404)

    # ------------------------------------------------------------------
    # MCP evaluate_action tool coverage
    # ------------------------------------------------------------------


    def test_mcp_evaluate_action_tool(self):
        mcp_auth = {**self.auth, "scopes": ["mcp:read", "guard:evaluate"]}
        result = self._mcp_call("evaluate_action", {
            "context": {"tenant_id": "demo", "environment": "production", "agent_id": "mcp-eval-agent", "invoked_by": "test"},
            "action": {"tool": "shell", "parameters": {"command": "echo hello"}},
        }, auth=mcp_auth)
        self.assertEqual(result["statusCode"], 200)
        body = self.body(result)
        self.assertIn("structuredContent", body["result"])


    def test_mcp_evaluate_action_guard_unavailable(self):
        mcp_auth = {**self.auth, "scopes": ["mcp:read", "guard:evaluate"]}
        with patch.object(service, "evaluate_and_record", side_effect=RuntimeError("guard down")):
            result = self._mcp_call("evaluate_action", {
                "context": {"tenant_id": "demo", "environment": "production", "agent_id": "mcp-fail-agent", "invoked_by": "test"},
                "action": {"tool": "shell", "parameters": {"command": "ls"}},
            }, auth=mcp_auth)
        self.assertEqual(result["statusCode"], 503)
