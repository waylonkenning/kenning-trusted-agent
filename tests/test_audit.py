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




class AuditTests(unittest.TestCase):
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



    def test_legal_hold_prevents_retention_and_clears_ttl_markers(self):
        config = build_tenant_config(
            "demo",
            {"retention_enabled": True, "retention_days": 1, "legal_hold_enabled": False},
        )
        self.store.put_tenant_config(config)
        self.table.put_item(
            {
                "pk": "TENANT#demo",
                "sk": "EVENT#legal-hold-old",
                "tenant_id": "demo",
                "event_type": "action.evaluated",
                "created_at": "2000-01-01T00:00:00Z",
                "retention_expires_at": 1,
            }
        )

        enabled = service.handle_put_tenant(
            "demo",
            {"legal_hold_enabled": True, "legal_hold_reason": "Investigation INV-42"},
            self.auth,
        )
        self.assertEqual(enabled["statusCode"], 200)
        self.assertTrue(self.body(enabled)["legal_hold_enabled"])
        self.assertNotIn("retention_expires_at", self.table.items[("TENANT#demo", "EVENT#legal-hold-old")])

        blocked = service.handle_retention_run("demo", {"execute": True}, self.auth)
        self.assertEqual(blocked["statusCode"], 409)
        self.assertEqual(self.body(blocked)["error"], "legal_hold_active")
        self.assertEqual(self.body(blocked)["deleted_count"], 0)
        self.assertIn(("TENANT#demo", "EVENT#legal-hold-old"), self.table.items)
        events = self.store.list_events("demo", filters={"event_type": "tenant.retention.blocked"})
        self.assertEqual(len(events), 1)


    def test_audit_listing_does_not_let_legacy_idempotent_events_hide_new_events(self):
        created_at = "2026-07-16T12:00:00Z"
        self.table.put_item(
            {
                "pk": "TENANT#demo",
                "sk": "EVENT#IDEMPOTENT#action-outcome:demo:old",
                "tenant_id": "demo",
                "event_type": "action.outcome",
                "action_id": "old-action",
                "created_at": created_at,
            }
        )
        self.table.put_item(
            {
                "pk": "TENANT#demo",
                "sk": "EVENT#2026-07-16T12:00:00Z#99999999999999999999evt-new",
                "tenant_id": "demo",
                "event_type": "action.evaluated",
                "action_id": "new-action",
                "created_at": created_at,
            }
        )
        events = self.store.list_events("demo", limit=1)
        self.assertEqual(events[0]["action_id"], "new-action")


    def test_external_audit_event_is_append_only_captured_and_idempotent(self):
        auth = {**self.auth, "scopes": self.auth["scopes"] + ["audit:write"]}
        self.store.put_tenant_config(
            build_tenant_config(
                "demo",
                {
                    "capture_policy": {
                        "store_original_action": False,
                        "redact_fields": ["parameters.secret"],
                    },
                },
            )
        )
        request = {
            "headers": {"Idempotency-Key": "agent-run-123"},
            "body": "{}",
        }
        first = service.handle_ingest_audit_event(
            request,
            {
                "context": {"tenant_id": "demo", "run_id": "run-123", "agent_id": "worker"},
                "event_type": "agent.run.completed",
                "action": {"tool": "shell", "parameters": {"secret": "do-not-store"}},
                "status": "success",
            },
            auth,
        )
        self.assertEqual(first["statusCode"], 201)
        self.assertEqual(self.body(first)["status"], "accepted")
        stored = self.table.items[("TENANT#demo", next(key[1] for key in self.table.items if key[0] == "TENANT#demo" and self.table.items[key].get("event_type") == "agent.run.completed"))]
        self.assertEqual(stored["action"]["parameters"]["secret"], "[REDACTED_BY_TENANT_POLICY]")
        self.assertNotIn("do-not-store", repr(stored))

        repeated = service.handle_ingest_audit_event(
            request,
            {
                "context": {"tenant_id": "demo"},
                "event_type": "agent.run.completed",
                "status": "success",
                "idempotency_key": "agent-run-123",
            },
            auth,
        )
        self.assertEqual(repeated["statusCode"], 200)
        self.assertEqual(self.body(repeated)["status"], "duplicate")
        self.assertEqual(
            len(self.store.list_events("demo", filters={"event_type": "agent.run.completed"})),
            1,
        )


    def test_audit_export_is_itself_audited(self):
        result = service.handle_audit_export(
            {"queryStringParameters": {"tenant_id": "demo", "format": "json"}},
            self.auth,
        )
        self.assertEqual(result["statusCode"], 200)
        events = self.store.list_events("demo", filters={"event_type": "audit.exported"})
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["export_format"], "json")
        self.assertEqual(events[0]["invoked_by"], "pat-admin-test")


    def test_failed_authentication_is_audited_without_bearer_material(self):
        presented = "kta_pat_expired-test-secret"
        token_table = Mock()
        token_table.get_item.return_value = {
            "Item": {
                "tenant_id": "demo",
                "token_id": "pat-expired-test",
                "status": "expired",
            }
        }
        with patch.object(service, "token_table", token_table):
            auth, error = service.authenticate({"headers": {"Authorization": f"Bearer {presented}"}})
        self.assertIsNone(auth)
        self.assertEqual(error["statusCode"], 401)
        events = self.store.list_events("system", filters={"event_type": "auth.failed"})
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["failure_reason"], "token_not_found_or_inactive")
        self.assertNotIn(presented, repr(events[0]))


    def test_handle_audit_returns_tenant_events(self):
        self.store.put_event({
            "event_type": "action.evaluated",
            "tenant_id": "demo",
            "run_id": "run-audit",
            "action_id": "action-audit",
            "agent_id": "audit-agent",
            "invoked_by": "test",
            "created_at": "2026-07-16T00:00:00Z",
            "decision": "allow",
        })
        result = service.handle_audit({"queryStringParameters": {}}, self.auth)
        self.assertEqual(result["statusCode"], 200)
        body = self.body(result)
        self.assertEqual(body["tenant_id"], "demo")
        self.assertGreaterEqual(len(body["events"]), 1)


    def test_handle_audit_rejects_cross_tenant(self):
        result = service.handle_audit({"queryStringParameters": {"tenant_id": "other"}}, self.auth)
        self.assertEqual(result["statusCode"], 403)


    def test_handle_security_events_filters_to_security_types(self):
        self.store.put_event({
            "event_type": "tenant.config.updated",
            "tenant_id": "demo",
            "run_id": "run-sec",
            "action_id": "action-sec",
            "agent_id": "sec-agent",
            "invoked_by": "test",
            "created_at": "2026-07-16T00:00:00Z",
            "status": "accepted",
        })
        self.store.put_event({
            "event_type": "action.evaluated",
            "tenant_id": "demo",
            "run_id": "run-sec2",
            "action_id": "action-sec2",
            "agent_id": "sec-agent",
            "invoked_by": "test",
            "created_at": "2026-07-16T00:00:01Z",
            "status": "allowed",
        })
        result = service.handle_security_events({"queryStringParameters": {}}, self.auth)
        self.assertEqual(result["statusCode"], 200)
        body = self.body(result)
        event_types = {e["event_type"] for e in body["events"]}
        self.assertIn("tenant.config.updated", event_types)
        self.assertNotIn("action.evaluated", event_types)


    def test_handle_audit_export_jsonl_format(self):
        self.store.put_event({
            "event_type": "action.evaluated",
            "tenant_id": "demo",
            "run_id": "run-export",
            "action_id": "action-export",
            "agent_id": "export-agent",
            "invoked_by": "test",
            "created_at": "2026-07-16T00:00:00Z",
            "decision": "allow",
        })
        result = service.handle_audit_export({"queryStringParameters": {"tenant_id": "demo", "format": "jsonl"}}, self.auth)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(result["headers"]["content-type"], "application/x-ndjson")
        lines = [line for line in result["body"].strip().split("\n") if line]
        self.assertGreaterEqual(len(lines), 1)
        parsed = json.loads(lines[0])
        self.assertIn("event_type", parsed)

    # ------------------------------------------------------------------
    # Metrics handler with date range
    # ------------------------------------------------------------------


    def test_handle_metrics_with_date_range(self):
        self.store.put_event({
            "event_type": "action.evaluated",
            "tenant_id": "demo",
            "run_id": "run-metrics-range",
            "action_id": "action-metrics-range",
            "agent_id": "metrics-agent",
            "invoked_by": "test",
            "created_at": "2026-07-16T12:00:00Z",
            "decision": "deny",
        })
        result = service.handle_metrics(
            {"queryStringParameters": {"start_time": "2026-07-01T00:00:00Z", "end_time": "2026-07-31T00:00:00Z"}},
            self.auth,
        )
        self.assertEqual(result["statusCode"], 200)
        body = self.body(result)
        self.assertEqual(body["period"]["start"], "2026-07-01")
        self.assertEqual(body["period"]["end"], "2026-07-31")


    def test_handle_metrics_rejects_inverted_range(self):
        with self.assertRaises(ValueError):
            service.handle_metrics(
                {"queryStringParameters": {"start_time": "2026-08-01T00:00:00Z", "end_time": "2026-07-01T00:00:00Z"}},
                self.auth,
            )

    # ------------------------------------------------------------------
    # Citation verify handler
    # ------------------------------------------------------------------


    def test_handle_citation_verify_records_event(self):
        citation_auth = {**self.auth, "scopes": self.auth["scopes"] + ["citation:verify"]}
        result = service.handle_citation_verify(
            {
                "response": "Example Domain is a test domain.",
                "citations": [{"url": "https://example.com", "claim": "Example Domain", "source_text": "Example Domain"}],
            },
            citation_auth,
        )
        self.assertEqual(result["statusCode"], 200)
        body = self.body(result)
        self.assertEqual(body["tenant_id"], "demo")
        self.assertIn(body["status"], {"pass", "warning", "fail"})
        events = self.store.list_events("demo", filters={"event_type": "citation.verified"})
        self.assertGreaterEqual(len(events), 1)

    # ------------------------------------------------------------------
    # Proof handlers
    # ------------------------------------------------------------------


    def test_record_auth_failure_writes_event(self):
        event = {"requestContext": {"requestId": "req-123"}, "headers": {"authorization": "Bearer kta_pat_test"}}
        service.record_auth_failure(event, "test_failure", tenant_id="demo")
        events = [item for item in self.table.items.values() if item.get("event_type") == "auth.failed"]
        self.assertTrue(len(events) >= 1)
        self.assertEqual(events[-1]["failure_reason"], "test_failure")


    def test_lambda_handler_audit_route(self):
        result = self._route("/v1/audit", "GET", query={"tenant_id": "demo"})
        self.assertEqual(result["statusCode"], 200)


    def test_lambda_handler_metrics_route(self):
        result = self._route("/v1/metrics", "GET", query={"tenant_id": "demo"})
        self.assertEqual(result["statusCode"], 200)


    def test_lambda_handler_security_events_route(self):
        result = self._route("/v1/security/events", "GET", query={"tenant_id": "demo"})
        self.assertEqual(result["statusCode"], 200)


    def test_lambda_handler_audit_export_route(self):
        result = self._route("/v1/audit/export", "GET", query={"tenant_id": "demo"})
        self.assertEqual(result["statusCode"], 200)


    def test_lambda_handler_audit_events_post_route(self):
        audit_auth = {**self.auth, "scopes": [*self.auth["scopes"], "audit:write"]}
        result = self._route("/v1/audit/events", "POST", body={
            "event_type": "custom.event",
            "tenant_id": "demo",
            "environment": "production",
            "run_id": "custom-run",
            "action_id": "custom-action",
            "agent_id": "custom-agent",
            "invoked_by": "test",
        }, auth=audit_auth)
        self.assertIn(result["statusCode"], (200, 201, 202))


    def test_handle_audit(self):
        event = {"queryStringParameters": {"tenant_id": "demo"}}
        result = service.handle_audit(event, self.auth)
        self.assertEqual(result["statusCode"], 200)


    def test_handle_security_events(self):
        event = {"queryStringParameters": {"tenant_id": "demo"}}
        result = service.handle_security_events(event, self.auth)
        self.assertEqual(result["statusCode"], 200)


    def test_handle_metrics(self):
        event = {"queryStringParameters": {"tenant_id": "demo"}}
        result = service.handle_metrics(event, self.auth)
        self.assertEqual(result["statusCode"], 200)


    def test_handle_audit_export(self):
        event = {"queryStringParameters": {"tenant_id": "demo"}}
        result = service.handle_audit_export(event, self.auth)
        self.assertEqual(result["statusCode"], 200)


    def test_handle_ingest_audit_event(self):
        audit_auth = {**self.auth, "scopes": [*self.auth["scopes"], "audit:write"]}
        event = {"queryStringParameters": {}}
        result = service.handle_ingest_audit_event(event, {
            "event_type": "custom.test",
            "tenant_id": "demo",
            "environment": "production",
            "run_id": "ingest-run",
            "action_id": "ingest-action",
            "agent_id": "ingest-agent",
            "invoked_by": "test",
        }, audit_auth)
        self.assertIn(result["statusCode"], (200, 201, 202))

    # ------------------------------------------------------------------
    # Tenant handlers
    # ------------------------------------------------------------------


    def test_route_audit_get(self):
        result = self._routed("/v1/audit")
        self.assertEqual(result["statusCode"], 200)


    def test_route_security_events_get(self):
        result = self._routed("/v1/security/events")
        self.assertEqual(result["statusCode"], 200)


    def test_route_audit_events_post(self):
        audit_auth = {**self.auth, "scopes": [*self.auth["scopes"], "audit:write"]}
        result = self._routed("/v1/audit/events", "POST", {
            "event_type": "route.test.event",
            "context": {"tenant_id": "demo"},
        }, auth=audit_auth)
        self.assertIn(result["statusCode"], (200, 201))


    def test_route_audit_export_get(self):
        result = self._routed("/v1/audit/export")
        self.assertEqual(result["statusCode"], 200)


    def test_route_metrics_get(self):
        result = self._routed("/v1/metrics")
        self.assertEqual(result["statusCode"], 200)


    def test_store_get_metrics(self):
        self.store.put_event({
            "event_type": "action.evaluated",
            "tenant_id": "demo",
            "action_id": "metric-action",
            "created_at": service.utc_now(),
            "decision": "allow",
        })
        result = self.store.get_metrics("demo")
        self.assertIsInstance(result, dict)

    # ------------------------------------------------------------------
    # Policy handler edge cases
    # ------------------------------------------------------------------
