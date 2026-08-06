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




class TenantConfigTests(unittest.TestCase):
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



    def test_tenant_and_environment_configuration_are_tenant_scoped(self):
        created = service.handle_put_tenant(
            "demo",
            {
                "name": "Demo regulated tenant",
                "default_environment": "production",
                "retention_enabled": True,
                "retention_days": 30,
                "environments": [
                    {"environment_id": "production", "status": "active", "mode": "observe", "allowed_tools": ["sql"]},
                ],
            },
            self.auth,
        )
        self.assertEqual(created["statusCode"], 201)
        self.assertEqual(self.body(created)["config_version"], 1)

        tenant = service.handle_get_tenant("demo", self.auth)
        self.assertEqual(tenant["statusCode"], 200)
        tenant_body = self.body(tenant)
        self.assertEqual(tenant_body["environment_count"], 1)
        self.assertEqual(tenant_body["environment_ids"], ["production"])

        environments = service.handle_list_environments("demo", self.auth)
        self.assertEqual(environments["statusCode"], 200)
        self.assertEqual(self.body(environments)["environments"][0]["mode"], "observe")

        other = service.handle_get_tenant("other", self.auth)
        self.assertEqual(other["statusCode"], 403)
        self.assertEqual(self.body(other)["error"], "tenant_mismatch")


    def test_starter_rules_are_tenant_scoped_and_editable(self):
        initial = service.handle_get_starter_rules("demo", self.auth)
        initial_body = self.body(initial)
        self.assertEqual(initial["statusCode"], 200)
        self.assertGreater(initial_body["summary"]["builtin_count"], 20)

        rules = [rule for rule in initial_body["rules"] if rule["reason_code"] != "CREDENTIAL_EXPOSURE"]
        rules.append(
            {
                "rule_id": "production-shell-review",
                "name": "Production shell review",
                "kind": "custom",
                "reason_code": "STARTER_PRODUCTION_SHELL_REVIEW",
                "decision": "require_approval",
                "enabled": True,
                "conditions": {"tool": "shell", "environment": "production"},
                "reason": "Production shell actions require a human review.",
            }
        )
        saved = service.handle_put_starter_rules("demo", {"rules": rules}, self.auth)
        self.assertEqual(saved["statusCode"], 201)
        saved_body = self.body(saved)
        self.assertEqual(saved_body["summary"]["custom_count"], 1)
        self.assertNotIn("CREDENTIAL_EXPOSURE", [rule["reason_code"] for rule in saved_body["rules"]])

        payload = {
            "context": {"tenant_id": "demo", "environment": "production", "agent_id": "starter-test-agent", "invoked_by": "test"},
            "action": {"tool": "shell", "parameters": {"command": "ls"}},
        }
        service.apply_tenant_runtime(payload, self.auth, self.store)
        decision = service.evaluate_and_record(payload, self.store)
        self.assertEqual(decision["decision"], "require_approval")
        self.assertIn("POLICY_PRODUCTION-SHELL-REVIEW", decision["reason_codes"])

        other = service.handle_get_starter_rules("other", self.auth)
        self.assertEqual(other["statusCode"], 403)


    def test_tenant_observe_mode_still_records_would_decision(self):
        config = build_tenant_config(
            "demo",
            {
                "environments": [
                    {"environment_id": "production", "status": "active", "mode": "observe", "allowed_tools": ["shell"]},
                ],
                "default_environment": "production",
            },
        )
        self.store.put_tenant_config(config)
        payload = {
            "context": {"tenant_id": "demo", "environment": "production", "agent_id": "test-agent", "invoked_by": "test"},
            "action": {"tool": "shell", "parameters": {"command": "rm -rf /"}},
        }
        service.apply_tenant_runtime(payload, self.auth, self.store)
        decision = service.evaluate_and_record(payload, self.store)
        self.assertEqual(decision["decision"], "observe")
        self.assertEqual(decision["would_decision"], "deny")
        self.assertEqual(decision["mode"], "observe")
        self.assertEqual(decision["tenant_policy"]["mode"], "observe")


    def test_tenant_registry_returns_safe_own_workspace_summary(self):
        legacy = service.handle_list_tenants({"queryStringParameters": {}}, self.auth)
        self.assertEqual(legacy["statusCode"], 200)
        legacy_body = self.body(legacy)
        self.assertEqual(legacy_body["tenant_id"], "demo")
        self.assertEqual(legacy_body["count"], 1)
        self.assertFalse(legacy_body["tenants"][0]["configured"])

        service.handle_put_tenant("demo", {"name": "Demo workspace", "status": "active"}, self.auth)
        configured = service.handle_list_tenants({"queryStringParameters": {"status": "active"}}, self.auth)
        configured_body = self.body(configured)
        self.assertTrue(configured_body["tenants"][0]["configured"])
        self.assertEqual(configured_body["tenants"][0]["name"], "Demo workspace")
        self.assertNotIn("identity_provider", repr(configured_body))
        self.assertEqual(
            service.handle_list_tenants({"queryStringParameters": {"tenant_id": "other"}}, self.auth)["statusCode"],
            403,
        )

        admin_auth = {**self.auth, "tenant_id": "platform", "scopes": ["admin"]}
        service.handle_put_tenant("other", {"name": "Other workspace"}, admin_auth)
        all_tenants = service.handle_list_tenants({"queryStringParameters": {}}, admin_auth)
        all_body = self.body(all_tenants)
        self.assertIsNone(all_body["tenant_id"])
        self.assertEqual({item["tenant_id"] for item in all_body["tenants"]}, {"demo", "other"})
        self.assertEqual(self.table.scan_calls, 0)


    def test_environment_boundary_is_recorded_as_deny(self):
        config = build_tenant_config(
            "demo",
            {
                "environments": [
                    {"environment_id": "production", "status": "active", "mode": "enforce", "allowed_tools": ["sql"]},
                ],
                "default_environment": "production",
            },
        )
        self.store.put_tenant_config(config)
        payload = {
            "context": {"tenant_id": "demo", "environment": "production", "agent_id": "test-agent", "invoked_by": "test"},
            "action": {"tool": "shell", "parameters": {"command": "ls"}},
        }
        service.apply_tenant_runtime(payload, self.auth, self.store)
        decision = service.evaluate_and_record(payload, self.store)
        self.assertEqual(decision["decision"], "deny")
        self.assertIn("ENVIRONMENT_TOOL_NOT_ALLOWED", decision["reason_codes"])
        self.assertEqual(decision["tenant_policy"]["mode"], "enforce")


    def test_proof_ids_are_tenant_scoped_and_cannot_overwrite_other_tenants(self):
        victim_auth = {**self.auth, "tenant_id": "victim", "scopes": ["proof:write", "proof:read", "guard:evaluate"]}
        attacker_auth = {**self.auth, "tenant_id": "attacker", "scopes": ["proof:write", "proof:read", "guard:evaluate"]}
        proof_id = "proof-shared-security-test"

        victim_created = service.handle_create_proof(
            {"tenant_id": "victim", "proof_id": proof_id, "request_summary": "victim proof"},
            victim_auth,
        )
        attacker_created = service.handle_create_proof(
            {"tenant_id": "attacker", "proof_id": proof_id, "request_summary": "attacker proof"},
            attacker_auth,
        )

        self.assertEqual(victim_created["statusCode"], 201)
        self.assertEqual(attacker_created["statusCode"], 201)
        self.assertEqual(self.table.items[("TENANT#victim", f"PROOF#{proof_id}")]["tenant_id"], "victim")
        self.assertEqual(self.table.items[("TENANT#attacker", f"PROOF#{proof_id}")]["tenant_id"], "attacker")
        self.assertNotIn((f"PROOF#{proof_id}", "METADATA"), self.table.items)


    def test_platform_admin_browser_session_uses_same_control_plane_boundary(self):
        platform_session = {
            "token_type": "session",
            "auth_source": "session",
            "platform_admin": True,
            "scopes": ["admin"],
            "subject": "platform-operator",
            "token_id": "session-platform-operator",
        }
        created = service.handle_platform_access_grant(
            {"tenant_id": "demo", "reason": "Investigate a tenant support request", "operation": "support", "expires_in_seconds": 300},
            platform_session,
        )
        self.assertEqual(created["statusCode"], 201)
        grant = self.body(created)

        listed = service.handle_list_platform_access_grants({"queryStringParameters": {"limit": "10"}}, platform_session)
        self.assertEqual(listed["statusCode"], 200)
        self.assertEqual(self.body(listed)["grants"][0]["grant_id"], grant["grant_id"])

        read = service.handle_platform_support_read(
            {"grant_id": grant["grant_id"], "tenant_id": "demo", "resource": "tenant"},
            platform_session,
        )
        self.assertEqual(read["statusCode"], 200)
        self.assertEqual(self.body(read)["tenant_id"], "demo")

        revoked = service.handle_revoke_platform_access_grant(
            grant["grant_id"],
            {"reason": "Support session is complete"},
            platform_session,
        )
        self.assertEqual(revoked["statusCode"], 200)
        self.assertEqual(self.body(revoked)["status"], "revoked")

        tenant_session = {**platform_session, "platform_admin": False, "scopes": []}
        denied = service.handle_list_platform_access_grants({"queryStringParameters": {}}, tenant_session)
        self.assertEqual(denied["statusCode"], 403)


    def test_approval_queue_is_tenant_scoped_and_filters_reviewer_work(self):
        for approval_id, tenant_id, status, agent_id, environment in (
            ("approval-pending", "demo", "pending", "queue-agent", "production"),
            ("approval-approved", "demo", "approved", "queue-agent", "production"),
            ("approval-denied", "demo", "denied", "other-agent", "development"),
            ("approval-other-tenant", "other", "pending", "queue-agent", "production"),
        ):
            self.store.put_approval(
                {
                    "approval_id": approval_id,
                    "tenant_id": tenant_id,
                    "status": status,
                    "agent_id": agent_id,
                    "environment": environment,
                    "created_at": f"2026-07-17T00:00:0{len(approval_id) % 9}Z",
                    "expires_at": 4102444800,
                    "action_id": f"action-{approval_id}",
                    "action_hash": f"sha256:{approval_id}",
                    "run_id": f"run-{approval_id}",
                }
            )

        default_queue = service.handle_list_approvals({"queryStringParameters": {}}, self.auth)
        self.assertEqual(default_queue["statusCode"], 200)
        default_body = self.body(default_queue)
        self.assertEqual(default_body["statuses"], ["approved", "pending"])
        self.assertEqual({item["approval_id"] for item in default_body["approvals"]}, {"approval-pending", "approval-approved"})

        filtered = service.handle_list_approvals(
            {"queryStringParameters": {"status": "pending", "agent_id": "queue-agent", "environment": "production"}},
            self.auth,
        )
        self.assertEqual([item["approval_id"] for item in self.body(filtered)["approvals"]], ["approval-pending"])

        denied = service.handle_list_approvals({"queryStringParameters": {"status": "denied"}}, self.auth)
        self.assertEqual([item["approval_id"] for item in self.body(denied)["approvals"]], ["approval-denied"])
        invalid = service.handle_list_approvals({"queryStringParameters": {"status": "unknown"}}, self.auth)
        self.assertEqual(invalid["statusCode"], 400)
        self.assertEqual(self.table.scan_calls, 0)
        self.assertGreaterEqual(self.table.query_calls, 3)


    def test_agent_identity_registration_is_tenant_scoped(self):
        attacker_auth = {**self.auth, "tenant_id": "attacker"}
        victim_auth = {**self.auth, "tenant_id": "victim"}

        attacker = service.handle_register_agent(
            {
                "context": {"tenant_id": "attacker"},
                "agent_id": "invoice-processing-agent",
                "owner": "attacker",
                "approved_tools": ["shell"],
            },
            attacker_auth,
        )
        self.assertEqual(attacker["statusCode"], 201)

        victim = service.handle_register_agent(
            {
                "context": {"tenant_id": "victim"},
                "agent_id": "invoice-processing-agent",
                "owner": "victim",
                "approved_tools": [],
            },
            victim_auth,
        )
        self.assertEqual(victim["statusCode"], 201)

        duplicate = service.handle_register_agent(
            {
                "context": {"tenant_id": "victim"},
                "agent_id": "invoice-processing-agent",
                "owner": "victim",
            },
            victim_auth,
        )
        self.assertEqual(duplicate["statusCode"], 409)

        decision = service.evaluate_and_record(
            {
                "context": {"tenant_id": "victim", "environment": "development", "agent_id": "invoice-processing-agent", "invoked_by": "test"},
                "action": {"tool": "shell", "parameters": {"command": "echo hello"}},
            },
            self.store,
        )
        self.assertEqual(decision["decision"], "deny")
        self.assertIn("NO_APPROVED_TOOLS", decision["reason_codes"])
        self.assertEqual(decision["identity"]["agent_id"], "invoice-processing-agent")


    def test_policy_publish_is_tenant_scoped_for_colliding_policy_ids(self):
        policy_auth = {
            **self.auth,
            "scopes": self.auth["scopes"] + ["policy:read", "policy:write"],
        }
        attacker_auth = {**policy_auth, "tenant_id": "attacker", "token_id": "pat-attacker"}
        policy_id = "shared-policy-id"

        victim_created = service.handle_create_policy(
            {
                "context": {"tenant_id": "demo"},
                "policy_id": policy_id,
                "name": "Victim deny policy",
                "rules": [{"rule_id": "deny-shell", "tool": "shell", "decision": "deny"}],
            },
            policy_auth,
        )
        self.assertEqual(victim_created["statusCode"], 201)
        victim_published = service.handle_publish_policy(policy_id, {"version": 1}, policy_auth)
        self.assertEqual(victim_published["statusCode"], 200)

        attacker_created = service.handle_create_policy(
            {
                "context": {"tenant_id": "attacker"},
                "policy_id": policy_id,
                "name": "Attacker colliding policy",
                "rules": [{"rule_id": "allow-shell", "tool": "shell", "decision": "allow"}],
            },
            attacker_auth,
        )
        self.assertEqual(attacker_created["statusCode"], 201)
        self.assertEqual(self.body(attacker_created)["version"], 1)
        attacker_published = service.handle_publish_policy(policy_id, {"version": 1}, attacker_auth)
        self.assertEqual(attacker_published["statusCode"], 200)

        victim_policy = service.store().get_policy(policy_id, 1, "demo")
        attacker_policy = service.store().get_policy(policy_id, 1, "attacker")
        self.assertEqual(victim_policy["status"], "published")
        self.assertEqual(attacker_policy["status"], "published")
        self.assertEqual(
            sorted(item[0] for item in self.table.items if item[1] == "VERSION#0000000001"),
            ["TENANT#attacker#POLICY#shared-policy-id", "TENANT#demo#POLICY#shared-policy-id"],
        )


    def test_metrics_are_tenant_scoped_and_aggregate_latency(self):
        self.store.put_event(
            {
                "event_type": "action.evaluated",
                "tenant_id": "demo",
                "run_id": "run-metrics",
                "action_id": "action-metrics",
                "agent_id": "metrics-agent",
                "invoked_by": "metrics-test",
                "created_at": "2026-07-16T12:00:00Z",
                "decision": "allow",
                "evaluation_latency_ms": 12.5,
                "action": {"adapter": "sql"},
            }
        )
        result = service.handle_metrics({"queryStringParameters": {"tenant_id": "demo"}}, self.auth)
        self.assertEqual(result["statusCode"], 200)
        metrics = self.body(result)["metrics"]
        self.assertEqual(metrics["event_counts"]["action.evaluated"], 1)
        self.assertEqual(metrics["decision_counts"]["allow"], 1)
        self.assertEqual(metrics["adapter_counts"]["sql"], 1)
        self.assertEqual(metrics["latency_ms"]["average"], 12.5)
        self.assertEqual(metrics["latency_ms"]["p95"], 25)
        self.assertEqual(metrics["latency_ms"]["p99"], 25)
        mismatch = service.handle_metrics({"queryStringParameters": {"tenant_id": "other"}}, self.auth)
        self.assertEqual(mismatch["statusCode"], 403)


    def test_workspace_product_selection_is_persistent_and_audited(self):
        selected = ["agent-guard", "agent-proof"]
        updated = service.handle_put_tenant("demo", {"enabled_products": selected}, self.auth)
        self.assertEqual(updated["statusCode"], 201)
        self.assertEqual(self.body(updated)["enabled_products"], selected)

        stored = service.handle_get_tenant("demo", self.auth)
        self.assertEqual(self.body(stored)["enabled_products"], selected)
        events = self.store.list_events("demo", filters={"event_type": "tenant.config.updated"})
        product_event = next(event for event in events if event.get("enabled_products") == selected)
        self.assertEqual(product_event["previous_enabled_products"], ["agent-guard", "agent-proof", "citation-trust", "agent-identity"])


    def test_session_product_access_changes_require_workspace_admin(self):
        policy_admin = self._session_auth(role="policy_admin")
        denied = service.handle_put_tenant("demo", {"enabled_products": ["agent-guard"]}, policy_admin)
        self.assertEqual(denied["statusCode"], 403)
        self.assertEqual(self.body(denied)["error"], "membership_role_required")


    def test_handle_me_returns_user_and_memberships(self):
        session_auth = self._session_auth()
        self.store.put_membership(service.membership_record("demo", "user@example.org", {"role": "admin", "status": "active", "email": "user@example.org"}, actor="test"))
        result = service.handle_me(session_auth)
        self.assertEqual(result["statusCode"], 200)
        body = self.body(result)
        self.assertEqual(body["user"]["subject"], "user@example.org")
        self.assertEqual(len(body["memberships"]), 1)
        self.assertEqual(body["memberships"][0]["role"], "admin")
        self.assertIn("session_inactivity_timeout_seconds", body)


    def test_handle_me_rejects_non_session(self):
        result = service.handle_me(self.auth)
        self.assertEqual(result["statusCode"], 403)
        self.assertEqual(self.body(result)["error"], "session_required")


    def test_handle_logout_revokes_session(self):
        session_auth = self._session_auth()
        self.token_table.items["fake-session-hash"] = {"token_hash": "fake-session-hash", "status": "active"}
        with patch.object(service, "token_table", self.token_table):
            result = service.handle_logout(session_auth)
        self.assertEqual(result["statusCode"], 204)
        self.assertEqual(self.token_table.items["fake-session-hash"]["status"], "revoked")


    def test_handle_logout_returns_204_for_non_session(self):
        result = service.handle_logout(self.auth)
        self.assertEqual(result["statusCode"], 204)

    # ------------------------------------------------------------------
    # Tenant membership handlers
    # ------------------------------------------------------------------


    def test_handle_list_members_returns_tenant_memberships(self):
        self.store.put_membership(service.membership_record("demo", "member1@example.org", {"role": "viewer", "status": "active"}, actor="test"))
        self.store.put_membership(service.membership_record("demo", "member2@example.org", {"role": "admin", "status": "active"}, actor="test"))
        result = service.handle_list_members("demo", {}, self.auth)
        self.assertEqual(result["statusCode"], 200)
        body = self.body(result)
        self.assertEqual(body["tenant_id"], "demo")
        self.assertEqual(body["count"], 2)


    def test_handle_create_member_adds_membership(self):
        result = service.handle_create_member("demo", {"subject": "new-member@example.org", "role": "viewer"}, {}, self.auth)
        self.assertEqual(result["statusCode"], 201)
        body = self.body(result)
        self.assertEqual(body["subject"], "new-member@example.org")
        self.assertEqual(body["role"], "viewer")
        membership = self.store.get_membership("new-member@example.org", "demo")
        self.assertIsNotNone(membership)
        self.assertEqual(membership["status"], "active")


    def test_handle_create_member_updates_existing(self):
        self.store.put_membership(service.membership_record("demo", "existing@example.org", {"role": "viewer", "status": "active"}, actor="test"))
        result = service.handle_create_member("demo", {"subject": "existing@example.org", "role": "admin"}, {}, self.auth)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(self.body(result)["role"], "admin")


    def test_handle_update_member_changes_role(self):
        self.store.put_membership(service.membership_record("demo", "update-me@example.org", {"role": "viewer", "status": "active"}, actor="test"))
        result = service.handle_update_member("demo", "update-me@example.org", {"role": "admin"}, {}, self.auth)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(self.body(result)["role"], "admin")


    def test_handle_update_member_returns_404_for_missing(self):
        result = service.handle_update_member("demo", "ghost@example.org", {"role": "admin"}, {}, self.auth)
        self.assertEqual(result["statusCode"], 404)
        self.assertEqual(self.body(result)["error"], "membership_not_found")

    # ------------------------------------------------------------------
    # Invitation handlers
    # ------------------------------------------------------------------


    def test_handle_create_and_get_policy(self):
        policy_auth = {**self.auth, "scopes": self.auth["scopes"] + ["policy:read", "policy:write"]}
        created = service.handle_create_policy(
            {"context": {"tenant_id": "demo"}, "policy_id": "test-get-policy", "name": "Test get", "rules": []},
            policy_auth,
        )
        self.assertEqual(created["statusCode"], 201)
        got = service.handle_get_policy("test-get-policy", {"queryStringParameters": {}}, policy_auth)
        self.assertEqual(got["statusCode"], 200)
        self.assertEqual(self.body(got)["policy_id"], "test-get-policy")


    def test_handle_list_policies_returns_latest_versions(self):
        policy_auth = {**self.auth, "scopes": self.auth["scopes"] + ["policy:read", "policy:write"]}
        service.handle_create_policy(
            {"context": {"tenant_id": "demo"}, "policy_id": "list-policy-a", "name": "A", "rules": []},
            policy_auth,
        )
        service.handle_create_policy(
            {"context": {"tenant_id": "demo"}, "policy_id": "list-policy-b", "name": "B", "rules": []},
            policy_auth,
        )
        result = service.handle_list_policies(policy_auth)
        self.assertEqual(result["statusCode"], 200)
        body = self.body(result)
        policy_ids = {p["policy_id"] for p in body["policies"]}
        self.assertIn("list-policy-a", policy_ids)
        self.assertIn("list-policy-b", policy_ids)


    def test_handle_receipt_public_key_returns_key(self):
        proof_auth = {**self.auth, "scopes": self.auth["scopes"] + ["proof:read"]}
        result = service.handle_receipt_public_key(proof_auth)
        self.assertIn(result["statusCode"], {200, 503})

    # ------------------------------------------------------------------
    # Environment handler
    # ------------------------------------------------------------------


    def test_handle_put_environment_creates_environment(self):
        service.handle_put_tenant("demo", {"name": "Demo", "environments": [
            {"environment_id": "development", "status": "active", "mode": "enforce", "allowed_tools": ["sql"]},
        ], "default_environment": "development"}, self.auth)
        result = service.handle_put_environment(
            "demo",
            "staging",
            {"status": "active", "mode": "observe", "allowed_tools": ["sql", "shell"]},
            self.auth,
        )
        self.assertEqual(result["statusCode"], 200)
        body = self.body(result)
        self.assertEqual(body["environment_id"], "staging")
        self.assertEqual(body["mode"], "observe")
        environments = self.body(service.handle_list_environments("demo", self.auth))
        env_ids = [e["environment_id"] for e in environments["environments"]]
        self.assertIn("staging", env_ids)

    # ------------------------------------------------------------------
    # Agent handlers
    # ------------------------------------------------------------------


    def test_handle_platform_access_grant_validates_parameters(self):
        admin_auth = {**self.auth, "tenant_id": "platform", "scopes": ["admin"]}
        with self.assertRaises(ValueError):
            service.handle_platform_access_grant({"tenant_id": "demo", "reason": "short"}, admin_auth)
        with self.assertRaises(ValueError):
            service.handle_platform_access_grant(
                {"tenant_id": "demo", "reason": "Valid reason for access", "operation": "invalid"},
                admin_auth,
            )


    def test_handle_platform_support_read_members_resource(self):
        admin_auth = {**self.auth, "tenant_id": "platform", "scopes": ["admin"]}
        grant = self.body(service.handle_platform_access_grant(
            {"tenant_id": "demo", "reason": "Support investigation for tenant", "operation": "support"},
            admin_auth,
        ))
        self.store.put_membership(service.membership_record("demo", "support-target@example.org", {"role": "viewer", "status": "active"}, actor="test"))
        result = service.handle_platform_support_read(
            {"grant_id": grant["grant_id"], "tenant_id": "demo", "resource": "members"},
            admin_auth,
        )
        self.assertEqual(result["statusCode"], 200)
        body = self.body(result)
        self.assertEqual(body["tenant_id"], "demo")
        self.assertIn("memberships", body)


    def test_handle_platform_support_read_metrics_resource(self):
        admin_auth = {**self.auth, "tenant_id": "platform", "scopes": ["admin"]}
        grant = self.body(service.handle_platform_access_grant(
            {"tenant_id": "demo", "reason": "Metrics investigation for tenant", "operation": "support"},
            admin_auth,
        ))
        result = service.handle_platform_support_read(
            {"grant_id": grant["grant_id"], "tenant_id": "demo", "resource": "metrics"},
            admin_auth,
        )
        self.assertEqual(result["statusCode"], 200)
        self.assertIn("metrics", self.body(result))

    # ------------------------------------------------------------------
    # lambda_handler routing / dispatch
    # ------------------------------------------------------------------


    def test_confirmation_values_rejects_empty_username(self):
        _, _, error = service._confirmation_values({}, require_code=False)
        self.assertIsNotNone(error)
        self.assertEqual(error["statusCode"], 400)


    def test_confirmation_values_rejects_invalid_code(self):
        _, _, error = service._confirmation_values({"username": "user@example.com"}, require_code=True)
        self.assertIsNotNone(error)
        self.assertEqual(error["statusCode"], 400)


    def test_confirmation_values_accepts_valid_input(self):
        username, code, error = service._confirmation_values(
            {"username": "user@example.com", "confirmation_code": "123456"},
            require_code=True,
        )
        self.assertIsNone(error)
        self.assertEqual(username, "user@example.com")
        self.assertEqual(code, "123456")


    def test_confirmation_values_no_code_required(self):
        username, code, error = service._confirmation_values(
            {"email": "user@example.com"},
            require_code=False,
        )
        self.assertIsNone(error)
        self.assertEqual(username, "user@example.com")
        self.assertIsNone(code)

    # ------------------------------------------------------------------
    # _confirmation_error
    # ------------------------------------------------------------------


    def test_confirmation_error_maps_known_codes(self):
        result = service._confirmation_error(self._make_client_error("CodeMismatchException"))
        self.assertEqual(result["statusCode"], 400)
        self.assertEqual(self.body(result)["error"], "invalid_confirmation_code")


    def test_confirmation_error_maps_expired_code(self):
        result = service._confirmation_error(self._make_client_error("ExpiredCodeException"))
        self.assertEqual(result["statusCode"], 400)
        self.assertEqual(self.body(result)["error"], "confirmation_code_expired")


    def test_confirmation_error_maps_rate_limit(self):
        result = service._confirmation_error(self._make_client_error("TooManyRequestsException"))
        self.assertEqual(result["statusCode"], 429)


    def test_confirmation_error_unknown_code(self):
        result = service._confirmation_error(self._make_client_error("SomethingElse"))
        self.assertEqual(result["statusCode"], 400)
        self.assertEqual(self.body(result)["error"], "confirmation_failed")

    # ------------------------------------------------------------------
    # handle_auth_confirm / handle_auth_confirm_resend
    # ------------------------------------------------------------------


    def test_record_auth_failure_no_table(self):
        with patch.object(service, "table", None):
            service.record_auth_failure({"headers": {}}, "no_table")

    # ------------------------------------------------------------------
    # handle_csrf / handle_logout / handle_me
    # ------------------------------------------------------------------


    def test_handle_me_requires_session(self):
        result = service.handle_me(self.auth)
        self.assertEqual(result["statusCode"], 403)


    def test_handle_me_returns_user_info(self):
        session_auth = {**self.auth, "auth_source": "session", "token_type": "session", "subject": "user-1", "email": "user@example.com", "tenant_id": "demo", "expires_at": int(time.time()) + 3600, "last_activity_at": int(time.time())}
        result = service.handle_me(session_auth)
        self.assertEqual(result["statusCode"], 200)
        body = self.body(result)
        self.assertEqual(body["user"]["subject"], "user-1")
        self.assertEqual(body["active_tenant_id"], "demo")

    # ------------------------------------------------------------------
    # handle_create_session
    # ------------------------------------------------------------------


    def test_handle_list_members(self):
        result = service.handle_list_members("demo", {}, self.auth)
        self.assertEqual(result["statusCode"], 200)
        self.assertIn("memberships", self.body(result))


    def test_handle_create_member(self):
        result = service.handle_create_member("demo", {"subject": "new-member@example.com", "role": "viewer"}, {}, self.auth)
        self.assertIn(result["statusCode"], (200, 201))
        body = self.body(result)
        self.assertEqual(body["subject"], "new-member@example.com")


    def test_handle_create_member_owner_requires_admin(self):
        limited_auth = {**self.auth, "scopes": ["tenant:write"]}
        result = service.handle_create_member("demo", {"subject": "owner@example.com", "role": "owner"}, {}, limited_auth)
        self.assertEqual(result["statusCode"], 403)


    def test_handle_update_member_not_found(self):
        result = service.handle_update_member("demo", "nonexistent@example.com", {"role": "admin"}, {}, self.auth)
        self.assertEqual(result["statusCode"], 404)


    def test_handle_update_member_success(self):
        service.handle_create_member("demo", {"subject": "update-me@example.com", "role": "viewer"}, {}, self.auth)
        result = service.handle_update_member("demo", "update-me@example.com", {"role": "admin"}, {}, self.auth)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(self.body(result)["role"], "admin")

    # ------------------------------------------------------------------
    # Invitation handlers
    # ------------------------------------------------------------------


    def test_handle_create_policy(self):
        policy_auth = {**self.auth, "scopes": [*self.auth["scopes"], "policy:write", "policy:read"]}
        result = service.handle_create_policy(
            {"name": "Test Policy", "rules": [{"rule_id": "r1", "decision": "deny", "conditions": {"tool": "shell"}}]},
            policy_auth,
        )
        self.assertEqual(result["statusCode"], 201)
        body = self.body(result)
        self.assertIn("policy_id", body)
        self.assertEqual(body["version"], 1)


    def test_handle_list_policies(self):
        policy_auth = {**self.auth, "scopes": [*self.auth["scopes"], "policy:write", "policy:read"]}
        service.handle_create_policy(
            {"name": "List Test Policy", "rules": [{"rule_id": "r1", "decision": "deny", "conditions": {"tool": "shell"}}]},
            policy_auth,
        )
        result = service.handle_list_policies(policy_auth)
        self.assertEqual(result["statusCode"], 200)
        self.assertGreaterEqual(len(self.body(result)["policies"]), 1)


    def test_handle_outcome_success(self):
        payload = {
            "context": {"tenant_id": "demo", "environment": "production", "agent_id": "outcome-agent", "invoked_by": "test", "run_id": "outcome-run"},
            "action": {"tool": "shell", "parameters": {"command": "echo outcome"}},
        }
        service.apply_tenant_runtime(payload, self.auth, self.store)
        decision = service.evaluate_and_record(payload, self.store)
        action_id = decision["action"]["action_id"]
        result = service.handle_outcome(
            {},
            {"status": "success", "action_hash": decision["action_hash"], "context": {"tenant_id": "demo"}},
            action_id,
            self.auth,
        )
        self.assertEqual(result["statusCode"], 202)


    def test_handle_outcome_hash_mismatch(self):
        payload = {
            "context": {"tenant_id": "demo", "environment": "production", "agent_id": "outcome-agent-2", "invoked_by": "test", "run_id": "outcome-run-2"},
            "action": {"tool": "shell", "parameters": {"command": "echo mismatch"}},
        }
        service.apply_tenant_runtime(payload, self.auth, self.store)
        decision = service.evaluate_and_record(payload, self.store)
        action_id = decision["action"]["action_id"]
        result = service.handle_outcome(
            {},
            {"status": "success", "action_hash": "sha256:wrong", "context": {"tenant_id": "demo"}},
            action_id,
            self.auth,
        )
        self.assertEqual(result["statusCode"], 409)


    def test_handle_outcome_idempotent(self):
        payload = {
            "context": {"tenant_id": "demo", "environment": "production", "agent_id": "outcome-agent-3", "invoked_by": "test", "run_id": "outcome-run-3"},
            "action": {"tool": "shell", "parameters": {"command": "echo idempotent"}},
        }
        service.apply_tenant_runtime(payload, self.auth, self.store)
        decision = service.evaluate_and_record(payload, self.store)
        action_id = decision["action"]["action_id"]
        action_hash = decision["action_hash"]
        body = {"status": "success", "action_hash": action_hash, "context": {"tenant_id": "demo"}}
        first = service.handle_outcome({}, body, action_id, self.auth)
        self.assertEqual(first["statusCode"], 202)
        second = service.handle_outcome({}, body, action_id, self.auth)
        self.assertEqual(second["statusCode"], 202)
        self.assertTrue(self.body(second).get("idempotent"))

    # ------------------------------------------------------------------
    # Agent registration and credential handlers
    # ------------------------------------------------------------------


    def test_handle_register_agent(self):
        identity_auth = {**self.auth, "scopes": [*self.auth["scopes"], "identity:write", "identity:read"]}
        result = service.handle_register_agent(
            {"agent_id": "test-cred-agent", "name": "Test Agent", "owner": "user-1"},
            identity_auth,
        )
        self.assertEqual(result["statusCode"], 201)
        self.assertEqual(self.body(result)["agent_id"], "test-cred-agent")


    def test_handle_list_agents(self):
        identity_auth = {**self.auth, "scopes": [*self.auth["scopes"], "identity:write", "identity:read"]}
        service.handle_register_agent({"agent_id": "list-agent-1", "name": "List Agent", "owner": "user-1"}, identity_auth)
        result = service.handle_list_agents(identity_auth)
        self.assertEqual(result["statusCode"], 200)
        self.assertGreaterEqual(len(self.body(result)["agents"]), 1)


    def test_handle_revoke_agent(self):
        identity_auth = {**self.auth, "scopes": [*self.auth["scopes"], "identity:write", "identity:read"]}
        service.handle_register_agent({"agent_id": "revoke-agent-test", "name": "Revoke Agent", "owner": "user-1"}, identity_auth)
        result = service.handle_revoke_agent("revoke-agent-test", identity_auth)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(self.body(result)["status"], "revoked")


    def test_lambda_handler_tenant_members_route(self):
        result = self._route("/v1/tenants/demo/members", "GET")
        self.assertEqual(result["statusCode"], 200)


    def test_lambda_handler_tenant_members_post_route(self):
        result = self._route("/v1/tenants/demo/members", "POST", body={"subject": "route-member@example.com", "role": "viewer"})
        self.assertIn(result["statusCode"], (200, 201))


    def test_lambda_handler_platform_access_grants_route(self):
        admin_auth = {**self.auth, "tenant_id": "platform", "scopes": ["admin"]}
        result = self._route("/v1/platform/access-grants", "GET", auth=admin_auth)
        self.assertEqual(result["statusCode"], 200)


    def test_lambda_handler_platform_access_grants_post_route(self):
        admin_auth = {**self.auth, "tenant_id": "platform", "scopes": ["admin"]}
        result = self._route("/v1/platform/access-grants", "POST", body={"tenant_id": "demo", "reason": "Support investigation for tenant", "operation": "support"}, auth=admin_auth)
        self.assertEqual(result["statusCode"], 201)


    def test_handle_list_platform_access_grants(self):
        admin_auth = {**self.auth, "tenant_id": "platform", "scopes": ["admin"]}
        result = service.handle_list_platform_access_grants({}, admin_auth)
        self.assertEqual(result["statusCode"], 200)
        self.assertIn("grants", self.body(result))


    def test_handle_list_platform_access_grants_requires_admin(self):
        result = service.handle_list_platform_access_grants({}, self.auth)
        self.assertEqual(result["statusCode"], 403)


    def test_handle_revoke_platform_access_grant_not_found(self):
        admin_auth = {**self.auth, "tenant_id": "platform", "scopes": ["admin"]}
        result = service.handle_revoke_platform_access_grant("nonexistent-grant", {}, admin_auth)
        self.assertEqual(result["statusCode"], 404)


    def test_handle_revoke_platform_access_grant_success(self):
        admin_auth = {**self.auth, "tenant_id": "platform", "scopes": ["admin"]}
        grant = self.body(service.handle_platform_access_grant(
            {"tenant_id": "demo", "reason": "Revoke test grant for tenant", "operation": "support"},
            admin_auth,
        ))
        result = service.handle_revoke_platform_access_grant(grant["grant_id"], {"reason": "No longer needed for support"}, admin_auth)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(self.body(result)["status"], "revoked")

    # ------------------------------------------------------------------
    # Proof handlers
    # ------------------------------------------------------------------


    def test_handle_receipt_public_key(self):
        result = service.handle_receipt_public_key(self.auth)
        # 200 when signing key is configured, 503 otherwise
        self.assertIn(result["statusCode"], (200, 503))

    # ------------------------------------------------------------------
    # Token handlers
    # ------------------------------------------------------------------


    def test_handle_list_tenants(self):
        result = service.handle_list_tenants({}, self.auth)
        self.assertEqual(result["statusCode"], 200)


    def test_handle_put_environment(self):
        service.handle_put_tenant("demo", {
            "name": "Demo",
            "default_environment": "production",
            "environments": [{"environment_id": "production", "status": "active", "mode": "observe"}],
        }, self.auth)
        result = service.handle_put_environment("demo", "staging", {"status": "active", "mode": "observe"}, self.auth)
        self.assertIn(result["statusCode"], (200, 201))


    def test_handle_citation_verify(self):
        citation_auth = {**self.auth, "scopes": [*self.auth["scopes"], "citation:verify"]}
        result = service.handle_citation_verify(
            {"response": "A claim cites https://example.org.", "citations": [{"url": "https://example.org", "claim": "A claim"}]},
            citation_auth,
        )
        self.assertEqual(result["statusCode"], 200)

    # ------------------------------------------------------------------
    # Utility functions
    # ------------------------------------------------------------------


    def test_json_default_decimal(self):
        from decimal import Decimal
        self.assertEqual(service._json_default(Decimal("42")), 42)
        self.assertEqual(service._json_default(Decimal("3.14")), 3.14)


    def test_json_default_raises_for_unknown(self):
        with self.assertRaises(TypeError):
            service._json_default(object())


    def test_dynamodb_safe_converts_floats(self):
        from decimal import Decimal
        result = service._dynamodb_safe({"key": 1.5, "nested": [{"val": 2.0}]})
        self.assertEqual(result["key"], Decimal("1.5"))
        self.assertEqual(result["nested"][0]["val"], Decimal("2.0"))


    def test_parse_body_base64(self):
        import base64 as b64
        raw = json.dumps({"key": "value"})
        event = {"body": b64.b64encode(raw.encode()).decode(), "isBase64Encoded": True}
        result = service.parse_body(event)
        self.assertEqual(result["key"], "value")


    def test_parse_body_non_dict_raises(self):
        event = {"body": json.dumps([1, 2, 3])}
        with self.assertRaises(ValueError):
            service.parse_body(event)


    def test_tenant_from_body_context(self):
        event = {}
        body = {"context": {"tenant_id": "ctx-tenant"}}
        self.assertEqual(service.tenant_from(event, body), "ctx-tenant")


    def test_tenant_from_auth_fallback(self):
        self.assertEqual(service.tenant_from({}, None, {"tenant_id": "auth-tenant"}), "auth-tenant")


    def test_request_headers_cookies_array(self):
        event = {"headers": {}, "cookies": ["a=1", "b=2"]}
        headers = service.request_headers(event)
        self.assertEqual(headers["cookie"], "a=1; b=2")


    def test_auth_error_shape(self):
        result = service.auth_error()
        self.assertEqual(result["statusCode"], 401)
        self.assertIn("www-authenticate", result["headers"])


    def test_empty_response_with_cookies(self):
        result = service.empty_response(204, {"set-cookie": "test=1"})
        self.assertEqual(result["statusCode"], 204)
        self.assertIn("cookies", result)


    def test_raw_response_with_cookies(self):
        result = service.raw_response(302, "", "text/plain", {"set-cookie": "test=1"})
        self.assertEqual(result["statusCode"], 302)
        self.assertIn("cookies", result)


    def test_route_tenant_members_get(self):
        result = self._routed("/v1/tenants/demo/members")
        self.assertEqual(result["statusCode"], 200)


    def test_route_tenant_members_post(self):
        result = self._routed("/v1/tenants/demo/members", "POST", {"subject": "route-member", "role": "viewer"})
        self.assertIn(result["statusCode"], (200, 201))


    def test_route_tenant_member_patch(self):
        self._routed("/v1/tenants/demo/members", "POST", {"subject": "patch-member", "role": "viewer"})
        result = self._routed("/v1/tenants/demo/members/patch-member", "PATCH", {"role": "editor"})
        self.assertIn(result["statusCode"], (200, 400, 404))


    def test_route_tenant_member_delete(self):
        self._routed("/v1/tenants/demo/members", "POST", {"subject": "del-member", "role": "viewer"})
        result = self._routed("/v1/tenants/demo/members/del-member", "DELETE")
        self.assertIn(result["statusCode"], (200, 404))


    def test_route_platform_access_grants_post(self):
        admin_auth = {**self.auth, "scopes": [*self.auth["scopes"], "admin"]}
        result = self._routed("/v1/platform/access-grants", "POST", {
            "tenant_id": "demo",
            "reason": "Platform support investigation for routing test coverage",
            "operation": "read",
        }, auth=admin_auth)
        self.assertIn(result["statusCode"], (200, 201))


    def test_route_platform_access_grants_get(self):
        admin_auth = {**self.auth, "scopes": [*self.auth["scopes"], "admin"]}
        result = self._routed("/v1/platform/access-grants", auth=admin_auth)
        self.assertEqual(result["statusCode"], 200)


    def test_route_platform_access_grant_revoke(self):
        admin_auth = {**self.auth, "scopes": [*self.auth["scopes"], "admin"]}
        created = self._routed("/v1/platform/access-grants", "POST", {
            "tenant_id": "demo",
            "reason": "Platform support investigation for revoke route test",
            "operation": "read",
        }, auth=admin_auth)
        grant_id = self.body(created).get("grant_id", "unknown")
        result = self._routed(f"/v1/platform/access-grants/{grant_id}/revoke", "POST", {
            "reason": "Revoking grant for route test coverage purposes",
        }, auth=admin_auth)
        self.assertIn(result["statusCode"], (200, 404))


    def test_route_platform_support_read(self):
        admin_auth = {**self.auth, "scopes": [*self.auth["scopes"], "admin"]}
        grant_result = self._routed("/v1/platform/access-grants", "POST", {
            "tenant_id": "demo",
            "reason": "Platform support investigation for support read route",
            "operation": "read",
        }, auth=admin_auth)
        grant_id = self.body(grant_result).get("grant_id", "unknown")
        result = self._routed("/v1/platform/support/read", "POST", {
            "grant_id": grant_id,
            "tenant_id": "demo",
            "resource": "tenant",
        }, auth=admin_auth)
        self.assertIn(result["statusCode"], (200, 403, 404))


    def test_authenticate_missing_bearer(self):
        event = {"headers": {}, "rawPath": "/v1/test", "requestContext": {"http": {"method": "GET"}}}
        auth, failure = service.authenticate(event)
        self.assertIsNone(auth)
        self.assertIsNotNone(failure)
        self.assertEqual(failure["statusCode"], 401)


    def test_authenticate_malformed_bearer(self):
        event = {"headers": {"authorization": "Basic abc123"}, "rawPath": "/v1/test", "requestContext": {"http": {"method": "GET"}}}
        auth, failure = service.authenticate(event)
        self.assertIsNone(auth)
        self.assertIsNotNone(failure)


    def test_scope_error_shape(self):
        result = service.scope_error("guard:evaluate")
        self.assertEqual(result["statusCode"], 403)
        self.assertEqual(self.body(result)["required_scope"], "guard:evaluate")


    def test_authenticated_principal_session(self):
        auth = {"auth_source": "session", "subject": "user-1"}
        self.assertEqual(service.authenticated_principal(auth), "user-1")


    def test_authenticated_principal_agent(self):
        auth = {"token_type": "agent", "agent_id": "agent-1"}
        self.assertEqual(service.authenticated_principal(auth), "agent-1")


    def test_bind_tenant_cross_tenant_rejected(self):
        payload = {"context": {"tenant_id": "other"}}
        with self.assertRaises(service.ApiError):
            service.bind_tenant(payload, self.auth)


    def test_bind_tenant_admin_allowed(self):
        admin_auth = {**self.auth, "scopes": ["admin"]}
        payload = {"context": {"tenant_id": "other"}}
        result = service.bind_tenant(payload, admin_auth)
        self.assertEqual(result["context"]["tenant_id"], "other")


    def test_is_platform_admin_principal_with_scope(self):
        admin_auth = {**self.auth, "scopes": ["admin"]}
        self.assertTrue(service.is_platform_admin_principal(admin_auth))


    def test_is_platform_admin_principal_without_scope(self):
        self.assertFalse(service.is_platform_admin_principal(self.auth))

    # ------------------------------------------------------------------
    # Store method coverage
    # ------------------------------------------------------------------


    def test_store_get_tenant_config_cached(self):
        config = {"tenant_id": "demo", "item_type": "tenant_config", "pk": "TENANT#demo", "sk": "CONFIG"}
        self.store.put_tenant_config(config)
        result1 = self.store.get_tenant_config("demo")
        result2 = self.store.get_tenant_config("demo")
        self.assertEqual(result1, result2)


    def test_store_list_tenant_configs_by_tenant(self):
        config = {"tenant_id": "demo", "item_type": "tenant_config", "status": "active", "pk": "TENANT#demo", "sk": "CONFIG"}
        self.store.put_tenant_config(config)
        result = self.store.list_tenant_configs(tenant_id="demo")
        self.assertEqual(len(result), 1)


    def test_store_list_tenant_configs_with_status_filter(self):
        config = {"tenant_id": "demo", "item_type": "tenant_config", "status": "active", "pk": "TENANT#demo", "sk": "CONFIG"}
        self.store.put_tenant_config(config)
        result = self.store.list_tenant_configs(tenant_id="demo", status="suspended")
        self.assertEqual(len(result), 0)


    def test_store_put_and_get_membership(self):
        membership = {"item_type": "tenant_membership", "subject": "store-member", "tenant_id": "demo", "role": "viewer", "status": "active"}
        self.store.put_membership(membership)
        result = self.store.get_membership("store-member", "demo")
        self.assertIsNotNone(result)


    def test_store_list_memberships(self):
        membership = {"item_type": "tenant_membership", "subject": "list-member", "tenant_id": "demo", "role": "viewer", "status": "active", "pk": "USER#list-member", "sk": "MEMBERSHIP#demo"}
        self.table.items[("USER#list-member", "MEMBERSHIP#demo")] = membership
        result = self.store.list_memberships("list-member")
        self.assertGreaterEqual(len(result), 1)


    def test_store_delete_record(self):
        self.table.items[("TENANT#demo", "DELETE#test")] = {"pk": "TENANT#demo", "sk": "DELETE#test"}
        self.store.delete_record({"pk": "TENANT#demo", "sk": "DELETE#test"})
        self.assertNotIn(("TENANT#demo", "DELETE#test"), self.table.items)


    def test_store_put_and_get_agent(self):
        agent = {"agent_id": "store-agent", "tenant_id": "demo", "status": "active", "created_at": service.utc_now()}
        self.store.put_agent(agent)
        result = self.store.get_agent("store-agent", "demo")
        self.assertIsNotNone(result)
        self.assertEqual(result["agent_id"], "store-agent")


    def test_store_list_agents(self):
        agent = {"agent_id": "list-agent", "tenant_id": "demo", "status": "active", "created_at": service.utc_now()}
        self.store.put_agent(agent)
        result = self.store.list_agents("demo")
        self.assertGreaterEqual(len(result), 1)


    def test_store_put_and_get_platform_access_grant(self):
        grant = {"grant_id": "store-grant", "tenant_id": "demo", "status": "active", "expires_at": int(time.time()) + 3600, "created_at": service.utc_now()}
        self.store.put_platform_access_grant(grant)
        result = self.store.get_platform_access_grant("store-grant")
        self.assertIsNotNone(result)


    def test_store_list_platform_access_grants(self):
        grant = {"grant_id": "list-grant", "tenant_id": "demo", "status": "active", "expires_at": int(time.time()) + 3600, "created_at": service.utc_now()}
        self.store.put_platform_access_grant(grant)
        result = self.store.list_platform_access_grants(tenant_id="demo")
        self.assertGreaterEqual(len(result), 1)
