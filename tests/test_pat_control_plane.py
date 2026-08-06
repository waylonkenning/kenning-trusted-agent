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




class PatControlPlaneTests(unittest.TestCase):
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



    def test_session_authentication_accepts_embedded_browser_pat_header(self):
        presented = "kta_pat_embedded-browser-test"
        token_table = Mock()
        token_table.get_item.return_value = {
            "Item": {
                "tenant_id": "demo",
                "token_id": "pat-embedded-browser-test",
                "token_type": "pat",
                "status": "active",
                "scopes": ["tenant:read"],
            }
        }
        with patch.object(service, "token_table", token_table):
            auth, error = service.authenticate(
                {"headers": {"X-Kenning-PAT": presented}, "rawPath": "/auth/session", "requestContext": {"http": {"method": "POST"}}}
            )
        self.assertIsNone(error)
        self.assertEqual(auth["token_id"], "pat-embedded-browser-test")


    def test_session_authentication_accepts_embedded_browser_pat_body(self):
        presented = "kta_pat_embedded-browser-body-test"
        token_table = Mock()
        token_table.get_item.return_value = {
            "Item": {
                "tenant_id": "demo",
                "token_id": "pat-embedded-browser-body-test",
                "token_type": "pat",
                "status": "active",
                "scopes": ["tenant:read"],
            }
        }
        event = {"headers": {}, "rawPath": "/auth/session", "requestContext": {"http": {"method": "POST"}}}
        with patch.object(service, "token_table", token_table):
            auth, error = service.authenticate(event, {"personal_access_token": presented})
        self.assertIsNone(error)
        self.assertEqual(auth["token_id"], "pat-embedded-browser-body-test")


    def test_pat_control_plane_creates_lists_and_revokes_tokens(self):
        created = service.handle_create_token(
            {"name": "automation-child", "scopes": ["guard:evaluate"], "expires_in_days": 1},
            self.auth,
        )
        self.assertEqual(created["statusCode"], 201)
        created_body = self.body(created)
        self.assertTrue(created_body["token"].startswith("kta_pat_"))
        self.assertEqual(created_body["token_metadata"]["scopes"], ["guard:evaluate"])
        self.assertNotIn("token_hash", repr(created_body["token_metadata"]))
        token_id = created_body["token_metadata"]["token_id"]

        listed = service.handle_list_tokens({"queryStringParameters": {"tenant_id": "demo"}}, self.auth)
        self.assertEqual(listed["statusCode"], 200)
        listed_body = self.body(listed)
        self.assertEqual(len(listed_body["tokens"]), 1)
        self.assertNotIn("token_hash", repr(listed_body))
        self.assertNotIn(created_body["token"], repr(listed_body))
        self.assertEqual(self.token_table.scan_calls, 0)
        self.assertGreaterEqual(self.token_table.query_calls, 1)

        revoked = service.handle_revoke_token(token_id, {}, self.auth)
        self.assertEqual(revoked["statusCode"], 200)
        self.assertEqual(self.body(revoked)["token_metadata"]["status"], "revoked")
        self.assertEqual(service.authenticate({"headers": {"Authorization": f"Bearer {created_body['token']}"}})[1]["statusCode"], 401)


    def test_pat_control_plane_inherits_and_restricts_reviewer_groups(self):
        grouped_auth = {**self.auth, "groups": ["security", "platform"]}
        created = service.handle_create_token(
            {"name": "security-reviewer", "scopes": ["approve:actions"]},
            grouped_auth,
        )
        self.assertEqual(created["statusCode"], 201)
        created_body = self.body(created)
        self.assertEqual(created_body["token_metadata"]["groups"], ["platform", "security"])
        escalated = service.handle_create_token(
            {"name": "escalated-reviewer", "scopes": ["approve:actions"], "groups": ["finance"]},
            grouped_auth,
        )
        self.assertEqual(escalated["statusCode"], 403)
        self.assertEqual(self.body(escalated)["error"], "token_group_escalation")


    def test_agent_registry_can_list_tenant_identities(self):
        registered = service.handle_register_agent(
            {
                "context": {"tenant_id": "demo"},
                "agent_id": "listed-agent",
                "owner": "identity-test",
                "approved_tools": ["shell"],
            },
            self.auth,
        )
        self.assertEqual(registered["statusCode"], 201)
        listed = service.handle_list_agents(self.auth)
        self.assertEqual(listed["statusCode"], 200)
        self.assertEqual(self.body(listed)["tenant_id"], "demo")
        self.assertEqual(self.body(listed)["agents"][0]["agent_id"], "listed-agent")
        self.assertEqual(self.table.scan_calls, 0)
        self.assertGreaterEqual(self.table.query_calls, 1)


    def test_agent_credential_can_delegate_child_within_authority_ceiling(self):
        parent = service.handle_register_agent(
            {
                "context": {"tenant_id": "demo"},
                "agent_id": "delegating-parent",
                "owner": "identity-test",
                "approved_tools": ["shell"],
                "maximum_authority": "high",
                "conditions": {"can_delegate_agents": True},
            },
            {**self.auth, "scopes": self.auth["scopes"] + ["identity:write"]},
        )
        self.assertEqual(parent["statusCode"], 201)
        parent_auth = {
            "tenant_id": "demo",
            "token_type": "agent",
            "token_id": "cred-parent",
            "agent_id": "delegating-parent",
            "scopes": ["identity:write"],
        }
        child = service.handle_register_agent(
            {
                "context": {"tenant_id": "demo"},
                "agent_id": "delegated-child",
                "purpose": "Perform bounded work",
                "approved_tools": ["shell"],
                "maximum_authority": "standard",
            },
            parent_auth,
        )
        self.assertEqual(child["statusCode"], 201)
        child_body = self.body(child)
        self.assertEqual(child_body["parent_agent_id"], "delegating-parent")
        self.assertEqual(child_body["delegated_by"], "delegating-parent")
        self.assertEqual(child_body["delegation_chain"], ["pat-admin-test", "delegating-parent"])
        self.assertEqual(child_body["maximum_authority"], "standard")


    def test_agent_credential_cannot_escalate_child_authority(self):
        parent = service.handle_register_agent(
            {
                "context": {"tenant_id": "demo"},
                "agent_id": "standard-parent",
                "approved_tools": ["shell"],
                "maximum_authority": "standard",
                "conditions": {"can_delegate_agents": True},
            },
            self.auth,
        )
        self.assertEqual(parent["statusCode"], 201)
        parent_auth = {
            "tenant_id": "demo",
            "token_type": "agent",
            "token_id": "cred-standard-parent",
            "agent_id": "standard-parent",
            "scopes": ["identity:write"],
        }
        denied = service.handle_register_agent(
            {
                "context": {"tenant_id": "demo"},
                "agent_id": "escalating-child",
                "approved_tools": ["shell"],
                "maximum_authority": "high",
            },
            parent_auth,
        )
        self.assertEqual(denied["statusCode"], 403)
        self.assertEqual(self.body(denied)["error"], "agent_authority_escalation")


    def test_agent_credential_cannot_escalate_issued_scopes(self):
        registered = service.handle_register_agent(
            {
                "context": {"tenant_id": "demo"},
                "agent_id": "scope-limited-agent",
                "approved_tools": ["shell"],
            },
            self.auth,
        )
        self.assertEqual(registered["statusCode"], 201)
        denied = service.handle_issue_agent_credential(
            "scope-limited-agent",
            {"context": {"tenant_id": "demo"}, "scopes": ["audit:write"]},
            {
                "tenant_id": "demo",
                "token_type": "agent",
                "token_id": "cred-scope-limited",
                "agent_id": "scope-limited-agent",
                "scopes": ["identity:write"],
            },
        )
        self.assertEqual(denied["statusCode"], 403)
        self.assertEqual(self.body(denied)["error"], "agent_credential_scope_escalation")


    def test_agent_credentials_use_agent_lookup_index(self):
        registered = service.handle_register_agent(
            {
                "context": {"tenant_id": "demo"},
                "agent_id": "credential-listed-agent",
                "owner": "identity-test",
                "approved_tools": ["shell"],
            },
            self.auth,
        )
        self.assertEqual(registered["statusCode"], 201)
        issued = service.handle_issue_agent_credential(
            "credential-listed-agent",
            {"context": {"tenant_id": "demo"}},
            self.auth,
        )
        self.assertEqual(issued["statusCode"], 201)
        listed = service.handle_list_agent_credentials("credential-listed-agent", self.auth)
        self.assertEqual(listed["statusCode"], 200)
        self.assertEqual(len(self.body(listed)["credentials"]), 1)
        self.assertEqual(self.token_table.scan_calls, 0)
        self.assertGreaterEqual(self.token_table.query_calls, 1)


    def test_agent_credential_cannot_submit_outcome_for_another_agents_action(self):
        action_id = "action-other-agent"
        self.store.put_event(
            {
                "event_type": "action.evaluated",
                "tenant_id": "demo",
                "run_id": "run-agent-binding",
                "action_id": action_id,
                "agent_id": "other-agent",
                "invoked_by": "requester@example.org",
                "created_at": "2026-07-16T00:00:00Z",
                "decision": "allow",
                "action_hash": "hash-other-agent",
            }
        )
        agent_auth = {**self.auth, "token_type": "agent", "agent_id": "bound-agent", "scopes": ["actions:write"]}

        denied = service.handle_outcome(
            {},
            {"tenant_id": "demo", "action_hash": "hash-other-agent", "status": "success"},
            action_id,
            agent_auth,
        )

        self.assertEqual(denied["statusCode"], 403)
        self.assertEqual(self.body(denied)["error"], "agent_credential_mismatch")


    def test_aws_iam_workload_authentication_maps_role_and_rejects_bearer_fallback(self):
        config = build_tenant_config(
            "demo",
            {
                "workload_identity": {
                    "enabled": True,
                    "provider": "aws_iam",
                    "allowed_account_ids": ["123456789012"],
                    "mappings": [{
                        "principal_arn": "arn:aws:iam::123456789012:role/procurement-*",
                        "agent_id": "procurement-agent",
                        "scopes": ["guard:evaluate", "audit:read"],
                        "maximum_authority": "standard",
                    }],
                }
            },
        )
        self.store.put_tenant_config(config)
        self.table.put_item({
            "pk": "AGENT#procurement-agent",
            "sk": "METADATA",
            "agent_id": "procurement-agent",
            "tenant_id": "demo",
            "status": "active",
            "maximum_authority": "admin",
            "approved_tools": ["aws"],
        })
        event = {
            "headers": {
                "Authorization": "Bearer kta_pat_should-not-be-used",
                "X-Kenning-Tenant-Id": "demo",
            },
            "requestContext": {
                "authorizer": {
                    "iam": {
                        "userArn": "arn:aws:iam::123456789012:role/procurement-prod",
                        "accountId": "123456789012",
                        "callerId": "AIDAEXAMPLE",
                    }
                }
            },
        }
        auth, error = service.authenticate(event, {"context": {"tenant_id": "demo", "agent_id": "spoofed"}})
        self.assertIsNone(error)
        self.assertEqual(auth["auth_source"], "aws_iam")
        self.assertEqual(auth["token_type"], "workload")
        self.assertEqual(auth["agent_id"], "procurement-agent")
        self.assertEqual(service.authenticated_principal(auth), "arn:aws:iam::123456789012:role/procurement-prod")
        bound = service.bind_tenant({"context": {"tenant_id": "demo", "agent_id": "procurement-agent"}}, auth)
        self.assertEqual(bound["context"]["invoked_by"], "arn:aws:iam::123456789012:role/procurement-prod")
        workload_payload = {
            "context": {"tenant_id": "demo", "agent_id": "procurement-agent"},
            "action": {"tool": "aws", "operation": "delete", "target": "security-group", "parameters": {"reversible": False}},
        }
        service.apply_tenant_runtime(workload_payload, auth, self.store)
        decision = service.evaluate_and_record(workload_payload, self.store)
        self.assertEqual(decision["identity"]["maximum_authority"], "standard")
        self.assertIn("AUTHORITY_CEILING", decision["reason_codes"])

        unmapped = {
            **event,
            "requestContext": {"authorizer": {"iam": {"userArn": "arn:aws:iam::123456789012:role/other"}}},
        }
        rejected, response = service.authenticate(unmapped, {"context": {"tenant_id": "demo"}})
        self.assertIsNone(rejected)
        self.assertEqual(response["statusCode"], 401)

    # ------------------------------------------------------------------
    # Store-level unit tests: expire_approval, revoke_approval, consume
    # ------------------------------------------------------------------


    def test_handle_create_session_from_pat(self):
        pat_auth = {
            "token_type": "pat",
            "auth_source": "pat",
            "tenant_id": "demo",
            "subject": "pat-user@example.org",
            "token_id": "pat-session-test",
            "scopes": ["session:create", "tenant:read"],
        }
        with patch.object(service, "token_table", self.token_table):
            result = service.handle_create_session({"headers": {}}, pat_auth)
        self.assertEqual(result["statusCode"], 201)
        body = self.body(result)
        self.assertEqual(body["user"]["subject"], "pat-user@example.org")
        self.assertIn("set-cookie", result["headers"])


    def test_handle_csrf_issues_token_for_session(self):
        session_auth = self._session_auth()
        self.token_table.items["fake-session-hash"] = {"token_hash": "fake-session-hash", "status": "active"}
        with patch.object(service, "token_table", self.token_table):
            result = service.handle_csrf(session_auth)
        self.assertEqual(result["statusCode"], 200)
        self.assertIn("csrf_token", self.body(result))


    def test_handle_create_invitation_returns_token_and_link(self):
        result = service.handle_create_invitation("demo", {"role": "viewer"}, {}, self.auth)
        self.assertEqual(result["statusCode"], 201)
        body = self.body(result)
        self.assertTrue(body["token"].startswith("kta_invite_"))
        self.assertIn("link", body)
        self.assertEqual(body["role"], "viewer")
        self.assertEqual(body["status"], "active")
        self.assertEqual(body["max_uses"], 1)


    def test_handle_redeem_invitation_rejects_exhausted_token(self):
        created = self.body(service.handle_create_invitation("demo", {"role": "viewer", "max_uses": 1}, {}, self.auth))
        token = created["token"]
        first = service.handle_redeem_invitation({"token": token, "subject": "first@example.org"}, {}, self.auth)
        self.assertEqual(first["statusCode"], 200)
        second = service.handle_redeem_invitation({"token": token, "subject": "second@example.org"}, {}, self.auth)
        self.assertEqual(second["statusCode"], 409)


    def test_handle_get_agent_returns_registered_agent(self):
        service.handle_register_agent(
            {"context": {"tenant_id": "demo"}, "agent_id": "get-test-agent", "owner": "test", "approved_tools": ["shell"]},
            self.auth,
        )
        result = service.handle_get_agent("get-test-agent", self.auth)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(self.body(result)["agent_id"], "get-test-agent")


    def test_handle_get_agent_returns_404_for_missing(self):
        result = service.handle_get_agent("nonexistent-agent", self.auth)
        self.assertEqual(result["statusCode"], 404)


    def test_handle_revoke_agent_sets_status(self):
        service.handle_register_agent(
            {"context": {"tenant_id": "demo"}, "agent_id": "revoke-test-agent", "owner": "test", "approved_tools": ["shell"]},
            self.auth,
        )
        result = service.handle_revoke_agent("revoke-test-agent", self.auth)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(self.body(result)["status"], "revoked")

    # ------------------------------------------------------------------
    # Platform access grant handlers
    # ------------------------------------------------------------------


    def test_lambda_handler_returns_404_for_unknown_path(self):
        event = {
            "rawPath": "/v1/nonexistent",
            "requestContext": {"http": {"method": "GET"}},
            "headers": {"authorization": "Bearer kta_pat_test"},
        }
        with patch.object(service, "authenticate", return_value=(self.auth, None)):
            result = service.lambda_handler(event, None)
        self.assertEqual(result["statusCode"], 404)
        self.assertEqual(self.body(result)["error"], "not_found")


    def test_handle_csrf_returns_token_for_session(self):
        from app.control_plane import session_hash as sh
        token = "kta_session_csrf_test_token"
        self.token_table.put_item(Item={
            "token_hash": sh(token),
            "token_id": "sess-csrf",
            "token_type": "session",
            "status": "active",
            "tenant_id": "demo",
            "subject": "user-1",
            "expires_at": int(time.time()) + 3600,
        })
        session_auth = {**self.auth, "auth_source": "session", "token_type": "session", "token_hash": sh(token)}
        result = service.handle_csrf(session_auth)
        self.assertEqual(result["statusCode"], 200)
        self.assertIn("csrf_token", self.body(result))


    def test_handle_create_session_rejects_workload(self):
        workload_auth = {**self.auth, "token_type": "pat", "principal_type": "workload", "subject": "user-1"}
        result = service.handle_create_session({"headers": {}}, workload_auth)
        self.assertEqual(result["statusCode"], 403)


    def test_handle_redeem_invitation_no_token(self):
        result = service.handle_redeem_invitation({}, {}, self.auth)
        self.assertEqual(result["statusCode"], 400)


    def test_handle_accept_invitation_no_token(self):
        session_auth = {**self.auth, "auth_source": "session", "token_type": "session", "subject": "user-1"}
        result = service.handle_accept_invitation({}, session_auth)
        self.assertEqual(result["statusCode"], 400)


    def test_handle_register_agent_duplicate(self):
        identity_auth = {**self.auth, "scopes": [*self.auth["scopes"], "identity:write", "identity:read"]}
        service.handle_register_agent({"agent_id": "dup-agent", "name": "Dup", "owner": "user-1"}, identity_auth)
        result = service.handle_register_agent({"agent_id": "dup-agent", "name": "Dup", "owner": "user-1"}, identity_auth)
        self.assertEqual(result["statusCode"], 409)


    def test_handle_get_agent_not_found(self):
        identity_auth = {**self.auth, "scopes": [*self.auth["scopes"], "identity:read"]}
        result = service.handle_get_agent("nonexistent-agent", identity_auth)
        self.assertEqual(result["statusCode"], 404)


    def test_handle_get_agent_success(self):
        identity_auth = {**self.auth, "scopes": [*self.auth["scopes"], "identity:write", "identity:read"]}
        service.handle_register_agent({"agent_id": "get-agent-test", "name": "Get Agent", "owner": "user-1"}, identity_auth)
        result = service.handle_get_agent("get-agent-test", identity_auth)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(self.body(result)["agent_id"], "get-agent-test")


    def test_handle_revoke_agent_not_found(self):
        identity_auth = {**self.auth, "scopes": [*self.auth["scopes"], "identity:write"]}
        result = service.handle_revoke_agent("nonexistent-revoke-agent", identity_auth)
        self.assertEqual(result["statusCode"], 404)


    def test_handle_issue_agent_credential(self):
        identity_auth = {**self.auth, "scopes": [*self.auth["scopes"], "identity:write", "identity:read"]}
        service.handle_register_agent({"agent_id": "cred-agent-test", "name": "Cred Agent", "owner": "user-1"}, identity_auth)
        result = service.handle_issue_agent_credential("cred-agent-test", {"expires_in_seconds": 900}, identity_auth)
        self.assertEqual(result["statusCode"], 201)
        body = self.body(result)
        self.assertIn("token", body)
        self.assertTrue(body["token"].startswith("kta_agent_"))


    def test_handle_issue_agent_credential_not_active(self):
        identity_auth = {**self.auth, "scopes": [*self.auth["scopes"], "identity:write", "identity:read"]}
        service.handle_register_agent({"agent_id": "inactive-cred-agent", "name": "Inactive", "owner": "user-1"}, identity_auth)
        service.handle_revoke_agent("inactive-cred-agent", identity_auth)
        result = service.handle_issue_agent_credential("inactive-cred-agent", {}, identity_auth)
        self.assertEqual(result["statusCode"], 409)


    def test_handle_issue_agent_credential_invalid_lifetime(self):
        identity_auth = {**self.auth, "scopes": [*self.auth["scopes"], "identity:write", "identity:read"]}
        service.handle_register_agent({"agent_id": "lifetime-cred-agent", "name": "Lifetime", "owner": "user-1"}, identity_auth)
        with self.assertRaises(ValueError):
            service.handle_issue_agent_credential("lifetime-cred-agent", {"expires_in_seconds": 10}, identity_auth)


    def test_handle_issue_agent_credential_invalid_scope(self):
        identity_auth = {**self.auth, "scopes": [*self.auth["scopes"], "identity:write", "identity:read"]}
        service.handle_register_agent({"agent_id": "scope-cred-agent", "name": "Scope", "owner": "user-1"}, identity_auth)
        result = service.handle_issue_agent_credential("scope-cred-agent", {"scopes": ["admin:everything"]}, identity_auth)
        self.assertEqual(result["statusCode"], 400)


    def test_handle_list_agent_credentials(self):
        identity_auth = {**self.auth, "scopes": [*self.auth["scopes"], "identity:write", "identity:read"]}
        service.handle_register_agent({"agent_id": "list-cred-agent", "name": "List Cred", "owner": "user-1"}, identity_auth)
        service.handle_issue_agent_credential("list-cred-agent", {}, identity_auth)
        result = service.handle_list_agent_credentials("list-cred-agent", identity_auth)
        self.assertEqual(result["statusCode"], 200)
        self.assertGreaterEqual(len(self.body(result)["credentials"]), 1)


    def test_handle_get_agent_credential_not_found(self):
        identity_auth = {**self.auth, "scopes": [*self.auth["scopes"], "identity:write", "identity:read"]}
        service.handle_register_agent({"agent_id": "get-cred-agent", "name": "Get Cred", "owner": "user-1"}, identity_auth)
        result = service.handle_get_agent_credential("get-cred-agent", "nonexistent-cred", identity_auth)
        self.assertEqual(result["statusCode"], 404)


    def test_handle_revoke_agent_credential(self):
        identity_auth = {**self.auth, "scopes": [*self.auth["scopes"], "identity:write", "identity:read"]}
        service.handle_register_agent({"agent_id": "revoke-cred-agent", "name": "Revoke Cred", "owner": "user-1"}, identity_auth)
        issued = service.handle_issue_agent_credential("revoke-cred-agent", {}, identity_auth)
        cred_id = self.body(issued)["credential"]["credential_id"]
        result = service.handle_revoke_agent_credential("revoke-cred-agent", cred_id, identity_auth)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(self.body(result)["credential"]["status"], "revoked")


    def test_handle_revoke_agent_credential_not_found(self):
        identity_auth = {**self.auth, "scopes": [*self.auth["scopes"], "identity:write", "identity:read"]}
        service.handle_register_agent({"agent_id": "revoke-cred-nf-agent", "name": "Revoke Cred NF", "owner": "user-1"}, identity_auth)
        result = service.handle_revoke_agent_credential("revoke-cred-nf-agent", "nonexistent-cred", identity_auth)
        self.assertEqual(result["statusCode"], 404)

    # ------------------------------------------------------------------
    # MCP tools/call handlers
    # ------------------------------------------------------------------


    def test_mcp_issue_agent_credential(self):
        profile = service.MCP_PROFILES["agent-identity"]
        self._mcp_call("register_agent", {"agent_id": "mcp-cred-agent", "name": "MCP Cred", "owner": "user-1"}, profile=profile)
        result = self._mcp_call("issue_agent_credential", {"agent_id": "mcp-cred-agent"}, profile=profile)
        self.assertEqual(result["statusCode"], 200)
        content = self.body(result)["result"]["structuredContent"]
        self.assertIn("token", content)


    def test_mcp_list_agent_credentials(self):
        profile = service.MCP_PROFILES["agent-identity"]
        self._mcp_call("register_agent", {"agent_id": "mcp-list-cred-agent", "name": "MCP List Cred", "owner": "user-1"}, profile=profile)
        self._mcp_call("issue_agent_credential", {"agent_id": "mcp-list-cred-agent"}, profile=profile)
        result = self._mcp_call("list_agent_credentials", {"agent_id": "mcp-list-cred-agent"}, profile=profile)
        self.assertEqual(result["statusCode"], 200)
        content = self.body(result)["result"]["structuredContent"]
        self.assertGreaterEqual(len(content["credentials"]), 1)


    def test_mcp_get_agent_credential(self):
        profile = service.MCP_PROFILES["agent-identity"]
        self._mcp_call("register_agent", {"agent_id": "mcp-get-cred-agent", "name": "MCP Get Cred", "owner": "user-1"}, profile=profile)
        issued = self._mcp_call("issue_agent_credential", {"agent_id": "mcp-get-cred-agent"}, profile=profile)
        cred_id = self.body(issued)["result"]["structuredContent"]["credential"]["credential_id"]
        result = self._mcp_call("get_agent_credential", {"agent_id": "mcp-get-cred-agent", "credential_id": cred_id}, profile=profile)
        self.assertEqual(result["statusCode"], 200)


    def test_mcp_revoke_agent_credential(self):
        profile = service.MCP_PROFILES["agent-identity"]
        self._mcp_call("register_agent", {"agent_id": "mcp-rev-cred-agent", "name": "MCP Rev Cred", "owner": "user-1"}, profile=profile)
        issued = self._mcp_call("issue_agent_credential", {"agent_id": "mcp-rev-cred-agent"}, profile=profile)
        cred_id = self.body(issued)["result"]["structuredContent"]["credential"]["credential_id"]
        result = self._mcp_call("revoke_agent_credential", {"agent_id": "mcp-rev-cred-agent", "credential_id": cred_id}, profile=profile)
        self.assertEqual(result["statusCode"], 200)
        content = self.body(result)["result"]["structuredContent"]
        self.assertEqual(content["credential"]["status"], "revoked")


    def test_lambda_handler_agent_get_route(self):
        identity_auth = {**self.auth, "scopes": [*self.auth["scopes"], "identity:read", "identity:write"]}
        service.handle_register_agent({"agent_id": "route-get-agent", "name": "Route Get", "owner": "user-1"}, identity_auth)
        result = self._route("/v1/agents/route-get-agent", "GET", auth=identity_auth)
        self.assertEqual(result["statusCode"], 200)


    def test_lambda_handler_agent_revoke_route(self):
        identity_auth = {**self.auth, "scopes": [*self.auth["scopes"], "identity:read", "identity:write"]}
        service.handle_register_agent({"agent_id": "route-revoke-agent", "name": "Route Revoke", "owner": "user-1"}, identity_auth)
        result = self._route("/v1/agents/route-revoke-agent/revoke", "POST", body={}, auth=identity_auth)
        self.assertEqual(result["statusCode"], 200)


    def test_lambda_handler_agent_credentials_route(self):
        identity_auth = {**self.auth, "scopes": [*self.auth["scopes"], "identity:read", "identity:write"]}
        service.handle_register_agent({"agent_id": "route-cred-agent", "name": "Route Cred", "owner": "user-1"}, identity_auth)
        result = self._route("/v1/agents/route-cred-agent/credentials", "POST", body={}, auth=identity_auth)
        self.assertEqual(result["statusCode"], 201)
        result = self._route("/v1/agents/route-cred-agent/credentials", "GET", auth=identity_auth)
        self.assertEqual(result["statusCode"], 200)


    def test_lambda_handler_tokens_route(self):
        token_auth = {**self.auth, "scopes": [*self.auth["scopes"], "token:admin"]}
        result = self._route("/v1/tokens", "GET", auth=token_auth)
        self.assertEqual(result["statusCode"], 200)


    def test_lambda_handler_tokens_post_route(self):
        token_auth = {**self.auth, "scopes": [*self.auth["scopes"], "token:admin"]}
        result = self._route("/v1/tokens", "POST", body={"name": "Route Token"}, auth=token_auth)
        self.assertEqual(result["statusCode"], 201)


    def test_handle_create_token(self):
        token_auth = {**self.auth, "scopes": [*self.auth["scopes"], "token:admin"]}
        result = service.handle_create_token({"name": "Test PAT"}, token_auth)
        self.assertEqual(result["statusCode"], 201)
        body = self.body(result)
        self.assertIn("token", body)
        self.assertTrue(body["token"].startswith("kta_pat_"))


    def test_handle_list_tokens(self):
        token_auth = {**self.auth, "scopes": [*self.auth["scopes"], "token:admin"]}
        service.handle_create_token({"name": "List PAT"}, token_auth)
        result = service.handle_list_tokens({}, token_auth)
        self.assertEqual(result["statusCode"], 200)


    def test_handle_revoke_token(self):
        token_auth = {**self.auth, "scopes": [*self.auth["scopes"], "token:admin"]}
        created = service.handle_create_token({"name": "Revoke PAT"}, token_auth)
        token_id = self.body(created)["token_metadata"]["token_id"]
        result = service.handle_revoke_token(token_id, {}, token_auth)
        self.assertEqual(result["statusCode"], 200)

    # ------------------------------------------------------------------
    # Audit handlers
    # ------------------------------------------------------------------


    def test_path_and_method(self):
        event = {"rawPath": "/v1/test/", "requestContext": {"http": {"method": "POST"}}}
        path, method = service.path_and_method(event)
        self.assertEqual(path, "/v1/test")
        self.assertEqual(method, "POST")


    def test_mcp_profile_for_path(self):
        self.assertIsNotNone(service.mcp_profile_for_path("/mcp"))
        self.assertIsNotNone(service.mcp_profile_for_path("/mcp/agent-guard"))
        self.assertIsNone(service.mcp_profile_for_path("/unknown"))


    def test_route_tokens_get(self):
        result = self._routed("/v1/tokens")
        self.assertEqual(result["statusCode"], 200)


    def test_route_tokens_post(self):
        result = self._routed("/v1/tokens", "POST", {"name": "route-test-token", "scopes": ["guard:evaluate"]})
        self.assertIn(result["statusCode"], (200, 201))


    def test_route_tokens_revoke(self):
        created = self._routed("/v1/tokens", "POST", {"name": "revoke-route-token", "scopes": ["guard:evaluate"]})
        created_body = self.body(created)
        token_id = created_body.get("token_id") or (created_body.get("token") or {}).get("token_id", "unknown") if isinstance(created_body.get("token"), dict) else created_body.get("token_id", "unknown")
        result = self._routed(f"/v1/tokens/{token_id}/revoke", "POST", {})
        self.assertIn(result["statusCode"], (200, 404))


    def test_route_agent_get(self):
        id_auth = {**self.auth, "scopes": [*self.auth["scopes"], "identity:write", "identity:read"]}
        self._routed("/v1/agents", "POST", {"agent_id": "route-get-agent", "name": "Route Get", "owner": "user-1"}, auth=id_auth)
        result = self._routed("/v1/agents/route-get-agent", auth=id_auth)
        self.assertIn(result["statusCode"], (200, 404))


    def test_route_agent_revoke(self):
        id_auth = {**self.auth, "scopes": [*self.auth["scopes"], "identity:write"]}
        self._routed("/v1/agents", "POST", {"agent_id": "route-revoke-agent", "name": "Route Revoke", "owner": "user-1"}, auth=id_auth)
        result = self._routed("/v1/agents/route-revoke-agent/revoke", "POST", {}, auth=id_auth)
        self.assertIn(result["statusCode"], (200, 404))


    def test_route_agent_credentials_post(self):
        id_auth = {**self.auth, "scopes": [*self.auth["scopes"], "identity:write", "identity:read"]}
        self._routed("/v1/agents", "POST", {"agent_id": "route-cred-agent", "name": "Route Cred", "owner": "user-1"}, auth=id_auth)
        result = self._routed("/v1/agents/route-cred-agent/credentials", "POST", {"expires_in_seconds": 900}, auth=id_auth)
        self.assertIn(result["statusCode"], (200, 201))


    def test_route_agent_credentials_get(self):
        id_auth = {**self.auth, "scopes": [*self.auth["scopes"], "identity:write", "identity:read"]}
        self._routed("/v1/agents", "POST", {"agent_id": "route-list-cred-agent", "name": "Route List Cred", "owner": "user-1"}, auth=id_auth)
        result = self._routed("/v1/agents/route-list-cred-agent/credentials", auth=id_auth)
        self.assertEqual(result["statusCode"], 200)


    def test_route_agent_credential_get(self):
        id_auth = {**self.auth, "scopes": [*self.auth["scopes"], "identity:write", "identity:read"]}
        self._routed("/v1/agents", "POST", {"agent_id": "route-get-cred-agent", "name": "Route Get Cred", "owner": "user-1"}, auth=id_auth)
        result = self._routed("/v1/agents/route-get-cred-agent/credentials/nonexistent", auth=id_auth)
        self.assertIn(result["statusCode"], (200, 404))


    def test_route_agent_credential_revoke(self):
        id_auth = {**self.auth, "scopes": [*self.auth["scopes"], "identity:write", "identity:read"]}
        self._routed("/v1/agents", "POST", {"agent_id": "route-rev-cred-agent", "name": "Route Rev Cred", "owner": "user-1"}, auth=id_auth)
        result = self._routed("/v1/agents/route-rev-cred-agent/credentials/nonexistent/revoke", "POST", {}, auth=id_auth)
        self.assertIn(result["statusCode"], (200, 404))


    def test_authenticate_pat_valid(self):
        token = "kta_pat_" + "a" * 32
        token_hash = __import__("hashlib").sha256(token.encode()).hexdigest()
        self.token_table.items[token_hash] = {
            "token_hash": token_hash,
            "token_id": "pat-auth-test",
            "token_type": "pat",
            "tenant_id": "demo",
            "scopes": ["guard:evaluate"],
            "status": "active",
            "expires_at": int(time.time()) + 3600,
        }
        event = {"headers": {"authorization": f"Bearer {token}"}, "rawPath": "/v1/test", "requestContext": {"http": {"method": "GET"}}}
        auth, failure = service.authenticate(event)
        self.assertIsNotNone(auth)
        self.assertIsNone(failure)
        self.assertEqual(auth["tenant_id"], "demo")


    def test_authenticate_pat_expired(self):
        token = "kta_pat_" + "b" * 32
        token_hash = __import__("hashlib").sha256(token.encode()).hexdigest()
        self.token_table.items[token_hash] = {
            "token_hash": token_hash,
            "token_id": "pat-expired",
            "token_type": "pat",
            "tenant_id": "demo",
            "scopes": ["guard:evaluate"],
            "status": "active",
            "expires_at": int(time.time()) - 100,
        }
        event = {"headers": {"authorization": f"Bearer {token}"}, "rawPath": "/v1/test", "requestContext": {"http": {"method": "GET"}}}
        auth, failure = service.authenticate(event)
        self.assertIsNone(auth)
        self.assertIsNotNone(failure)
        self.assertEqual(failure["statusCode"], 401)


    def test_authenticate_pat_inactive(self):
        token = "kta_pat_" + "c" * 32
        token_hash = __import__("hashlib").sha256(token.encode()).hexdigest()
        self.token_table.items[token_hash] = {
            "token_hash": token_hash,
            "token_id": "pat-inactive",
            "token_type": "pat",
            "tenant_id": "demo",
            "scopes": ["guard:evaluate"],
            "status": "revoked",
        }
        event = {"headers": {"authorization": f"Bearer {token}"}, "rawPath": "/v1/test", "requestContext": {"http": {"method": "GET"}}}
        auth, failure = service.authenticate(event)
        self.assertIsNone(auth)
        self.assertIsNotNone(failure)


    def test_authenticate_pat_not_found(self):
        token = "kta_pat_" + "d" * 32
        event = {"headers": {"authorization": f"Bearer {token}"}, "rawPath": "/v1/test", "requestContext": {"http": {"method": "GET"}}}
        auth, failure = service.authenticate(event)
        self.assertIsNone(auth)
        self.assertIsNotNone(failure)


    def test_authenticate_agent_credential_valid(self):
        token = "kta_agent_" + "e" * 32
        token_hash = __import__("hashlib").sha256(token.encode()).hexdigest()
        self.token_table.items[token_hash] = {
            "token_hash": token_hash,
            "token_id": "cred-auth-test",
            "token_type": "agent",
            "agent_id": "agent-auth-test",
            "tenant_id": "demo",
            "scopes": ["guard:evaluate"],
            "status": "active",
            "expires_at": int(time.time()) + 3600,
        }
        event = {"headers": {"authorization": f"Bearer {token}"}, "rawPath": "/v1/test", "requestContext": {"http": {"method": "GET"}}}
        auth, failure = service.authenticate(event)
        self.assertIsNotNone(auth)
        self.assertIsNone(failure)
        self.assertEqual(auth["agent_id"], "agent-auth-test")


    def test_authenticate_agent_credential_missing_agent_id(self):
        token = "kta_agent_" + "f" * 32
        token_hash = __import__("hashlib").sha256(token.encode()).hexdigest()
        self.token_table.items[token_hash] = {
            "token_hash": token_hash,
            "token_id": "cred-no-agent",
            "token_type": "agent",
            "tenant_id": "demo",
            "scopes": ["guard:evaluate"],
            "status": "active",
            "expires_at": int(time.time()) + 3600,
        }
        event = {"headers": {"authorization": f"Bearer {token}"}, "rawPath": "/v1/test", "requestContext": {"http": {"method": "GET"}}}
        auth, failure = service.authenticate(event)
        self.assertIsNone(auth)
        self.assertIsNotNone(failure)


    def test_authenticate_session_pat_header_fallback(self):
        token = "kta_pat_" + "g" * 32
        token_hash = __import__("hashlib").sha256(token.encode()).hexdigest()
        self.token_table.items[token_hash] = {
            "token_hash": token_hash,
            "token_id": "pat-session-fallback",
            "token_type": "pat",
            "tenant_id": "demo",
            "scopes": ["session:create"],
            "status": "active",
            "expires_at": int(time.time()) + 3600,
        }
        event = {
            "headers": {"x-kenning-pat": token},
            "rawPath": "/auth/session",
            "requestContext": {"http": {"method": "POST"}},
            "body": json.dumps({}),
        }
        auth, failure = service.authenticate(event, {})
        self.assertIsNotNone(auth)
        self.assertIsNone(failure)

    # ------------------------------------------------------------------
    # Auth route coverage (login, logout, callback)
    # ------------------------------------------------------------------


    def test_authenticated_principal_pat(self):
        auth = {"token_id": "pat-1"}
        self.assertEqual(service.authenticated_principal(auth), "pat-1")


    def test_bind_tenant_agent_binding(self):
        agent_auth = {**self.auth, "agent_id": "bound-agent"}
        payload = {"context": {"tenant_id": "demo", "agent_id": "different-agent"}}
        with self.assertRaises(service.ApiError):
            service.bind_tenant(payload, agent_auth)


    def test_mcp_register_agent_tool(self):
        mcp_auth = {**self.auth, "scopes": ["mcp:read", "identity:write"]}
        result = self._mcp_call("register_agent", {"agent_id": "mcp-reg-agent", "name": "MCP Agent", "owner": "user-1"}, auth=mcp_auth)
        self.assertEqual(result["statusCode"], 200)


    def test_mcp_get_agent_tool(self):
        mcp_auth = {**self.auth, "scopes": ["mcp:read", "identity:write", "identity:read"]}
        self._mcp_call("register_agent", {"agent_id": "mcp-get-agent", "name": "MCP Get", "owner": "user-1"}, auth=mcp_auth)
        result = self._mcp_call("get_agent", {"agent_id": "mcp-get-agent"}, auth=mcp_auth)
        self.assertEqual(result["statusCode"], 200)


    def test_mcp_revoke_agent_tool(self):
        mcp_auth = {**self.auth, "scopes": ["mcp:read", "identity:write"]}
        self._mcp_call("register_agent", {"agent_id": "mcp-rev-agent", "name": "MCP Rev", "owner": "user-1"}, auth=mcp_auth)
        result = self._mcp_call("revoke_agent", {"agent_id": "mcp-rev-agent"}, auth=mcp_auth)
        self.assertEqual(result["statusCode"], 200)


    def test_mcp_issue_agent_credential_tool(self):
        mcp_auth = {**self.auth, "scopes": ["mcp:read", "identity:write", "identity:read"]}
        self._mcp_call("register_agent", {"agent_id": "mcp-cred-agent", "name": "MCP Cred", "owner": "user-1"}, auth=mcp_auth)
        result = self._mcp_call("issue_agent_credential", {"agent_id": "mcp-cred-agent"}, auth=mcp_auth)
        self.assertEqual(result["statusCode"], 200)


    def test_mcp_list_agent_credentials_tool(self):
        mcp_auth = {**self.auth, "scopes": ["mcp:read", "identity:write", "identity:read"]}
        self._mcp_call("register_agent", {"agent_id": "mcp-lc-agent", "name": "MCP LC", "owner": "user-1"}, auth=mcp_auth)
        result = self._mcp_call("list_agent_credentials", {"agent_id": "mcp-lc-agent"}, auth=mcp_auth)
        self.assertEqual(result["statusCode"], 200)


    def test_mcp_get_agent_credential_tool(self):
        mcp_auth = {**self.auth, "scopes": ["mcp:read", "identity:write", "identity:read"]}
        self._mcp_call("register_agent", {"agent_id": "mcp-gc-agent", "name": "MCP GC", "owner": "user-1"}, auth=mcp_auth)
        result = self._mcp_call("get_agent_credential", {"agent_id": "mcp-gc-agent", "credential_id": "nonexistent"}, auth=mcp_auth)
        self.assertEqual(result["statusCode"], 200)


    def test_mcp_revoke_agent_credential_tool(self):
        mcp_auth = {**self.auth, "scopes": ["mcp:read", "identity:write", "identity:read"]}
        self._mcp_call("register_agent", {"agent_id": "mcp-rc-agent", "name": "MCP RC", "owner": "user-1"}, auth=mcp_auth)
        result = self._mcp_call("revoke_agent_credential", {"agent_id": "mcp-rc-agent", "credential_id": "nonexistent"}, auth=mcp_auth)
        self.assertEqual(result["statusCode"], 200)
