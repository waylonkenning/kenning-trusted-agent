"""Targeted branch coverage for agent-delegation validation in
app/lambda_function.py::_prepare_agent_registration (#271).

Covers the agent-token delegation path (parent mismatch, inactive delegating
agent, cycle, depth) and the requested-parent admin gate, plus the no-parent
admin-authority gate.
"""

import json
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
        event["body"] = json.dumps(body) if isinstance(body, dict) else body
    if query:
        event["queryStringParameters"] = query
    return event


class AgentDelegationCoverageTests(unittest.TestCase):
    def setUp(self):
        self.table = FakeTable()
        service.table = self.table
        self.token_table = FakeTokenTable()
        service.token_table = self.token_table
        self.admin_auth = {
            "tenant_id": "demo",
            "token_id": "pat-admin",
            "scopes": ["admin", "agent:write"],
            "subject": "admin@demo.test",
        }

    def _call(self, method, path, body=None, query=None, auth=None):
        event = make_event(method, path, body, query)
        with patch.object(service, "authenticate", return_value=(auth or self.admin_auth, None)):
            return service.lambda_handler(event, None)

    def _status(self, result):
        return result.get("statusCode", 200)

    def _body(self, result):
        raw = result.get("body", "{}")
        return json.loads(raw) if isinstance(raw, str) else raw

    def _put_agent(self, agent_id, **fields):
        item = {
            "pk": f"AGENT#{agent_id}", "sk": "METADATA",
            "agent_id": agent_id, "tenant_id": "demo",
            "status": "active", "item_type": "agent",
        }
        item.update(fields)
        self.table.put_item(Item=item)

    # --- Agent-token delegation path (caller_agent_id set) -----------------

    def test_agent_token_parent_mismatch(self):
        """Line 4002: agent token requests a parent that is not itself."""
        self._put_agent("caller-agent", conditions={"can_delegate_agents": True},
                        maximum_authority="admin")
        auth = {"tenant_id": "demo", "token_id": "t", "scopes": ["identity:write"],
                "agent_id": "caller-agent", "token_type": "agent"}
        result = self._call("POST", "/v1/agents",
                            {"agent_id": "child", "parent_agent_id": "some-other-parent"},
                            auth=auth)
        self.assertEqual(self._status(result), 403)
        self.assertEqual(self._body(result)["error"], "agent_delegation_parent_mismatch")

    def test_agent_token_delegating_agent_not_found(self):
        """Line 4005: agent token but the caller agent record is missing."""
        auth = {"tenant_id": "demo", "token_id": "t", "scopes": ["identity:write"],
                "agent_id": "ghost-agent", "token_type": "agent"}
        result = self._call("POST", "/v1/agents", {"agent_id": "child"}, auth=auth)
        self.assertEqual(self._status(result), 403)
        self.assertEqual(self._body(result)["error"], "delegating_agent_not_found")

    def test_agent_token_delegating_agent_not_active(self):
        """Line 4007: agent token caller exists but is suspended."""
        self._put_agent("suspended-caller", status="suspended",
                        conditions={"can_delegate_agents": True},
                        maximum_authority="admin")
        auth = {"tenant_id": "demo", "token_id": "t", "scopes": ["identity:write"],
                "agent_id": "suspended-caller", "token_type": "agent"}
        result = self._call("POST", "/v1/agents", {"agent_id": "child"}, auth=auth)
        self.assertEqual(self._status(result), 409)
        self.assertEqual(self._body(result)["error"], "delegating_agent_not_active")

    def test_agent_token_delegation_cycle(self):
        """Line 4023: agent token caller already appears in its own chain."""
        self._put_agent("cycle-caller",
                        conditions={"can_delegate_agents": True},
                        maximum_authority="admin",
                        delegation_chain=["root", "cycle-caller"])
        auth = {"tenant_id": "demo", "token_id": "t", "scopes": ["identity:write"],
                "agent_id": "cycle-caller", "token_type": "agent"}
        result = self._call("POST", "/v1/agents", {"agent_id": "child"}, auth=auth)
        self.assertEqual(self._status(result), 409)
        self.assertEqual(self._body(result)["error"], "agent_delegation_cycle")

    def test_agent_token_delegation_depth_exceeded(self):
        """Line 4026: agent token caller chain already at max depth."""
        deep_chain = [f"agent-{i}" for i in range(service.MAX_DELEGATION_DEPTH)]
        self._put_agent("deep-caller",
                        conditions={"can_delegate_agents": True},
                        maximum_authority="admin",
                        delegation_chain=deep_chain)
        auth = {"tenant_id": "demo", "token_id": "t", "scopes": ["identity:write"],
                "agent_id": "deep-caller", "token_type": "agent"}
        result = self._call("POST", "/v1/agents", {"agent_id": "child"}, auth=auth)
        self.assertEqual(self._status(result), 403)
        self.assertEqual(self._body(result)["error"], "agent_delegation_depth_exceeded")

    def test_agent_token_authority_escalation(self):
        """Line 4012-4020: agent token child requests higher authority than parent."""
        self._put_agent("limited-caller",
                        conditions={"can_delegate_agents": True},
                        maximum_authority="read")
        auth = {"tenant_id": "demo", "token_id": "t", "scopes": ["identity:write"],
                "agent_id": "limited-caller", "token_type": "agent"}
        result = self._call("POST", "/v1/agents",
                            {"agent_id": "child", "maximum_authority": "admin"},
                            auth=auth)
        self.assertEqual(self._status(result), 403)
        self.assertEqual(self._body(result)["error"], "agent_authority_escalation")

    def test_agent_token_delegation_success(self):
        """Lines 4024-4028, 4062-4068: happy path for agent-token delegation."""
        self._put_agent("good-caller",
                        conditions={"can_delegate_agents": True},
                        maximum_authority="admin",
                        delegation_chain=["root"])
        auth = {"tenant_id": "demo", "token_id": "t", "scopes": ["identity:write"],
                "agent_id": "good-caller", "token_type": "agent"}
        result = self._call("POST", "/v1/agents",
                            {"agent_id": "child-ok", "purpose": "test",
                             "allowed_environments": ["development"],
                             "approved_tools": ["shell"]},
                            auth=auth)
        self.assertIn(self._status(result), [200, 201])

    # --- Requested-parent path (human/admin caller) ------------------------

    def test_requested_parent_requires_admin(self):
        """Line 4031: non-admin token requests a parent agent."""
        self._put_agent("some-parent", maximum_authority="admin")
        auth = {"tenant_id": "demo", "token_id": "t", "scopes": ["identity:write"],
                "subject": "user@demo.test"}
        result = self._call("POST", "/v1/agents",
                            {"agent_id": "child", "parent_agent_id": "some-parent"},
                            auth=auth)
        self.assertEqual(self._status(result), 403)
        self.assertEqual(self._body(result)["error"], "parent_delegation_requires_admin")

    def test_requested_parent_cycle(self):
        """Lines 4048-4049: requested parent already in its own chain."""
        self._put_agent("cycle-parent", maximum_authority="admin",
                        delegation_chain=["root", "cycle-parent"])
        result = self._call("POST", "/v1/agents",
                            {"agent_id": "child", "parent_agent_id": "cycle-parent"})
        self.assertEqual(self._status(result), 409)
        self.assertEqual(self._body(result)["error"], "agent_delegation_cycle")

    def test_requested_parent_depth_exceeded(self):
        """Lines 4051-4052: requested parent chain at max depth."""
        deep_chain = [f"agent-{i}" for i in range(service.MAX_DELEGATION_DEPTH)]
        self._put_agent("deep-parent", maximum_authority="admin",
                        delegation_chain=deep_chain)
        result = self._call("POST", "/v1/agents",
                            {"agent_id": "child", "parent_agent_id": "deep-parent"})
        self.assertEqual(self._status(result), 403)
        self.assertEqual(self._body(result)["error"], "agent_delegation_depth_exceeded")

    def test_requested_parent_success(self):
        """Lines 4053-4054, 4062-4068: happy path for requested-parent delegation."""
        self._put_agent("healthy-parent", maximum_authority="admin",
                        delegation_chain=["root"])
        result = self._call("POST", "/v1/agents",
                            {"agent_id": "child-parented", "purpose": "test",
                             "parent_agent_id": "healthy-parent",
                             "allowed_environments": ["development"],
                             "approved_tools": ["shell"]})
        self.assertIn(self._status(result), [200, 201])

    # --- No-parent path ----------------------------------------------------

    def test_admin_authority_requires_admin_scope(self):
        """Line 4057: no-parent registration requesting admin authority without admin scope."""
        auth = {"tenant_id": "demo", "token_id": "t", "scopes": ["identity:write"],
                "subject": "user@demo.test"}
        result = self._call("POST", "/v1/agents",
                            {"agent_id": "wants-admin", "maximum_authority": "admin",
                             "purpose": "test",
                             "allowed_environments": ["development"],
                             "approved_tools": ["shell"]},
                            auth=auth)
        self.assertEqual(self._status(result), 403)
        self.assertEqual(self._body(result)["error"], "agent_authority_requires_admin")


if __name__ == "__main__":
    unittest.main()
