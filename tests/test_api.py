"""HTTP and MCP integration tests.

The suite runs against an in-process Lambda HTTP harness by default, so the
functional API tests run locally without AWS. Set ``KENNING_API_URL`` and the
PAT variables to run the same tests against a deployed service instead. The
deployed QA workflow always supplies those values and therefore remains the
source of evidence for AWS, Lambda, DynamoDB, KMS, and external-network
behaviour.
"""

from __future__ import annotations

import json
import os
import time
import unittest
import urllib.error
import urllib.request
import uuid
from typing import Any
import urllib.parse

try:
    from local_api_harness import LocalApiFixture
except ModuleNotFoundError:  # pragma: no cover - package-style test discovery
    from tests.local_api_harness import LocalApiFixture


API_URL = os.environ.get("KENNING_API_URL", "").rstrip("/")
PAT = os.environ.get("KENNING_PAT", "")
PROOF_PAT = os.environ.get("KENNING_PROOF_PAT", "")
CITATION_PAT = os.environ.get("KENNING_CITATION_PAT", "")
IDENTITY_PAT = os.environ.get("KENNING_IDENTITY_PAT", "")
POLICY_PAT = os.environ.get("KENNING_POLICY_PAT", "")
TENANT_PAT = os.environ.get("KENNING_TENANT_PAT", "")
REVIEWER_PAT = os.environ.get("KENNING_REVIEWER_PAT", "")
TENANT_ADMIN_TENANT_ID = os.environ.get("KENNING_TENANT_ADMIN_TENANT_ID", "tenant-admin-api-test")
TENANT_ID = os.environ.get("KENNING_TEST_TENANT_ID", "demo")
LOCAL_API_ENABLED = os.environ.get("KENNING_LOCAL_API", "1").strip().lower() not in {"0", "false", "no"}


def _use_local_api() -> bool:
    return not (API_URL and PAT) and LOCAL_API_ENABLED


class LocalApiTestMixin:
    """Switch the module-level request client between local and deployed mode."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._local_fixture = None
        cls._api_globals = {
            name: globals()[name]
            for name in (
                "API_URL",
                "PAT",
                "PROOF_PAT",
                "CITATION_PAT",
                "IDENTITY_PAT",
                "POLICY_PAT",
                "TENANT_PAT",
                "REVIEWER_PAT",
                "TENANT_ADMIN_TENANT_ID",
                "TENANT_ID",
            )
        }
        if _use_local_api():
            cls._local_fixture = LocalApiFixture()
            values = cls._local_fixture.start()
            globals().update(
                {
                    "API_URL": values["api_url"],
                    "PAT": values["pat"],
                    "PROOF_PAT": values["proof_pat"],
                    "CITATION_PAT": values["citation_pat"],
                    "IDENTITY_PAT": values["identity_pat"],
                    "POLICY_PAT": values["policy_pat"],
                    "TENANT_PAT": values["tenant_pat"],
                    "REVIEWER_PAT": values["reviewer_pat"],
                    "TENANT_ADMIN_TENANT_ID": values["tenant_admin_tenant_id"],
                    "TENANT_ID": values["tenant_id"],
                }
            )

    @classmethod
    def tearDownClass(cls):
        try:
            if cls._local_fixture is not None:
                cls._local_fixture.stop()
        finally:
            for name, value in getattr(cls, "_api_globals", {}).items():
                globals()[name] = value
            super().tearDownClass()


@unittest.skipUnless(
    (API_URL and PAT) or _use_local_api(),
    "Set KENNING_API_URL and KENNING_PAT, or enable the local API harness.",
)
class AgentGuardApiTests(LocalApiTestMixin, unittest.TestCase):
    maxDiff = None

    @staticmethod
    def _report_deployed_failure(method: str, path: str, status: int, body: dict[str, Any] | None) -> None:
        if LOCAL_API_ENABLED or status < 500:
            return
        print(
            "Deployed API failure: "
            + json.dumps(
                {"method": method, "path": path, "status": status, "body": body},
                sort_keys=True,
                default=str,
            )
        )

    def request(
        self,
        path: str,
        method: str = "GET",
        payload: dict[str, Any] | None = None,
        authenticated: bool = True,
        headers: dict[str, str] | None = None,
        token: str | None = None,
    ) -> tuple[int, dict[str, Any] | None, dict[str, str]]:
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(f"{API_URL}{path}", data=body, method=method)
        request.add_header("Accept", "application/json, text/event-stream")
        if body is not None:
            request.add_header("Content-Type", "application/json")
        if authenticated:
            request.add_header("Authorization", f"Bearer {token or PAT}")
        for name, value in (headers or {}).items():
            request.add_header(name, value)

        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw_body = response.read().decode("utf-8")
                response_headers = {key.lower(): value for key, value in response.headers.items()}
                decoded = self.decode_body(raw_body, response_headers.get("content-type", ""))
                self._report_deployed_failure(method, path, response.status, decoded)
                return response.status, decoded, response_headers
        except urllib.error.HTTPError as error:
            try:
                raw_body = error.read().decode("utf-8")
                error_headers = {key.lower(): value for key, value in error.headers.items()}
                decoded = self.decode_body(raw_body, error_headers.get("content-type", ""))
                self._report_deployed_failure(method, path, error.code, decoded)
                return error.code, decoded, error_headers
            finally:
                error.close()

    @staticmethod
    def decode_body(raw_body: str, content_type: str = "") -> dict[str, Any] | None:
        if not raw_body:
            return None
        if "application/x-ndjson" in content_type:
            return {"format": "jsonl", "events": [line for line in raw_body.splitlines() if line.strip()]}
        decoded = json.loads(raw_body)
        return decoded if isinstance(decoded, dict) else {"value": decoded}

    def context(self, **overrides: str) -> dict[str, str]:
        return {
            "tenant_id": TENANT_ID,
            "environment": "development",
            "agent_id": "automated-test-agent",
            "invoked_by": "api-test-suite",
            **overrides,
        }

    def evaluate(self, action: dict[str, Any], token: str | None = None, **context_overrides: str) -> tuple[int, dict[str, Any] | None]:
        status, body, _ = self.request(
            "/v1/actions/evaluate",
            method="POST",
            payload={"context": self.context(**context_overrides), "action": action},
            token=token,
        )
        return status, body

    def assert_credential_listed(self, agent_id: str, credential_id: str, token: str) -> None:
        # Credential listing reads a DynamoDB GSI that is eventually consistent
        # in the deployed environment, so a just-issued credential may not be
        # visible on the first read. Poll briefly. The in-process harness is
        # strongly consistent and returns on the first attempt.
        deadline = time.monotonic() + 60
        while True:
            listed_status, listed_body, _ = self.request(
                f"/v1/agents/{agent_id}/credentials",
                token=token,
            )
            self.assertEqual(listed_status, 200)
            if any(item["credential_id"] == credential_id for item in listed_body["credentials"]):
                return
            if time.monotonic() >= deadline:
                self.fail(f"credential {credential_id} was not listed for agent {agent_id}")
            time.sleep(0.5)

    def test_health_is_public(self):
        status, body, _ = self.request("/health", authenticated=False)
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")

    def test_protected_endpoint_rejects_missing_pat(self):
        status, body, headers = self.request(
            "/v1/actions/evaluate",
            method="POST",
            payload={"action": {"tool": "shell", "parameters": {"command": "ls"}}},
            authenticated=False,
        )
        self.assertEqual(status, 401)
        self.assertEqual(body["error"], "unauthorized")
        self.assertIn(
            "Bearer",
            {
                headers.get("www-authenticate"),
                headers.get("x-amzn-remapped-www-authenticate"),
            },
        )

    def test_unparseable_supported_action_fails_closed_to_approval(self):
        status, body = self.evaluate({"tool": "sql", "parameters": {}})
        self.assertEqual(status, 200)
        self.assertEqual(body["decision"], "require_approval")
        self.assertIn("UNPARSEABLE_SQL_ACTION", body["reason_codes"])

    def test_action_context_risk_signals_are_returned(self):
        status, body = self.evaluate(
            {
                "tool": "shell",
                "intent": "Inspect the report file",
                "parameters": {
                    "command": "rm /tmp/report.txt",
                    "reversible": False,
                    "requested_scope": [f"resource-{index}" for index in range(11)],
                    "affected_resource_count": 1001,
                },
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["decision"], "require_approval")
        self.assertTrue(
            {"IRREVERSIBLE_ACTION", "BROAD_RESOURCE_SCOPE", "LARGE_AFFECTED_RESOURCE_COUNT", "INTENT_SCOPE_MISMATCH"}.issubset(
                set(body["reason_codes"])
            )
        )

    def test_evaluate_action_and_read_audit(self):
        status, body = self.evaluate({"tool": "shell", "parameters": {"command": "ls -la"}})
        self.assertEqual(status, 200)
        self.assertEqual(body["decision"], "allow")
        self.assertEqual(body["action"]["tenant_id"], TENANT_ID)
        self.assertTrue(body["proof_id"].startswith("proof-"))
        self.assertEqual(body["evidence_status"], "not_provided")
        self.assertTrue(body["receipt"]["integrity"]["record_hash"].startswith("sha256:"))

        audit_status, audit_body, _ = self.request(f"/v1/audit?tenant_id={TENANT_ID}&limit=10")
        self.assertEqual(audit_status, 200)
        self.assertEqual(audit_body["tenant_id"], TENANT_ID)
        self.assertTrue(any(event["action_id"] == body["action"]["action_id"] for event in audit_body["events"]))

        search_status, search_body, _ = self.request(
            f"/v1/audit?action_id={body['action']['action_id']}&event_type=action.evaluated"
        )
        self.assertEqual(search_status, 200)
        self.assertEqual(len(search_body["events"]), 1)
        self.assertEqual(search_body["events"][0]["run_id"], body["action"]["run_id"])

        for correlation_field, correlation_value in (
            ("receipt_id", body["receipt"]["receipt_id"]),
            ("proof_id", body["proof_id"]),
            ("action_hash", body["action_hash"]),
        ):
            correlation_status, correlation_body, _ = self.request(
                f"/v1/audit?{correlation_field}={urllib.parse.quote(correlation_value)}"
            )
            self.assertEqual(correlation_status, 200)
            self.assertTrue(any(event["action_id"] == body["action"]["action_id"] for event in correlation_body["events"]))

        if PROOF_PAT:
            proof_status, proof_body, _ = self.request(f"/v1/proofs/{body['proof_id']}", token=PROOF_PAT)
            self.assertEqual(proof_status, 200)
            self.assertEqual(proof_body["proof_uri"], body["proof_uri"])

        verify_status, verification, _ = self.request(
            f"/v1/proofs/{body['proof_id']}/verify",
            token=PROOF_PAT or PAT,
        )
        self.assertEqual(verify_status, 200)
        self.assertTrue(verification["valid"])
        self.assertTrue(verification["proof_integrity"]["valid"])
        self.assertTrue(verification["receipt_integrity"]["valid"])
        self.assertTrue(verification["receipt_integrity"]["signature_present"])
        self.assertEqual(verification["receipt_integrity"]["signature_algorithm"], "kms-rsassa-pss-sha256")

        key_status, public_key, _ = self.request("/v1/receipts/public-key", token=PROOF_PAT or PAT)
        self.assertEqual(key_status, 200)
        self.assertEqual(public_key["key_usage"], "SIGN_VERIFY")
        self.assertEqual(public_key["public_key_format"], "DER SubjectPublicKeyInfo")
        self.assertTrue(public_key["public_key_der_base64"])

    def test_action_evaluation_is_idempotent_for_retries(self):
        action_id = f"stable-api-action-{uuid.uuid4().hex[:10]}"
        payload = {
            "context": {**self.context(environment="production", action_id=action_id)},
            "action": {"tool": "sql", "parameters": {"statement": "UPDATE orders SET status = closed"}},
        }
        first_status, first, _ = self.request("/v1/actions/evaluate", method="POST", payload=payload)
        second_status, second, _ = self.request("/v1/actions/evaluate", method="POST", payload=payload)
        self.assertEqual(first_status, 200)
        self.assertEqual(second_status, 200)
        self.assertTrue(second["idempotent"])
        self.assertEqual(second["approval"]["approval_id"], first["approval"]["approval_id"])
        self.assertEqual(second["proof_id"], first["proof_id"])

        changed = json.loads(json.dumps(payload))
        changed["action"]["parameters"]["statement"] = "UPDATE orders SET status = closed WHERE id = 42"
        conflict_status, conflict, _ = self.request("/v1/actions/evaluate", method="POST", payload=changed)
        self.assertEqual(conflict_status, 409)
        self.assertEqual(conflict["error"], "action_id_reuse")

    def test_pat_control_plane_issues_scoped_token_and_revokes_it(self):
        created_status, created, _ = self.request(
            "/v1/tokens",
            method="POST",
            payload={
                "name": f"api-test-child-{uuid.uuid4().hex[:8]}",
                "scopes": ["guard:evaluate"],
                "expires_in_days": 1,
            },
        )
        self.assertEqual(created_status, 201)
        child_token = created["token"]
        token_metadata = created["token_metadata"]
        token_id = token_metadata["token_id"]
        self.assertTrue(child_token.startswith("kta_pat_"))
        self.assertEqual(token_metadata["scopes"], ["guard:evaluate"])
        self.assertNotIn("token_hash", repr(created))

        try:
            listed_token = None
            listed = None
            deadline = time.time() + 10
            while time.time() < deadline:
                list_status, listed, _ = self.request("/v1/tokens")
                self.assertEqual(list_status, 200)
                listed_token = next((item for item in listed["tokens"] if item["token_id"] == token_id), None)
                if listed_token:
                    break
                time.sleep(0.5)
            self.assertIsNotNone(listed_token, f"token {token_id} was not listed after creation")
            self.assertEqual(listed_token["status"], "active")
            self.assertNotIn(child_token, repr(listed))
            self.assertNotIn("token_hash", repr(listed))

            child_status, child_body = self.evaluate(
                {"tool": "shell", "parameters": {"command": "ls"}},
                token=child_token,
            )
            self.assertEqual(child_status, 200)
            self.assertEqual(child_body["decision"], "allow")

            revoke_status, revoked, _ = self.request(
                f"/v1/tokens/{token_id}/revoke",
                method="POST",
                payload={},
            )
            self.assertEqual(revoke_status, 200)
            self.assertEqual(revoked["token_metadata"]["status"], "revoked")

            rejected_status, rejected = self.evaluate(
                {"tool": "shell", "parameters": {"command": "ls"}},
                token=child_token,
            )
            self.assertEqual(rejected_status, 401)
            self.assertEqual(rejected["error"], "unauthorized")
        finally:
            if token_id:
                self.request(f"/v1/tokens/{token_id}/revoke", method="POST", payload={})

    def test_external_audit_event_is_durable_and_idempotent(self):
        action_id = f"external-audit-{uuid.uuid4().hex[:10]}"
        payload = {
            "context": {
                "tenant_id": TENANT_ID,
                "run_id": f"run-{uuid.uuid4().hex[:10]}",
                "agent_id": "automated-test-agent",
                "invoked_by": "api-test-suite",
            },
            "event_type": "agent.run.completed",
            "action_id": action_id,
            "status": "success",
            "metadata": {"test": True},
        }
        idempotency_key = f"api-test-{uuid.uuid4().hex[:12]}"
        status, body, _ = self.request(
            "/v1/audit/events",
            method="POST",
            payload=payload,
            headers={"Idempotency-Key": idempotency_key},
        )
        self.assertEqual(status, 201)
        self.assertEqual(body["status"], "accepted")
        self.assertEqual(body["event_type"], "agent.run.completed")

        repeated_status, repeated_body, _ = self.request(
            "/v1/audit/events",
            method="POST",
            payload={**payload, "idempotency_key": idempotency_key},
            headers={"Idempotency-Key": idempotency_key},
        )
        self.assertEqual(repeated_status, 200)
        self.assertEqual(repeated_body["status"], "duplicate")

        audit_status, audit_body, _ = self.request(
            f"/v1/audit?event_type=agent.run.completed&action_id={urllib.parse.quote(action_id)}"
        )
        self.assertEqual(audit_status, 200)
        self.assertEqual(len(audit_body["events"]), 1)

    def test_tenant_boundary_is_enforced(self):
        status, body = self.evaluate(
            {"tool": "shell", "parameters": {"command": "ls"}},
            tenant_id=f"{TENANT_ID}-other",
        )
        self.assertEqual(status, 403)
        self.assertEqual(body["error"], "tenant_mismatch")

    def test_tenant_registry_is_safe_and_tenant_scoped(self):
        status, body, _ = self.request("/v1/tenants?limit=100")
        self.assertEqual(status, 200)
        self.assertEqual(body["tenant_id"], TENANT_ID)
        self.assertTrue(any(item["tenant_id"] == TENANT_ID for item in body["tenants"]))
        self.assertNotIn("identity_provider", repr(body))
        self.assertNotIn("audit_sink", repr(body))

        mismatch_status, mismatch, _ = self.request("/v1/tenants?tenant_id=another-tenant")
        self.assertEqual(mismatch_status, 403)
        self.assertEqual(mismatch["error"], "tenant_mismatch")

    def test_high_risk_action_can_be_denied(self):
        status, body = self.evaluate(
            {"tool": "sql", "parameters": {"statement": "UPDATE orders SET status = 'closed'"}},
            environment="production",
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["decision"], "require_approval")
        approval_id = body["approval"]["approval_id"]

        decision_status, decision_body, _ = self.request(
            f"/v1/approvals/{approval_id}/decision",
            method="POST",
            payload={"tenant_id": TENANT_ID, "decision": "deny", "approver": "automated-test-suite"},
        )
        self.assertEqual(decision_status, 200)
        self.assertEqual(decision_body["approval"]["status"], "denied")

    def test_policy_approval_requires_verified_reviewer_group(self):
        if not REVIEWER_PAT:
            self.skipTest("Set KENNING_REVIEWER_PAT to run reviewer-group integration tests.")
        policy_id = f"group-approval-{uuid.uuid4().hex[:12]}"
        target = f"reviewer-group-test-{uuid.uuid4().hex[:12]}"
        create_status, create_body, _ = self.request(
            "/v1/policies",
            method="POST",
            payload={
                "context": {"tenant_id": TENANT_ID},
                "policy_id": policy_id,
                "name": "Security approval group integration test",
                "mode": "enforce",
                "rules": [
                    {
                        "rule_id": "security-review",
                        "tool": "sql",
                        "environment": "production",
                        "target": target,
                        "decision": "require_approval",
                        "approver_groups": ["security"],
                    }
                ],
            },
        )
        self.assertEqual(create_status, 201)
        publish_status, _, _ = self.request(
            f"/v1/policies/{policy_id}/publish",
            method="POST",
            payload={"tenant_id": TENANT_ID, "version": 1},
        )
        self.assertEqual(publish_status, 200)

        evaluate_status, evaluated = self.evaluate(
            {"tool": "sql", "target": target, "parameters": {"statement": "UPDATE reviewer_group_test SET status = 'closed'"}},
            environment="production",
        )
        self.assertEqual(evaluate_status, 200)
        self.assertEqual(evaluated["decision"], "require_approval")
        self.assertEqual(evaluated["approval"]["approval_requirements"][0]["groups"], ["security"])
        approval_id = evaluated["approval"]["approval_id"]
        proof_status, proof, _ = self.request(f"/v1/proofs/{evaluated['proof_id']}")
        self.assertEqual(proof_status, 200)
        self.assertEqual(proof["policy_evaluations"][0]["policy_matches"][0]["rule_id"], "security-review")
        self.assertEqual(proof["policy_evaluations"][0]["policy_resolution"]["selected_match"]["rule_id"], "security-review")
        self.assertEqual(proof["policy_evaluations"][0]["approval_requirements"][0]["groups"], ["security"])

        blocked_status, blocked, _ = self.request(
            f"/v1/approvals/{approval_id}/decision",
            method="POST",
            payload={"tenant_id": TENANT_ID, "decision": "approve", "action_hash": evaluated["action_hash"]},
        )
        self.assertEqual(blocked_status, 403)
        self.assertEqual(blocked["error"], "approver_group_required")

        approved_status, approved, _ = self.request(
            f"/v1/approvals/{approval_id}/decision",
            method="POST",
            payload={"tenant_id": TENANT_ID, "decision": "approve", "action_hash": evaluated["action_hash"]},
            token=REVIEWER_PAT,
        )
        self.assertEqual(approved_status, 200)
        self.assertEqual(approved["approval"]["status"], "approved")

    def test_approval_queue_lists_pending_work_for_reviewers(self):
        status, body = self.evaluate(
            {"tool": "sql", "parameters": {"statement": "UPDATE approval_queue_test SET status = 'closed'"}},
            environment="production",
        )
        self.assertEqual(status, 200)
        approval_id = body["approval"]["approval_id"]
        queue_status, queue, _ = self.request(
            "/v1/approvals?status=pending&agent_id=automated-test-agent&environment=production&limit=100"
        )
        self.assertEqual(queue_status, 200)
        self.assertEqual(queue["tenant_id"], TENANT_ID)
        self.assertEqual(queue["statuses"], ["pending"])
        self.assertTrue(any(item["approval_id"] == approval_id for item in queue["approvals"]))

        decision_status, decision, _ = self.request(
            f"/v1/approvals/{approval_id}/decision",
            method="POST",
            payload={"tenant_id": TENANT_ID, "decision": "deny", "approver": "approval-queue-test"},
        )
        self.assertEqual(decision_status, 200)
        self.assertEqual(decision["approval"]["status"], "denied")

    def test_approval_records_triggering_rule_from_policy(self):
        policy_id = f"trigger-rule-{uuid.uuid4().hex[:12]}"
        target = f"trigger-rule-test-{uuid.uuid4().hex[:12]}"
        create_status, _, _ = self.request(
            "/v1/policies",
            method="POST",
            payload={
                "context": {"tenant_id": TENANT_ID},
                "policy_id": policy_id,
                "name": "Triggering rule capture test",
                "mode": "enforce",
                "rules": [
                    {
                        "rule_id": "trigger-capture-rule",
                        "tool": "sql",
                        "environment": "production",
                        "target": target,
                        "decision": "require_approval",
                        "reason": "Capture the triggering rule for reviewer context.",
                    }
                ],
            },
        )
        self.assertEqual(create_status, 201)
        publish_status, _, _ = self.request(
            f"/v1/policies/{policy_id}/publish",
            method="POST",
            payload={"tenant_id": TENANT_ID, "version": 1},
        )
        self.assertEqual(publish_status, 200)

        evaluate_status, evaluated = self.evaluate(
            {"tool": "sql", "target": target, "parameters": {"statement": "UPDATE trigger_rule_test SET status = 'closed'"}},
            environment="production",
        )
        self.assertEqual(evaluate_status, 200)
        self.assertEqual(evaluated["decision"], "require_approval")
        approval = evaluated["approval"]
        triggering = approval.get("triggering_rule")
        self.assertIsNotNone(triggering)
        self.assertEqual(triggering["rule_source"], "workspace")
        self.assertEqual(triggering["selected_rule"]["rule_id"], "trigger-capture-rule")
        self.assertEqual(triggering["selected_rule"]["policy_id"], policy_id)
        self.assertTrue(any(match["rule_id"] == "trigger-capture-rule" for match in triggering["matched_rules"]))

        # The triggering rule must also be returned by the approval queue and detail reads.
        approval_id = approval["approval_id"]
        detail_status, detail, _ = self.request(f"/v1/approvals/{approval_id}")
        self.assertEqual(detail_status, 200)
        self.assertEqual(detail["approval"]["triggering_rule"]["selected_rule"]["rule_id"], "trigger-capture-rule")

        # Clean up: deny the approval and suspend the policy.
        self.request(
            f"/v1/approvals/{approval_id}/decision",
            method="POST",
            payload={"tenant_id": TENANT_ID, "decision": "deny", "approver": "triggering-rule-test"},
        )

    def test_duration_grant_auto_approves_matching_actions(self):
        policy_id = f"grant-policy-{uuid.uuid4().hex[:12]}"
        target = f"grant-test-{uuid.uuid4().hex[:12]}"
        create_status, _, _ = self.request(
            "/v1/policies",
            method="POST",
            payload={
                "context": {"tenant_id": TENANT_ID},
                "policy_id": policy_id,
                "name": "Duration grant test",
                "mode": "enforce",
                "rules": [
                    {
                        "rule_id": "grant-capture-rule",
                        "tool": "sql",
                        "environment": "production",
                        "target": target,
                        "decision": "require_approval",
                    }
                ],
            },
        )
        self.assertEqual(create_status, 201)
        publish_status, _, _ = self.request(
            f"/v1/policies/{policy_id}/publish",
            method="POST",
            payload={"tenant_id": TENANT_ID, "version": 1},
        )
        self.assertEqual(publish_status, 200)

        action_body = {"tool": "sql", "target": target, "parameters": {"statement": "UPDATE grant_test SET status = 'closed'"}}

        # First evaluation requires approval.
        first_status, first = self.evaluate(dict(action_body), environment="production")
        self.assertEqual(first_status, 200)
        self.assertEqual(first["decision"], "require_approval")
        approval_id = first["approval"]["approval_id"]

        # Approve with a one-hour grant.
        decide_status, decided, _ = self.request(
            f"/v1/approvals/{approval_id}/decision",
            method="POST",
            payload={"tenant_id": TENANT_ID, "decision": "approve", "action_hash": first["action_hash"], "approver": "grant-test-reviewer", "grant_duration": 3600},
        )
        self.assertEqual(decide_status, 200)
        self.assertEqual(decided["approval"]["status"], "approved")
        self.assertIn("grant", decided)
        grant_id = decided["grant"]["grant_id"]
        self.assertEqual(decided["grant"]["duration_seconds"], 3600)

        # A new evaluation of the same semantic action is auto-approved.
        second_status, second = self.evaluate(dict(action_body), environment="production")
        self.assertEqual(second_status, 200)
        self.assertEqual(second["decision"], "allow")
        self.assertTrue(second.get("auto_approved"))
        self.assertEqual(second.get("grant_id"), grant_id)
        self.assertIn("AUTO_APPROVED_BY_GRANT", second["reason_codes"])

        # A different action does not match the grant.
        other_status, other = self.evaluate(
            {"tool": "sql", "target": target, "parameters": {"statement": "UPDATE grant_test SET status = 'deleted'"}},
            environment="production",
        )
        self.assertEqual(other_status, 200)
        self.assertEqual(other["decision"], "require_approval")
        self.assertNotEqual(other["action_hash"], first["action_hash"])

        # The grant appears in the grants list.
        list_status, listed, _ = self.request("/v1/grants")
        self.assertEqual(list_status, 200)
        self.assertTrue(any(item["grant_id"] == grant_id for item in listed["grants"]))

        # Revoke the grant; a further matching action requires approval again.
        revoke_status, revoked, _ = self.request(
            f"/v1/grants/{grant_id}/revoke",
            method="POST",
            payload={"tenant_id": TENANT_ID},
        )
        self.assertEqual(revoke_status, 200)
        self.assertEqual(revoked["grant"]["status"], "revoked")

        third_status, third = self.evaluate(dict(action_body), environment="production")
        self.assertEqual(third_status, 200)
        self.assertEqual(third["decision"], "require_approval")

        # Reject the over-maximum duration.
        bad_status, bad, _ = self.request(
            f"/v1/approvals/{third['approval']['approval_id']}/decision",
            method="POST",
            payload={"tenant_id": TENANT_ID, "decision": "approve", "action_hash": third["action_hash"], "approver": "grant-test-reviewer", "grant_duration": 999999},
        )
        self.assertEqual(bad_status, 200)
        self.assertNotIn("grant", bad)

    def test_multi_step_approval_chain_advances_and_completes(self):
        policy_id = f"chain-policy-{uuid.uuid4().hex[:12]}"
        target = f"chain-test-{uuid.uuid4().hex[:12]}"
        create_status, _, _ = self.request(
            "/v1/policies",
            method="POST",
            payload={
                "context": {"tenant_id": TENANT_ID},
                "policy_id": policy_id,
                "name": "Approval chain test",
                "mode": "enforce",
                "rules": [
                    {
                        "rule_id": "chain-rule",
                        "tool": "sql",
                        "environment": "production",
                        "target": target,
                        "decision": "require_approval",
                        "approval_chain": [
                            {"label": "Peer review", "approver_groups": [], "separation_of_duties": False},
                            {"label": "Manager sign-off", "approver_groups": [], "separation_of_duties": False},
                        ],
                    }
                ],
            },
        )
        self.assertEqual(create_status, 201)
        publish_status, _, _ = self.request(
            f"/v1/policies/{policy_id}/publish",
            method="POST",
            payload={"tenant_id": TENANT_ID, "version": 1},
        )
        self.assertEqual(publish_status, 200)

        action_body = {"tool": "sql", "target": target, "parameters": {"statement": "UPDATE chain_test SET status = 'closed'"}}
        eval_status, evaluated = self.evaluate(dict(action_body), environment="production")
        self.assertEqual(eval_status, 200)
        self.assertEqual(evaluated["decision"], "require_approval")
        approval = evaluated["approval"]
        approval_id = approval["approval_id"]
        self.assertEqual(approval["total_steps"], 2)
        self.assertEqual(approval["current_step"], 1)
        self.assertEqual(len(approval["chain_steps"]), 2)

        # Approving step 1 keeps the approval pending and advances to step 2.
        step1_status, step1, _ = self.request(
            f"/v1/approvals/{approval_id}/decision",
            method="POST",
            payload={"tenant_id": TENANT_ID, "decision": "approve", "action_hash": evaluated["action_hash"], "approver": "peer-reviewer", "step": 1},
        )
        self.assertEqual(step1_status, 200)
        self.assertEqual(step1["approval"]["status"], "pending")
        self.assertEqual(step1["approval"]["current_step"], 2)
        self.assertEqual(step1["chain_complete"], False)
        self.assertEqual(step1["approval"]["chain_steps"][0]["status"], "approved")

        # An out-of-order decision on step 1 is rejected.
        ooo_status, ooo, _ = self.request(
            f"/v1/approvals/{approval_id}/decision",
            method="POST",
            payload={"tenant_id": TENANT_ID, "decision": "approve", "action_hash": evaluated["action_hash"], "approver": "peer-reviewer", "step": 1},
        )
        self.assertEqual(ooo_status, 409)
        self.assertEqual(ooo["error"], "approval_step_not_actionable")

        # Approving step 2 completes the chain.
        step2_status, step2, _ = self.request(
            f"/v1/approvals/{approval_id}/decision",
            method="POST",
            payload={"tenant_id": TENANT_ID, "decision": "approve", "action_hash": evaluated["action_hash"], "approver": "manager-reviewer", "step": 2},
        )
        self.assertEqual(step2_status, 200)
        self.assertEqual(step2["approval"]["status"], "approved")
        self.assertEqual(step2["chain_complete"], True)
        self.assertEqual(step2["approval"]["chain_steps"][1]["status"], "approved")

    def test_approval_chain_denial_at_any_step_denies_all(self):
        policy_id = f"chain-deny-{uuid.uuid4().hex[:12]}"
        target = f"chain-deny-test-{uuid.uuid4().hex[:12]}"
        create_status, _, _ = self.request(
            "/v1/policies",
            method="POST",
            payload={
                "context": {"tenant_id": TENANT_ID},
                "policy_id": policy_id,
                "name": "Approval chain denial test",
                "mode": "enforce",
                "rules": [
                    {
                        "rule_id": "chain-deny-rule",
                        "tool": "sql",
                        "environment": "production",
                        "target": target,
                        "decision": "require_approval",
                        "approval_chain": [
                            {"label": "Peer review", "approver_groups": [], "separation_of_duties": False},
                            {"label": "Manager sign-off", "approver_groups": [], "separation_of_duties": False},
                        ],
                    }
                ],
            },
        )
        self.assertEqual(create_status, 201)
        self.request(f"/v1/policies/{policy_id}/publish", method="POST", payload={"tenant_id": TENANT_ID, "version": 1})

        action_body = {"tool": "sql", "target": target, "parameters": {"statement": "UPDATE chain_deny_test SET status = 'closed'"}}
        eval_status, evaluated = self.evaluate(dict(action_body), environment="production")
        self.assertEqual(eval_status, 200)
        approval_id = evaluated["approval"]["approval_id"]

        # Approve step 1, then deny step 2 — the whole approval is denied.
        self.request(
            f"/v1/approvals/{approval_id}/decision",
            method="POST",
            payload={"tenant_id": TENANT_ID, "decision": "approve", "action_hash": evaluated["action_hash"], "approver": "peer-reviewer", "step": 1},
        )
        deny_status, denied, _ = self.request(
            f"/v1/approvals/{approval_id}/decision",
            method="POST",
            payload={"tenant_id": TENANT_ID, "decision": "deny", "action_hash": evaluated["action_hash"], "approver": "manager-reviewer", "step": 2},
        )
        self.assertEqual(deny_status, 200)
        self.assertEqual(denied["approval"]["status"], "denied")
        self.assertEqual(denied["approval"]["chain_steps"][1]["status"], "denied")

    def test_approval_can_be_revoked_before_execution(self):
        status, body = self.evaluate(
            {"tool": "sql", "parameters": {"statement": "UPDATE invoices SET status = 'cancelled'"}},
            environment="production",
        )
        self.assertEqual(status, 200)
        approval_id = body["approval"]["approval_id"]

        revoke_status, revoked, _ = self.request(
            f"/v1/approvals/{approval_id}/revoke",
            method="POST",
            payload={"tenant_id": TENANT_ID, "reason": "Live lifecycle test cancellation."},
        )
        self.assertEqual(revoke_status, 200)
        self.assertEqual(revoked["approval"]["status"], "revoked")

        repeated_status, repeated, _ = self.request(
            f"/v1/approvals/{approval_id}/revoke",
            method="POST",
            payload={"tenant_id": TENANT_ID},
        )
        self.assertEqual(repeated_status, 200)
        self.assertTrue(repeated["idempotent"])

        decision_status, decision, _ = self.request(
            f"/v1/approvals/{approval_id}/decision",
            method="POST",
            payload={"tenant_id": TENANT_ID, "decision": "approve", "approver": "security@example.org", "action_hash": body["action_hash"]},
        )
        self.assertEqual(decision_status, 409)
        self.assertEqual(decision["error"], "approval_expired_or_already_decided")

    def test_approval_retrieval_and_action_binding(self):
        action_id = f"approval-binding-{uuid.uuid4().hex[:12]}"
        status, body = self.evaluate(
            {"tool": "shell", "parameters": {"command": "rm -rf /tmp/approval-binding-test"}},
            environment="development",
            run_id=f"approval-binding-run-{uuid.uuid4().hex[:12]}",
            action_id=action_id,
        )
        self.assertEqual(status, 200)
        approval_id = body["approval"]["approval_id"]
        self.assertEqual(body["action"]["action_id"], action_id)
        action_hash = body["action_hash"]

        get_status, approval_body, _ = self.request(f"/v1/approvals/{approval_id}")
        self.assertEqual(get_status, 200)
        self.assertEqual(approval_body["approval"]["action_hash"], action_hash)
        self.assertEqual(approval_body["approval"]["action"]["action_id"], action_id)
        self.assertEqual(approval_body["approval"]["proof_id"], body["proof_id"])

        mismatch_status, _, _ = self.request(
            f"/v1/approvals/{approval_id}/decision",
            method="POST",
            payload={
                "tenant_id": TENANT_ID,
                "decision": "approve",
                "approver": "automated-test-suite",
                "action_hash": "sha256:not-the-original-action",
            },
        )
        self.assertEqual(mismatch_status, 409)

        approve_status, approved_body, _ = self.request(
            f"/v1/approvals/{approval_id}/decision",
            method="POST",
            payload={
                "tenant_id": TENANT_ID,
                "decision": "approve",
                "approver": "automated-test-suite",
                "action_hash": action_hash,
            },
        )
        self.assertEqual(approve_status, 200)
        self.assertEqual(approved_body["approval"]["status"], "approved")

        changed_intent_status, _, _ = self.request(
            "/v1/actions/evaluate",
            method="POST",
            payload={
                "context": {
                    **self.context(),
                    "run_id": body["action"]["run_id"],
                    "action_id": action_id,
                },
                "intent": "A different operation description must not reuse this approval.",
                "action": {"tool": "shell", "parameters": {"command": "rm -rf /tmp/approval-binding-test"}},
                "approval_id": approval_id,
                "action_hash": action_hash,
            },
        )
        self.assertEqual(changed_intent_status, 409)

        resume_status, resumed_body, _ = self.request(
            "/v1/actions/evaluate",
            method="POST",
            payload={
                "context": {
                    **self.context(),
                    "run_id": body["action"]["run_id"],
                    "action_id": action_id,
                },
                "action": {"tool": "shell", "parameters": {"command": "rm -rf /tmp/approval-binding-test"}},
                "approval_id": approval_id,
                "action_hash": action_hash,
            },
        )
        self.assertEqual(resume_status, 200)
        self.assertEqual(resumed_body["decision"], "allow")
        self.assertTrue(resumed_body["approval_resume"])
        self.assertEqual(resumed_body["approval_id"], approval_id)
        self.assertEqual(resumed_body["approval_status"], "consumed")

        replay_status, replay_body, _ = self.request(
            "/v1/actions/evaluate",
            method="POST",
            payload={
                "context": {
                    **self.context(),
                    "run_id": body["action"]["run_id"],
                    "action_id": action_id,
                },
                "action": {"tool": "shell", "parameters": {"command": "rm -rf /tmp/approval-binding-test"}},
                "approval_id": approval_id,
                "action_hash": action_hash,
            },
        )
        self.assertEqual(replay_status, 409)
        self.assertEqual(replay_body["error"], "approval_not_approved")
        self.assertEqual(replay_body["status"], "consumed")

        repeat_status, _, _ = self.request(
            f"/v1/approvals/{approval_id}/decision",
            method="POST",
            payload={
                "tenant_id": TENANT_ID,
                "decision": "approve",
                "approver": "automated-test-suite",
                "action_hash": action_hash,
            },
        )
        self.assertEqual(repeat_status, 409)

        bad_outcome_status, _, _ = self.request(
            f"/v1/actions/{action_id}/outcome",
            method="POST",
            payload={
                "tenant_id": TENANT_ID,
                "proof_id": body["proof_id"],
                "approval_id": approval_id,
                "action_hash": "sha256:not-the-original-action",
                "status": "success",
            },
        )
        self.assertEqual(bad_outcome_status, 409)

        outcome_status, outcome_body, _ = self.request(
            f"/v1/actions/{action_id}/outcome",
            method="POST",
            payload={
                "tenant_id": TENANT_ID,
                "proof_id": body["proof_id"],
                "approval_id": approval_id,
                "action_hash": action_hash,
                "status": "success",
                "result": "approved test action completed",
            },
        )
        self.assertEqual(outcome_status, 202)
        self.assertEqual(outcome_body["approval_id"], approval_id)

        repeated_outcome_status, repeated_outcome, _ = self.request(
            f"/v1/actions/{action_id}/outcome",
            method="POST",
            payload={
                "tenant_id": TENANT_ID,
                "proof_id": body["proof_id"],
                "approval_id": approval_id,
                "action_hash": action_hash,
                "status": "success",
                "result": "approved test action completed",
            },
        )
        self.assertEqual(repeated_outcome_status, 202)
        self.assertTrue(repeated_outcome["idempotent"])

        consumed_status, consumed_body, _ = self.request(f"/v1/approvals/{approval_id}")
        self.assertEqual(consumed_status, 200)
        self.assertEqual(consumed_body["approval"]["status"], "consumed")

        revoke_consumed_status, revoke_consumed_body, _ = self.request(
            f"/v1/approvals/{approval_id}/revoke",
            method="POST",
            payload={"tenant_id": TENANT_ID},
        )
        self.assertEqual(revoke_consumed_status, 409)
        self.assertEqual(revoke_consumed_body["error"], "approval_not_revivable")

    def test_aws_cloud_adapter_is_evaluated_before_execution(self):
        status, body = self.evaluate(
            {
                "tool": "aws",
                "operation": "ec2:TerminateInstances",
                "target": {"type": "ec2-instance", "id": "i-api-test"},
                "parameters": {
                    "region": "us-east-1",
                    "requested_scope": ["i-api-test"],
                },
            },
            environment="production",
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["action"]["adapter"], "aws")
        self.assertEqual(body["action"]["adapter_context"]["service"], "ec2")
        self.assertEqual(body["decision"], "require_approval")
        self.assertIn("AWS_DESTRUCTIVE_OPERATION", body["reason_codes"])

    def test_financial_transaction_risk_signal_requires_approval(self):
        status, body = self.evaluate(
            {
                "tool": "payments",
                "operation": "create_payment",
                "target": "supplier-invoice",
                "parameters": {
                    "amount": 5000,
                    "currency": "NZD",
                    "beneficiary_account": "account-ref",
                },
            },
            environment="production",
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["decision"], "require_approval")
        self.assertIn("FINANCIAL_TRANSACTION", body["reason_codes"])

        read_status, read_body = self.evaluate(
            {
                "tool": "sql",
                "operation": "select",
                "target": "payments",
                "parameters": {"statement": "SELECT id, amount FROM payments"},
            }
        )
        self.assertEqual(read_status, 200)
        self.assertNotIn("FINANCIAL_TRANSACTION", read_body["reason_codes"])

    def test_shell_execution_context_is_normalised_and_inspected(self):
        status, body = self.evaluate(
            {
                "tool": "shell",
                "parameters": {
                    "executable": "python",
                    "args": ["-m", "maintenance"],
                    "working_directory": "/etc",
                    "environment_variables": {"AWS_SECRET_ACCESS_KEY": "hosted-secret-value", "MODE": "production"},
                    "execution_context": {"run_as": "root"},
                },
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["decision"], "deny")
        self.assertEqual(body["action"]["shell_context"]["arguments"], ["-m", "maintenance"])
        self.assertEqual(body["action"]["shell_context"]["environment_variables"]["AWS_SECRET_ACCESS_KEY"], "[REDACTED]")
        self.assertIn("SHELL_PROTECTED_WORKING_DIRECTORY", body["reason_codes"])
        self.assertIn("CREDENTIAL_EXPOSURE", body["reason_codes"])
        self.assertIn("PRIVILEGE_ESCALATION", body["reason_codes"])
        self.assertNotIn("hosted-secret-value", json.dumps(body))

    def test_github_and_email_adapters_use_common_guard_contract(self):
        github_status, github_body = self.evaluate(
            {
                "tool": "github",
                "operation": "merge_pull_request",
                "parameters": {"repository": "kenning/trusted-agent", "base_branch": "main", "requested_scope": ["pull/42"]},
            },
            environment="production",
        )
        self.assertEqual(github_status, 200)
        self.assertEqual(github_body["action"]["adapter"], "github")
        self.assertIn("GITHUB_PROTECTED_BRANCH_CHANGE", github_body["reason_codes"])

        email_status, email_body = self.evaluate(
            {
                "tool": "email",
                "operation": "bulk_send",
                "parameters": {"recipients": [f"person-{index}@example.org" for index in range(20)], "external_recipients": True},
            }
        )
        self.assertEqual(email_status, 200)
        self.assertEqual(email_body["action"]["adapter"], "email")
        self.assertIn("BULK_OUTBOUND_MESSAGE", email_body["reason_codes"])

    def test_action_outcome_is_recorded(self):
        status, body = self.evaluate({"tool": "shell", "parameters": {"command": "printf test"}})
        self.assertEqual(status, 200)
        action_id = body["action"]["action_id"]
        proof_id = body["proof_id"]

        outcome_status, outcome_body, _ = self.request(
            f"/v1/actions/{action_id}/outcome",
            method="POST",
            payload={"tenant_id": TENANT_ID, "proof_id": proof_id, "status": "success", "result": "test completed"},
        )
        self.assertEqual(outcome_status, 202)
        self.assertEqual(outcome_body["event_type"], "action.outcome")
        self.assertEqual(outcome_body["action_id"], action_id)
        self.assertEqual(outcome_body["proof_id"], proof_id)

    def test_mcp_lifecycle_and_evaluate_tool(self):
        initialize_status, initialize_body, _ = self.request(
            "/mcp",
            method="POST",
            payload={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "api-test-suite", "version": "1.0.0"},
                },
            },
        )
        self.assertEqual(initialize_status, 200)
        self.assertEqual(initialize_body["result"]["serverInfo"]["name"], "kenning-trusted-agent")

        list_status, list_body, _ = self.request(
            "/mcp",
            method="POST",
            payload={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            headers={"MCP-Protocol-Version": "2025-06-18"},
        )
        self.assertEqual(list_status, 200)
        self.assertEqual(
            {tool["name"] for tool in list_body["result"]["tools"]},
            {"evaluate_action", "verify_citations", "create_proof", "verify_proof", "get_receipt_public_key"},
        )

        ping_status, ping_body, _ = self.request(
            "/mcp",
            method="POST",
            payload={"jsonrpc": "2.0", "id": 3, "method": "ping"},
            headers={"MCP-Protocol-Version": "2025-06-18"},
        )
        self.assertEqual(ping_status, 200)
        self.assertEqual(ping_body["result"], {})

        notification_status, notification_body, _ = self.request(
            "/mcp",
            method="POST",
            payload={"jsonrpc": "2.0", "method": "notifications/initialized"},
            headers={"MCP-Protocol-Version": "2025-06-18"},
        )
        self.assertEqual(notification_status, 202)
        self.assertIsNone(notification_body)

        call_status, call_body, _ = self.request(
            "/mcp",
            method="POST",
            payload={
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "evaluate_action",
                    "arguments": {
                        "context": self.context(),
                        "action": {"tool": "shell", "parameters": {"command": "pwd"}},
                    },
                },
            },
            headers={"MCP-Protocol-Version": "2025-06-18"},
        )
        self.assertEqual(call_status, 200)
        self.assertEqual(call_body["result"]["structuredContent"]["decision"], "allow")

        verify_status, verify_body, _ = self.request(
            "/mcp",
            method="POST",
            payload={
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "verify_proof",
                    "arguments": {"proof_id": call_body["result"]["structuredContent"]["proof_id"]},
                },
            },
            headers={"MCP-Protocol-Version": "2025-06-18"},
        )
        self.assertEqual(verify_status, 200)
        self.assertTrue(verify_body["result"]["structuredContent"]["valid"])

        key_status, key_body, _ = self.request(
            "/mcp",
            method="POST",
            payload={
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {"name": "get_receipt_public_key", "arguments": {}},
            },
            headers={"MCP-Protocol-Version": "2025-06-18"},
        )
        self.assertEqual(key_status, 200)
        self.assertEqual(key_body["result"]["structuredContent"]["key_usage"], "SIGN_VERIFY")

        create_status, create_body, _ = self.request(
            "/mcp",
            method="POST",
            payload={
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {
                    "name": "create_proof",
                    "arguments": {
                        "context": self.context(agent_id="mcp-proof-agent"),
                        "request": {"summary": "Record MCP provenance"},
                        "evidence": [{"claim": "MCP proof tool was invoked", "source": "api-test-suite"}],
                    },
                },
            },
            headers={"MCP-Protocol-Version": "2025-06-18"},
        )
        self.assertEqual(create_status, 200)
        self.assertTrue(create_body["result"]["structuredContent"]["proof_id"].startswith("proof-"))

        if CITATION_PAT:
            citation_status, citation_body, _ = self.request(
                "/mcp",
                method="POST",
                token=CITATION_PAT,
                payload={
                    "jsonrpc": "2.0",
                    "id": 8,
                    "method": "tools/call",
                    "params": {
                        "name": "verify_citations",
                        "arguments": {
                            "context": self.context(),
                            "response": "Example Domain",
                            "citations": [{"url": "https://example.com", "claim": "Example Domain", "source_text": "Example Domain"}],
                        },
                    },
                },
                headers={"MCP-Protocol-Version": "2025-06-18"},
            )
            self.assertEqual(citation_status, 200)
            self.assertEqual(citation_body["result"]["structuredContent"]["status"], "pass")

    def test_mcp_approved_action_can_resume_from_approval_reference(self):
        action_id = f"mcp-approval-resume-{uuid.uuid4().hex[:12]}"
        run_id = f"mcp-approval-run-{uuid.uuid4().hex[:12]}"
        context = self.context(
            environment="development",
            agent_id="mcp-approval-agent",
            run_id=run_id,
            action_id=action_id,
        )
        action = {"tool": "shell", "parameters": {"command": "rm -rf /tmp/mcp-approval-resume-test"}}
        initial_status, initial_body, _ = self.request(
            "/mcp",
            method="POST",
            payload={
                "jsonrpc": "2.0",
                "id": 91,
                "method": "tools/call",
                "params": {"name": "evaluate_action", "arguments": {"context": context, "action": action}},
            },
            headers={"MCP-Protocol-Version": "2025-06-18"},
        )
        self.assertEqual(initial_status, 200)
        self.assertEqual(initial_body["result"]["structuredContent"]["decision"], "require_approval")
        structured = initial_body["result"]["structuredContent"]
        approval_id = structured["approval"]["approval_id"]
        action_hash = structured["action_hash"]

        approve_status, _, _ = self.request(
            f"/v1/approvals/{approval_id}/decision",
            method="POST",
            payload={"tenant_id": TENANT_ID, "decision": "approve", "action_hash": action_hash},
        )
        self.assertEqual(approve_status, 200)

        resumed_status, resumed_body, _ = self.request(
            "/mcp",
            method="POST",
            payload={
                "jsonrpc": "2.0",
                "id": 92,
                "method": "tools/call",
                "params": {
                    "name": "evaluate_action",
                    "arguments": {
                        "context": context,
                        "intent": f"Retry the exact action previously approved under {approval_id}",
                        "action": action,
                    },
                },
            },
            headers={"MCP-Protocol-Version": "2025-06-18"},
        )
        self.assertEqual(resumed_status, 200)
        resumed = resumed_body["result"]["structuredContent"]
        self.assertEqual(resumed["decision"], "allow")
        self.assertTrue(resumed["approval_resume"])
        self.assertEqual(resumed["approval_id"], approval_id)
        self.assertEqual(resumed["approval_status"], "consumed")

        outcome_status, outcome_body, _ = self.request(
            f"/v1/actions/{action_id}/outcome",
            method="POST",
            payload={
                "tenant_id": TENANT_ID,
                "proof_id": initial_body["result"]["structuredContent"]["proof_id"],
                "approval_id": approval_id,
                "action_hash": action_hash,
                "status": "success",
                "result": "MCP approval resume test completed",
            },
        )
        self.assertEqual(outcome_status, 202)
        self.assertEqual(outcome_body["approval_id"], approval_id)

    def test_mcp_get_is_not_supported(self):
        status, body, headers = self.request("/mcp", method="GET")
        self.assertEqual(status, 405)
        self.assertEqual(body, {"error": "method_not_allowed", "allow": "POST"})

    def test_operational_metrics_are_exposed_without_action_payloads(self):
        status, body, _ = self.request(f"/v1/metrics?tenant_id={TENANT_ID}")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(body["metrics"]["event_counts"].get("action.evaluated", 0), 1)
        self.assertGreaterEqual(body["metrics"]["latency_ms"]["samples"], 1)
        self.assertTrue({"average", "p50", "p95", "p99"}.issubset(body["metrics"]["latency_ms"]))
        self.assertNotIn("parameters", json.dumps(body["metrics"]))

        mismatch_status, mismatch_body, _ = self.request(f"/v1/metrics?tenant_id={TENANT_ID}-other")
        self.assertEqual(mismatch_status, 403)
        self.assertEqual(mismatch_body["error"], "tenant_mismatch")

    def test_options_is_supported_for_browser_clients(self):
        status, body, _ = self.request("/v1/actions/evaluate", method="OPTIONS", authenticated=False)
        self.assertEqual(status, 204)
        self.assertIsNone(body)

    def test_manual_proof_create_retrieve_and_report(self):
        if not PROOF_PAT:
            self.skipTest("Set KENNING_PROOF_PAT to test the proof:read and proof:write endpoints.")
        status, body, _ = self.request(
            "/v1/proofs",
            method="POST",
            token=PROOF_PAT,
            payload={
                "context": {"tenant_id": TENANT_ID, "agent_id": "proof-test-agent", "invoked_by": "api-test-suite"},
                "request": {"summary": "Recommend a preferred supplier"},
                "inputs": [{"type": "document", "id": "proposal-a.pdf", "content": "supplier pricing"}],
                "evidence": [{"evidence_id": "pricing", "claim": "Supplier A has the lowest total cost", "source": "pricing.xlsx", "location": "Sheet 1, D12:D18"}],
                "decision_factors": [{"factor": "Price", "weight": 0.35, "result": "Supplier A ranked first", "evidence_refs": ["pricing"]}],
                "recommendation": "Select Supplier A",
            },
        )
        self.assertEqual(status, 201)
        proof_id = body["proof_id"]
        self.assertEqual(body["evidence_status"], "verified")

        get_status, retrieved, _ = self.request(f"/v1/proofs/{proof_id}", token=PROOF_PAT)
        self.assertEqual(get_status, 200)
        self.assertEqual(retrieved["proof_id"], proof_id)
        self.assertNotIn("content", retrieved["inputs"][0])

        report_status, report_body, _ = self.request(f"/v1/proofs/{proof_id}/report", token=PROOF_PAT)
        self.assertEqual(report_status, 200)
        self.assertEqual(report_body["format"], "markdown")
        self.assertIn("Supplier A has the lowest total cost", report_body["report"])

    def test_citation_verification_endpoint(self):
        if not CITATION_PAT:
            self.skipTest("Set KENNING_CITATION_PAT to test the citation:verify endpoint.")
        status, body, _ = self.request(
            "/v1/citations/verify",
            method="POST",
            token=CITATION_PAT,
            payload={
                "context": {"tenant_id": TENANT_ID, "agent_id": "citation-test-agent", "invoked_by": "api-test-suite"},
                "response": "Example Domain",
                "citations": [{"url": "https://example.com", "claim": "Example Domain", "source_text": "Example Domain"}],
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "pass")
        self.assertEqual(body["citations"][0]["supports_claim"], True)
        self.assertEqual(body["tenant_id"], TENANT_ID)

    def test_agent_identity_register_enforce_and_revoke(self):
        if not IDENTITY_PAT:
            self.skipTest("Set KENNING_IDENTITY_PAT to test the identity endpoints.")
        agent_id = f"api-test-agent-{uuid.uuid4().hex[:8]}"
        register_status, registered, _ = self.request(
            "/v1/agents",
            method="POST",
            token=IDENTITY_PAT,
            payload={
                "context": {"tenant_id": TENANT_ID},
                "agent_id": agent_id,
                "owner": "api-test-suite",
                "purpose": "Test delegated shell access",
                "allowed_environments": ["development"],
                "approved_tools": ["shell"],
                "may": ["shell:execute:*"],
                "conditions": {
                    "not_before": "2020-01-01T00:00:00Z",
                    "not_after": "2099-01-01T00:00:00Z",
                },
            },
        )
        self.assertEqual(register_status, 201)
        self.assertEqual(registered["status"], "active")
        self.assertEqual(registered["conditions"]["not_after"], "2099-01-01T00:00:00Z")

        list_status, listed, _ = self.request("/v1/agents", token=IDENTITY_PAT)
        self.assertEqual(list_status, 200)
        self.assertTrue(any(item["agent_id"] == agent_id for item in listed["agents"]))

        get_status, fetched, _ = self.request(f"/v1/agents/{agent_id}", token=IDENTITY_PAT)
        self.assertEqual(get_status, 200)
        self.assertEqual(fetched["agent_id"], agent_id)

        evaluate_status, evaluated = self.evaluate(
            {"tool": "shell", "parameters": {"command": "ls"}},
            agent_id=agent_id,
            environment="development",
        )
        self.assertEqual(evaluate_status, 200)
        self.assertTrue(evaluated["identity"]["authorized"])
        self.assertEqual(evaluated["decision"], "allow")

        expired_agent_id = f"api-test-expired-agent-{uuid.uuid4().hex[:8]}"
        expired_register_status, _, _ = self.request(
            "/v1/agents",
            method="POST",
            token=IDENTITY_PAT,
            payload={
                "context": {"tenant_id": TENANT_ID},
                "agent_id": expired_agent_id,
                "owner": "api-test-suite",
                "purpose": "Expired delegation test",
                "allowed_environments": ["development"],
                "approved_tools": ["shell"],
                "conditions": {"not_after": "2020-01-01T00:00:00Z"},
            },
        )
        self.assertEqual(expired_register_status, 201)
        expired_eval_status, expired_eval = self.evaluate(
            {"tool": "shell", "parameters": {"command": "ls"}},
            agent_id=expired_agent_id,
            environment="development",
        )
        self.assertEqual(expired_eval_status, 200)
        self.assertEqual(expired_eval["decision"], "deny")
        self.assertIn("DELEGATION_EXPIRED", expired_eval["reason_codes"])
        expired_revoke_status, _, _ = self.request(
            f"/v1/agents/{expired_agent_id}/revoke", method="POST", token=IDENTITY_PAT
        )
        self.assertEqual(expired_revoke_status, 200)

        credential_status, credential_body, _ = self.request(
            f"/v1/agents/{agent_id}/credentials",
            method="POST",
            token=IDENTITY_PAT,
            payload={"expires_in_seconds": 300, "name": "automated-test-credential"},
        )
        self.assertEqual(credential_status, 201)
        credential = credential_body["credential"]
        agent_token = credential_body["token"]
        self.assertTrue(agent_token.startswith("kta_agent_"))
        self.assertEqual(credential["agent_id"], agent_id)

        self.assert_credential_listed(agent_id, credential["credential_id"], IDENTITY_PAT)

        credential_get_status, credential_metadata_body, _ = self.request(
            f"/v1/agents/{agent_id}/credentials/{credential['credential_id']}",
            token=IDENTITY_PAT,
        )
        self.assertEqual(credential_get_status, 200)
        self.assertEqual(credential_metadata_body["credential"]["credential_id"], credential["credential_id"])

        credential_eval_status, credential_evaluated = self.evaluate(
            {"tool": "shell", "parameters": {"command": "ls"}},
            token=agent_token,
            agent_id=agent_id,
            environment="development",
        )
        self.assertEqual(credential_eval_status, 200)
        self.assertEqual(credential_evaluated["action"]["agent_id"], agent_id)

        impersonation_status, impersonation_body, _ = self.request(
            "/v1/actions/evaluate",
            method="POST",
            token=agent_token,
            payload={
                "context": {"tenant_id": TENANT_ID, "environment": "development", "agent_id": "different-agent", "invoked_by": "api-test-suite"},
                "action": {"tool": "shell", "parameters": {"command": "ls"}},
            },
        )
        self.assertEqual(impersonation_status, 403)
        self.assertEqual(impersonation_body["error"], "agent_credential_mismatch")

        credential_revoke_status, revoked_credential_body, _ = self.request(
            f"/v1/agents/{agent_id}/credentials/{credential['credential_id']}/revoke",
            method="POST",
            token=IDENTITY_PAT,
            payload={},
        )
        self.assertEqual(credential_revoke_status, 200)
        self.assertEqual(revoked_credential_body["credential"]["status"], "revoked")

        revoked_eval_status, _, _ = self.request(
            "/v1/actions/evaluate",
            method="POST",
            token=agent_token,
            payload={"context": {"tenant_id": TENANT_ID}, "action": {"tool": "shell", "parameters": {"command": "ls"}}},
        )
        self.assertEqual(revoked_eval_status, 401)

        revoke_status, revoked, _ = self.request(f"/v1/agents/{agent_id}/revoke", method="POST", token=IDENTITY_PAT)
        self.assertEqual(revoke_status, 200)
        self.assertEqual(revoked["status"], "revoked")

        denied_status, denied = self.evaluate(
            {"tool": "shell", "parameters": {"command": "ls"}},
            agent_id=agent_id,
            environment="development",
        )
        self.assertEqual(denied_status, 200)
        self.assertEqual(denied["decision"], "deny")
        self.assertIn("AGENT_REVOKED", denied["reason_codes"])

    def test_identity_separation_of_duties_blocks_self_approval(self):
        if not IDENTITY_PAT:
            self.skipTest("Set KENNING_IDENTITY_PAT to test separation-of-duties enforcement.")
        agent_id = f"api-test-sod-agent-{uuid.uuid4().hex[:8]}"
        register_status, _, _ = self.request(
            "/v1/agents",
            method="POST",
            token=IDENTITY_PAT,
            payload={
                "context": {"tenant_id": TENANT_ID},
                "agent_id": agent_id,
                "owner": "finance@example.org",
                "purpose": "Create payment records",
                "allowed_environments": ["production"],
                "approved_tools": ["sql"],
                "may": ["sql:execute:orders"],
                "conditions": {
                    "human_approval_required": True,
                    "separation_of_duties": {"approver_must_differ_from_invoked_by": True},
                },
            },
        )
        self.assertEqual(register_status, 201)
        eval_status, evaluated, _ = self.request(
            "/v1/actions/evaluate",
            method="POST",
            token=IDENTITY_PAT,
            payload={
                "context": {"tenant_id": TENANT_ID, "environment": "production", "agent_id": agent_id, "invoked_by": "finance@example.org"},
                "action": {"tool": "sql", "target": "orders", "parameters": {"statement": "UPDATE orders SET status='closed' WHERE id=1"}},
            },
        )
        self.assertEqual(eval_status, 200)
        approval_id = evaluated["approval"]["approval_id"]
        action_hash = evaluated["action_hash"]

        self_status, self_body, _ = self.request(
            f"/v1/approvals/{approval_id}/decision",
            method="POST",
            token=IDENTITY_PAT,
            payload={"decision": "approve", "approver": "finance@example.org", "action_hash": action_hash},
        )
        self.assertEqual(self_status, 403)
        self.assertEqual(self_body["error"], "separation_of_duties_violation")

        approved_status, approved, _ = self.request(
            f"/v1/approvals/{approval_id}/decision",
            method="POST",
            token=REVIEWER_PAT or IDENTITY_PAT,
            payload={"decision": "approve", "approver": "security@example.org", "action_hash": action_hash},
        )
        self.assertEqual(approved_status, 200)
        self.assertEqual(approved["approval"]["status"], "approved")
        revoke_status, revoked, _ = self.request(f"/v1/agents/{agent_id}/revoke", method="POST", token=IDENTITY_PAT)
        self.assertEqual(revoke_status, 200)
        self.assertEqual(revoked["status"], "revoked")

    def test_policy_create_simulate_publish_and_export(self):
        if not POLICY_PAT:
            self.skipTest("Set KENNING_POLICY_PAT to test policy administration and simulation.")
        policy_id = f"api-test-policy-{uuid.uuid4().hex[:8]}"
        create_status, created, _ = self.request(
            "/v1/policies",
            method="POST",
            token=POLICY_PAT,
            payload={
                "context": {"tenant_id": TENANT_ID},
                "policy_id": policy_id,
                "name": "API test policy",
                "description": "Temporary policy for integration verification.",
                "rules": [
                    {
                        "rule_id": "deny-test-agent-shell",
                        "tool": "shell",
                        "environment": "production",
                        "agent_id": "policy-test-agent",
                        "decision": "deny",
                        "reason": "Test agent shell actions are prohibited in production.",
                    }
                ],
                "test_cases": [
                    {
                        "case_id": "production-shell-denied",
                        "context": {"tenant_id": TENANT_ID, "environment": "production", "agent_id": "policy-test-agent", "invoked_by": "api-test-suite"},
                        "action": {"tool": "shell", "parameters": {"command": "ls"}},
                        "expected_decision": "deny",
                        "expected_reason_codes": ["POLICY_DENY-TEST-AGENT-SHELL"],
                    }
                ],
            },
        )
        self.assertEqual(create_status, 201)
        self.assertEqual(created["version"], 1)
        self.assertEqual(created["status"], "draft")

        update_status, updated, _ = self.request(
            f"/v1/policies/{policy_id}",
            method="PUT",
            token=POLICY_PAT,
            payload={
                "version": 1,
                "name": "Edited API test policy",
                "rules": created["rules"],
                "test_cases": created["test_cases"],
            },
        )
        self.assertEqual(update_status, 200)
        self.assertEqual(updated["name"], "Edited API test policy")

        get_status, fetched, _ = self.request(f"/v1/policies/{policy_id}", token=POLICY_PAT)
        self.assertEqual(get_status, 200)
        self.assertEqual(fetched["policy_id"], policy_id)
        self.assertEqual(fetched["version"], 1)

        test_status, tested, _ = self.request(
            f"/v1/policies/{policy_id}/test",
            method="POST",
            token=POLICY_PAT,
            payload={"version": 1},
        )
        self.assertEqual(test_status, 200)
        self.assertTrue(tested["all_passed"])
        self.assertEqual(tested["passed_count"], 1)

        simulate_status, simulated, _ = self.request(
            f"/v1/policies/{policy_id}/simulate",
            method="POST",
            token=POLICY_PAT,
            payload={
                "version": 1,
                "context": {"tenant_id": TENANT_ID, "environment": "production", "agent_id": "policy-test-agent", "invoked_by": "api-test-suite"},
                "action": {"tool": "shell", "parameters": {"command": "ls"}},
            },
        )
        self.assertEqual(simulate_status, 200)
        self.assertTrue(simulated["simulation"])
        self.assertEqual(simulated["decision"], "deny")
        self.assertEqual(simulated["policy_matches"][0]["policy_id"], policy_id)
        self.assertEqual(simulated["policy_resolution"]["strategy"], "most_restrictive_wins")
        self.assertEqual(simulated["policy_resolution"]["selected_match"]["rule_id"], "deny-test-agent-shell")

        publish_status, published, _ = self.request(
            f"/v1/policies/{policy_id}/publish",
            method="POST",
            token=POLICY_PAT,
            payload={"version": 1, "published_by": "api-test-suite"},
        )
        self.assertEqual(publish_status, 200)
        self.assertEqual(published["status"], "published")

        delete_policy_id = f"api-test-draft-delete-{uuid.uuid4().hex[:8]}"
        delete_create_status, _, _ = self.request(
            "/v1/policies",
            method="POST",
            token=POLICY_PAT,
            payload={
                "policy_id": delete_policy_id,
                "name": "API draft to delete",
                "rules": [],
            },
        )
        self.assertEqual(delete_create_status, 201)
        delete_status, deleted, _ = self.request(
            f"/v1/policies/{delete_policy_id}",
            method="DELETE",
            token=POLICY_PAT,
            payload={"version": 1},
        )
        self.assertEqual(delete_status, 200)
        self.assertEqual(deleted["status"], "deleted")
        missing_status, missing, _ = self.request(f"/v1/policies/{delete_policy_id}", token=POLICY_PAT)
        self.assertEqual(missing_status, 404)

        list_status, listed, _ = self.request("/v1/policies", token=POLICY_PAT)
        self.assertEqual(list_status, 200)
        self.assertTrue(any(item["policy_id"] == policy_id for item in listed["policies"]))

        evaluate_status, evaluated = self.evaluate(
            {"tool": "shell", "parameters": {"command": "ls"}},
            agent_id="policy-test-agent",
            environment="production",
        )
        self.assertEqual(evaluate_status, 200)
        self.assertEqual(evaluated["decision"], "deny")
        self.assertTrue(any(match["policy_id"] == policy_id for match in evaluated["policy_matches"]))

        historical_status, historical, _ = self.request(
            f"/v1/policies/{policy_id}/simulate",
            method="POST",
            token=POLICY_PAT,
            payload={
                "version": 1,
                "context": {"tenant_id": TENANT_ID},
                "source_action_id": evaluated["action"]["action_id"],
            },
        )
        self.assertEqual(historical_status, 200)
        self.assertTrue(historical["simulation"])
        self.assertEqual(historical["decision"], "deny")
        self.assertEqual(historical["simulation_source"]["type"], "historical_action")
        self.assertEqual(historical["simulation_source"]["action_id"], evaluated["action"]["action_id"])

        export_status, exported, _ = self.request(f"/v1/audit/export?tenant_id={TENANT_ID}&format=jsonl&limit=20")
        self.assertEqual(export_status, 200)
        self.assertEqual(exported["format"], "jsonl")
        self.assertTrue(all(isinstance(item, str) for item in exported["events"]))


@unittest.skipUnless(
    (API_URL and TENANT_PAT) or _use_local_api(),
    "Set deployed API credentials or enable the local API harness.",
)
class TenantAdministrationApiTests(LocalApiTestMixin, unittest.TestCase):
    def request(self, path: str, method: str = "GET", payload: dict[str, Any] | None = None) -> tuple[int, dict[str, Any] | None]:
        body = None if method == "GET" else json.dumps(payload or {}).encode("utf-8")
        request = urllib.request.Request(f"{API_URL}{path}", data=body, method=method)
        request.add_header("Accept", "application/json")
        request.add_header("Authorization", f"Bearer {TENANT_PAT}")
        if body is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            try:
                return error.code, json.loads(error.read().decode("utf-8"))
            finally:
                error.close()

    def test_tenant_boundary_environment_mode_and_retention(self):
        tenant = TENANT_ADMIN_TENANT_ID
        get_status, legacy = self.request(f"/v1/tenants/{tenant}")
        self.assertEqual(get_status, 200)
        self.assertEqual(legacy["tenant_id"], tenant)

        put_status, config = self.request(
            f"/v1/tenants/{tenant}",
            method="PUT",
            payload={
                "name": "Automated tenant admin test",
                "status": "active",
                "default_environment": "production",
                "retention_enabled": True,
                "retention_days": 30,
                "legal_hold_enabled": False,
                "data_residency_region": "us-east-1",
                "capture_policy": {
                    "store_original_action": False,
                    "redact_fields": ["target"],
                    "hash_fields": ["parameters.statement"],
                },
                "citation_policy": {
                    "allowed_domains": ["example.com", "example.govt.nz"],
                    "require_https": True,
                    "allow_inline_source_text": True,
                    "minimum_source_quality": "unknown",
                    "claim_type_policies": {
                        "legal": {
                            "minimum_source_quality": "authoritative",
                            "max_age_days": 30,
                            "require_currency": True,
                        }
                    },
                },
                "environments": [
                    {"environment_id": "production", "status": "active", "mode": "enforce", "allowed_tools": ["sql"]},
                ],
            },
        )
        self.assertIn(put_status, {200, 201})
        self.assertTrue(config["retention_enabled"])

        environment_status, environment = self.request(
            f"/v1/tenants/{tenant}/environments/staging",
            method="PUT",
            payload={"status": "active", "mode": "observe", "allowed_tools": ["shell"]},
        )
        self.assertEqual(environment_status, 200)
        self.assertEqual(environment["environment_id"], "staging")
        self.assertEqual(environment["mode"], "observe")

        environment_list_status, environment_list = self.request(f"/v1/tenants/{tenant}/environments")
        self.assertEqual(environment_list_status, 200)
        self.assertTrue(any(item["environment_id"] == "staging" for item in environment_list["environments"]))

        denied_status, denied = self.request(
            "/v1/actions/evaluate",
            method="POST",
            payload={
                "context": {"tenant_id": tenant, "environment": "production", "agent_id": "tenant-api-test-agent", "invoked_by": "api-test"},
                "action": {"tool": "shell", "parameters": {"command": "ls"}},
            },
        )
        self.assertEqual(denied_status, 200)
        self.assertEqual(denied["decision"], "deny")
        self.assertIn("ENVIRONMENT_TOOL_NOT_ALLOWED", denied["reason_codes"])

        secret_statement = "UPDATE accounts SET status='closed', note='live-capture-secret-9842'"
        captured_status, captured = self.request(
            "/v1/actions/evaluate",
            method="POST",
            payload={
                "context": {"tenant_id": tenant, "environment": "production", "agent_id": "tenant-api-capture-agent", "invoked_by": "api-test"},
                "action": {"tool": "sql", "target": "accounts", "parameters": {"statement": secret_statement}},
            },
        )
        self.assertEqual(captured_status, 200)
        self.assertNotIn(secret_statement, json.dumps(captured))
        self.assertNotIn("original_action", captured["action"])
        self.assertTrue(captured["action"]["parameters"]["statement"].startswith("sha256:"))

        citation_status, citation = self.request(
            "/v1/citations/verify",
            method="POST",
            payload={
                "context": {"tenant_id": tenant, "agent_id": "tenant-api-citation-agent", "invoked_by": "api-test"},
                "response": "Example Domain",
                "citations": [{"url": "https://example.com", "claim": "Example Domain", "source_text": "Example Domain"}],
            },
        )
        self.assertEqual(citation_status, 200)
        self.assertEqual(citation["status"], "pass")
        self.assertEqual(citation["citation_policy"]["allowed_domains"], ["example.com", "example.govt.nz"])

        claim_type_status, claim_type_citation = self.request(
            "/v1/citations/verify",
            method="POST",
            payload={
                "context": {"tenant_id": tenant, "agent_id": "tenant-api-citation-agent", "invoked_by": "api-test"},
                "response": "The legal policy applies to public agencies.",
                "citations": [
                    {
                        "url": "https://example.govt.nz/policy",
                        "claim": "The legal policy applies to public agencies.",
                        "claim_type": "legal",
                        "published_at": "2026-07-16T00:00:00Z",
                        "source_text": "The legal policy applies to public agencies.",
                    }
                ],
            },
        )
        self.assertEqual(claim_type_status, 200)
        self.assertEqual(claim_type_citation["status"], "pass")
        finding = claim_type_citation["citations"][0]
        self.assertEqual(finding["claim_type"], "legal")
        self.assertEqual(finding["policy_scope"]["minimum_source_quality"], "authoritative")
        self.assertTrue(finding["currency_acceptable"])

        retention_status, retention = self.request(f"/v1/tenants/{tenant}/retention/run", method="POST", payload={})
        self.assertEqual(retention_status, 200)
        self.assertTrue(retention["dry_run"])

        hold_status, hold = self.request(
            f"/v1/tenants/{tenant}",
            method="PUT",
            payload={
                "legal_hold_enabled": True,
                "legal_hold_reason": "Automated integration investigation",
                "data_residency_region": "us-east-1",
            },
        )
        self.assertEqual(hold_status, 200)
        self.assertTrue(hold["legal_hold_enabled"])
        blocked_status, blocked = self.request(
            f"/v1/tenants/{tenant}/retention/run",
            method="POST",
            payload={"execute": True},
        )
        self.assertEqual(blocked_status, 409)
        self.assertEqual(blocked["error"], "legal_hold_active")

        mismatch_status, mismatch = self.request(f"/v1/tenants/{TENANT_ID}")
        self.assertEqual(mismatch_status, 403)
        self.assertEqual(mismatch["error"], "tenant_mismatch")


if __name__ == "__main__":
    unittest.main()
