"""Dependency-free Python SDK for synchronous pre-execution Guard checks."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class ApiError(RuntimeError):
    """Raised when the Guard API returns a non-success response."""

    def __init__(self, status_code: int, body: Any) -> None:
        self.status_code = status_code
        self.body = body
        super().__init__(f"Kenning API returned HTTP {status_code}: {body}")


class GuardBlocked(RuntimeError):
    """Raised by :func:`before_tool_call` when the action cannot proceed."""

    def __init__(self, decision: dict[str, Any]) -> None:
        self.decision = decision
        super().__init__(
            f"Kenning Guard returned {decision.get('decision', 'unknown')}: "
            f"{', '.join(decision.get('reason_codes') or [])}"
        )


class GuardClient:
    """Minimal HTTP client for the synchronous Guard integration surface."""

    def __init__(self, base_url: str, pat: str, *, tenant_id: str | None = None, timeout: int = 30) -> None:
        self.base_url = str(base_url).rstrip("/")
        self.pat = str(pat)
        self.tenant_id = tenant_id
        self.timeout = timeout

    def _context(self, context: dict[str, Any] | None) -> dict[str, Any]:
        result = dict(context or {})
        if self.tenant_id and not result.get("tenant_id"):
            result["tenant_id"] = self.tenant_id
        return result

    @staticmethod
    def _decode(raw: str, content_type: str) -> Any:
        if not raw:
            return None
        if "application/x-ndjson" in content_type:
            return [json.loads(line) for line in raw.splitlines() if line.strip()]
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw

    def _request(self, path: str, method: str = "GET", payload: dict[str, Any] | None = None) -> Any:
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(f"{self.base_url}{path}", data=body, method=method)
        request.add_header("Accept", "application/json, application/x-ndjson")
        request.add_header("Authorization", f"Bearer {self.pat}")
        if body is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8")
                content_type = str(response.headers.get("content-type") or "")
                if response.status >= 400:
                    raise ApiError(response.status, self._decode(raw, content_type))
                return self._decode(raw, content_type)
        except urllib.error.HTTPError as error:
            raw = error.read().decode("utf-8")
            content_type = str(error.headers.get("content-type") or "")
            raise ApiError(error.code, self._decode(raw, content_type)) from error

    def _query(self, path: str, query: dict[str, Any] | None = None) -> Any:
        """Issue a tenant-aware GET request with only populated query values."""

        params = {str(key): value for key, value in (query or {}).items() if value not in (None, "")}
        if self.tenant_id and "tenant_id" not in params:
            params["tenant_id"] = self.tenant_id
        query_string = urllib.parse.urlencode(params)
        return self._request(f"{path}?{query_string}" if query_string else path)

    def _tenant_id(self, tenant_id: str | None = None) -> str:
        selected = str(tenant_id or self.tenant_id or "").strip()
        if not selected:
            raise ValueError("tenant_id is required for this SDK operation.")
        return selected

    def evaluate(
        self,
        action: dict[str, Any],
        *,
        context: dict[str, Any] | None = None,
        intent: str | None = None,
        mode: str | None = None,
        proof: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"context": self._context(context), "action": action}
        if intent is not None:
            payload["intent"] = intent
        if mode is not None:
            payload["mode"] = mode
        if proof is not None:
            payload["proof"] = proof
        return self._request("/v1/actions/evaluate", "POST", payload)

    def record_outcome(
        self,
        action_id: str,
        *,
        status: str,
        action_hash: str,
        proof_id: str | None = None,
        approval_id: str | None = None,
        result: Any = None,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "context": self._context(context),
            "status": status,
            "action_hash": action_hash,
        }
        for key, value in (("proof_id", proof_id), ("approval_id", approval_id), ("result", result)):
            if value is not None:
                payload[key] = value
        return self._request(f"/v1/actions/{action_id}/outcome", "POST", payload)

    def get_approval(self, approval_id: str) -> dict[str, Any]:
        return self._request(f"/v1/approvals/{approval_id}")

    def list_approvals(
        self,
        *,
        status: str | None = None,
        agent_id: str | None = None,
        environment: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Return the tenant-scoped reviewer queue."""

        return self._query(
            "/v1/approvals",
            {"status": status, "agent_id": agent_id, "environment": environment, "limit": limit},
        )

    def decide_approval(
        self,
        approval_id: str,
        decision: str,
        approver: str | None = None,
        action_hash: str = "",
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "context": self._context(None),
            "decision": decision,
            "action_hash": action_hash,
        }
        if approver is not None:
            payload["approver"] = approver
        return self._request(f"/v1/approvals/{approval_id}/decision", "POST", payload)

    def revoke_approval(self, approval_id: str, *, reason: str | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {"context": self._context(None)}
        if reason is not None:
            payload["reason"] = reason
        return self._request(f"/v1/approvals/{approval_id}/revoke", "POST", payload)

    def export_audit(self, *, query: dict[str, Any] | None = None, format: str = "json") -> Any:
        params = dict(query or {})
        params["format"] = format
        if self.tenant_id and "tenant_id" not in params:
            params["tenant_id"] = self.tenant_id
        query_string = urllib.parse.urlencode(params)
        return self._request(f"/v1/audit/export?{query_string}")

    def search_audit(self, *, query: dict[str, Any] | None = None) -> dict[str, Any]:
        """Search correlated tenant audit events."""

        return self._query("/v1/audit", query)

    def metrics(self, *, start_time: str | None = None, end_time: str | None = None) -> dict[str, Any]:
        return self._query("/v1/metrics", {"start_time": start_time, "end_time": end_time})

    def verify_citations(
        self,
        response: str,
        *,
        citations: list[dict[str, Any]] | None = None,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"context": self._context(context), "response": response}
        if citations is not None:
            payload["citations"] = citations
        return self._request("/v1/citations/verify", "POST", payload)

    def create_proof(
        self,
        request: dict[str, Any],
        *,
        context: dict[str, Any] | None = None,
        inputs: list[dict[str, Any]] | None = None,
        evidence: list[dict[str, Any]] | None = None,
        decision_factors: list[dict[str, Any]] | None = None,
        recommendation: Any = None,
        limitations: list[str] | None = None,
        model: dict[str, Any] | None = None,
        tools_used: list[dict[str, Any]] | None = None,
        approvals: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"context": self._context(context), "request": request}
        optional = {
            "inputs": inputs,
            "evidence": evidence,
            "decision_factors": decision_factors,
            "recommendation": recommendation,
            "limitations": limitations,
            "model": model,
            "tools_used": tools_used,
            "approvals": approvals,
        }
        payload.update({key: value for key, value in optional.items() if value is not None})
        return self._request("/v1/proofs", "POST", payload)

    def get_proof(self, proof_id: str, *, report: bool = False) -> dict[str, Any]:
        suffix = "/report" if report else ""
        return self._request(f"/v1/proofs/{proof_id}{suffix}")

    def verify_proof(self, proof_id: str) -> dict[str, Any]:
        return self._request(f"/v1/proofs/{proof_id}/verify")

    def receipt_public_key(self) -> dict[str, Any]:
        return self._request("/v1/receipts/public-key")

    def list_tenants(self, *, status: str | None = None, limit: int = 100) -> dict[str, Any]:
        return self._query("/v1/tenants", {"status": status, "limit": limit})

    def get_tenant(self, tenant_id: str | None = None) -> dict[str, Any]:
        return self._request(f"/v1/tenants/{self._tenant_id(tenant_id)}")

    def put_tenant(self, config: dict[str, Any], *, tenant_id: str | None = None) -> dict[str, Any]:
        return self._request(f"/v1/tenants/{self._tenant_id(tenant_id)}", "PUT", dict(config))

    def list_environments(self, tenant_id: str | None = None) -> dict[str, Any]:
        selected = self._tenant_id(tenant_id)
        return self._request(f"/v1/tenants/{selected}/environments")

    def put_environment(
        self,
        environment_id: str,
        config: dict[str, Any],
        *,
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        selected = self._tenant_id(tenant_id)
        return self._request(f"/v1/tenants/{selected}/environments/{environment_id}", "PUT", dict(config))

    def run_retention(self, *, execute: bool = False, tenant_id: str | None = None) -> dict[str, Any]:
        selected = self._tenant_id(tenant_id)
        return self._request(
            f"/v1/tenants/{selected}/retention/run",
            "POST",
            {"execute": execute},
        )

    def register_agent(self, agent: dict[str, Any], *, context: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = dict(agent)
        payload["context"] = self._context(context)
        return self._request("/v1/agents", "POST", payload)

    def list_agents(self) -> dict[str, Any]:
        return self._request("/v1/agents")

    def get_agent(self, agent_id: str) -> dict[str, Any]:
        return self._request(f"/v1/agents/{agent_id}")

    def revoke_agent(self, agent_id: str) -> dict[str, Any]:
        return self._request(f"/v1/agents/{agent_id}/revoke", "POST", {})

    def issue_agent_credential(
        self,
        agent_id: str,
        *,
        name: str | None = None,
        expires_in_seconds: int = 900,
        scopes: list[str] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"expires_in_seconds": expires_in_seconds}
        if name is not None:
            payload["name"] = name
        if scopes is not None:
            payload["scopes"] = scopes
        return self._request(f"/v1/agents/{agent_id}/credentials", "POST", payload)

    def list_agent_credentials(self, agent_id: str) -> dict[str, Any]:
        return self._request(f"/v1/agents/{agent_id}/credentials")

    def get_agent_credential(self, agent_id: str, credential_id: str) -> dict[str, Any]:
        return self._request(f"/v1/agents/{agent_id}/credentials/{credential_id}")

    def revoke_agent_credential(self, agent_id: str, credential_id: str) -> dict[str, Any]:
        return self._request(f"/v1/agents/{agent_id}/credentials/{credential_id}/revoke", "POST", {})

    def list_tokens(self) -> dict[str, Any]:
        return self._query("/v1/tokens")

    def create_token(
        self,
        name: str,
        *,
        scopes: list[str] | None = None,
        groups: list[str] | None = None,
        expires_in_days: int = 0,
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"name": name, "expires_in_days": expires_in_days}
        if scopes is not None:
            payload["scopes"] = scopes
        if groups is not None:
            payload["groups"] = groups
        selected = tenant_id or self.tenant_id
        if selected:
            payload["tenant_id"] = selected
        return self._request("/v1/tokens", "POST", payload)

    def revoke_token(self, token_id: str, *, tenant_id: str | None = None) -> dict[str, Any]:
        selected = tenant_id or self.tenant_id
        payload = {"tenant_id": selected} if selected else {}
        return self._request(f"/v1/tokens/{token_id}/revoke", "POST", payload)

    def list_policies(self) -> dict[str, Any]:
        return self._request("/v1/policies")

    def create_policy(self, policy: dict[str, Any], *, context: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = dict(policy)
        payload["context"] = self._context(context)
        return self._request("/v1/policies", "POST", payload)

    def get_policy(self, policy_id: str, *, version: int | None = None) -> dict[str, Any]:
        return self._query(f"/v1/policies/{policy_id}", {"version": version})

    def publish_policy(
        self,
        policy_id: str,
        *,
        version: int | None = None,
        published_by: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        if version is not None:
            payload["version"] = version
        if published_by is not None:
            payload["published_by"] = published_by
        return self._request(f"/v1/policies/{policy_id}/publish", "POST", payload)

    def simulate_policy(
        self,
        policy_id: str,
        action: dict[str, Any] | None = None,
        *,
        version: int | None = None,
        context: dict[str, Any] | None = None,
        mode: str | None = None,
        source_action_id: str | None = None,
    ) -> dict[str, Any]:
        if action is None and not source_action_id:
            raise ValueError("action or source_action_id is required for policy simulation.")
        payload = dict(action or {})
        payload["context"] = self._context(context)
        if version is not None:
            payload["version"] = version
        if mode is not None:
            payload["mode"] = mode
        if source_action_id is not None:
            payload["source_action_id"] = source_action_id
        return self._request(f"/v1/policies/{policy_id}/simulate", "POST", payload)

    def test_policy(
        self,
        policy_id: str,
        *,
        version: int | None = None,
        cases: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        if version is not None:
            payload["version"] = version
        if cases is not None:
            payload["cases"] = cases
        return self._request(f"/v1/policies/{policy_id}/test", "POST", payload)

    def ingest_audit_event(
        self,
        event_type: str,
        *,
        context: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
        **fields: Any,
    ) -> dict[str, Any]:
        """Append one external run, tool, or outcome event to the audit trail."""

        payload: dict[str, Any] = {"context": self._context(context), "event_type": event_type, **fields}
        if idempotency_key is not None:
            payload["idempotency_key"] = idempotency_key
        return self._request("/v1/audit/events", "POST", payload)


def before_tool_call(
    client: GuardClient,
    action: dict[str, Any],
    *,
    context: dict[str, Any] | None = None,
    intent: str | None = None,
    proof: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Evaluate an action synchronously and raise before unsafe execution."""

    decision = client.evaluate(action, context=context, intent=intent, proof=proof)
    if decision.get("decision") not in {"allow", "warn", "observe"}:
        raise GuardBlocked(decision)
    return decision
