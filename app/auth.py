"""Authentication and authorization helpers for Kenning Agent Guard (#250).

Pure functions that do not depend on module-level DynamoDB state live here.
Stateful functions (authenticate, session_authentication, record_auth_failure)
remain in lambda_function.py until the dependency-injection refactor lands.
"""

from __future__ import annotations

import os
from typing import Any


def has_scope(auth: dict[str, Any], required: str) -> bool:
    scopes = set(auth.get("scopes") or [])
    return "admin" in scopes or required in scopes


def scope_error(required: str) -> dict[str, Any]:
    # Imported lazily to avoid circular dependency at module load time.
    try:  # pragma: no cover
        from lambda_function import response
    except ImportError:  # pragma: no cover
        from .lambda_function import response

    return response(403, {"error": "insufficient_scope", "required_scope": required})


def is_session_auth(auth: dict[str, Any]) -> bool:
    return str(auth.get("auth_source") or auth.get("token_type") or "") == "session"


def is_platform_admin_session(auth: dict[str, Any]) -> bool:
    """Return whether a browser session was created from an admin PAT.

    The session is still constrained to the platform-admin capability. The
    browser never receives the original PAT, and tenant membership remains a
    separate authorization boundary for tenant-scoped resources.
    """

    return bool(is_session_auth(auth) and auth.get("platform_admin"))


def configured_platform_admin_groups() -> set[str]:
    """Return the explicitly configured OIDC groups that may administer the platform."""

    raw = str(os.environ.get("CONTROL_PLANE_PLATFORM_ADMIN_GROUPS") or "")
    return {item.strip() for item in raw.split(",") if item.strip()}


def is_platform_admin_principal(auth: dict[str, Any]) -> bool:
    """Return whether a verified principal has the platform-admin capability."""

    if has_scope(auth, "admin"):
        return True
    configured = configured_platform_admin_groups()
    groups = {str(item).strip() for item in (auth.get("groups") or []) if str(item).strip()}
    return bool(configured and configured.intersection(groups))


def authenticated_principal(auth: dict[str, Any]) -> str:
    """Return the non-secret identity that authenticated the request."""

    if auth.get("auth_source") in {"oidc", "oauth2", "session", "aws_iam"}:
        return str(auth.get("subject") or auth.get("token_id") or "unknown-principal")
    if auth.get("token_type") == "agent":
        return str(auth.get("agent_id") or auth.get("token_id") or "unknown-agent")
    return str(auth.get("token_id") or "unknown-principal")


def product_for_api_path(path: str) -> str | None:
    """Map product-specific HTTP resources to their workspace entitlement."""

    if path.startswith("/v1/actions") or path.startswith("/v1/policies") or path.startswith("/v1/compliance/") or path.startswith("/v1/approvals") or path == "/v1/tokens" or path.startswith("/v1/tokens/"):
        return "agent-guard"
    if path == "/v1/receipts/public-key" or path.startswith("/v1/proofs"):
        return "agent-proof"
    if path.startswith("/v1/citations") or path.startswith("/v1/citation-reports"):
        return "citation-trust"
    if path.startswith("/v1/agents") or path.startswith("/v1/models") or path.startswith("/v1/workload-identity"):
        return "agent-identity"
    if path == "/mcp/agent-guard":
        return "agent-guard"
    if path == "/mcp/agent-proof":
        return "agent-proof"
    if path == "/mcp/citation-trust":
        return "citation-trust"
    if path == "/mcp/agent-identity":
        return "agent-identity"
    return None
