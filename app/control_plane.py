"""Tenant control-plane primitives.

The control plane deliberately keeps browser sessions separate from machine
credentials.  Sessions are opaque, short-lived values stored as hashes in the
token table; tenant membership is looked up from the shared audit table on
every tenant-scoped request.
"""

from __future__ import annotations

import hashlib
import os
import re
from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import urlparse


SESSION_COOKIE_NAME = "kta_session"
SESSION_TOKEN_PREFIX = "kta_session_"
DEFAULT_SESSION_TTL_SECONDS = 8 * 60 * 60
MAX_SESSION_TTL_SECONDS = 24 * 60 * 60
DEFAULT_SESSION_INACTIVITY_SECONDS = 30 * 60
MAX_SESSION_INACTIVITY_SECONDS = 8 * 60 * 60
SUBJECT_PATTERN = re.compile(r"^[^\x00-\x1f\x7f]{1,256}$")
EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

ROLE_ORDER = {
    "viewer": 10,
    "auditor": 20,
    "approver": 30,
    "policy_admin": 40,
    "agent_integrations": 40,
    "admin": 50,
    "owner": 60,
}

ROLE_SCOPES = {
    "viewer": {"tenant:read", "audit:read", "proof:read", "policy:read", "identity:read", "model:read"},
    "auditor": {"tenant:read", "audit:read", "proof:read", "policy:read", "identity:read", "model:read"},
    "approver": {
        "tenant:read", "audit:read", "proof:read", "approve:actions",
        "token:admin", "guard:evaluate", "mcp:read",
    },
    "policy_admin": {"tenant:read", "tenant:write", "audit:read", "proof:read", "policy:read", "policy:write", "policy:simulate", "model:read", "model:write"},
    "agent_integrations": {"tenant:read", "identity:read", "identity:write", "policy:read", "model:read"},
    "admin": {
        "tenant:read", "tenant:write", "tenant:retention", "audit:read", "audit:write",
        "approve:actions", "actions:write", "proof:read", "proof:write", "citation:verify",
        "identity:read", "identity:write", "policy:read", "policy:write", "policy:simulate",
        "model:read", "model:write",
        "token:admin", "guard:evaluate", "mcp:read",
    },
    "owner": {
        "tenant:read", "tenant:write", "tenant:retention", "audit:read", "audit:write",
        "approve:actions", "actions:write", "proof:read", "proof:write", "citation:verify",
        "identity:read", "identity:write", "policy:read", "policy:write", "policy:simulate",
        "model:read", "model:write",
        "token:admin", "guard:evaluate", "mcp:read",
    },
}


def normalise_subject(value: Any) -> str:
    subject = str(value or "").strip()
    if not subject or not SUBJECT_PATTERN.fullmatch(subject):
        raise ValueError("subject is required and must be a printable identifier no longer than 256 characters.")
    return subject


def normalise_role(value: Any) -> str:
    role = str(value or "viewer").strip().lower().replace("-", "_")
    if role not in ROLE_ORDER:
        raise ValueError(f"role must be one of: {', '.join(sorted(ROLE_ORDER))}.")
    return role


def normalise_email(value: Any) -> str | None:
    email = str(value or "").strip().lower()
    if not email:
        return None
    if len(email) > 320 or not EMAIL_PATTERN.fullmatch(email):
        raise ValueError("email must be a valid email address.")
    return email


def role_scopes(role: str) -> list[str]:
    return sorted(ROLE_SCOPES[normalise_role(role)])


def membership_record(
    tenant_id: str,
    subject: str,
    payload: dict[str, Any] | None = None,
    existing: dict[str, Any] | None = None,
    *,
    actor: str = "control-plane",
) -> dict[str, Any]:
    payload = payload if isinstance(payload, dict) else {}
    existing = existing if isinstance(existing, dict) else {}
    tenant_id = str(tenant_id or "").strip()
    if not tenant_id or len(tenant_id) > 64:
        raise ValueError("tenant_id is required and must be no longer than 64 characters.")
    subject = normalise_subject(subject)
    role = normalise_role(payload.get("role") if "role" in payload else existing.get("role") or "viewer")
    status = str(payload.get("status") if "status" in payload else existing.get("status") or "active").strip().lower()
    if status not in {"active", "invited", "suspended", "revoked"}:
        raise ValueError("status must be one of: active, invited, suspended, revoked.")
    display_name = str(payload.get("display_name") if "display_name" in payload else existing.get("display_name") or "").strip()
    if len(display_name) > 256:
        raise ValueError("display_name must be no longer than 256 characters.")
    email = normalise_email(payload.get("email") if "email" in payload else existing.get("email"))
    now = str(existing.get("updated_at") or "") or None
    from datetime import datetime, timezone
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return {
        "item_type": "tenant_membership",
        "tenant_id": tenant_id,
        "subject": subject,
        "email": email,
        "display_name": display_name or None,
        "role": role,
        "status": status,
        "created_at": str(existing.get("created_at") or timestamp),
        "updated_at": timestamp,
        "created_by": str(existing.get("created_by") or actor),
        "updated_by": actor,
        "role_scopes": role_scopes(role),
    }


def membership_summary(record: dict[str, Any], product_entitlements: list[str] | None = None) -> dict[str, Any]:
    summary = {
        "tenant_id": record.get("tenant_id"),
        "subject": record.get("subject"),
        "email": record.get("email"),
        "display_name": record.get("display_name"),
        "role": record.get("role"),
        "status": record.get("status"),
        "created_at": record.get("created_at"),
        "updated_at": record.get("updated_at"),
    }
    if product_entitlements is not None:
        summary["product_entitlements"] = list(product_entitlements)
    return summary


def session_hash(token: str) -> str:
    return hashlib.sha256(str(token).encode("utf-8")).hexdigest()


def session_ttl() -> int:
    try:
        configured = int(os.environ.get("CONTROL_PLANE_SESSION_TTL_SECONDS", DEFAULT_SESSION_TTL_SECONDS))
    except (TypeError, ValueError):
        configured = DEFAULT_SESSION_TTL_SECONDS
    return max(900, min(configured, MAX_SESSION_TTL_SECONDS))


def session_inactivity_ttl() -> int:
    try:
        configured = int(os.environ.get("CONTROL_PLANE_SESSION_INACTIVITY_SECONDS", DEFAULT_SESSION_INACTIVITY_SECONDS))
    except (TypeError, ValueError):
        configured = DEFAULT_SESSION_INACTIVITY_SECONDS
    return max(300, min(configured, MAX_SESSION_INACTIVITY_SECONDS))


def portal_origin() -> str:
    """Return the configured HTTPS origin used after an OIDC callback."""

    value = str(os.environ.get("CONTROL_PLANE_PORTAL_ORIGIN") or "").strip().rstrip("/")
    if not value:
        return ""
    parsed = urlparse(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise ValueError("CONTROL_PLANE_PORTAL_ORIGIN must be an HTTPS origin without a path or query.")
    return value


def parse_cookie(header_value: Any, name: str = SESSION_COOKIE_NAME) -> str | None:
    cookie = SimpleCookie()
    try:
        cookie.load(str(header_value or ""))
    except Exception:  # pragma: no cover
        return None
    morsel = cookie.get(name)
    value = str(morsel.value) if morsel else ""
    if not value or (name == SESSION_COOKIE_NAME and not value.startswith(SESSION_TOKEN_PREFIX)) or len(value) > 256:
        return None
    return value


def session_cookie(token: str, *, max_age: int | None = None) -> str:
    ttl = session_ttl() if max_age is None else max(0, int(max_age))
    return f"{SESSION_COOKIE_NAME}={token}; Max-Age={ttl}; Path=/; HttpOnly; Secure; SameSite=None"


def clear_session_cookie() -> str:
    return session_cookie("", max_age=0).replace(f"{SESSION_COOKIE_NAME}=;", f"{SESSION_COOKIE_NAME}=;", 1)


def is_session_auth(auth: dict[str, Any] | None) -> bool:
    return bool(auth and auth.get("token_type") == "session" and auth.get("auth_source") == "session")


def role_allows(actual_role: str, minimum_role: str) -> bool:
    return ROLE_ORDER.get(normalise_role(actual_role), 0) >= ROLE_ORDER.get(normalise_role(minimum_role), 999)
