"""POC Agent Identity registration and delegated action authorisation."""

from __future__ import annotations

import fnmatch
import re
import uuid
from datetime import datetime, timezone
from typing import Any

try:
    from guard import _redact, utc_now
    from governance import normalise_documentation
except ModuleNotFoundError:  # Local package import during tests.
    from .guard import _redact, utc_now
    from .governance import normalise_documentation


AUTHORITY_RANK = {
    "read": 10,
    "standard": 20,
    "high": 30,
    "admin": 40,
}
DEFAULT_AUTHORITY = "high"
MAX_DELEGATION_DEPTH = 8
AUTHORITY_ALIASES = {
    "low": "read",
    "medium": "standard",
    "elevated": "high",
    "critical": "admin",
}


def normalise_authority_level(value: Any, field: str = "maximum_authority") -> str:
    """Return a bounded authority level for an agent delegation."""

    level = str(value or DEFAULT_AUTHORITY).strip().lower()
    level = AUTHORITY_ALIASES.get(level, level)
    if level not in AUTHORITY_RANK:
        raise ValueError(f"{field} must be read, standard, high, or admin.")
    return level


def authority_rank(value: Any) -> int:
    return AUTHORITY_RANK[normalise_authority_level(value)]


def normalise_delegation_chain(value: Any) -> list[str]:
    """Validate the non-secret principal chain that created an agent."""

    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("delegation_chain must be an array.")
    if len(value) > MAX_DELEGATION_DEPTH:
        raise ValueError(f"delegation_chain may contain at most {MAX_DELEGATION_DEPTH} principals.")
    chain = [str(item).strip() for item in value if str(item).strip()]
    if len(chain) != len(set(chain)):
        raise ValueError("delegation_chain must not contain duplicate principals.")
    return chain


def required_authority(action: dict[str, Any]) -> str:
    """Infer the minimum authority needed from the action, not caller input."""

    tool = str(action.get("tool") or "").lower()
    operation = str(action.get("operation") or "execute").lower()
    environment = str(action.get("environment") or "development").lower()
    parameters = action.get("parameters") if isinstance(action.get("parameters"), dict) else {}
    target = str(action.get("target") or "").lower()
    text = f"{tool} {operation} {target} {parameters}".lower()
    mutation_pattern = r"\b(update|insert|delete|drop|truncate|create|alter|grant|revoke|write|destroy|terminate|deploy|send|transfer|pay|charge)\b"
    high_risk_pattern = r"\b(delete|drop|truncate|create|alter|grant|revoke|destroy|terminate|transfer|pay|charge|refund|withdraw|payout|wire|approve)\b"
    read_only = operation in {"read", "get", "list", "view", "inspect", "check", "query", "select", "describe", "status"}
    sql_read_only = False
    if tool in {"sql", "database"}:
        raw_statement = str(parameters.get("statement") or parameters.get("query") or "")
        # Strip leading SQL comments so commented queries keep read authority.
        stripped = re.sub(r"\A(\s*(--[^\n]*\n|/\*.*?\*/)\s*)*", "", raw_statement, flags=re.DOTALL).lstrip().lower()
        # A multi-statement payload (e.g. "SELECT 1; DROP TABLE x") must not
        # take the read-only fast path even if it begins with a read verb.
        single_statement = not re.search(r";\s*\S", stripped)
        sql_read_only = stripped.startswith(("select", "show", "describe", "explain")) and single_statement
        read_only = sql_read_only or (read_only and not stripped)
    if tool in {"aws", "azure", "cloud"} and re.search(r"\b(iam|kms|secretsmanager|key[_-]?vault|policy|security[_-]?group|role)\b", text):
        return "admin"
    # SHOW CREATE is read-only metadata, but mutation checks must still inspect
    # the complete SQL statement so stacked statements cannot bypass authority.
    mutation_text = re.sub(r"\bshow\s+create\b", "show metadata", text) if sql_read_only else text
    if read_only and not re.search(mutation_pattern, mutation_text):
        return "read"
    if environment == "production" or parameters.get("reversible") is False or re.search(high_risk_pattern, text):
        return "high"
    return "standard"


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


def _canonical_timestamp(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field} must be an ISO-8601 timestamp.")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be an ISO-8601 timestamp.") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone offset.")
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _normalise_delegation_window(conditions: dict[str, Any]) -> dict[str, str]:
    """Validate optional time bounds on an agent's delegated authority."""

    start = conditions.get("not_before") or conditions.get("valid_from")
    end = conditions.get("not_after") or conditions.get("valid_until") or conditions.get("expires_at")
    time_window = conditions.get("time_window")
    if isinstance(time_window, dict):
        start = start or time_window.get("start")
        end = end or time_window.get("end")

    normalised: dict[str, str] = {}
    if start is not None:
        normalised["not_before"] = _canonical_timestamp(start, "conditions.not_before")
    if end is not None:
        normalised["not_after"] = _canonical_timestamp(end, "conditions.not_after")
    if normalised.get("not_before") and normalised.get("not_after"):
        if normalised["not_before"] > normalised["not_after"]:
            raise ValueError("conditions.not_before must not be after conditions.not_after.")
    return normalised


def build_agent_record(payload: dict[str, Any], tenant_id: str) -> dict[str, Any]:
    agent_id = str(payload.get("agent_id") or payload.get("id") or "").strip()
    if not agent_id:
        raise ValueError("agent_id is required.")
    allowed_environments = _string_list(payload.get("allowed_environments") or payload.get("environment") or "development")
    conditions = _redact(payload.get("conditions") if isinstance(payload.get("conditions"), dict) else {})
    conditions.update(_normalise_delegation_window(conditions))
    delegation_chain = normalise_delegation_chain(payload.get("delegation_chain"))
    delegated_by = str(payload.get("delegated_by") or "")
    record = {
        "agent_id": agent_id,
        "tenant_id": str(tenant_id),
        "owner": str(payload.get("owner") or "unknown-owner"),
        "purpose": str(payload.get("purpose") or ""),
        "version": str(payload.get("version") or "1.0.0"),
        "model_id": str(payload.get("model_id") or "") or None,
        "model_version": str(payload.get("model_version") or "") or None,
        "allowed_environments": allowed_environments,
        "approved_tools": _string_list(payload.get("approved_tools")),
        "may": _string_list(payload.get("may")),
        "may_not": _string_list(payload.get("may_not")),
        "conditions": conditions,
        "delegated_by": delegated_by,
        "delegation_chain": delegation_chain,
        "delegation_root": str(payload.get("delegation_root") or (delegation_chain[0] if delegation_chain else delegated_by or payload.get("owner") or "unknown-principal")),
        "delegation_depth": max(0, len(delegation_chain) - 1),
        "parent_agent_id": str(payload.get("parent_agent_id") or "") or None,
        "maximum_authority": normalise_authority_level(payload.get("maximum_authority") or payload.get("authority_level")),
        "documentation": normalise_documentation(payload.get("documentation")),
        "status": "active",
        "created_at": utc_now(),
        "updated_at": utc_now(),
    }
    return record


def _matches(pattern: str, values: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(value.lower(), pattern.lower()) for value in values)


def authorize_action(agent: dict[str, Any], action: dict[str, Any]) -> dict[str, Any]:
    """Evaluate a normalised action against a registered agent delegation."""

    reasons: list[dict[str, str]] = []
    tool = str(action.get("tool") or "")
    operation = str(action.get("operation") or "execute")
    target = str(action.get("target") or "")
    candidates = [tool, f"{tool}:{operation}", f"{tool}:{operation}:{target}"]
    environment = str(action.get("environment") or "development")
    maximum_authority = normalise_authority_level(agent.get("maximum_authority") or agent.get("authority_level"))
    required = required_authority(action)

    def deny(code: str, message: str) -> None:
        reasons.append({"code": code, "message": message})

    if agent.get("status") != "active":
        deny("AGENT_REVOKED", "The registered agent identity is not active.")
    if authority_rank(maximum_authority) < authority_rank(required):
        deny(
            "AUTHORITY_CEILING",
            f"Action requires {required} authority but this agent is limited to {maximum_authority}.",
        )
    allowed_environments = agent.get("allowed_environments") or []
    if allowed_environments and environment not in allowed_environments:
        deny("ENVIRONMENT_BOUNDARY", f"Agent is not delegated to operate in the {environment} environment.")
    approved_tools = agent.get("approved_tools") or []
    if approved_tools and tool not in approved_tools:
        deny("TOOL_NOT_DELEGATED", f"Agent is not delegated to use the {tool} tool.")
    if not approved_tools:
        deny("NO_APPROVED_TOOLS", "Agent has no approved tools in its delegation.")
    may = agent.get("may") or []
    if may and not any(_matches(pattern, candidates) for pattern in may):
        deny("ACTION_NOT_DELEGATED", "Action is outside the agent's delegated permissions.")
    for pattern in agent.get("may_not") or []:
        if _matches(pattern, candidates):
            deny("ACTION_EXPLICITLY_PROHIBITED", f"Action matches an explicit prohibition: {pattern}.")

    conditions = agent.get("conditions") if isinstance(agent.get("conditions"), dict) else {}
    delegation_window = {
        "not_before": conditions.get("not_before"),
        "not_after": conditions.get("not_after"),
    }
    requested_at = str(action.get("requested_at") or utc_now())
    try:
        requested_at = _canonical_timestamp(requested_at, "action.requested_at")
    except ValueError:
        requested_at = ""
        deny("INVALID_ACTION_TIMESTAMP", "The action timestamp could not be validated against the agent delegation window.")
    if requested_at and delegation_window["not_before"] and requested_at < str(delegation_window["not_before"]):
        deny("DELEGATION_NOT_YET_ACTIVE", "The agent delegation is not active at the requested action time.")
    if requested_at and delegation_window["not_after"] and requested_at > str(delegation_window["not_after"]):
        deny("DELEGATION_EXPIRED", "The agent delegation has expired at the requested action time.")
    amount = action.get("parameters", {}).get("amount") if isinstance(action.get("parameters"), dict) else None
    maximum = conditions.get("maximum_payment") or conditions.get("maximum_amount")
    if maximum is not None and amount is not None:
        try:
            if float(amount) > float(maximum):
                deny("TRANSACTION_LIMIT", f"Action amount exceeds the delegated maximum of {maximum}.")
        except (TypeError, ValueError):
            deny("UNPARSEABLE_TRANSACTION_AMOUNT", "Action amount could not be compared with the delegated transaction limit.")

    decision = "deny" if reasons else ("require_approval" if conditions.get("human_approval_required") else "allow")
    return {
        "authorized": decision != "deny",
        "decision": decision,
        "reasons": reasons,
        "agent_id": agent.get("agent_id"),
        "delegated_by": agent.get("delegated_by") or agent.get("owner"),
        "delegation_window": delegation_window,
        "maximum_authority": maximum_authority,
        "required_authority": required,
        "delegation_chain": list(agent.get("delegation_chain") or []),
        "delegation_depth": int(agent.get("delegation_depth") or 0),
        "requested_at": requested_at or None,
        "checked_at": utc_now(),
        "identity_check_id": f"identity-check-{uuid.uuid4().hex[:16]}",
    }


def check_approval_separation(
    agent: dict[str, Any] | None,
    approval: dict[str, Any],
    approver: str,
    auth: dict[str, Any] | None = None,
    approver_principal: str | None = None,
) -> dict[str, Any]:
    """Check optional separation-of-duties constraints before approval."""

    conditions = agent.get("conditions") if isinstance(agent, dict) and isinstance(agent.get("conditions"), dict) else {}
    separation = conditions.get("separation_of_duties")
    if separation is True:
        separation = {}
    if not isinstance(separation, dict):
        separation = {}
    reasons: list[dict[str, str]] = []
    approver = str(approver or "").strip()
    approver_principal = str(approver_principal or "").strip()
    approver_identities = {value.lower() for value in (approver, approver_principal) if value}
    invoked_by = str(approval.get("requested_by") or approval.get("invoked_by") or "").strip()
    if separation.get("agent_cannot_approve") and (auth or {}).get("token_type") == "agent":
        reasons.append({"code": "AGENT_CANNOT_APPROVE_OWN_ACTION", "message": "An agent credential cannot approve an action it initiated."})
    if separation.get("approver_must_differ_from_invoked_by") and invoked_by.lower() in approver_identities:
        reasons.append({"code": "APPROVER_EQUALS_REQUESTER", "message": "The approver must be different from the action requester."})
    prohibited = _string_list(separation.get("prohibited_approvers"))
    if any(item.lower() in approver_identities for item in prohibited):
        reasons.append({"code": "APPROVER_PROHIBITED", "message": "The proposed approver is prohibited by the agent separation-of-duties policy."})
    return {
        "allowed": not reasons,
        "reasons": reasons,
        "checked_at": utc_now(),
    }
