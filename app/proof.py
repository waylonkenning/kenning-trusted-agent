"""Structured Agent Proof records and tamper-evident reports.

Proof records capture decision-grade provenance without storing hidden
chain-of-thought content. The module is dependency-free so it can be bundled
with the Lambda function and tested locally.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from decimal import Decimal
from typing import Any

try:
    from capture import apply_capture_policy as capture_record  # pragma: no cover
    from guard import _redact, refresh_receipt, utc_now  # pragma: no cover
except ModuleNotFoundError:  # Local package import during tests.
    from .capture import apply_capture_policy as capture_record
    from .guard import _redact, refresh_receipt, utc_now


_INTEGRITY_METADATA_FIELDS = frozenset({"integrity", "pk", "sk", "retention_expires_at"})


def _canonical_default(value: Any) -> Any:
    if isinstance(value, Decimal):
        return int(value) if value % 1 == 0 else float(value)
    raise TypeError(f"Cannot serialise {type(value).__name__}")


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=_canonical_default)


def sha256_value(value: Any) -> str:
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        raw = value.encode("utf-8")
    else:
        raw = _canonical(value).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _hash_input(item: dict[str, Any]) -> str | None:
    for key in ("hash", "content_hash", "sha256"):
        value = item.get(key)
        if value:
            return str(value)
    if "content" in item:
        return sha256_value(item["content"])
    return None


def normalise_input(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        result = _redact(value)
        content_hash = _hash_input(value)
        result.pop("content", None)
        if content_hash:
            result["hash"] = content_hash
            result["hash_algorithm"] = "sha256"
            result["hash_status"] = "verified" if any(key in value for key in ("hash", "content_hash", "sha256")) else "computed"
        else:
            result["hash_status"] = "not_provided"
        return result
    return {"value": _redact(value), "hash_status": "not_provided"}


def normalise_evidence(value: Any, index: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        value = {"source": str(value)}
    result = _redact(value)
    result.setdefault("evidence_id", f"evidence-{index + 1}")
    result.setdefault("claim", "")
    result.setdefault("source", "")
    result.setdefault("location", "")
    return result


def _normalise_agent(value: Any, action: dict[str, Any] | None) -> dict[str, Any]:
    if isinstance(value, str):
        agent = {"id": value}
    elif isinstance(value, dict):
        agent = _redact(value)
    else:
        agent = {}
    if action:
        agent.setdefault("id", action.get("agent_id", "unregistered-agent"))
    agent.setdefault("id", "unregistered-agent")
    return agent


def _normalise_decision_factors(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [_redact(item) if isinstance(item, dict) else {"factor": str(item)} for item in value]


def _evidence_gaps(record: dict[str, Any]) -> list[str]:
    gaps: list[str] = []
    evidence = record.get("evidence") or []
    recommendation = record.get("recommendation")
    if recommendation and not evidence:
        gaps.append("Recommendation has no associated evidence.")

    evidence_ids = {item.get("evidence_id") for item in evidence if isinstance(item, dict)}
    for factor in record.get("decision_factors") or []:
        if not isinstance(factor, dict):
            continue
        references = factor.get("evidence_refs") or factor.get("evidence_ids") or []
        if isinstance(references, str):
            references = [references]
        missing = [str(reference) for reference in references if str(reference) not in evidence_ids]
        if missing:
            gaps.append(f"Decision factor '{factor.get('factor', 'unnamed')}' references missing evidence: {', '.join(missing)}.")

    required = record.get("required_evidence") or []
    present_sources = {str(item.get("source")) for item in evidence if isinstance(item, dict)}
    for requirement in required:
        if str(requirement) not in present_sources and str(requirement) not in evidence_ids:
            gaps.append(f"Required evidence is missing: {requirement}.")
    return gaps


def _seal(record: dict[str, Any]) -> dict[str, Any]:
    unsigned = {key: value for key, value in record.items() if key not in _INTEGRITY_METADATA_FIELDS}
    record["integrity"] = {
        "algorithm": "sha256",
        "record_hash": sha256_value(unsigned),
    }
    return record


def verify_integrity(record: dict[str, Any] | None) -> dict[str, Any]:
    """Recompute a Proof record hash without mutating the stored record."""

    if not isinstance(record, dict):
        return {"valid": False, "reason": "proof_missing"}
    integrity = record.get("integrity") if isinstance(record.get("integrity"), dict) else {}
    expected_hash = str(integrity.get("record_hash") or "")
    actual_hash = sha256_value({key: value for key, value in record.items() if key not in _INTEGRITY_METADATA_FIELDS})
    return {
        "valid": expected_hash == actual_hash,
        "algorithm": str(integrity.get("algorithm") or "unknown"),
        "record_hash": expected_hash,
        "actual_hash": actual_hash,
        "proof_id": record.get("proof_id"),
    }


def build_proof_record(
    payload: dict[str, Any] | None = None,
    *,
    action: dict[str, Any] | None = None,
    decision: dict[str, Any] | None = None,
    receipt: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a redacted, structured proof record from supplied and Guard data."""

    payload = payload if isinstance(payload, dict) else {}
    context = payload.get("context") if isinstance(payload.get("context"), dict) else {}
    tenant_id = str((action or {}).get("tenant_id") or context.get("tenant_id") or payload.get("tenant_id") or "demo")
    run_id = str((action or {}).get("run_id") or context.get("run_id") or payload.get("run_id") or f"run-{uuid.uuid4().hex[:12]}")
    action_id = str((action or {}).get("action_id") or context.get("action_id") or payload.get("action_id") or f"action-{uuid.uuid4().hex[:12]}")
    proof_id = str(payload.get("proof_id") or f"proof-{uuid.uuid4().hex[:16]}")
    proof_uri = str(payload.get("proof_uri") or f"proof://{run_id}/{action_id}")

    request = payload.get("request") if isinstance(payload.get("request"), dict) else {}
    if not request.get("summary"):
        request["summary"] = str(payload.get("request_summary") or (action or {}).get("intent") or "Agent decision or action")

    evidence = [normalise_evidence(item, index) for index, item in enumerate(payload.get("evidence") or [])]
    inputs = [normalise_input(item) for item in payload.get("inputs") or []]
    model = _redact(payload.get("model") if isinstance(payload.get("model"), dict) else {})
    approvals = _redact(payload.get("approvals") if isinstance(payload.get("approvals"), list) else [])
    if decision and decision.get("approval") and not approvals:
        approvals = [_redact(decision["approval"])]

    policy_evaluations = _redact(payload.get("policy_evaluations") if isinstance(payload.get("policy_evaluations"), list) else [])
    if decision and not policy_evaluations:
        policy_evaluations = [
            {
                "decision": decision.get("decision"),
                "would_decision": decision.get("would_decision"),
                "risk": decision.get("risk"),
                "risk_score": decision.get("risk_score"),
                "reason_codes": decision.get("reason_codes", []),
                "policy_id": decision.get("policy_id", "kenning-agent-guard-mvp"),
                "policy_version": decision.get("policy_version", 1),
                "policy_matches": decision.get("policy_matches", []),
                "policy_resolution": decision.get("policy_resolution"),
                "approval_requirements": decision.get("approval_requirements", []),
                "identity": decision.get("identity"),
                "evaluated_at": decision.get("evaluated_at"),
            }
        ]

    tools_used = _redact(payload.get("tools_used") if isinstance(payload.get("tools_used"), list) else [])
    if action and not tools_used:
        tools_used = [{"tool": action.get("tool"), "operation": action.get("operation"), "action_id": action_id}]

    record: dict[str, Any] = {
        "proof_id": proof_id,
        "proof_uri": proof_uri,
        "tenant_id": tenant_id,
        "run_id": run_id,
        "action_id": action_id,
        "agent": _normalise_agent(payload.get("agent"), action),
        "request": _redact(request),
        "inputs": inputs,
        "evidence": evidence,
        "decision_factors": _normalise_decision_factors(payload.get("decision_factors")),
        "recommendation": _redact(payload.get("recommendation")),
        "action": _redact(action) if action else _redact(payload.get("action")),
        "limitations": _redact(payload.get("limitations") if isinstance(payload.get("limitations"), list) else []),
        "required_evidence": _redact(payload.get("required_evidence") if isinstance(payload.get("required_evidence"), list) else []),
        "model": model,
        "tools_used": tools_used,
        "approvals": approvals,
        "policy_evaluations": policy_evaluations,
        "outcome": _redact(payload.get("outcome")),
        "created_at": str(payload.get("created_at") or utc_now()),
    }
    record["evidence_gaps"] = _evidence_gaps(record)
    record["evidence_status"] = "incomplete" if record["evidence_gaps"] else ("verified" if evidence or inputs else "not_provided")
    if receipt:
        record["trusted_action_receipt"] = _redact(receipt)
    return _seal(record)


def attach_receipt(record: dict[str, Any], receipt: dict[str, Any]) -> dict[str, Any]:
    record["trusted_action_receipt"] = _redact(receipt)
    return _seal(record)


def apply_capture(record: dict[str, Any], policy: Any = None) -> dict[str, Any]:
    """Apply tenant capture controls and reseal the Proof record."""

    captured = capture_record(record, policy)
    return _seal(captured)


def attach_outcome(record: dict[str, Any], outcome: dict[str, Any]) -> dict[str, Any]:
    record["outcome"] = _redact(outcome)
    receipt = record.get("trusted_action_receipt")
    if isinstance(receipt, dict):
        record["trusted_action_receipt"] = refresh_receipt(
            receipt,
            result=str(outcome.get("status") or "unknown"),
            outcome=_redact(outcome),
        )
    return _seal(record)


def render_report(record: dict[str, Any]) -> str:
    def render_value(value: Any) -> str:
        if value is None or value == "":
            return "Not provided"
        if isinstance(value, (dict, list)):
            return f"```json\n{json.dumps(value, indent=2, default=str)}\n```"
        return str(value)

    lines = [
        f"# Agent Proof {record.get('proof_id')}",
        "",
        f"- Tenant: `{record.get('tenant_id')}`",
        f"- Run: `{record.get('run_id')}`",
        f"- Action: `{record.get('action_id')}`",
        f"- Evidence status: **{record.get('evidence_status', 'not_provided')}**",
        f"- Integrity: `{record.get('integrity', {}).get('record_hash', 'not sealed')}`",
        "",
        "## Request",
        "",
        render_value(record.get("request")),
        "",
        "## Evidence",
        "",
    ]
    evidence = record.get("evidence") or []
    if evidence:
        for item in evidence:
            lines.append(f"- **{item.get('evidence_id', 'evidence')}** — {item.get('claim') or 'Unspecified claim'} ({item.get('source') or 'unknown source'}{', ' + str(item.get('location')) if item.get('location') else ''})")
    else:
        lines.append("No evidence was recorded.")

    lines.extend(["", "## Decision factors", ""])
    factors = record.get("decision_factors") or []
    if factors:
        lines.extend(f"- **{item.get('factor', 'Factor')}**: {item.get('result', 'Not specified')}" for item in factors)
    else:
        lines.append("No decision factors were recorded.")

    lines.extend(["", "## Evidence gaps", ""])
    gaps = record.get("evidence_gaps") or []
    lines.extend(f"- {gap}" for gap in gaps) if gaps else lines.append("No evidence gaps detected.")
    lines.extend(["", "## Recommendation or action", "", render_value(record.get("recommendation") or record.get("action")), ""])
    lines.extend(["## Approvals", "", render_value(record.get("approvals")), ""])
    lines.extend(["## Outcome", "", render_value(record.get("outcome")), ""])
    lines.append("This record contains structured provenance and excludes private model reasoning.")
    return "\n".join(lines)
