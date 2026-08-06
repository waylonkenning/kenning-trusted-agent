"""Validation helpers for ISO/IEC 42001 governance records."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any


NONCONFORMITY_SEVERITIES = {"low", "medium", "high"}
SUPPLIER_ROLES = {"data_provider", "model_provider", "platform_provider", "integrator"}
RISK_RATINGS = {"low", "medium", "high"}
DATA_RESOURCE_CATEGORIES = {"training", "validation", "test", "production"}
DOCUMENTATION_SECTIONS = ("design", "resources", "verification", "operational")
GOVERNANCE_TEXT_LIMIT = 10_000
GOVERNANCE_NAME_LIMIT = 4096


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _text(value: Any, field: str, *, required: bool = False, limit: int = GOVERNANCE_TEXT_LIMIT) -> str:
    if value in (None, ""):
        if required:
            raise ValueError(f"{field} is required.")
        return ""
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string.")
    text = value.strip()
    if required and not text:
        raise ValueError(f"{field} is required.")
    if len(text) > limit:
        raise ValueError(f"{field} must be no longer than {limit} characters.")
    return text


def normalise_nonconformity(payload: dict[str, Any], tenant_id: str, *, now: str | None = None) -> dict[str, Any]:
    severity = str(payload.get("severity") or "").strip().lower()
    if severity not in NONCONFORMITY_SEVERITIES:
        raise ValueError("severity must be low, medium, or high.")
    created_at = now or _utc_now()
    return {
        "nc_id": f"nc-{uuid.uuid4().hex[:16]}",
        "tenant_id": str(tenant_id),
        "title": _text(payload.get("title"), "title", required=True, limit=GOVERNANCE_NAME_LIMIT),
        "description": _text(payload.get("description"), "description", required=True),
        "severity": severity,
        "source_event_id": _text(payload.get("source_event_id"), "source_event_id", limit=256),
        "status": "open",
        "created_at": created_at,
    }


def normalise_concern(payload: dict[str, Any], tenant_id: str, *, now: str | None = None) -> dict[str, Any]:
    anonymous = payload.get("anonymous", False)
    if not isinstance(anonymous, bool):
        raise ValueError("anonymous must be a boolean.")
    return {
        "concern_id": f"concern-{uuid.uuid4().hex[:16]}",
        "tenant_id": str(tenant_id),
        "description": _text(payload.get("description"), "description", required=True),
        "anonymous": anonymous,
        "created_at": now or _utc_now(),
    }


def normalise_documentation(value: Any) -> dict[str, str]:
    if value in (None, ""):
        return {section: "" for section in DOCUMENTATION_SECTIONS}
    if not isinstance(value, dict):
        raise ValueError("documentation must be an object.")
    unknown = sorted(set(value) - set(DOCUMENTATION_SECTIONS))
    if unknown:
        raise ValueError(f"documentation contains unsupported sections: {', '.join(unknown)}.")
    return {
        section: _text(value.get(section), f"documentation.{section}")
        for section in DOCUMENTATION_SECTIONS
    }


def documentation_metadata(documentation: Any) -> dict[str, Any]:
    normalised = normalise_documentation(documentation)
    completed = sum(1 for value in normalised.values() if value)
    return {
        "documentation_completeness": f"{completed}/{len(DOCUMENTATION_SECTIONS)}",
        "documentation_sections_completed": completed,
        "documentation_sections_total": len(DOCUMENTATION_SECTIONS),
    }


def normalise_data_resource(
    payload: dict[str, Any],
    tenant_id: str,
    model_id: str,
    *,
    now: str | None = None,
) -> dict[str, Any]:
    category = str(payload.get("category") or "").strip().lower()
    if category not in DATA_RESOURCE_CATEGORIES:
        raise ValueError("category must be training, validation, test, or production.")
    return {
        "data_resource_id": f"data-resource-{uuid.uuid4().hex[:16]}",
        "tenant_id": str(tenant_id),
        "model_id": str(model_id),
        "name": _text(payload.get("name"), "name", required=True, limit=GOVERNANCE_NAME_LIMIT),
        "source": _text(payload.get("source"), "source", required=True),
        "category": category,
        "acquisition_date": _text(payload.get("acquisition_date"), "acquisition_date", limit=128),
        "provenance": _text(payload.get("provenance"), "provenance"),
        "preparation_notes": _text(payload.get("preparation_notes"), "preparation_notes"),
        "created_at": now or _utc_now(),
    }


def normalise_supplier(payload: dict[str, Any], tenant_id: str, *, now: str | None = None) -> dict[str, Any]:
    role = str(payload.get("role") or "").strip().lower()
    if role not in SUPPLIER_ROLES:
        raise ValueError("role must be data_provider, model_provider, platform_provider, or integrator.")
    risk_rating = str(payload.get("risk_rating") or "").strip().lower()
    if risk_rating not in RISK_RATINGS:
        raise ValueError("risk_rating must be low, medium, or high.")
    created_at = now or _utc_now()
    return {
        "supplier_id": f"supplier-{uuid.uuid4().hex[:16]}",
        "tenant_id": str(tenant_id),
        "name": _text(payload.get("name"), "name", required=True, limit=GOVERNANCE_NAME_LIMIT),
        "role": role,
        "risk_rating": risk_rating,
        "status": "active",
        "created_at": created_at,
        "updated_at": created_at,
    }
