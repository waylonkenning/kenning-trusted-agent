"""Validation and risk helpers for the tenant AI model registry."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any


MODEL_RISK_RANK = {"low": 1, "medium": 2, "high": 3}
MODEL_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
MODEL_VERSION_PATTERN = re.compile(r"^[^\s]{1,64}$")
MODEL_TEXT_LIMIT = 4096


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalise_model_record(payload: dict[str, Any], tenant_id: str, *, now: str | None = None) -> dict[str, Any]:
    """Validate a model registration and return its durable representation."""
    model_id = str(payload.get("model_id") or "").strip()
    if not MODEL_ID_PATTERN.fullmatch(model_id):
        raise ValueError("model_id is required and must be a safe identifier no longer than 128 characters.")
    name = str(payload.get("name") or "").strip()
    vendor = str(payload.get("vendor") or "").strip()
    version = str(payload.get("version") or "").strip()
    if not name or len(name) > MODEL_TEXT_LIMIT:
        raise ValueError("name is required and must be no longer than 4096 characters.")
    if not vendor or len(vendor) > MODEL_TEXT_LIMIT:
        raise ValueError("vendor is required and must be no longer than 4096 characters.")
    if not MODEL_VERSION_PATTERN.fullmatch(version):
        raise ValueError("version is required and must be a non-whitespace value no longer than 64 characters.")
    risk_tier = str(payload.get("risk_tier") or "").strip().lower()
    if risk_tier not in MODEL_RISK_RANK:
        raise ValueError("risk_tier must be low, medium, or high.")
    bias_tested = payload.get("bias_tested", False)
    if not isinstance(bias_tested, bool):
        raise ValueError("bias_tested must be a boolean.")
    provenance = str(payload.get("provenance") or "").strip()
    if len(provenance) > MODEL_TEXT_LIMIT:
        raise ValueError("provenance must be no longer than 4096 characters.")
    supplier_id = str(payload.get("supplier_id") or "").strip()
    if len(supplier_id) > 128:
        raise ValueError("supplier_id must be no longer than 128 characters.")
    timestamp = now or _utc_now()
    return {
        "item_type": "ai_model",
        "model_id": model_id,
        "tenant_id": str(tenant_id),
        "name": name,
        "vendor": vendor,
        "version": version,
        "risk_tier": risk_tier,
        "bias_tested": bias_tested,
        "provenance": provenance,
        "supplier_id": supplier_id or None,
        "status": "registered",
        "created_at": timestamp,
        "updated_at": timestamp,
    }


def model_risk_at_least(actual: Any, minimum: Any) -> bool:
    """Return whether a registered model meets a policy risk threshold."""
    actual_rank = MODEL_RISK_RANK.get(str(actual or "").strip().lower(), 0)
    minimum_rank = MODEL_RISK_RANK.get(str(minimum or "").strip().lower(), 0)
    return bool(actual_rank and minimum_rank and actual_rank >= minimum_rank)
