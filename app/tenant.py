"""Tenant, environment, and retention configuration primitives.

The prototype stores configuration in the shared DynamoDB table so that the
same tenant boundary used by actions, policies, proofs, and audit records is
also applied to administrative controls.  This module is dependency-free and
keeps validation deterministic for unit tests and future control-plane APIs.
"""

from __future__ import annotations

import os
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any

try:  # pragma: no cover
    from audit_delivery import normalise_sink
    from capture import normalise_capture_policy
    from citation import normalise_citation_policy
    from federation import normalise_provider
    from starter_rules import default_starter_rules, normalise_starter_rules
    from workload_identity import normalise_workload_identity
except ModuleNotFoundError:  # Local package import during tests.
    from .audit_delivery import normalise_sink
    from .capture import normalise_capture_policy
    from .citation import normalise_citation_policy
    from .federation import normalise_provider
    from .starter_rules import default_starter_rules, normalise_starter_rules
    from .workload_identity import normalise_workload_identity


TENANT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
ENVIRONMENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,31}$")
TENANT_STATUSES = {"active", "suspended"}
ENVIRONMENT_STATUSES = {"active", "suspended"}
GUARD_MODES = {"observe", "enforce"}
DEFAULT_ENVIRONMENT_IDS = ("development", "staging", "production")
PRODUCT_IDS = ("agent-guard", "agent-proof", "citation-trust", "agent-identity")
DEFAULT_ENABLED_PRODUCTS = PRODUCT_IDS
PRODUCT_DEPENDENCIES = {
    "agent-guard": (),
    "agent-proof": ("agent-guard",),
    "citation-trust": ("agent-guard",),
    "agent-identity": ("agent-guard",),
}
DEPLOYMENT_REGION = str(os.environ.get("AWS_REGION") or "us-east-1").strip().lower()
REGION_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _validate_id(value: str, pattern: re.Pattern[str], field: str) -> str:
    value = str(value or "").strip()
    if not value or not pattern.fullmatch(value):
        raise ValueError(f"{field} must contain only letters, numbers, ., _, :, or - and be within its length limit.")
    return value


def _positive_days(value: Any, field: str = "retention_days") -> int:
    try:
        days = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be an integer between 1 and 3650.") from exc
    if days < 1 or days > 3650:
        raise ValueError(f"{field} must be an integer between 1 and 3650.")
    return days


def _region(value: Any, field: str = "data_residency_region") -> str:
    value = str(value or "").strip().lower()
    if not value or not REGION_PATTERN.fullmatch(value):
        raise ValueError(f"{field} must be a valid deployment region identifier.")
    if value != DEPLOYMENT_REGION:
        raise ValueError(f"{field} must match the current deployment region ({DEPLOYMENT_REGION}) for this deployment.")
    return value


def _boolean(value: Any, field: str, default: bool = False) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be a boolean.")
    return value


def normalise_enabled_products(value: Any) -> list[str]:
    """Validate the workspace product set and enforce product dependencies."""

    if value is None:
        return list(DEFAULT_ENABLED_PRODUCTS)
    if not isinstance(value, list):
        raise ValueError("enabled_products must be an array of product identifiers.")
    requested = [str(item).strip().lower() for item in value]
    if len(requested) != len(set(requested)):
        raise ValueError("enabled_products must not contain duplicate product identifiers.")
    unknown = sorted(set(requested) - set(PRODUCT_IDS))
    if unknown:
        raise ValueError(f"enabled_products contains unsupported products: {', '.join(unknown)}.")
    enabled = set(requested)
    missing_dependencies = sorted({dependency for product in enabled for dependency in PRODUCT_DEPENDENCIES[product] if dependency not in enabled})
    if missing_dependencies:
        raise ValueError(f"enabled_products must include required products: {', '.join(missing_dependencies)}.")
    if "agent-guard" not in enabled:
        raise ValueError("agent-guard is the required base product and cannot be disabled.")
    return [product for product in PRODUCT_IDS if product in enabled]


def enabled_products_for_config(config: dict[str, Any] | None) -> list[str]:
    """Return a legacy-safe, dependency-validated product set."""

    return normalise_enabled_products((config or {}).get("enabled_products"))


def default_tenant_config(tenant_id: str) -> dict[str, Any]:
    """Return a non-persisted permissive config for legacy tenants."""

    tenant_id = _validate_id(tenant_id, TENANT_ID_PATTERN, "tenant_id")
    return {
        "item_type": "tenant_config",
        "tenant_id": tenant_id,
        "name": tenant_id,
        "status": "active",
        "default_environment": "development",
        "environments": [],
        "retention_enabled": False,
        "retention_days": None,
        "legal_hold_enabled": False,
        "legal_hold_reason": "",
        "legal_hold_set_by": "",
        "legal_hold_updated_at": None,
        "data_residency_region": DEPLOYMENT_REGION,
        "audit_sink": {"enabled": False, "format": "json", "timeout_ms": 1000},
        "identity_provider": {"enabled": False},
        "workload_identity": normalise_workload_identity(),
        "starter_rules": default_starter_rules(),
        "capture_policy": normalise_capture_policy(),
        "citation_policy": normalise_citation_policy(),
        "enabled_products": list(DEFAULT_ENABLED_PRODUCTS),
        "config_version": 1,
        "configured": False,
    }


def _normalise_environment(value: Any, field: str = "environment_id") -> str:
    return _validate_id(str(value or ""), ENVIRONMENT_ID_PATTERN, field)


def build_environment_config(
    tenant_id: str,
    environment_id: str,
    payload: dict[str, Any] | None = None,
    existing: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = payload if isinstance(payload, dict) else {}
    existing = existing if isinstance(existing, dict) else {}
    tenant_id = _validate_id(tenant_id, TENANT_ID_PATTERN, "tenant_id")
    environment_id = _normalise_environment(environment_id)
    status = str(payload.get("status") or existing.get("status") or "active").lower()
    if status not in ENVIRONMENT_STATUSES:
        raise ValueError(f"status must be one of: {', '.join(sorted(ENVIRONMENT_STATUSES))}.")
    mode = str(payload.get("mode") or existing.get("mode") or "enforce").lower()
    if mode not in GUARD_MODES:
        raise ValueError(f"mode must be one of: {', '.join(sorted(GUARD_MODES))}.")
    allowed_tools = _string_list(payload.get("allowed_tools"))
    if "allowed_tools" not in payload:
        allowed_tools = _string_list(existing.get("allowed_tools"))
    record = {
        "environment_id": environment_id,
        "name": str(payload.get("name") or existing.get("name") or environment_id),
        "status": status,
        "mode": mode,
        "allowed_tools": sorted(set(tool.lower() for tool in allowed_tools)),
        "updated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    return record


def build_tenant_config(
    tenant_id: str,
    payload: dict[str, Any] | None = None,
    existing: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = payload if isinstance(payload, dict) else {}
    existing = existing if isinstance(existing, dict) else {}
    tenant_id = _validate_id(tenant_id, TENANT_ID_PATTERN, "tenant_id")
    status = str(payload.get("status") or existing.get("status") or "active").lower()
    if status not in TENANT_STATUSES:
        raise ValueError(f"status must be one of: {', '.join(sorted(TENANT_STATUSES))}.")

    current_environments = existing.get("environments") if isinstance(existing.get("environments"), list) else []
    supplied_environments = payload.get("environments")
    if supplied_environments is None:
        environments = [dict(item) for item in current_environments if isinstance(item, dict)]
    elif isinstance(supplied_environments, list):
        environments = [
            build_environment_config(tenant_id, item.get("environment_id") or item.get("id"), item)
            for item in supplied_environments
            if isinstance(item, dict)
        ]
    else:
        raise ValueError("environments must be an array of environment configuration objects.")

    seen: set[str] = set()
    for environment in environments:
        environment_id = environment["environment_id"]
        if environment_id in seen:
            raise ValueError(f"environment_id is duplicated: {environment_id}.")
        seen.add(environment_id)
    default_environment = _normalise_environment(
        payload.get("default_environment") or existing.get("default_environment") or "development",
        "default_environment",
    )
    if environments and default_environment not in seen:
        raise ValueError("default_environment must reference a configured environment.")

    retention_enabled = bool(
        payload.get("retention_enabled")
        if "retention_enabled" in payload
        else existing.get("retention_enabled", False)
    )
    retention_value = payload.get("retention_days") if "retention_days" in payload else existing.get("retention_days")
    retention_days = None if retention_value in (None, "", 0, "0") else _positive_days(retention_value)
    if retention_enabled and retention_days is None:
        raise ValueError("retention_days is required when retention_enabled is true.")
    data_residency_region = _region(
        payload.get("data_residency_region") if "data_residency_region" in payload else existing.get("data_residency_region") or DEPLOYMENT_REGION
    )
    legal_hold_enabled = _boolean(
        payload.get("legal_hold_enabled") if "legal_hold_enabled" in payload else existing.get("legal_hold_enabled"),
        "legal_hold_enabled",
    )
    legal_hold_reason = str(
        payload.get("legal_hold_reason") if "legal_hold_reason" in payload else existing.get("legal_hold_reason") or ""
    ).strip()
    if len(legal_hold_reason) > 512:
        raise ValueError("legal_hold_reason must be no longer than 512 characters.")
    if legal_hold_enabled and not legal_hold_reason:
        raise ValueError("legal_hold_reason is required when legal_hold_enabled is true.")
    audit_sink = normalise_sink(payload.get("audit_sink") if "audit_sink" in payload else existing.get("audit_sink"), tenant_id=tenant_id)
    identity_provider = normalise_provider(payload.get("identity_provider") if "identity_provider" in payload else existing.get("identity_provider"))
    workload_identity = normalise_workload_identity(
        payload.get("workload_identity") if "workload_identity" in payload else existing.get("workload_identity")
    )
    capture_policy = normalise_capture_policy(
        payload.get("capture_policy") if "capture_policy" in payload else existing.get("capture_policy")
    )
    citation_policy = normalise_citation_policy(
        payload.get("citation_policy") if "citation_policy" in payload else existing.get("citation_policy")
    )
    enabled_products = normalise_enabled_products(
        payload.get("enabled_products") if "enabled_products" in payload else existing.get("enabled_products")
    )
    starter_rules = normalise_starter_rules(
        payload.get("starter_rules") if "starter_rules" in payload else existing.get("starter_rules")
    )

    version = int(existing.get("config_version") or 0) + 1
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return {
        "item_type": "tenant_config",
        "tenant_id": tenant_id,
        "name": str(payload.get("name") or existing.get("name") or tenant_id),
        "status": status,
        "default_environment": default_environment,
        "environments": environments,
        "retention_enabled": retention_enabled,
        "retention_days": retention_days,
        "legal_hold_enabled": legal_hold_enabled,
        "legal_hold_reason": legal_hold_reason,
        "legal_hold_set_by": str(existing.get("legal_hold_set_by") or ""),
        "legal_hold_updated_at": existing.get("legal_hold_updated_at"),
        "data_residency_region": data_residency_region,
        "audit_sink": audit_sink,
        "identity_provider": identity_provider,
        "workload_identity": workload_identity,
        "starter_rules": starter_rules,
        "capture_policy": capture_policy,
        "citation_policy": citation_policy,
        "enabled_products": enabled_products,
        "config_version": version,
        "created_at": str(existing.get("created_at") or now),
        "updated_at": now,
        "configured": True,
    }


def environment_for(config: dict[str, Any], environment_id: str) -> dict[str, Any] | None:
    environment_id = str(environment_id or "development")
    for environment in config.get("environments") or []:
        if isinstance(environment, dict) and environment.get("environment_id") == environment_id:
            return environment
    return None


def runtime_constraints(config: dict[str, Any], environment_id: str, tool: str = "") -> dict[str, Any]:
    """Return enforcement inputs without making an action decision."""

    environment = environment_for(config, environment_id)
    reasons: list[dict[str, str]] = []
    if config.get("status") != "active":
        reasons.append({"code": "TENANT_SUSPENDED", "message": "The tenant is suspended and cannot submit agent actions."})
    if config.get("environments") and environment is None:
        reasons.append({"code": "ENVIRONMENT_NOT_CONFIGURED", "message": f"The {environment_id} environment is not configured for this tenant."})
    if environment and environment.get("status") != "active":
        reasons.append({"code": "ENVIRONMENT_SUSPENDED", "message": f"The {environment_id} environment is suspended."})
    allowed_tools = [str(item).lower() for item in (environment or {}).get("allowed_tools") or []]
    if allowed_tools and tool and tool.lower() not in allowed_tools:
        reasons.append({"code": "ENVIRONMENT_TOOL_NOT_ALLOWED", "message": f"The {tool} tool is not allowed in the {environment_id} environment."})
    return {
        "mode": ((environment or {}).get("mode") or "enforce") if config.get("configured") else None,
        "environment": environment_id,
        "reasons": reasons,
        "config_version": config.get("config_version"),
    }


def retention_cutoff(config: dict[str, Any], now: int | None = None) -> int | None:
    if not config.get("retention_enabled") or not config.get("retention_days"):
        return None
    return int(now if now is not None else time.time()) - _positive_days(config["retention_days"]) * 86400


def iso_from_epoch(value: int) -> str:
    return datetime.fromtimestamp(int(value), timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def is_retained_item(item: dict[str, Any], tenant_id: str, cutoff: int) -> bool:
    if str(item.get("tenant_id") or "") != str(tenant_id):
        return False
    if item.get("item_type") == "tenant_config":
        return False
    if not (item.get("event_type") or item.get("proof_id") or item.get("approval_id")):
        return False
    created_at = str(item.get("created_at") or "")
    if not created_at:
        return False
    try:
        timestamp = datetime.fromisoformat(created_at.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return False
    return int(timestamp) < int(cutoff)
