"""Materialised policy bundles for the low-latency Guard evaluation path.

The bundle is a server-side read model. It is never accepted as an
authorization assertion from a client. Administrative writes refresh its
revision, and evaluation refuses to use a stale or malformed bundle.
"""

from __future__ import annotations

import copy
import hashlib
import json
from decimal import Decimal
from typing import Any


BUNDLE_SCHEMA_VERSION = 1


def _json_default(value: Any) -> Any:
    if isinstance(value, Decimal):
        return int(value) if value % 1 == 0 else float(value)
    raise TypeError(f"Cannot serialise {type(value).__name__}")


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=_json_default,
    )


def _evaluator_policy(policy: dict[str, Any]) -> dict[str, Any]:
    """Keep only the policy fields needed by the evaluator and explanations."""

    rules = policy.get("rules")
    if not isinstance(rules, list) or any(not isinstance(rule, dict) for rule in rules):
        raise ValueError("Published policy rules must be an array of objects.")
    return {
        "item_type": "policy",
        "policy_id": str(policy.get("policy_id") or ""),
        "tenant_id": str(policy.get("tenant_id") or ""),
        "name": str(policy.get("name") or ""),
        "version": int(policy.get("version") or 1),
        "status": str(policy.get("status") or ""),
        "mode": str(policy.get("mode") or "enforce"),
        "rules": copy.deepcopy(rules),
    }


def _is_valid_bundle_policy(policy: Any, tenant_id: str) -> bool:
    if not isinstance(policy, dict):
        return False
    if policy.get("item_type") != "policy":
        return False
    if str(policy.get("tenant_id") or "") != str(tenant_id):
        return False
    if str(policy.get("status") or "") != "published":
        return False
    rules = policy.get("rules")
    return isinstance(rules, list) and all(isinstance(rule, dict) for rule in rules)


def build_policy_bundle(
    tenant_id: str,
    config: dict[str, Any] | None,
    policies: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a deterministic, tenant-scoped published-policy read model."""

    selected = [
        _evaluator_policy(policy)
        for policy in policies
        if isinstance(policy, dict)
        and str(policy.get("tenant_id") or "") == str(tenant_id)
        and str(policy.get("status") or "") == "published"
    ]
    selected.sort(key=lambda item: (item["policy_id"], item["version"]))
    payload = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "tenant_id": str(tenant_id),
        "config_version": int((config or {}).get("config_version") or 1),
        "policy_bundle_revision": int((config or {}).get("policy_bundle_revision") or 0),
        "policies": selected,
    }
    digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    return {
        **payload,
        "bundle_id": f"bundle-{digest[:24]}",
        "bundle_hash": f"sha256:{digest}",
    }


def is_current_bundle(
    bundle: Any,
    tenant_id: str,
    config: dict[str, Any] | None,
) -> bool:
    """Return whether a stored bundle can authoritatively serve this request."""

    if not isinstance(bundle, dict) or not isinstance(bundle.get("policies"), list):
        return False
    try:
        schema_version = int(bundle.get("schema_version") or 0)
        bundle_config_version = int(bundle.get("config_version") or 0)
        bundle_revision = int(bundle.get("policy_bundle_revision") or 0)
        expected_config_version = int((config or {}).get("config_version") or 1)
        expected_revision = int((config or {}).get("policy_bundle_revision") or 0)
    except (TypeError, ValueError):
        return False
    if schema_version != BUNDLE_SCHEMA_VERSION:
        return False
    if str(bundle.get("tenant_id") or "") != str(tenant_id):
        return False
    if not all(_is_valid_bundle_policy(policy, tenant_id) for policy in bundle.get("policies", [])):
        return False
    payload = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "tenant_id": str(tenant_id),
        "config_version": expected_config_version,
        "policy_bundle_revision": expected_revision,
        "policies": bundle.get("policies"),
    }
    digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    return (
        bundle_config_version == expected_config_version
        and bundle_revision == expected_revision
        and bundle.get("bundle_id") == f"bundle-{digest[:24]}"
        and bundle.get("bundle_hash") == f"sha256:{digest}"
        and isinstance(bundle.get("policies"), list)
    )
