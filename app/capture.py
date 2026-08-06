"""Tenant-configurable capture controls for persisted and returned records.

Guard evaluates the normalised action before this module is called.  Capture
controls only change what is retained or returned, so they cannot weaken the
decision or the action hash used for approval binding.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from decimal import Decimal
from typing import Any

try:
    from guard import refresh_receipt
except ModuleNotFoundError:  # Local package import during tests.
    from .guard import refresh_receipt


DEFAULT_CAPTURE_POLICY = {
    "store_original_action": True,
    "redact_fields": [],
    "hash_fields": [],
    "max_field_length": 4096,
}

CAPTURE_FIELD_PATTERN = re.compile(r"^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*$")
MAX_CAPTURE_FIELDS = 100
MIN_CAPTURE_FIELD_LENGTH = 64
MAX_CAPTURE_FIELD_LENGTH = 16384


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _normalise_fields(value: Any, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, (str, list)):
        raise ValueError(f"{field} must be an array of dot-delimited field paths.")
    fields = _string_list(value)
    if len(fields) > MAX_CAPTURE_FIELDS:
        raise ValueError(f"{field} may contain at most {MAX_CAPTURE_FIELDS} fields.")
    if len(set(fields)) != len(fields):
        raise ValueError(f"{field} must not contain duplicate paths.")
    for path in fields:
        if not CAPTURE_FIELD_PATTERN.fullmatch(path):
            raise ValueError(f"{field} paths must be dot-delimited object fields using letters, numbers, or underscores.")
    return fields


def _paths_overlap(left: str, right: str) -> bool:
    left_parts = left.split(".")
    right_parts = right.split(".")
    return left_parts[: len(right_parts)] == right_parts or right_parts[: len(left_parts)] == left_parts


def normalise_capture_policy(value: Any = None) -> dict[str, Any]:
    """Validate and return a stable tenant capture policy."""

    if value is None:
        return copy.deepcopy(DEFAULT_CAPTURE_POLICY)
    if not isinstance(value, dict):
        raise ValueError("capture_policy must be an object.")

    store_original = value.get("store_original_action", DEFAULT_CAPTURE_POLICY["store_original_action"])
    if not isinstance(store_original, bool):
        raise ValueError("capture_policy.store_original_action must be a boolean.")

    redact_fields = _normalise_fields(value.get("redact_fields", []), "capture_policy.redact_fields")
    hash_fields = _normalise_fields(value.get("hash_fields", []), "capture_policy.hash_fields")
    for redact_path in redact_fields:
        if any(_paths_overlap(redact_path, hash_path) for hash_path in hash_fields):
            raise ValueError("capture_policy.redact_fields and hash_fields must not overlap.")

    max_field_length = value.get("max_field_length", DEFAULT_CAPTURE_POLICY["max_field_length"])
    if isinstance(max_field_length, bool):
        raise ValueError(f"capture_policy.max_field_length must be an integer between {MIN_CAPTURE_FIELD_LENGTH} and {MAX_CAPTURE_FIELD_LENGTH}.")
    try:
        max_field_length = int(max_field_length)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"capture_policy.max_field_length must be an integer between {MIN_CAPTURE_FIELD_LENGTH} and {MAX_CAPTURE_FIELD_LENGTH}.") from exc
    if max_field_length < MIN_CAPTURE_FIELD_LENGTH or max_field_length > MAX_CAPTURE_FIELD_LENGTH:
        raise ValueError(f"capture_policy.max_field_length must be an integer between {MIN_CAPTURE_FIELD_LENGTH} and {MAX_CAPTURE_FIELD_LENGTH}.")

    return {
        "store_original_action": store_original,
        "redact_fields": redact_fields,
        "hash_fields": hash_fields,
        "max_field_length": max_field_length,
    }


def capture_policy_summary(policy: Any = None) -> dict[str, Any]:
    """Return a response-safe representation of the active policy."""

    normalised = normalise_capture_policy(policy)
    return {
        "store_original_action": normalised["store_original_action"],
        "redact_fields": list(normalised["redact_fields"]),
        "hash_fields": list(normalised["hash_fields"]),
        "max_field_length": normalised["max_field_length"],
    }


def _canonical_default(value: Any) -> Any:
    if isinstance(value, Decimal):
        return float(value)
    raise TypeError(f"Cannot serialise {type(value).__name__}")


def _hash_value(value: Any) -> str:
    if isinstance(value, str):
        raw = value.encode("utf-8")
    else:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=_canonical_default).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _set_path(document: dict[str, Any], path: str, replacement: Any) -> None:
    parts = path.split(".")
    current: Any = document
    for part in parts[:-1]:
        if not isinstance(current, dict) or part not in current:
            return
        current = current[part]
    if isinstance(current, dict) and parts[-1] in current:
        current[parts[-1]] = replacement


def _apply_path(document: dict[str, Any], path: str, replacement: Any) -> None:
    """Apply a path to the action and, for action-relative paths, its source."""

    if path.startswith("original_action."):
        original = document.get("original_action")
        if isinstance(original, dict):
            _set_path(original, path.removeprefix("original_action."), replacement)
        return
    _set_path(document, path, replacement)
    original = document.get("original_action")
    if isinstance(original, dict):
        _set_path(original, path, replacement)


def _truncate(value: Any, maximum: int) -> Any:
    if isinstance(value, dict):
        return {str(key): _truncate(item, maximum) for key, item in value.items()}
    if isinstance(value, list):
        return [_truncate(item, maximum) for item in value]
    if isinstance(value, str) and len(value) > maximum:
        return value[:maximum] + "...[TRUNCATED]"
    return value


def capture_action(action: Any, policy: Any = None) -> Any:
    """Return a policy-captured copy of a normalised action."""

    if not isinstance(action, dict):
        return action
    normalised = normalise_capture_policy(policy)
    captured = copy.deepcopy(action)
    for path in normalised["redact_fields"]:
        _apply_path(captured, path, "[REDACTED_BY_TENANT_POLICY]")
    for path in normalised["hash_fields"]:
        marker = object()
        current: Any = captured
        parts = path.split(".")
        for part in parts:
            if not isinstance(current, dict) or part not in current:
                current = marker
                break
            current = current[part]
        if current is not marker:
            _apply_path(captured, path, _hash_value(current))
    if not normalised["store_original_action"]:
        captured.pop("original_action", None)
    return _truncate(captured, normalised["max_field_length"])


def apply_capture_policy(record: Any, policy: Any = None) -> Any:
    """Apply capture controls to a Proof-like record and reseal it upstream."""

    if not isinstance(record, dict):
        return record
    normalised = normalise_capture_policy(policy)
    captured = copy.deepcopy(record)
    if isinstance(captured.get("action"), dict):
        captured["action"] = capture_action(captured["action"], normalised)
    approvals = captured.get("approvals")
    if isinstance(approvals, list):
        for approval in approvals:
            if isinstance(approval, dict) and isinstance(approval.get("action"), dict):
                approval["action"] = capture_action(approval["action"], normalised)
    receipt = captured.get("trusted_action_receipt")
    if isinstance(receipt, dict) and isinstance(receipt.get("approval"), dict):
        if isinstance(receipt["approval"].get("action"), dict):
            receipt["approval"]["action"] = capture_action(receipt["approval"]["action"], normalised)
        captured["trusted_action_receipt"] = refresh_receipt(receipt)
    captured["capture_policy"] = capture_policy_summary(normalised)
    return captured
