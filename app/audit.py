"""Dependency-free audit search helpers shared by HTTP and export adapters."""

from __future__ import annotations

import json
from typing import Any


SEARCHABLE_FIELDS = (
    "event_type",
    "decision",
    "agent_id",
    "invoked_by",
    "run_id",
    "action_id",
    "action_hash",
    "policy_id",
    "environment",
    "receipt_id",
    "proof_id",
    "approval_id",
)


def normalise_filters(query: dict[str, Any] | None) -> dict[str, Any]:
    """Return validated audit filters while keeping query parsing deterministic."""

    query = query or {}
    filters: dict[str, Any] = {}
    for field in SEARCHABLE_FIELDS:
        value = query.get(field)
        if value not in (None, ""):
            filters[field] = str(value)
    for field in ("start_time", "end_time", "resource"):
        value = query.get(field)
        if value not in (None, ""):
            filters[field] = str(value)
    try:
        filters["limit"] = max(1, min(int(query.get("limit") or 50), 100))
    except (TypeError, ValueError) as exc:
        raise ValueError("limit must be an integer between 1 and 100") from exc
    return filters


def event_matches(event: dict[str, Any], filters: dict[str, Any]) -> bool:
    """Match scalar correlation fields and a redacted resource search term."""

    for field in SEARCHABLE_FIELDS:
        expected = filters.get(field)
        if expected is None:
            continue
        if field == "receipt_id":
            actual = (event.get("receipt") or {}).get("receipt_id") if isinstance(event.get("receipt"), dict) else None
        else:
            actual = event.get(field)
        if str(actual or "") != expected:
            return False

    created_at = str(event.get("created_at", ""))
    if filters.get("start_time") and created_at < str(filters["start_time"]):
        return False
    if filters.get("end_time") and created_at > str(filters["end_time"]):
        return False

    resource = filters.get("resource")
    if resource:
        searchable = json.dumps(
            {
                "action": event.get("action"),
                "target": event.get("target"),
                "resource": event.get("resource"),
            },
            sort_keys=True,
            ensure_ascii=False,
            default=str,
        ).lower()
        if str(resource).lower() not in searchable:
            return False
    return True
