"""Tenant-scoped operational metric helpers for the prototype.

Metrics deliberately contain aggregate dimensions and timing only. They never
store action parameters, prompts, source content, or result payloads.
"""

from __future__ import annotations

from datetime import datetime, timezone
from math import ceil
from typing import Any


LATENCY_BUCKET_LIMITS = (1, 5, 10, 25, 50, 100, 150, 250, 500, 1000, 2500, 5000, 10000)


def _day(value: Any) -> str:
    text = str(value or "").strip()
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).date().isoformat()
    except (TypeError, ValueError):
        return datetime.now(timezone.utc).date().isoformat()


def _safe_dimension(value: Any, fallback: str = "unknown") -> str:
    text = str(value or fallback).strip().lower()
    return text[:128] or fallback


def _latency_bucket(value: float) -> str:
    for limit in LATENCY_BUCKET_LIMITS:
        if value <= limit:
            return f"le_{limit}"
    return f"gt_{LATENCY_BUCKET_LIMITS[-1]}"


def _percentile(buckets: dict[str, int], samples: int, percentile: int) -> int | None:
    if not samples or not buckets:
        return None
    target = max(1, ceil(samples * percentile / 100))
    cumulative = 0
    for limit in LATENCY_BUCKET_LIMITS:
        cumulative += int(buckets.get(f"le_{limit}") or 0)
        if cumulative >= target:
            return limit
    return None


def metric_updates(event: dict[str, Any], delivery_status: str | None = None, include_event: bool = True) -> list[dict[str, Any]]:
    """Return aggregate metric updates without copying event payloads."""

    tenant_id = str(event.get("tenant_id") or "")
    if not tenant_id:
        return []
    day = _day(event.get("created_at"))
    updates: list[dict[str, Any]] = []

    def add(dimension: str, name: Any, count: int = 1, value: float | None = None) -> None:
        item = {
            "tenant_id": tenant_id,
            "metric_day": day,
            "dimension": _safe_dimension(dimension),
            "name": _safe_dimension(name),
            "count": int(count),
        }
        if value is not None:
            item["value"] = float(value)
        updates.append(item)

    if include_event:
        add("event", event.get("event_type"))
        if event.get("decision"):
            add("decision", event.get("decision"))
        action = event.get("action") if isinstance(event.get("action"), dict) else {}
        adapter = action.get("adapter") or action.get("tool")
        if adapter:
            add("adapter", adapter)
        latency = event.get("evaluation_latency_ms")
        if latency is not None:
            try:
                latency_value = float(latency)
                if latency_value >= 0:
                    add("latency", "evaluation", value=latency_value)
                    add("latency_bucket", _latency_bucket(latency_value))
            except (TypeError, ValueError):
                pass
    if delivery_status is not None:
        add("delivery", delivery_status)
    return updates


def aggregate(items: list[dict[str, Any]], start_day: str | None = None, end_day: str | None = None) -> dict[str, Any]:
    """Aggregate metric rows into the public operational response shape."""

    result: dict[str, Any] = {
        "event_counts": {},
        "decision_counts": {},
        "adapter_counts": {},
        "delivery_counts": {},
        "latency_ms": {"samples": 0, "average": None, "p50": None, "p95": None, "p99": None},
    }
    latency_sum = 0.0
    latency_buckets: dict[str, int] = {}
    for item in items:
        day = str(item.get("metric_day") or "")
        if start_day and day < start_day:
            continue
        if end_day and day > end_day:
            continue
        dimension = str(item.get("dimension") or "")
        name = str(item.get("name") or "unknown")
        count = int(item.get("metric_count") or item.get("count") or 0)
        if dimension == "latency":
            result["latency_ms"]["samples"] += count
            latency_sum += float(item.get("value_sum") if item.get("value_sum") is not None else (item.get("value") or 0) * count)
            continue
        if dimension == "latency_bucket":
            latency_buckets[name] = int(latency_buckets.get(name, 0)) + count
            continue
        target = {
            "event": result["event_counts"],
            "decision": result["decision_counts"],
            "adapter": result["adapter_counts"],
            "delivery": result["delivery_counts"],
        }.get(dimension)
        if target is not None:
            target[name] = int(target.get(name, 0)) + count
    samples = result["latency_ms"]["samples"]
    if samples:
        result["latency_ms"]["average"] = round(latency_sum / samples, 3)
        for percentile in (50, 95, 99):
            result["latency_ms"][f"p{percentile}"] = _percentile(latency_buckets, samples, percentile)
    return result
