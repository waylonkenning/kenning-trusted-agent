#!/usr/bin/env python3
"""Run a safe concurrent end-to-end load test against the Guard HTTP API."""

from __future__ import annotations

import argparse
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import sys
from time import perf_counter
from typing import Any
import urllib.error
import urllib.request
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.benchmark_guard import percentile


def build_payload(tenant_id: str, scenario: str) -> dict[str, Any]:
    if scenario not in {"allow", "approval"}:
        raise ValueError("scenario must be allow or approval")
    action = (
        {"tool": "shell", "parameters": {"command": "printf kenning-load-test"}}
        if scenario == "allow"
        else {"tool": "sql", "target": "load_test_table", "parameters": {"statement": "UPDATE load_test_table SET status = 'closed'"}}
    )
    return {
        "context": {
            "tenant_id": tenant_id,
            "environment": "development",
            "agent_id": "api-load-test-agent",
            "invoked_by": "api-load-test",
            "action_id": f"load-test-{uuid.uuid4().hex[:16]}",
        },
        "action": action,
    }


def _request(base_url: str, pat: str, tenant_id: str, timeout: float, scenario: str) -> dict[str, Any]:
    payload = build_payload(tenant_id, scenario)
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/v1/actions/evaluate",
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {pat}",
            "Content-Type": "application/json",
        },
    )
    started = perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
            return {
                "status": int(response.status),
                "decision": body.get("decision"),
                "approval_creation_latency_ms": body.get("approval_creation_latency_ms"),
                "audit_acceptance_latency_ms": body.get("audit_acceptance_latency_ms"),
                "elapsed_ms": (perf_counter() - started) * 1000,
                "error": None,
            }
    except urllib.error.HTTPError as error:
        try:
            error.read()
        finally:
            error.close()
        return {"status": int(error.code), "decision": None, "elapsed_ms": (perf_counter() - started) * 1000, "error": "http_error"}
    except (OSError, TimeoutError, ValueError) as error:
        return {"status": None, "decision": None, "elapsed_ms": (perf_counter() - started) * 1000, "error": type(error).__name__}


def summarise(results: list[dict[str, Any]]) -> dict[str, Any]:
    if not results:
        raise ValueError("results must not be empty")
    timings = [float(item["elapsed_ms"]) for item in results]
    approval_timings = [
        float(item["approval_creation_latency_ms"])
        for item in results
        if item.get("approval_creation_latency_ms") is not None
    ]
    audit_timings = [
        float(item["audit_acceptance_latency_ms"])
        for item in results
        if item.get("audit_acceptance_latency_ms") is not None
    ]
    successful = [item for item in results if int(item.get("status") or 0) // 100 == 2]
    summary = {
        "requests": len(results),
        "successful": len(successful),
        "failed": len(results) - len(successful),
        "status_counts": {
            str(status): sum(1 for item in results if item.get("status") == status)
            for status in sorted({item.get("status") for item in results}, key=lambda value: str(value))
        },
        "decisions": sorted({str(item.get("decision")) for item in successful}),
        "p50_ms": round(percentile(timings, 50), 3),
        "p95_ms": round(percentile(timings, 95), 3),
        "p99_ms": round(percentile(timings, 99), 3),
        "max_ms": round(max(timings), 3),
    }
    if approval_timings:
        summary["approval_creation_p50_ms"] = round(percentile(approval_timings, 50), 3)
        summary["approval_creation_p95_ms"] = round(percentile(approval_timings, 95), 3)
        summary["approval_creation_p99_ms"] = round(percentile(approval_timings, 99), 3)
        summary["approval_creation_max_ms"] = round(max(approval_timings), 3)
    if audit_timings:
        summary["audit_acceptance_p50_ms"] = round(percentile(audit_timings, 50), 3)
        summary["audit_acceptance_p95_ms"] = round(percentile(audit_timings, 95), 3)
        summary["audit_acceptance_p99_ms"] = round(percentile(audit_timings, 99), 3)
        summary["audit_acceptance_max_ms"] = round(max(audit_timings), 3)
    return summary


def run_load_test(
    base_url: str,
    pat: str,
    tenant_id: str,
    request_count: int,
    concurrency: int,
    timeout: float,
    scenario: str = "allow",
) -> dict[str, Any]:
    if request_count < 1:
        raise ValueError("request_count must be at least 1")
    if concurrency < 1:
        raise ValueError("concurrency must be at least 1")
    with ThreadPoolExecutor(max_workers=min(concurrency, request_count)) as executor:
        futures = [executor.submit(_request, base_url, pat, tenant_id, timeout, scenario) for _ in range(request_count)]
        results = [future.result() for future in as_completed(futures)]
    return summarise(results)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=os.environ.get("KENNING_API_URL", ""), help="Deployed API base URL.")
    parser.add_argument("--tenant-id", default=os.environ.get("KENNING_TEST_TENANT_ID", ""))
    parser.add_argument("--requests", type=int, default=20, dest="request_count")
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--scenario", choices=["allow", "approval"], default="allow")
    parser.add_argument("--max-p95-ms", type=float, help="Fail if end-to-end p95 exceeds this threshold.")
    parser.add_argument("--max-p99-ms", type=float, help="Fail if end-to-end p99 exceeds this threshold.")
    parser.add_argument("--max-approval-p95-ms", type=float, help="Fail if the measured approval persistence p95 exceeds this threshold.")
    parser.add_argument("--max-audit-p95-ms", type=float, help="Fail if the measured durable audit acceptance p95 exceeds this threshold.")
    args = parser.parse_args()
    pat = os.environ.get("KENNING_PAT", "")
    if not args.url or not args.tenant_id or not pat:
        parser.error("--url, --tenant-id, and KENNING_PAT (or KENNING_API_URL/KENNING_TEST_TENANT_ID) are required")
    result = run_load_test(args.url, pat, args.tenant_id, args.request_count, args.concurrency, args.timeout, args.scenario)
    print(json.dumps(result, sort_keys=True))
    expected_decision = "require_approval" if args.scenario == "approval" else "allow"
    threshold_failed = (
        (args.max_p95_ms is not None and result["p95_ms"] > args.max_p95_ms)
        or (args.max_p99_ms is not None and result["p99_ms"] > args.max_p99_ms)
        or (
            args.max_approval_p95_ms is not None
            and result.get("approval_creation_p95_ms", float("inf")) > args.max_approval_p95_ms
        )
        or (
            args.max_audit_p95_ms is not None
            and result.get("audit_acceptance_p95_ms", float("inf")) > args.max_audit_p95_ms
        )
    )
    decision_failed = expected_decision not in result["decisions"]
    if threshold_failed:
        print(f"Latency threshold failed for {args.scenario} scenario.", file=sys.stderr)
    if decision_failed:
        print(f"Expected decision {expected_decision!r} was not observed.", file=sys.stderr)
    return 0 if result["failed"] == 0 and not threshold_failed and not decision_failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
