#!/usr/bin/env python3
"""Benchmark dependency-free policy evaluation against the PRD latency targets."""

from __future__ import annotations

import argparse
import json
from math import ceil
from pathlib import Path
import sys
from time import perf_counter
from typing import Any

# Make the repository root importable when this file is invoked directly.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.guard import evaluate, normalise_action


def percentile(samples: list[float], percent: int) -> float:
    """Return the nearest-rank percentile in milliseconds."""

    if not samples:
        raise ValueError("samples must not be empty")
    if percent < 0 or percent > 100:
        raise ValueError("percent must be between 0 and 100")
    ordered = sorted(samples)
    index = max(0, ceil(len(ordered) * percent / 100) - 1)
    return ordered[index]


def benchmark(iterations: int = 1000) -> dict[str, Any]:
    if iterations < 1:
        raise ValueError("iterations must be at least 1")
    action = normalise_action(
        {
            "context": {
                "tenant_id": "benchmark",
                "environment": "development",
                "agent_id": "benchmark-agent",
                "invoked_by": "benchmark",
                "run_id": "benchmark-run",
                "action_id": "benchmark-action",
                "requested_at": "2026-07-17T00:00:00Z",
            },
            "action": {"tool": "shell", "parameters": {"command": "printf benchmark"}},
        }
    )
    timings: list[float] = []
    decisions: set[str] = set()
    for _ in range(iterations):
        started = perf_counter()
        result = evaluate(action)
        timings.append((perf_counter() - started) * 1000)
        decisions.add(str(result.get("decision") or ""))
    p95 = percentile(timings, 95)
    p99 = percentile(timings, 99)
    return {
        "iterations": iterations,
        "decisions": sorted(decisions),
        "p50_ms": round(percentile(timings, 50), 3),
        "p95_ms": round(p95, 3),
        "p99_ms": round(p99, 3),
        "max_ms": round(max(timings), 3),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=1000, help="Number of policy-only evaluations to execute.")
    parser.add_argument("--p95-ms", type=float, default=150, help="Maximum permitted p95 in milliseconds.")
    parser.add_argument("--p99-ms", type=float, default=500, help="Maximum permitted p99 in milliseconds.")
    args = parser.parse_args()
    result = benchmark(args.iterations)
    result["thresholds_ms"] = {"p95": args.p95_ms, "p99": args.p99_ms}
    result["passed"] = result["p95_ms"] <= args.p95_ms and result["p99_ms"] <= args.p99_ms
    print(json.dumps(result, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
