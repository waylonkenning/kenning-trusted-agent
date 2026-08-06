import unittest
from datetime import datetime, timezone

from app.metrics import aggregate, metric_updates


class MetricsTests(unittest.TestCase):
    def test_updates_are_aggregate_only(self):
        updates = metric_updates(
            {
                "tenant_id": "demo",
                "event_type": "action.evaluated",
                "decision": "require_approval",
                "created_at": "2026-07-16T12:00:00Z",
                "evaluation_latency_ms": 12.5,
                "action": {"adapter": "sql", "parameters": {"statement": "secret content"}},
            },
            delivery_status="disabled",
        )
        self.assertEqual({item["dimension"] for item in updates}, {"event", "decision", "adapter", "latency", "latency_bucket", "delivery"})
        self.assertNotIn("parameters", str(updates))
        self.assertNotIn("secret content", str(updates))

    def test_aggregate_calculates_daily_latency_and_dimensions(self):
        result = aggregate(
            [
                {"metric_day": "2026-07-16", "dimension": "event", "name": "action.evaluated", "count": 2},
                {"metric_day": "2026-07-16", "dimension": "decision", "name": "allow", "count": 1},
                {"metric_day": "2026-07-16", "dimension": "latency", "name": "evaluation", "count": 2, "value_sum": 30},
                {"metric_day": "2026-07-17", "dimension": "event", "name": "action.evaluated", "count": 5},
            ],
            start_day="2026-07-16",
            end_day="2026-07-16",
        )
        self.assertEqual(result["event_counts"], {"action.evaluated": 2})
        self.assertEqual(result["decision_counts"], {"allow": 1})
        self.assertEqual(result["latency_ms"], {"samples": 2, "average": 15.0, "p50": None, "p95": None, "p99": None})

    def test_aggregate_estimates_latency_percentiles_from_fixed_buckets(self):
        result = aggregate(
            [
                {"metric_day": "2026-07-16", "dimension": "latency", "name": "evaluation", "count": 100, "value_sum": 5000},
                {"metric_day": "2026-07-16", "dimension": "latency_bucket", "name": "le_10", "count": 50},
                {"metric_day": "2026-07-16", "dimension": "latency_bucket", "name": "le_50", "count": 45},
                {"metric_day": "2026-07-16", "dimension": "latency_bucket", "name": "le_100", "count": 5},
            ]
        )
        self.assertEqual(result["latency_ms"]["average"], 50.0)
        self.assertEqual(result["latency_ms"]["p50"], 10)
        self.assertEqual(result["latency_ms"]["p95"], 50)
        self.assertEqual(result["latency_ms"]["p99"], 100)

    def test_day_falls_back_to_today_on_invalid_date(self):
        updates = metric_updates({"tenant_id": "demo", "event_type": "test", "created_at": "not-a-date"})
        self.assertEqual(len(updates), 1)
        today = datetime.now(timezone.utc).date().isoformat()
        self.assertEqual(updates[0]["metric_day"], today)

    def test_safe_dimension_falls_back_on_whitespace_only_value(self):
        updates = metric_updates({"tenant_id": "demo", "event_type": "   "})
        self.assertEqual(updates[0]["name"], "unknown")

    def test_empty_tenant_id_returns_no_updates(self):
        self.assertEqual(metric_updates({}), [])
        self.assertEqual(metric_updates({"tenant_id": ""}), [])

    def test_missing_event_type_uses_unknown_dimension_name(self):
        updates = metric_updates({"tenant_id": "demo"})
        event_update = next(u for u in updates if u["dimension"] == "event")
        self.assertEqual(event_update["name"], "unknown")

    def test_aggregate_with_empty_rows_returns_defaults(self):
        result = aggregate([])
        self.assertEqual(result["event_counts"], {})
        self.assertEqual(result["decision_counts"], {})
        self.assertEqual(result["latency_ms"]["samples"], 0)
        self.assertIsNone(result["latency_ms"]["average"])

    def test_aggregate_skips_unknown_dimensions(self):
        result = aggregate([{"dimension": "nonexistent", "name": "x", "count": 5}])
        self.assertEqual(result["event_counts"], {})
        self.assertEqual(result["decision_counts"], {})
        self.assertEqual(result["adapter_counts"], {})
        self.assertEqual(result["delivery_counts"], {})

    def test_latency_bucket_overflow_returns_gt_max(self):
        updates = metric_updates({"tenant_id": "demo", "event_type": "test", "evaluation_latency_ms": 20000})
        bucket = next(u for u in updates if u["dimension"] == "latency_bucket")
        self.assertEqual(bucket["name"], "gt_10000")

    def test_aggregate_percentile_none_when_buckets_insufficient(self):
        result = aggregate(
            [
                {"metric_day": "2026-07-16", "dimension": "latency", "name": "evaluation", "count": 100, "value_sum": 5000},
                {"metric_day": "2026-07-16", "dimension": "latency_bucket", "name": "le_10", "count": 1},
            ]
        )
        self.assertIsNone(result["latency_ms"]["p50"])
        self.assertIsNone(result["latency_ms"]["p95"])
        self.assertIsNone(result["latency_ms"]["p99"])

    def test_latency_non_numeric_is_silently_skipped(self):
        updates = metric_updates({"tenant_id": "t", "event_type": "evaluate", "evaluation_latency_ms": "not-a-number"})
        names = [u["name"] for u in updates if u["dimension"] == "latency"]
        self.assertEqual(names, [])

    def test_delivery_status_dimension_is_recorded(self):
        updates = metric_updates({"tenant_id": "t", "event_type": "deliver"}, delivery_status="sent")
        delivery = [u for u in updates if u["dimension"] == "delivery"]
        self.assertEqual(len(delivery), 1)
        self.assertEqual(delivery[0]["name"], "sent")

    def test_aggregate_filters_by_start_day(self):
        rows = [
            {"metric_day": "2026-01-01", "dimension": "event", "name": "evaluate", "count": 5},
            {"metric_day": "2026-01-10", "dimension": "event", "name": "evaluate", "count": 3},
        ]
        result = aggregate(rows, start_day="2026-01-05")
        self.assertEqual(result["event_counts"]["evaluate"], 3)


if __name__ == "__main__":
    unittest.main()
