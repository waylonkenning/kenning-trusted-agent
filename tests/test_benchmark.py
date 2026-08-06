import unittest

from scripts.benchmark_guard import benchmark, percentile


class GuardBenchmarkTests(unittest.TestCase):
    def test_percentile_uses_nearest_rank(self):
        self.assertEqual(percentile([1.0, 2.0, 3.0, 4.0], 50), 2.0)
        self.assertEqual(percentile([1.0, 2.0, 3.0, 4.0], 95), 4.0)

    def test_benchmark_reports_policy_only_latency(self):
        result = benchmark(iterations=10)
        self.assertEqual(result["iterations"], 10)
        self.assertEqual(result["decisions"], ["allow"])
        self.assertGreaterEqual(result["p95_ms"], result["p50_ms"])
        self.assertGreaterEqual(result["p99_ms"], result["p95_ms"])


if __name__ == "__main__":
    unittest.main()
