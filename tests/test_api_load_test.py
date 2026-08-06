import unittest

from scripts.api_load_test import build_payload, summarise


class ApiLoadTestTests(unittest.TestCase):
    def test_build_payload_supports_safe_allow_and_approval_scenarios(self):
        allow = build_payload("tenant", "allow")
        self.assertEqual(allow["action"]["tool"], "shell")
        self.assertEqual(allow["action"]["parameters"]["command"], "printf kenning-load-test")

        approval = build_payload("tenant", "approval")
        self.assertEqual(approval["action"]["tool"], "sql")
        self.assertIn("UPDATE", approval["action"]["parameters"]["statement"])

    def test_summarise_reports_successes_and_statuses(self):
        result = summarise(
            [
                {"status": 200, "decision": "allow", "elapsed_ms": 10.0},
                {"status": 200, "decision": "allow", "elapsed_ms": 20.0},
                {"status": 503, "decision": None, "elapsed_ms": 30.0},
            ]
        )
        self.assertEqual(result["requests"], 3)
        self.assertEqual(result["successful"], 2)
        self.assertEqual(result["failed"], 1)
        self.assertEqual(result["status_counts"], {"200": 2, "503": 1})
        self.assertEqual(result["decisions"], ["allow"])
        self.assertEqual(result["p95_ms"], 30.0)

    def test_summarise_reports_approval_persistence_timings(self):
        result = summarise(
            [
                {"status": 200, "decision": "require_approval", "elapsed_ms": 1000.0, "approval_creation_latency_ms": 20.0},
                {"status": 200, "decision": "require_approval", "elapsed_ms": 1100.0, "approval_creation_latency_ms": 40.0, "audit_acceptance_latency_ms": 30.0},
            ]
        )
        self.assertEqual(result["approval_creation_p95_ms"], 40.0)

    def test_summarise_reports_audit_acceptance_timings(self):
        result = summarise(
            [
                {"status": 200, "decision": "allow", "elapsed_ms": 100.0, "audit_acceptance_latency_ms": 15.0},
                {"status": 200, "decision": "allow", "elapsed_ms": 110.0, "audit_acceptance_latency_ms": 25.0},
            ]
        )
        self.assertEqual(result["audit_acceptance_p95_ms"], 25.0)


if __name__ == "__main__":
    unittest.main()
