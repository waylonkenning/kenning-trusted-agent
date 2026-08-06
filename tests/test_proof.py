from decimal import Decimal
import unittest

from app.guard import build_receipt, normalise_action
from app.proof import (
    _evidence_gaps,
    apply_capture,
    attach_outcome,
    attach_receipt,
    build_proof_record,
    normalise_evidence,
    normalise_input,
    render_report,
    sha256_value,
    verify_integrity,
)


class ProofRecordTests(unittest.TestCase):
    def action(self):
        return normalise_action(
            {
                "context": {
                    "tenant_id": "demo",
                    "run_id": "run-proof-test",
                    "agent_id": "procurement-agent",
                    "invoked_by": "test-user",
                },
                "action": {"tool": "sql", "parameters": {"statement": "SELECT * FROM pricing"}},
            }
        )

    def test_input_content_is_hashed_and_not_stored(self):
        record = build_proof_record(
            {
                "tenant_id": "demo",
                "inputs": [{"type": "document", "id": "proposal.pdf", "content": "supplier pricing"}],
            }
        )
        input_record = record["inputs"][0]
        self.assertNotIn("content", input_record)
        self.assertTrue(input_record["hash"].startswith("sha256:"))
        self.assertEqual(input_record["hash_status"], "computed")

    def test_missing_evidence_is_identified(self):
        record = build_proof_record({"recommendation": "Select Supplier A"})
        self.assertEqual(record["evidence_status"], "incomplete")
        self.assertIn("Recommendation has no associated evidence.", record["evidence_gaps"])

    def test_record_links_evidence_factors_and_receipt(self):
        action = self.action()
        receipt = build_receipt(action, "allow", proof_record="proof://run-proof-test/action-1")
        record = build_proof_record(
            {
                "request": {"summary": "Recommend a supplier"},
                "evidence": [
                    {
                        "evidence_id": "pricing-table",
                        "claim": "Supplier A has the lowest total cost",
                        "source": "pricing.xlsx",
                        "location": "Sheet 1, D12:D18",
                    }
                ],
                "decision_factors": [{"factor": "Price", "weight": 0.35, "result": "Supplier A ranked first", "evidence_refs": ["pricing-table"]}],
                "recommendation": "Select Supplier A",
            },
            action=action,
        )
        record = attach_receipt(record, receipt)
        self.assertEqual(record["evidence_status"], "verified")
        self.assertEqual(record["trusted_action_receipt"]["proof_record"], "proof://run-proof-test/action-1")
        self.assertTrue(record["integrity"]["record_hash"].startswith("sha256:"))
        report = render_report(record)
        self.assertIn("Supplier A has the lowest total cost", report)
        self.assertIn("No evidence gaps detected.", report)
        self.assertNotIn("chain-of-thought", report.lower())

    def test_decision_record_preserves_policy_and_identity_context(self):
        action = self.action()
        decision = {
            "decision": "require_approval",
            "risk": "high",
            "risk_score": 80,
            "reason_codes": ["POLICY_SECURITY_REVIEW"],
            "policy_id": "production-review",
            "policy_version": 4,
            "policy_matches": [
                {
                    "policy_id": "production-review",
                    "policy_version": 4,
                    "rule_id": "security-review",
                    "decision": "require_approval",
                }
            ],
            "policy_resolution": {
                "strategy": "most_restrictive_wins",
                "selected_decision": "require_approval",
                "selected_match": {"rule_id": "security-review"},
            },
            "approval_requirements": [{"groups": ["security"]}],
            "identity": {"authorized": True, "decision": "allow"},
        }
        record = build_proof_record({}, action=action, decision=decision)
        evaluation = record["policy_evaluations"][0]
        self.assertEqual(evaluation["policy_matches"][0]["rule_id"], "security-review")
        self.assertEqual(evaluation["policy_resolution"]["strategy"], "most_restrictive_wins")
        self.assertEqual(evaluation["approval_requirements"][0]["groups"], ["security"])
        self.assertTrue(evaluation["identity"]["authorized"])

    def test_outcome_reseals_receipt_and_record(self):
        action = self.action()
        record = build_proof_record({}, action=action)
        receipt = build_receipt(action, "allow", proof_record=record["proof_uri"])
        record = attach_receipt(record, receipt)
        updated = attach_outcome(record, {"status": "success", "result": "completed"})
        self.assertEqual(updated["outcome"]["status"], "success")
        self.assertEqual(updated["trusted_action_receipt"]["result"], "success")
        self.assertTrue(updated["trusted_action_receipt"]["integrity"]["record_hash"].startswith("sha256:"))
        self.assertTrue(updated["integrity"]["record_hash"].startswith("sha256:"))
        self.assertTrue(verify_integrity(updated)["valid"])

        tampered = {**updated, "recommendation": "Select Supplier B"}
        self.assertFalse(verify_integrity(tampered)["valid"])

    def test_outcome_reseals_persisted_record_without_storage_metadata(self):
        action = self.action()
        record = build_proof_record({}, action=action)
        receipt = build_receipt(action, "allow", proof_record=record["proof_uri"])
        record = attach_receipt(record, receipt)
        persisted = {
            **record,
            "pk": f"PROOF#{record['proof_id']}",
            "sk": "METADATA",
            "retention_expires_at": 1_800_000_000,
        }

        updated = attach_outcome(persisted, {"status": "success", "result": "completed"})

        self.assertTrue(verify_integrity(updated)["valid"])

    # --- Coverage: sha256_value and canonical serialization ---

    def test_sha256_value_with_decimal(self):
        """Decimal values are serialised via _canonical_default (lines 28-30)."""
        result = sha256_value({"amount": Decimal("10")})
        self.assertTrue(result.startswith("sha256:"))
        result_float = sha256_value({"amount": Decimal("10.5")})
        self.assertTrue(result_float.startswith("sha256:"))

    def test_sha256_value_with_dict(self):
        """Non-bytes, non-str values use _canonical (line 39)."""
        result = sha256_value({"key": "value"})
        self.assertTrue(result.startswith("sha256:"))

    # --- Coverage: _hash_input and normalise_input ---

    def test_input_with_explicit_hash_is_verified(self):
        """Input with a hash key gets hash_status verified (line 51)."""
        result = normalise_input({"id": "doc-1", "hash": "sha256:abc123"})
        self.assertEqual(result["hash"], "sha256:abc123")
        self.assertEqual(result["hash_status"], "verified")

    def test_input_without_hash_or_content(self):
        """Input dict without hash or content gets not_provided (lines 54, 67)."""
        result = normalise_input({"id": "doc-1", "type": "reference"})
        self.assertEqual(result["hash_status"], "not_provided")
        self.assertNotIn("hash", result)

    def test_normalise_input_non_dict(self):
        """Non-dict input is wrapped (line 69)."""
        result = normalise_input("plain string input")
        self.assertEqual(result["value"], "plain string input")
        self.assertEqual(result["hash_status"], "not_provided")

    # --- Coverage: normalise_evidence ---

    def test_normalise_evidence_non_dict(self):
        """Non-dict evidence is wrapped with source (line 74)."""
        result = normalise_evidence("https://example.org/source", 0)
        self.assertEqual(result["source"], "https://example.org/source")
        self.assertEqual(result["evidence_id"], "evidence-1")
        self.assertEqual(result["claim"], "")

    # --- Coverage: _normalise_agent ---

    def test_agent_as_dict(self):
        """Agent supplied as dict is redacted (line 85)."""
        record = build_proof_record({"agent": {"id": "custom-agent", "version": "2.0"}})
        self.assertEqual(record["agent"]["id"], "custom-agent")

    def test_agent_as_non_string_non_dict(self):
        """Agent supplied as non-str/non-dict defaults (line 87)."""
        record = build_proof_record({"agent": 12345})
        self.assertEqual(record["agent"]["id"], "unregistered-agent")

    # --- Coverage: _evidence_gaps edge cases ---

    def test_evidence_gaps_non_dict_factor_skipped(self):
        """Non-dict decision factors are skipped (line 112)."""
        record = build_proof_record(
            {
                "evidence": [{"evidence_id": "e1", "claim": "test", "source": "s"}],
                "decision_factors": ["string-factor", {"factor": "Cost", "result": "Low"}],
            }
        )
        self.assertEqual(record["evidence_status"], "verified")

    def test_evidence_gaps_string_evidence_refs(self):
        """String evidence_refs are wrapped in list (line 115)."""
        record = build_proof_record(
            {
                "evidence": [{"evidence_id": "e1", "claim": "test", "source": "s"}],
                "decision_factors": [{"factor": "Cost", "evidence_refs": "e1"}],
            }
        )
        self.assertEqual(record["evidence_gaps"], [])

    def test_evidence_gaps_missing_evidence_refs(self):
        """Decision factor referencing missing evidence (line 118)."""
        record = build_proof_record(
            {
                "evidence": [{"evidence_id": "e1", "claim": "test", "source": "s"}],
                "decision_factors": [{"factor": "Cost", "evidence_refs": ["e-missing"]}],
            }
        )
        self.assertIn("references missing evidence: e-missing", record["evidence_gaps"][0])

    def test_evidence_gaps_required_evidence_missing(self):
        """Required evidence not present (lines 123-124)."""
        record = build_proof_record(
            {
                "evidence": [{"evidence_id": "e1", "claim": "test", "source": "pricing.xlsx"}],
                "required_evidence": ["pricing.xlsx", "missing-source.pdf"],
            }
        )
        self.assertTrue(any("missing-source.pdf" in gap for gap in record["evidence_gaps"]))
        self.assertFalse(any("pricing.xlsx" in gap for gap in record["evidence_gaps"]))

    # --- Coverage: verify_integrity ---

    def test_verify_integrity_non_dict(self):
        """Non-dict record returns proof_missing (line 141)."""
        result = verify_integrity(None)
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "proof_missing")

    # --- Coverage: build_proof_record with decision approval and receipt ---

    def test_build_proof_record_with_decision_approval(self):
        """Decision approval is used when no explicit approvals (line 180)."""
        action = self.action()
        decision = {"decision": "require_approval", "approval": {"approved_by": "admin", "groups": ["security"]}}
        record = build_proof_record({}, action=action, decision=decision)
        self.assertEqual(record["approvals"][0]["approved_by"], "admin")

    def test_build_proof_record_with_receipt(self):
        """Receipt passed to build_proof_record is attached (line 230)."""
        action = self.action()
        receipt = build_receipt(action, "allow", proof_record="proof://test/action-1")
        record = build_proof_record({}, action=action, receipt=receipt)
        self.assertIn("trusted_action_receipt", record)
        self.assertTrue(record["integrity"]["record_hash"].startswith("sha256:"))

    # --- Coverage: apply_capture ---

    def test_apply_capture_reseals_record(self):
        """apply_capture applies capture policy and reseals (lines 242-243)."""
        action = self.action()
        record = build_proof_record({}, action=action)
        captured = apply_capture(record)
        self.assertTrue(captured["integrity"]["record_hash"].startswith("sha256:"))
        self.assertTrue(verify_integrity(captured)["valid"])

    # --- Coverage: render_report with location and factors ---

    def test_render_report_with_evidence_location_and_factors(self):
        """Report renders evidence location and decision factors."""
        record = build_proof_record(
            {
                "evidence": [
                    {"evidence_id": "e1", "claim": "Cost is low", "source": "pricing.xlsx", "location": "Sheet 1"}
                ],
                "decision_factors": [{"factor": "Price", "result": "Supplier A ranked first"}],
                "recommendation": "Select Supplier A",
            }
        )
        report = render_report(record)
        self.assertIn("Sheet 1", report)
        self.assertIn("**Price**: Supplier A ranked first", report)

    def test_sha256_value_with_bytes(self):
        """Bytes input uses raw bytes directly (line 39)."""
        result = sha256_value(b"raw bytes data")
        self.assertTrue(result.startswith("sha256:"))

    def test_canonical_default_non_decimal_raises(self):
        """Non-Decimal non-serializable value raises TypeError (line 30)."""
        with self.assertRaises(TypeError):
            sha256_value({"key": object()})

    def test_agent_as_string(self):
        """Agent supplied as string uses it as id (line 85)."""
        record = build_proof_record({"agent": "my-agent-id"})
        self.assertEqual(record["agent"]["id"], "my-agent-id")

    def test_evidence_gaps_non_dict_factor_directly(self):
        """Non-dict factor in _evidence_gaps is skipped (line 112)."""
        record = {
            "evidence": [{"evidence_id": "e1"}],
            "decision_factors": ["not-a-dict", {"factor": "Cost"}],
            "recommendation": None,
            "required_evidence": [],
        }
        gaps = _evidence_gaps(record)
        self.assertEqual(gaps, [])

    def test_render_report_no_evidence_no_factors(self):
        """Report with no evidence and no factors (lines 287, 294)."""
        record = build_proof_record({})
        report = render_report(record)
        self.assertIn("No evidence was recorded.", report)
        self.assertIn("No decision factors were recorded.", report)


if __name__ == "__main__":
    unittest.main()
