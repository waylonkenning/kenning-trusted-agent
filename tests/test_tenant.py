import os
import unittest

from app.tenant import (
    DEPLOYMENT_REGION,
    build_environment_config,
    build_tenant_config,
    default_tenant_config,
    environment_for,
    is_retained_item,
    iso_from_epoch,
    normalise_enabled_products,
    retention_cutoff,
    runtime_constraints,
)


DEPLOYMENT_ENVIRONMENT = str(os.environ.get("KENNING_ENV") or os.environ.get("KENNING_ENVIRONMENT") or "prototype").strip()


class TenantConfigurationTests(unittest.TestCase):
    def test_legacy_and_new_tenants_enable_all_products_by_default(self):
        self.assertEqual(default_tenant_config("demo")["enabled_products"], ["agent-guard", "agent-proof", "citation-trust", "agent-identity"])
        config = build_tenant_config("tenant-001")
        self.assertEqual(config["enabled_products"], ["agent-guard", "agent-proof", "citation-trust", "agent-identity"])

    def test_product_dependencies_and_base_product_are_enforced(self):
        self.assertEqual(normalise_enabled_products(["agent-guard", "citation-trust"]), ["agent-guard", "citation-trust"])
        with self.assertRaisesRegex(ValueError, "required products"):
            normalise_enabled_products(["citation-trust"])
        with self.assertRaisesRegex(ValueError, "base product"):
            normalise_enabled_products([])
        with self.assertRaisesRegex(ValueError, "unsupported"):
            normalise_enabled_products(["agent-guard", "unknown"])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            normalise_enabled_products(["agent-guard", "agent-guard"])

    def test_product_selection_is_preserved_and_versioned(self):
        config = build_tenant_config("tenant-001", {"enabled_products": ["agent-guard", "agent-proof"]})
        self.assertEqual(config["enabled_products"], ["agent-guard", "agent-proof"])
        updated = build_tenant_config("tenant-001", {"name": "Updated"}, config)
        self.assertEqual(updated["enabled_products"], ["agent-guard", "agent-proof"])
    def test_legal_hold_and_data_residency_are_validated(self):
        config = build_tenant_config(
            "tenant-001",
            {
                "retention_enabled": True,
                "retention_days": 30,
                "legal_hold_enabled": True,
                "legal_hold_reason": "Investigation INV-1",
                "data_residency_region": DEPLOYMENT_REGION,
            },
        )
        self.assertTrue(config["legal_hold_enabled"])
        self.assertEqual(config["legal_hold_reason"], "Investigation INV-1")
        self.assertEqual(config["data_residency_region"], DEPLOYMENT_REGION)

        wrong_region = "eu-west-1" if DEPLOYMENT_REGION != "eu-west-1" else "us-east-1"
        with self.assertRaises(ValueError):
            build_tenant_config("tenant-001", {"data_residency_region": wrong_region})
        with self.assertRaises(ValueError):
            build_tenant_config("tenant-001", {"legal_hold_enabled": True})

    def test_tenant_config_versions_and_retention_are_validated(self):
        config = build_tenant_config(
            "tenant-001",
            {
                "name": "Regulated tenant",
                "retention_enabled": True,
                "retention_days": 30,
                "audit_sink": {
                    "enabled": True,
                    "endpoint_url": "https://siem.example.org/v1/events",
                    "secret_arn": f"arn:aws:secretsmanager:us-east-1:123456789012:secret:kenning/audit-sinks/{DEPLOYMENT_ENVIRONMENT}/tenant-001/siem",
                    "format": "ndjson",
                },
                "capture_policy": {
                    "store_original_action": False,
                    "redact_fields": ["parameters.command"],
                    "hash_fields": ["parameters.statement"],
                },
                "citation_policy": {
                    "allowed_domains": ["*.govt.nz"],
                    "require_https": True,
                    "minimum_source_quality": "authoritative",
                },
                "environments": [
                    {"environment_id": "production", "mode": "enforce", "allowed_tools": ["sql"]},
                ],
                "default_environment": "production",
            },
        )
        self.assertEqual(config["config_version"], 1)
        self.assertTrue(config["retention_enabled"])
        self.assertEqual(config["environments"][0]["allowed_tools"], ["sql"])
        self.assertEqual(config["audit_sink"]["format"], "ndjson")
        self.assertFalse(config["capture_policy"]["store_original_action"])
        self.assertEqual(config["capture_policy"]["hash_fields"], ["parameters.statement"])
        self.assertEqual(config["citation_policy"]["allowed_domains"], ["*.govt.nz"])
        self.assertTrue(config["citation_policy"]["require_https"])
        self.assertTrue(config["citation_policy"]["respect_robots"])
        self.assertIsNotNone(retention_cutoff(config, now=30 * 86400))

        next_config = build_tenant_config("tenant-001", {"status": "suspended"}, config)
        self.assertEqual(next_config["config_version"], 2)
        self.assertEqual(next_config["status"], "suspended")

    def test_environment_runtime_constraints_fail_closed(self):
        config = build_tenant_config(
            "tenant-001",
            {
                "environments": [
                    {"environment_id": "production", "status": "suspended", "mode": "enforce", "allowed_tools": ["sql"]},
                ],
                "default_environment": "production",
            },
        )
        constraints = runtime_constraints(config, "production", "shell")
        self.assertEqual(constraints["mode"], "enforce")
        self.assertEqual(
            {reason["code"] for reason in constraints["reasons"]},
            {"ENVIRONMENT_SUSPENDED", "ENVIRONMENT_TOOL_NOT_ALLOWED"},
        )

        unknown = runtime_constraints(config, "staging", "sql")
        self.assertEqual(unknown["reasons"][0]["code"], "ENVIRONMENT_NOT_CONFIGURED")

    def test_legacy_tenant_has_no_runtime_restriction(self):
        config = default_tenant_config("demo")
        constraints = runtime_constraints(config, "development", "shell")
        self.assertIsNone(constraints["mode"])
        self.assertEqual(constraints["reasons"], [])
        self.assertTrue(config["capture_policy"]["store_original_action"])
        self.assertEqual(config["workload_identity"], {"enabled": False, "provider": "aws_iam", "allowed_account_ids": [], "mappings": []})

    def test_aws_workload_identity_is_normalised_with_scoped_authority(self):
        config = build_tenant_config(
            "tenant-001",
            {
                "workload_identity": {
                    "enabled": True,
                    "provider": "aws_iam",
                    "allowed_account_ids": ["123456789012"],
                    "mappings": [{
                        "principal_arn": "arn:aws:iam::123456789012:role/agent",
                        "agent_id": "agent-1",
                        "scopes": ["guard:evaluate"],
                        "maximum_authority": "standard",
                    }],
                }
            },
        )
        self.assertTrue(config["workload_identity"]["enabled"])
        self.assertEqual(config["workload_identity"]["mappings"][0]["maximum_authority"], "standard")

    def test_retention_candidate_filter_excludes_configuration(self):
        cutoff = 2_000_000_000
        self.assertTrue(is_retained_item({"tenant_id": "demo", "event_type": "action.evaluated", "created_at": "2000-01-01T00:00:00Z"}, "demo", cutoff))
        self.assertTrue(is_retained_item({"tenant_id": "demo", "proof_id": "proof-1", "created_at": "2000-01-01T00:00:00Z"}, "demo", cutoff))
        self.assertFalse(is_retained_item({"tenant_id": "demo", "item_type": "tenant_config", "created_at": "2000-01-01T00:00:00Z"}, "demo", cutoff))
        self.assertFalse(is_retained_item({"tenant_id": "other", "event_type": "action.evaluated", "created_at": "2000-01-01T00:00:00Z"}, "demo", cutoff))

    # --- Coverage: _string_list edge cases ---

    def test_environment_allowed_tools_string_input(self):
        """String allowed_tools is wrapped in list (line 45)."""
        env = build_environment_config("tenant-001", "staging", {"allowed_tools": "sql"})
        self.assertEqual(env["allowed_tools"], ["sql"])

    def test_environment_allowed_tools_non_list(self):
        """Non-list allowed_tools returns empty (line 47)."""
        env = build_environment_config("tenant-001", "staging", {"allowed_tools": 123})
        self.assertEqual(env["allowed_tools"], [])

    # --- Coverage: _validate_id ---

    def test_invalid_tenant_id_raises(self):
        """Invalid tenant_id raises ValueError (line 54)."""
        with self.assertRaises(ValueError):
            build_tenant_config("invalid tenant!")

    # --- Coverage: _positive_days ---

    def test_retention_days_non_integer_raises(self):
        """Non-integer retention_days raises ValueError (lines 61-62)."""
        with self.assertRaises(ValueError):
            build_tenant_config("tenant-001", {"retention_enabled": True, "retention_days": "not-a-number"})

    def test_retention_days_out_of_range_raises(self):
        """Out-of-range retention_days raises ValueError (line 64)."""
        with self.assertRaises(ValueError):
            build_tenant_config("tenant-001", {"retention_enabled": True, "retention_days": 9999})

    # --- Coverage: _region ---

    def test_invalid_region_pattern_raises(self):
        """Invalid region pattern raises ValueError (line 71)."""
        with self.assertRaises(ValueError):
            build_tenant_config("tenant-001", {"data_residency_region": "invalid region!"})

    # --- Coverage: _boolean ---

    def test_non_boolean_legal_hold_raises(self):
        """Non-boolean legal_hold_enabled raises ValueError (line 81)."""
        with self.assertRaises(ValueError):
            build_tenant_config("tenant-001", {"legal_hold_enabled": "yes"})

    # --- Coverage: build_environment_config validation ---

    def test_environment_bad_status_raises(self):
        """Invalid environment status raises ValueError (line 130)."""
        with self.assertRaises(ValueError):
            build_environment_config("tenant-001", "staging", {"status": "deleted"})

    def test_environment_bad_mode_raises(self):
        """Invalid environment mode raises ValueError (line 133)."""
        with self.assertRaises(ValueError):
            build_environment_config("tenant-001", "staging", {"mode": "disabled"})

    def test_environment_inherits_allowed_tools_from_existing(self):
        """allowed_tools inherited from existing when not in payload (line 136)."""
        existing = build_environment_config("tenant-001", "staging", {"allowed_tools": ["sql", "shell"]})
        updated = build_environment_config("tenant-001", "staging", {"name": "Updated"}, existing)
        self.assertEqual(updated["allowed_tools"], ["shell", "sql"])

    # --- Coverage: build_tenant_config validation ---

    def test_tenant_bad_status_raises(self):
        """Invalid tenant status raises ValueError (line 158)."""
        with self.assertRaises(ValueError):
            build_tenant_config("tenant-001", {"status": "deleted"})

    def test_tenant_non_list_environments_raises(self):
        """Non-list environments raises ValueError (line 171)."""
        with self.assertRaises(ValueError):
            build_tenant_config("tenant-001", {"environments": "not-a-list"})

    def test_tenant_duplicate_environment_raises(self):
        """Duplicate environment_id raises ValueError (line 177)."""
        with self.assertRaises(ValueError):
            build_tenant_config(
                "tenant-001",
                {"environments": [
                    {"environment_id": "production"},
                    {"environment_id": "production"},
                ]},
            )

    def test_tenant_bad_default_environment_raises(self):
        """default_environment not in environments raises ValueError (line 184)."""
        with self.assertRaises(ValueError):
            build_tenant_config(
                "tenant-001",
                {
                    "environments": [{"environment_id": "production"}],
                    "default_environment": "staging",
                },
            )

    def test_tenant_retention_enabled_without_days_raises(self):
        """retention_enabled without retention_days raises ValueError (line 194)."""
        with self.assertRaises(ValueError):
            build_tenant_config("tenant-001", {"retention_enabled": True})

    def test_tenant_long_legal_hold_reason_raises(self):
        """legal_hold_reason over 512 chars raises ValueError (line 206)."""
        with self.assertRaises(ValueError):
            build_tenant_config("tenant-001", {"legal_hold_reason": "x" * 513})

    # --- Coverage: environment_for ---

    def test_environment_for_returns_none_when_not_found(self):
        """environment_for returns None for missing environment (line 267)."""
        config = default_tenant_config("demo")
        self.assertIsNone(environment_for(config, "nonexistent"))

    # --- Coverage: runtime_constraints suspended tenant ---

    def test_runtime_constraints_suspended_tenant(self):
        """Suspended tenant adds TENANT_SUSPENDED reason (line 285)."""
        config = build_tenant_config("tenant-001", {"status": "suspended"})
        constraints = runtime_constraints(config, "development")
        codes = {reason["code"] for reason in constraints["reasons"]}
        self.assertIn("TENANT_SUSPENDED", codes)

    # --- Coverage: retention_cutoff ---

    def test_retention_cutoff_returns_none_when_disabled(self):
        """retention_cutoff returns None when retention disabled (line 285)."""
        config = default_tenant_config("demo")
        self.assertIsNone(retention_cutoff(config))

    # --- Coverage: iso_from_epoch ---

    def test_iso_from_epoch(self):
        """iso_from_epoch converts epoch to ISO string (line 302)."""
        result = iso_from_epoch(0)
        self.assertEqual(result, "1970-01-01T00:00:00Z")

    # --- Coverage: is_retained_item edge cases ---

    def test_is_retained_item_no_identifiers(self):
        """Item without event_type/proof_id/approval_id returns False (line 299)."""
        self.assertFalse(is_retained_item({"tenant_id": "demo", "created_at": "2000-01-01T00:00:00Z"}, "demo", 2_000_000_000))

    def test_is_retained_item_no_created_at(self):
        """Item without created_at returns False (line 302)."""
        self.assertFalse(is_retained_item({"tenant_id": "demo", "event_type": "action.evaluated"}, "demo", 2_000_000_000))

    def test_is_retained_item_invalid_date(self):
        """Item with invalid created_at returns False (lines 305-306)."""
        self.assertFalse(is_retained_item({"tenant_id": "demo", "event_type": "action.evaluated", "created_at": "not-a-date"}, "demo", 2_000_000_000))

    def test_is_retained_item_with_approval_id(self):
        """Item with approval_id is a retention candidate."""
        self.assertTrue(is_retained_item({"tenant_id": "demo", "approval_id": "approval-1", "created_at": "2000-01-01T00:00:00Z"}, "demo", 2_000_000_000))


if __name__ == "__main__":
    unittest.main()
