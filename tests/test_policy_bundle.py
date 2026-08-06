import unittest

from app.policy_bundle import build_policy_bundle, is_current_bundle


class PolicyBundleTests(unittest.TestCase):
    def test_bundle_is_deterministic_and_excludes_unpublished_or_other_tenant_policies(self):
        config = {"config_version": 4, "policy_bundle_revision": 2}
        policies = [
            {
                "tenant_id": "demo",
                "policy_id": "z-policy",
                "version": 1,
                "status": "published",
                "mode": "enforce",
                "rules": [{"rule_id": "z", "decision": "warn"}],
                "test_cases": [{"secret": "must not ship"}],
            },
            {
                "tenant_id": "demo",
                "policy_id": "draft-policy",
                "version": 3,
                "status": "draft",
                "rules": [{"rule_id": "draft", "decision": "deny"}],
            },
            {
                "tenant_id": "other",
                "policy_id": "other-policy",
                "version": 1,
                "status": "published",
                "rules": [{"rule_id": "other", "decision": "deny"}],
            },
        ]

        first = build_policy_bundle("demo", config, policies)
        second = build_policy_bundle("demo", config, list(reversed(policies)))

        self.assertEqual(first["bundle_id"], second["bundle_id"])
        self.assertEqual(first["bundle_hash"], second["bundle_hash"])
        self.assertEqual([item["policy_id"] for item in first["policies"]], ["z-policy"])
        self.assertNotIn("test_cases", first["policies"][0])

    def test_current_bundle_requires_matching_tenant_and_revisions(self):
        bundle = build_policy_bundle(
            "demo",
            {"config_version": 4, "policy_bundle_revision": 2},
            [],
        )

        self.assertTrue(is_current_bundle(bundle, "demo", {"config_version": 4, "policy_bundle_revision": 2}))
        self.assertFalse(is_current_bundle(bundle, "other", {"config_version": 4, "policy_bundle_revision": 2}))
        self.assertFalse(is_current_bundle(bundle, "demo", {"config_version": 5, "policy_bundle_revision": 2}))
        self.assertFalse(is_current_bundle(bundle, "demo", {"config_version": 4, "policy_bundle_revision": 3}))

    def test_published_bundle_rejects_malformed_rules(self):
        with self.assertRaisesRegex(ValueError, "rules must be an array"):
            build_policy_bundle(
                "demo",
                {"config_version": 1, "policy_bundle_revision": 0},
                [
                    {
                        "tenant_id": "demo",
                        "policy_id": "bad-policy",
                        "version": 1,
                        "status": "published",
                        "rules": ["not-a-rule-object"],
                    }
                ],
            )

    def test_malformed_bundle_is_not_current(self):
        self.assertFalse(is_current_bundle({}, "demo", {"config_version": 1, "policy_bundle_revision": 0}))
        self.assertFalse(is_current_bundle(None, "demo", {"config_version": 1, "policy_bundle_revision": 0}))


if __name__ == "__main__":
    unittest.main()
