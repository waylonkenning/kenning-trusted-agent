import unittest

from app.integration_adapters import (
    GITHUB_DESTRUCTIVE_OPERATIONS,
    GITHUB_PRIVILEGED_OPERATIONS,
    normalise_integration_action,
)


class IntegrationAdapterTests(unittest.TestCase):
    def test_non_integration_tool_is_left_unchanged(self):
        action = {"tool": "sql", "parameters": {"statement": "SELECT 1"}}
        self.assertEqual(normalise_integration_action(action), action)
        self.assertNotIn("adapter", normalise_integration_action(action))

    def test_github_action_is_enriched_with_repository_and_branch(self):
        enriched = normalise_integration_action(
            {
                "tool": "github",
                "operation": "Merge_Pull_Request",
                "parameters": {"repository": "kenning/trusted-agent", "base_branch": "main", "requested_scope": ["pull/42"]},
            }
        )
        self.assertEqual(enriched["adapter"], "github")
        context = enriched["adapter_context"]
        self.assertEqual(context["provider"], "github")
        self.assertEqual(context["operation"], "merge_pull_request")
        self.assertEqual(context["repository"], "kenning/trusted-agent")
        self.assertEqual(context["branch"], "main")
        self.assertEqual(context["requested_scope"], ["pull/42"])

    def test_github_repository_and_scope_aliases_are_supported(self):
        enriched = normalise_integration_action(
            {"tool": "github", "operation": "delete_branch", "parameters": {"repo": "acme/api", "branch": "dev", "files": ["src/app.py"]}}
        )
        context = enriched["adapter_context"]
        self.assertEqual(context["repository"], "acme/api")
        self.assertEqual(context["branch"], "dev")
        self.assertEqual(context["requested_scope"], ["src/app.py"])

    def test_github_repository_falls_back_to_target(self):
        enriched = normalise_integration_action(
            {"tool": "github", "operation": "force_push", "target": "acme/web", "parameters": {}}
        )
        self.assertEqual(enriched["adapter_context"]["repository"], "acme/web")

    def test_email_action_counts_recipients_and_flags_external(self):
        enriched = normalise_integration_action(
            {
                "tool": "email",
                "operation": "bulk_send",
                "parameters": {"recipients": [f"person-{i}@example.org" for i in range(20)], "external_recipients": True},
            }
        )
        self.assertEqual(enriched["adapter"], "email")
        context = enriched["adapter_context"]
        self.assertEqual(context["provider"], "email")
        self.assertEqual(context["recipients_count"], 20)
        self.assertTrue(context["external_recipients"])
        self.assertEqual(len(context["requested_scope"]), 20)

    def test_email_string_recipient_is_normalised_to_a_list(self):
        enriched = normalise_integration_action(
            {"tool": "mail", "operation": "send", "parameters": {"to": "person@example.org"}}
        )
        self.assertEqual(enriched["adapter"], "email")
        self.assertEqual(enriched["adapter_context"]["recipients_count"], 1)
        self.assertEqual(enriched["adapter_context"]["requested_scope"], ["person@example.org"])

    def test_messaging_alias_and_missing_recipients_yield_zero_count(self):
        enriched = normalise_integration_action({"tool": "messaging", "operation": "send", "parameters": {}})
        self.assertEqual(enriched["adapter"], "email")
        self.assertEqual(enriched["adapter_context"]["recipients_count"], 0)
        self.assertFalse(enriched["adapter_context"]["external_recipients"])

    def test_github_destructive_and_privileged_sets_are_known(self):
        self.assertIn("delete_repository", GITHUB_DESTRUCTIVE_OPERATIONS)
        self.assertIn("force_push", GITHUB_DESTRUCTIVE_OPERATIONS)
        self.assertIn("change_branch_protection", GITHUB_PRIVILEGED_OPERATIONS)
        self.assertIn("modify_permissions", GITHUB_PRIVILEGED_OPERATIONS)


if __name__ == "__main__":
    unittest.main()
