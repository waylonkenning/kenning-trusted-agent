import unittest

from app.aws_adapter import (
    AWS_DESTRUCTIVE_OPERATIONS,
    AWS_MUTATING_PREFIXES,
    AWS_PRIVILEGED_OPERATIONS,
    aws_operation,
    is_mutating_operation,
    normalise_aws_action,
)


class AwsAdapterTests(unittest.TestCase):
    def test_non_aws_provider_is_left_unchanged(self):
        action = {"tool": "shell", "parameters": {"command": "ls"}}
        self.assertEqual(normalise_aws_action(action), action)
        self.assertNotIn("adapter", normalise_aws_action(action))

    def test_aws_tool_defaults_provider_to_aws(self):
        enriched = normalise_aws_action({"tool": "aws", "parameters": {"service": "ec2"}})
        self.assertEqual(enriched["adapter"], "aws")
        self.assertEqual(enriched["adapter_context"]["provider"], "aws")

    def test_explicit_provider_is_required_to_enrich(self):
        enriched = normalise_aws_action(
            {"tool": "cloud", "parameters": {"provider": "aws", "service": "s3"}}
        )
        self.assertEqual(enriched["adapter"], "aws")
        not_aws = normalise_aws_action(
            {"tool": "cloud", "parameters": {"provider": "gcp", "service": "storage"}}
        )
        self.assertNotIn("adapter", not_aws)

    def test_service_and_operation_are_parsed_from_parameters(self):
        enriched = normalise_aws_action(
            {
                "tool": "aws",
                "parameters": {
                    "service": "S3",
                    "api_operation": "DeleteBucket",
                    "region": "us-east-1",
                    "resource": "arn:aws:s3:::reports",
                    "requested_scope": ["reports"],
                },
            }
        )
        context = enriched["adapter_context"]
        self.assertEqual(context["service"], "s3")
        self.assertEqual(context["api_operation"], "DeleteBucket")
        self.assertEqual(context["region"], "us-east-1")
        self.assertEqual(context["resource"], "arn:aws:s3:::reports")
        self.assertEqual(context["requested_scope"], ["reports"])

    def test_service_is_split_from_a_colon_operation(self):
        enriched = normalise_aws_action(
            {"tool": "aws", "operation": "ec2:TerminateInstances", "parameters": {}}
        )
        context = enriched["adapter_context"]
        self.assertEqual(context["service"], "ec2")
        self.assertEqual(context["api_operation"], "TerminateInstances")

    def test_service_name_alias_and_api_action_alias_are_supported(self):
        enriched = normalise_aws_action(
            {"tool": "aws", "parameters": {"service_name": "iam", "api_action": "CreateAccessKey"}}
        )
        context = enriched["adapter_context"]
        self.assertEqual(context["service"], "iam")
        self.assertEqual(context["api_operation"], "CreateAccessKey")

    def test_resource_falls_back_to_action_target_and_scope_to_resources(self):
        enriched = normalise_aws_action(
            {
                "tool": "aws",
                "target": "i-123",
                "parameters": {"service": "ec2", "api_operation": "TerminateInstances", "resources": ["i-123"]},
            }
        )
        context = enriched["adapter_context"]
        self.assertEqual(context["resource"], "i-123")
        self.assertEqual(context["requested_scope"], ["i-123"])

    def test_aws_operation_is_lowercased_service_and_operation(self):
        enriched = normalise_aws_action(
            {"tool": "aws", "parameters": {"service": "RDS", "api_operation": "DeleteDBInstance"}}
        )
        self.assertEqual(aws_operation(enriched), "rds:deletedbinstance")
        self.assertEqual(aws_operation({"tool": "aws"}), "")
        self.assertEqual(aws_operation({}), "")

    def test_is_mutating_operation_uses_prefix_matching(self):
        mutating = normalise_aws_action(
            {"tool": "aws", "parameters": {"service": "s3", "api_operation": "DeleteBucket"}}
        )
        read_only = normalise_aws_action(
            {"tool": "aws", "parameters": {"service": "s3", "api_operation": "ListBuckets"}}
        )
        self.assertTrue(is_mutating_operation(mutating))
        self.assertFalse(is_mutating_operation(read_only))
        self.assertFalse(is_mutating_operation({}))

    def test_destructive_and_privileged_sets_are_lowercased_and_known(self):
        self.assertIn("s3:deletebucket", AWS_DESTRUCTIVE_OPERATIONS)
        self.assertIn("ec2:terminateinstances", AWS_DESTRUCTIVE_OPERATIONS)
        self.assertIn("iam:createaccesskey", AWS_PRIVILEGED_OPERATIONS)
        self.assertIn("secretsmanager:putsecretvalue", AWS_PRIVILEGED_OPERATIONS)
        for operation in AWS_DESTRUCTIVE_OPERATIONS | AWS_PRIVILEGED_OPERATIONS:
            self.assertEqual(operation, operation.lower())
        for prefix in AWS_MUTATING_PREFIXES:
            self.assertTrue(prefix.islower())


if __name__ == "__main__":
    unittest.main()
