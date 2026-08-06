import unittest

from app.workload_identity import (
    aws_iam_context,
    map_aws_iam_principal,
    normalise_workload_identity,
)


class WorkloadIdentityTests(unittest.TestCase):
    @staticmethod
    def config():
        return {
            "enabled": True,
            "provider": "aws_iam",
            "allowed_account_ids": ["123456789012"],
            "mappings": [
                {
                    "principal_arn": "arn:aws:iam::123456789012:role/procurement-*",
                    "agent_id": "procurement-agent",
                    "scopes": ["audit:read", "guard:evaluate"],
                    "groups": ["procurement"],
                    "maximum_authority": "standard",
                }
            ],
        }

    def test_role_mapping_is_bounded_and_records_verified_principal(self):
        record = map_aws_iam_principal(
            {
                "principal_arn": "arn:aws:iam::123456789012:role/procurement-prod",
                "account_id": "123456789012",
                "caller_id": "AIDAEXAMPLE",
            },
            "demo",
            self.config(),
        )
        self.assertEqual(record["auth_source"], "aws_iam")
        self.assertEqual(record["token_type"], "workload")
        self.assertEqual(record["tenant_id"], "demo")
        self.assertEqual(record["agent_id"], "procurement-agent")
        self.assertEqual(record["scopes"], ["audit:read", "guard:evaluate"])
        self.assertEqual(record["maximum_authority"], "standard")
        self.assertEqual(record["invoked_by"], "arn:aws:iam::123456789012:role/procurement-prod")

    def test_assumed_role_session_is_canonicalised_before_mapping(self):
        record = map_aws_iam_principal(
            {"principal_arn": "arn:aws:sts::123456789012:assumed-role/procurement-prod/session-42"},
            "demo",
            {
                **self.config(),
                "mappings": [{**self.config()["mappings"][0], "principal_arn": "arn:aws:iam::123456789012:role/procurement-prod"}],
            },
        )
        self.assertEqual(record["workload_identity"]["principal_arn"], "arn:aws:iam::123456789012:role/procurement-prod")
        self.assertEqual(record["workload_identity"]["source_principal_arn"], "arn:aws:sts::123456789012:assumed-role/procurement-prod/session-42")

    def test_context_extracts_api_gateway_iam_authorizer(self):
        context = aws_iam_context(
            {
                "requestContext": {
                    "authorizer": {
                        "iam": {
                            "userArn": "arn:aws:iam::123456789012:role/procurement-prod",
                            "accountId": "123456789012",
                            "callerId": "AIDAEXAMPLE",
                        }
                    }
                }
            }
        )
        self.assertEqual(context["principal_arn"], "arn:aws:iam::123456789012:role/procurement-prod")
        self.assertEqual(context["account_id"], "123456789012")

    def test_invalid_or_ambiguous_principals_fail_closed(self):
        with self.assertRaises(ValueError):
            map_aws_iam_principal({"principal_arn": "arn:aws:iam::999999999999:role/other"}, "demo", self.config())
        with self.assertRaises(ValueError):
            map_aws_iam_principal({"principal_arn": "arn:aws:iam::123456789012:user/user"}, "demo", self.config())
        with self.assertRaises(ValueError):
            normalise_workload_identity(
                {
                    **self.config(),
                    "mappings": [{**self.config()["mappings"][0], "scopes": ["token:admin"]}],
                }
            )

        ambiguous = {
            **self.config(),
            "mappings": [
                self.config()["mappings"][0],
                {**self.config()["mappings"][0], "principal_arn": "arn:aws:iam::123456789012:role/procurement-*"},
            ],
        }
        with self.assertRaises(ValueError):
            map_aws_iam_principal({"principal_arn": "arn:aws:iam::123456789012:role/procurement-prod"}, "demo", ambiguous)

    # --- _string_list validation edge cases ---

    def test_string_list_rejects_non_list(self):
        with self.assertRaises(ValueError):
            normalise_workload_identity({**self.config(), "allowed_account_ids": 12345})

    def test_string_list_rejects_too_many_values(self):
        with self.assertRaises(ValueError):
            normalise_workload_identity({**self.config(), "allowed_account_ids": [f"{i:012d}" for i in range(51)]})

    def test_string_list_rejects_duplicates(self):
        with self.assertRaises(ValueError):
            normalise_workload_identity({**self.config(), "allowed_account_ids": ["123456789012", "123456789012"]})

    # --- _normalise_principal_pattern edge cases ---

    def test_principal_pattern_rejects_empty(self):
        with self.assertRaises(ValueError):
            normalise_workload_identity({
                **self.config(),
                "mappings": [{"principal_arn": "", "agent_id": "test", "scopes": ["guard:evaluate"]}],
            })

    def test_principal_pattern_rejects_whitespace(self):
        with self.assertRaises(ValueError):
            normalise_workload_identity({
                **self.config(),
                "mappings": [{"principal_arn": "arn:aws:iam::123456789012:role/bad role", "agent_id": "test", "scopes": ["guard:evaluate"]}],
            })

    def test_principal_pattern_rejects_non_role_arn(self):
        with self.assertRaises(ValueError):
            normalise_workload_identity({
                **self.config(),
                "mappings": [{"principal_arn": "arn:aws:iam::123456789012:user/test", "agent_id": "test", "scopes": ["guard:evaluate"]}],
            })

    # --- _normalise_mapping edge cases ---

    def test_mapping_rejects_non_dict(self):
        with self.assertRaises(ValueError):
            normalise_workload_identity({**self.config(), "mappings": ["not-a-dict"]})

    def test_mapping_rejects_invalid_agent_id(self):
        with self.assertRaises(ValueError):
            normalise_workload_identity({
                **self.config(),
                "mappings": [{"principal_arn": "arn:aws:iam::123456789012:role/test", "agent_id": "", "scopes": ["guard:evaluate"]}],
            })

    def test_mapping_rejects_empty_scopes(self):
        with self.assertRaises(ValueError):
            normalise_workload_identity({
                **self.config(),
                "mappings": [{"principal_arn": "arn:aws:iam::123456789012:role/test", "agent_id": "test", "scopes": []}],
            })

    def test_mapping_rejects_long_group(self):
        with self.assertRaises(ValueError):
            normalise_workload_identity({
                **self.config(),
                "mappings": [{**self.config()["mappings"][0], "groups": ["x" * 129]}],
            })

    def test_mapping_rejects_invalid_authority(self):
        with self.assertRaises(ValueError):
            normalise_workload_identity({
                **self.config(),
                "mappings": [{**self.config()["mappings"][0], "maximum_authority": "superuser"}],
            })

    def test_mapping_accepts_string_scope(self):
        result = normalise_workload_identity({
            **self.config(),
            "mappings": [{**self.config()["mappings"][0], "scopes": "guard:evaluate"}],
        })
        self.assertEqual(result["mappings"][0]["scopes"], ["guard:evaluate"])

    # --- normalise_workload_identity edge cases ---

    def test_normalise_rejects_non_dict(self):
        with self.assertRaises(ValueError):
            normalise_workload_identity("not-a-dict")

    def test_normalise_rejects_non_bool_enabled(self):
        with self.assertRaises(ValueError):
            normalise_workload_identity({"enabled": "yes"})

    def test_normalise_rejects_wrong_provider(self):
        with self.assertRaises(ValueError):
            normalise_workload_identity({"enabled": True, "provider": "gcp"})

    def test_normalise_rejects_invalid_account_ids(self):
        with self.assertRaises(ValueError):
            normalise_workload_identity({**self.config(), "allowed_account_ids": ["12345"]})

    def test_normalise_rejects_empty_mappings(self):
        with self.assertRaises(ValueError):
            normalise_workload_identity({**self.config(), "mappings": []})

    def test_normalise_rejects_non_list_mappings(self):
        with self.assertRaises(ValueError):
            normalise_workload_identity({**self.config(), "mappings": "not-a-list"})

    def test_normalise_rejects_duplicate_patterns(self):
        mapping = self.config()["mappings"][0]
        with self.assertRaises(ValueError):
            normalise_workload_identity({**self.config(), "mappings": [mapping, dict(mapping)]})

    def test_normalise_disabled_returns_defaults(self):
        result = normalise_workload_identity({"enabled": False})
        self.assertFalse(result["enabled"])
        self.assertEqual(result["mappings"], [])
        self.assertEqual(result["allowed_account_ids"], [])

    def test_normalise_uses_existing_when_value_is_none(self):
        result = normalise_workload_identity(None, existing={"enabled": False})
        self.assertFalse(result["enabled"])

    def test_normalise_none_value_non_dict_existing(self):
        result = normalise_workload_identity(None, existing="not-a-dict")
        self.assertFalse(result["enabled"])

    def test_mapping_account_must_be_in_allowed_ids(self):
        with self.assertRaises(ValueError):
            normalise_workload_identity({
                **self.config(),
                "allowed_account_ids": ["999999999999"],
            })

    # --- aws_iam_context edge cases ---

    def test_context_extracts_aws_iam_alternate_key(self):
        context = aws_iam_context({
            "requestContext": {
                "authorizer": {
                    "aws_iam": {
                        "userArn": "arn:aws:iam::123456789012:role/test",
                        "accountId": "123456789012",
                    }
                }
            }
        })
        self.assertEqual(context["principal_arn"], "arn:aws:iam::123456789012:role/test")

    def test_context_extracts_identity_fallback(self):
        context = aws_iam_context({
            "requestContext": {
                "identity": {
                    "userArn": "arn:aws:iam::123456789012:role/test",
                    "accountId": "123456789012",
                }
            }
        })
        self.assertEqual(context["principal_arn"], "arn:aws:iam::123456789012:role/test")

    def test_context_returns_none_without_iam(self):
        self.assertIsNone(aws_iam_context({"requestContext": {}}))
        self.assertIsNone(aws_iam_context({}))

    # --- map_aws_iam_principal edge cases ---

    def test_map_rejects_disabled_config(self):
        with self.assertRaises(ValueError):
            map_aws_iam_principal({"principal_arn": "arn:aws:iam::123456789012:role/test"}, "demo", {"enabled": False})

    def test_map_rejects_unmapped_role_in_allowed_account(self):
        with self.assertRaises(ValueError):
            map_aws_iam_principal({"principal_arn": "arn:aws:iam::123456789012:role/unmapped-role"}, "demo", self.config())

    def test_map_rejects_multiple_matching_patterns(self):
        config = {
            **self.config(),
            "mappings": [
                {**self.config()["mappings"][0], "principal_arn": "arn:aws:iam::123456789012:role/procurement-*"},
                {**self.config()["mappings"][0], "principal_arn": "arn:aws:iam::123456789012:role/*-prod", "agent_id": "other-agent"},
            ],
        }
        with self.assertRaises(ValueError):
            map_aws_iam_principal({"principal_arn": "arn:aws:iam::123456789012:role/procurement-prod"}, "demo", config)

    def test_map_uses_role_arn_field(self):
        record = map_aws_iam_principal(
            {"role_arn": "arn:aws:iam::123456789012:role/procurement-prod", "principal_arn": ""},
            "demo",
            {
                **self.config(),
                "mappings": [{**self.config()["mappings"][0], "principal_arn": "arn:aws:iam::123456789012:role/procurement-prod"}],
            },
        )
        self.assertEqual(record["agent_id"], "procurement-agent")


if __name__ == "__main__":
    unittest.main()
