import unittest

from app import lambda_function as service


class PaginatedAgentCredentialTable:
    """Simulate a delayed GSI with the credential beyond the first 5,000 items."""

    def __init__(self):
        self.query_calls = 0
        self.scan_calls = 0
        self.items = [
            {
                "token_hash": f"pat-{index}",
                "token_id": f"pat-{index}",
                "token_type": "pat",
                "agent_id": "other-agent",
                "tenant_id": "demo",
            }
            for index in range(5000)
        ]
        self.items.append(
            {
                "token_hash": "agent-credential-hash",
                "token_id": "cred-after-large-prefix",
                "credential_id": "cred-after-large-prefix",
                "token_type": "agent",
                "agent_id": "target-agent",
                "tenant_id": "demo",
                "scopes": ["guard:evaluate"],
                "status": "active",
            }
        )

    def query(self, **_kwargs):
        self.query_calls += 1
        return {"Items": []}

    def scan(self, **kwargs):
        self.scan_calls += 1
        start = int((kwargs.get("ExclusiveStartKey") or {}).get("offset", 0))
        limit = int(kwargs.get("Limit") or 100)
        end = min(start + limit, len(self.items))
        result = {"Items": self.items[start:end]}
        if end < len(self.items):
            result["LastEvaluatedKey"] = {"offset": end}
        return result


class AgentCredentialVisibilityTests(unittest.TestCase):
    def test_strong_fallback_scans_large_token_table(self):
        previous_table = service.token_table
        table = PaginatedAgentCredentialTable()
        service.token_table = table
        try:
            records = service.list_agent_credentials("target-agent", "demo")
        finally:
            service.token_table = previous_table

        self.assertEqual([record["credential_id"] for record in records], ["cred-after-large-prefix"])
        self.assertEqual(table.query_calls, 5)
        self.assertEqual(table.scan_calls, 6)


if __name__ == "__main__":
    unittest.main()
