import unittest

from scripts.invoke_pat import pat_request


class InvokeCredentialTests(unittest.TestCase):
    def test_pat_request_accepts_product_pat(self):
        request = pat_request("https://example.test", "GET", b"", "kta_pat_example")
        self.assertEqual(request.get_header("Authorization"), "Bearer kta_pat_example")

    def test_pat_request_accepts_agent_credential(self):
        request = pat_request("https://example.test", "GET", b"", "kta_agent_example")
        self.assertEqual(request.get_header("Authorization"), "Bearer kta_agent_example")

    def test_pat_request_rejects_other_bearer_values(self):
        with self.assertRaises(ValueError):
            pat_request("https://example.test", "GET", b"", "opaque-token")


if __name__ == "__main__":
    unittest.main()
