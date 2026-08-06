"""Targeted tests for authentication branches in lambda_function.py (#271).

Covers: session_authentication, _oauth_client_secret, authenticate
early branches (IAM, PAT, malformed bearer).
"""

import hashlib
import time
import unittest
from unittest.mock import MagicMock, patch

from app import lambda_function as service
from tests.test_federation import FakeTable, FakeTokenTable


def make_event(method, path, body=None, query=None, headers=None):
    event = {
        "rawPath": path,
        "requestContext": {"http": {"method": method}},
        "headers": headers or {},
    }
    if body is not None:
        event["body"] = body
    if query:
        event["queryStringParameters"] = query
    return event


class SessionAuthTests(unittest.TestCase):
    def setUp(self):
        self.table = FakeTable()
        service.table = self.table
        self.token_table = FakeTokenTable()
        service.token_table = self.token_table

    def test_session_auth_no_token_table(self):
        """Line 637: missing token table returns (None, None)."""
        with patch.object(service, "token_table", None):
            auth, error = service.session_authentication(make_event("GET", "/v1/me"))
        self.assertIsNone(auth)
        self.assertIsNone(error)

    def test_session_auth_no_cookie(self):
        """Line 640: no session cookie returns (None, None)."""
        auth, error = service.session_authentication(make_event("GET", "/v1/me"))
        self.assertIsNone(auth)
        self.assertIsNone(error)

    def test_session_auth_expired_session(self):
        """Line 646: expired session returns auth error."""
        token = "kta_session_test123"
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        self.token_table.put_item(Item={
            "token_hash": token_hash,
            "token_type": "session",
            "status": "active",
            "expires_at": int(time.time()) - 100,
            "tenant_id": "demo",
            "subject": "user@example.com",
        })
        event = make_event("GET", "/v1/me", headers={"cookie": f"kta_session={token}"})
        auth, error = service.session_authentication(event)
        self.assertIsNone(auth)
        self.assertIsNotNone(error)

    def test_session_auth_inactivity_timeout(self):
        """Lines 657-658: inactivity timeout revokes session."""
        token = "kta_session_test123"
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        self.token_table.put_item(Item={
            "token_hash": token_hash,
            "token_type": "session",
            "status": "active",
            "expires_at": int(time.time()) + 3600,
            "last_activity_at": int(time.time()) - 100000,
            "tenant_id": "demo",
            "subject": "user@example.com",
        })
        event = make_event("GET", "/v1/me", headers={"cookie": f"kta_session={token}"})
        auth, error = service.session_authentication(event)
        self.assertIsNone(auth)
        self.assertIsNotNone(error)


class OAuthSecretTests(unittest.TestCase):
    def test_oauth_secret_no_client(self):
        """Line 721: missing secrets client raises RuntimeError."""
        with patch.object(service, "secrets_client", None):
            with self.assertRaises(RuntimeError):
                service._oauth_client_secret("arn:aws:secretsmanager:us-east-1:123:secret:test")

    def test_oauth_secret_json_dict(self):
        """Lines 730-732: JSON dict with client_secret key."""
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = {"SecretString": '{"client_secret": "s3cret"}'}
        with patch.object(service, "secrets_client", mock_client):
            result = service._oauth_client_secret("arn:test")
        self.assertEqual(result, "s3cret")

    def test_oauth_secret_invalid_json_dict(self):
        """Line 733: JSON dict without supported keys raises ValueError."""
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = {"SecretString": '{"unsupported": "value"}'}
        with patch.object(service, "secrets_client", mock_client):
            with self.assertRaises(ValueError):
                service._oauth_client_secret("arn:test")

    def test_oauth_secret_empty(self):
        """Line 737: empty secret raises ValueError."""
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = {}
        with patch.object(service, "secrets_client", mock_client):
            with self.assertRaises(ValueError):
                service._oauth_client_secret("arn:test")


class AuthenticateTests(unittest.TestCase):
    def setUp(self):
        self.table = FakeTable()
        service.table = self.table
        self.token_table = FakeTokenTable()
        service.token_table = self.token_table

    def test_authenticate_malformed_bearer(self):
        """Line 787: malformed bearer returns auth error."""
        event = make_event("GET", "/v1/me", headers={"authorization": "Basic abc123"})
        auth, error = service.authenticate(event)
        self.assertIsNone(auth)
        self.assertIsNotNone(error)

    def test_authenticate_pat_no_token_table(self):
        """Line 792: PAT with missing token table returns auth error."""
        event = make_event("GET", "/v1/me", headers={"authorization": "Bearer kta_pat_test123"})
        with patch.object(service, "token_table", None):
            auth, error = service.authenticate(event)
        self.assertIsNone(auth)
        self.assertIsNotNone(error)

    def test_authenticate_pat_expired(self):
        """Line 802: expired PAT returns auth error."""
        token = "kta_pat_test123"
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        self.token_table.put_item(Item={
            "token_hash": token_hash,
            "token_type": "pat",
            "status": "active",
            "expires_at": int(time.time()) - 100,
            "tenant_id": "demo",
            "subject": "user@example.com",
        })
        event = make_event("GET", "/v1/me", headers={"authorization": f"Bearer {token}"})
        auth, error = service.authenticate(event)
        self.assertIsNone(auth)
        self.assertIsNotNone(error)

    def test_authenticate_agent_missing_identity(self):
        """Line 807: agent credential without agent_id returns auth error."""
        token = "kta_agent_test123"
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        self.token_table.put_item(Item={
            "token_hash": token_hash,
            "token_type": "agent",
            "status": "active",
            "tenant_id": "demo",
        })
        event = make_event("GET", "/v1/me", headers={"authorization": f"Bearer {token}"})
        auth, error = service.authenticate(event)
        self.assertIsNone(auth)
        self.assertIsNotNone(error)

    def test_authenticate_iam_no_table(self):
        """Line 751: IAM context with missing table returns auth error."""
        event = make_event("GET", "/v1/me", headers={"x-kenning-tenant-id": "demo"})
        with patch.object(service, "table", None):
            with patch.object(service, "aws_iam_context", return_value={"account_id": "123", "role_name": "test"}):
                auth, error = service.authenticate(event)
        self.assertIsNone(auth)
        self.assertIsNotNone(error)

    def test_authenticate_iam_missing_tenant(self):
        """Line 761: IAM context without tenant hint returns auth error."""
        event = make_event("GET", "/v1/me")
        with patch.object(service, "aws_iam_context", return_value={"account_id": "123", "role_name": "test"}):
            auth, error = service.authenticate(event)
        self.assertIsNone(auth)
        self.assertIsNotNone(error)


if __name__ == "__main__":
    unittest.main()
