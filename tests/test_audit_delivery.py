import os
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from app.audit_delivery import _secret_token, deliver_event, normalise_sink, validate_secret_arn


DEPLOYMENT_ENVIRONMENT = str(os.environ.get("KENNING_ENV") or os.environ.get("KENNING_ENVIRONMENT") or "prototype").strip()


class FakeResponse:
    status = 202

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class FakeSecrets:
    def get_secret_value(self, SecretId):
        self.secret_id = SecretId
        return {"SecretString": '{"token":"sink-secret"}'}


class AuditDeliveryTests(unittest.TestCase):
    def test_sink_configuration_requires_https_and_secret_reference(self):
        self.assertFalse(normalise_sink({"enabled": False})["enabled"])
        with self.assertRaises(ValueError):
            normalise_sink({"enabled": True, "endpoint_url": "http://example.test/hook", "secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:test"})
        with self.assertRaises(ValueError):
            normalise_sink({"enabled": True, "endpoint_url": "https://example.test/hook", "bearer_token": "raw-secret", "secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:test"})

    def test_sink_secret_must_be_tenant_owned_when_tenant_is_known(self):
        sink = normalise_sink({
            "enabled": True,
            "endpoint_url": "https://example.test/hook",
            "secret_arn": f"arn:aws:secretsmanager:us-east-1:123456789012:secret:kenning/audit-sinks/{DEPLOYMENT_ENVIRONMENT}/demo/sink-token",
        }, tenant_id="demo")
        self.assertEqual(
            sink["secret_arn"],
            f"arn:aws:secretsmanager:us-east-1:123456789012:secret:kenning/audit-sinks/{DEPLOYMENT_ENVIRONMENT}/demo/sink-token",
        )
        with self.assertRaises(ValueError):
            normalise_sink({
                "enabled": True,
                "endpoint_url": "https://example.test/hook",
                "secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:other-tenant-prod-oauth",
            }, tenant_id="demo")

    def test_delivery_uses_secret_manager_and_records_success(self):
        sink = normalise_sink({
            "enabled": True,
            "endpoint_url": "https://example.test/hook",
            "format": "ndjson",
            "secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:test",
        })
        captured = {}

        def opener(request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return FakeResponse()

        result = deliver_event({"event_type": "action.evaluated", "tenant_id": "demo"}, sink, FakeSecrets(), opener)
        self.assertEqual(result["status"], "delivered")
        self.assertEqual(result["http_status"], 202)
        self.assertEqual(captured["timeout"], 1.0)
        self.assertEqual(captured["request"].get_header("Authorization"), "Bearer sink-secret")
        self.assertEqual(captured["request"].get_header("Content-type"), "application/x-ndjson")

    def test_delivery_failure_is_non_blocking_and_redacted(self):
        sink = normalise_sink({
            "enabled": True,
            "endpoint_url": "https://example.test/hook",
            "secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:test",
        })
        result = deliver_event({"event_type": "action.evaluated"}, sink, None, lambda *_args, **_kwargs: FakeResponse())
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_code"], "RuntimeError")
        self.assertNotIn("secret", str(result).lower())

    # --- validate_secret_arn edge cases ---

    def test_validate_secret_arn_rejects_non_arn(self):
        with self.assertRaises(ValueError):
            validate_secret_arn("not-an-arn")

    def test_validate_secret_arn_rejects_empty(self):
        with self.assertRaises(ValueError):
            validate_secret_arn("")

    def test_validate_secret_arn_rejects_wrong_region(self):
        with patch.dict(os.environ, {"AWS_REGION": "eu-west-1"}, clear=False):
            with self.assertRaises(ValueError):
                validate_secret_arn("arn:aws:secretsmanager:us-east-1:123456789012:secret:test")

    def test_validate_secret_arn_rejects_wrong_account(self):
        with patch.dict(os.environ, {"AWS_ACCOUNT_ID": "999999999999"}, clear=False):
            with self.assertRaises(ValueError):
                validate_secret_arn("arn:aws:secretsmanager:us-east-1:123456789012:secret:test")

    # --- normalise_sink edge cases ---

    def test_normalise_sink_rejects_non_dict_payload(self):
        with self.assertRaises(ValueError):
            normalise_sink("not-a-dict")

    def test_normalise_sink_uses_existing_when_payload_is_none(self):
        result = normalise_sink(None, existing={"enabled": False})
        self.assertFalse(result["enabled"])

    def test_normalise_sink_none_payload_non_dict_existing(self):
        result = normalise_sink(None, existing="not-a-dict")
        self.assertFalse(result["enabled"])

    def test_normalise_sink_rejects_embedded_credentials(self):
        with self.assertRaises(ValueError):
            normalise_sink({
                "enabled": True,
                "endpoint_url": "https://user:pass@example.test/hook",
                "secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:test",
            })

    def test_normalise_sink_rejects_invalid_format(self):
        with self.assertRaises(ValueError):
            normalise_sink({
                "enabled": True,
                "endpoint_url": "https://example.test/hook",
                "format": "xml",
                "secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:test",
            })

    def test_normalise_sink_rejects_non_integer_timeout(self):
        with self.assertRaises(ValueError):
            normalise_sink({
                "enabled": True,
                "endpoint_url": "https://example.test/hook",
                "timeout_ms": "abc",
                "secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:test",
            })

    def test_normalise_sink_rejects_out_of_range_timeout(self):
        with self.assertRaises(ValueError):
            normalise_sink({
                "enabled": True,
                "endpoint_url": "https://example.test/hook",
                "timeout_ms": 100,
                "secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:test",
            })

    def test_normalise_sink_requires_secret_arn_when_enabled(self):
        with self.assertRaises(ValueError):
            normalise_sink({"enabled": True, "endpoint_url": "https://example.test/hook"})

    # --- _secret_token edge cases ---

    def test_secret_token_reads_binary_bytes(self):
        class BinarySecrets:
            def get_secret_value(self, SecretId):
                return {"SecretBinary": b'{"token":"binary-token"}'}

        self.assertEqual(_secret_token(BinarySecrets(), "arn:test"), "binary-token")

    def test_secret_token_reads_binary_non_bytes(self):
        class BinaryStrSecrets:
            def get_secret_value(self, SecretId):
                return {"SecretBinary": '{"token":"str-binary-token"}'}

        self.assertEqual(_secret_token(BinaryStrSecrets(), "arn:test"), "str-binary-token")

    def test_secret_token_rejects_empty_secret(self):
        class EmptySecrets:
            def get_secret_value(self, SecretId):
                return {"SecretString": ""}

        with self.assertRaises(RuntimeError):
            _secret_token(EmptySecrets(), "arn:test")

    def test_secret_token_accepts_raw_non_json_string(self):
        class RawSecrets:
            def get_secret_value(self, SecretId):
                return {"SecretString": "plain-token-value"}

        self.assertEqual(_secret_token(RawSecrets(), "arn:test"), "plain-token-value")

    def test_secret_token_rejects_dict_without_token_keys(self):
        class NoTokenSecrets:
            def get_secret_value(self, SecretId):
                return {"SecretString": '{"other":"data"}'}

        with self.assertRaises(RuntimeError):
            _secret_token(NoTokenSecrets(), "arn:test")

    # --- deliver_event edge cases ---

    def test_deliver_event_disabled_sink(self):
        result = deliver_event({"event_type": "test"}, {"enabled": False})
        self.assertEqual(result["status"], "disabled")
        self.assertFalse(result["delivered"])

    def test_deliver_event_none_sink(self):
        result = deliver_event({"event_type": "test"}, None)
        self.assertEqual(result["status"], "disabled")
        self.assertFalse(result["delivered"])

    def test_deliver_event_http_error(self):
        sink = {"enabled": True, "endpoint_url": "https://example.test/hook", "secret_arn": "arn:test", "format": "json", "timeout_ms": 1000}

        class TokenSecrets:
            def get_secret_value(self, SecretId):
                return {"SecretString": "token"}

        def opener(request, timeout):
            raise HTTPError("https://example.test/hook", 403, "Forbidden", {}, None)

        result = deliver_event({"event_type": "test"}, sink, TokenSecrets(), opener)
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["http_status"], 403)
        self.assertFalse(result["delivered"])

    def test_deliver_event_url_error(self):
        sink = {"enabled": True, "endpoint_url": "https://example.test/hook", "secret_arn": "arn:test", "format": "json", "timeout_ms": 1000}

        class TokenSecrets:
            def get_secret_value(self, SecretId):
                return {"SecretString": "token"}

        def opener(request, timeout):
            raise URLError("connection refused")

        result = deliver_event({"event_type": "test"}, sink, TokenSecrets(), opener)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_code"], "URLError")

    def test_deliver_event_timeout_error(self):
        sink = {"enabled": True, "endpoint_url": "https://example.test/hook", "secret_arn": "arn:test", "format": "json", "timeout_ms": 1000}

        class TokenSecrets:
            def get_secret_value(self, SecretId):
                return {"SecretString": "token"}

        def opener(request, timeout):
            raise TimeoutError("timed out")

        result = deliver_event({"event_type": "test"}, sink, TokenSecrets(), opener)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_code"], "TimeoutError")

    def test_deliver_event_generic_exception(self):
        sink = {"enabled": True, "endpoint_url": "https://example.test/hook", "secret_arn": "arn:test", "format": "json", "timeout_ms": 1000}

        class TokenSecrets:
            def get_secret_value(self, SecretId):
                return {"SecretString": "token"}

        def opener(request, timeout):
            raise Exception("unexpected provider error")

        result = deliver_event({"event_type": "test"}, sink, TokenSecrets(), opener)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_code"], "Exception")

    def test_deliver_event_non_2xx_status(self):
        sink = {"enabled": True, "endpoint_url": "https://example.test/hook", "secret_arn": "arn:test", "format": "json", "timeout_ms": 1000}

        class TokenSecrets:
            def get_secret_value(self, SecretId):
                return {"SecretString": "token"}

        class ServerErrorResponse:
            status = 500

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        result = deliver_event({"event_type": "test"}, sink, TokenSecrets(), lambda req, timeout: ServerErrorResponse())
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["http_status"], 500)
        self.assertFalse(result["delivered"])

    def test_deliver_event_uses_getcode_fallback(self):
        sink = {"enabled": True, "endpoint_url": "https://example.test/hook", "secret_arn": "arn:test", "format": "json", "timeout_ms": 1000}

        class TokenSecrets:
            def get_secret_value(self, SecretId):
                return {"SecretString": "token"}

        class GetcodeResponse:
            status = None

            def getcode(self):
                return 201

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        result = deliver_event({"event_type": "test"}, sink, TokenSecrets(), lambda req, timeout: GetcodeResponse())
        self.assertEqual(result["status"], "delivered")
        self.assertEqual(result["http_status"], 201)

    def test_deliver_event_json_format_content_type(self):
        sink = {"enabled": True, "endpoint_url": "https://example.test/hook", "secret_arn": "arn:test", "format": "json", "timeout_ms": 1000}

        class TokenSecrets:
            def get_secret_value(self, SecretId):
                return {"SecretString": "token"}

        captured = {}

        def opener(request, timeout):
            captured["content_type"] = request.get_header("Content-type")
            return FakeResponse()

        result = deliver_event({"event_type": "test"}, sink, TokenSecrets(), opener)
        self.assertEqual(result["status"], "delivered")
        self.assertEqual(captured["content_type"], "application/json")


if __name__ == "__main__":
    unittest.main()
