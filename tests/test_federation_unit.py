"""Direct unit tests for app/federation.py — every function, every branch."""

import base64
import hashlib
import io
import json
import time
import unittest
from unittest.mock import MagicMock, patch

from app import federation


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _make_jwt(header: dict, claims: dict, sig: bytes = b"signature") -> str:
    return f"{_b64url(json.dumps(header).encode())}.{_b64url(json.dumps(claims).encode())}.{_b64url(sig)}"


def _fake_opener(response_body: bytes, status: int = 200):
    """Return a callable that mimics urlopen and returns a context manager."""
    def opener(request, timeout=None):
        resp = MagicMock()
        resp.read = MagicMock(return_value=response_body)
        resp.status = status
        cm = MagicMock()
        cm.__enter__ = MagicMock(return_value=resp)
        cm.__exit__ = MagicMock(return_value=False)
        return cm
    return opener


# Minimal RSA key pair for signature tests (512-bit, test-only)
# Generated deterministically so tests are reproducible.
_RSA_N = int(
    "c9a0a4b8c4e2f1a3d5b7c9e0f2a4b6d8e0f1a3c5b7d9e1f3a5c7b9d1e3f5a7"
    "c9b1d3e5f7a9c1b3d5e7f9a1c3b5d7e9f1a3c5b7d9e1f3a5c7b9d1e3f5a709", 16
)
_RSA_E = 65537
_RSA_D = None  # We'll compute a valid signature differently


def _rsa_public_jwk(kid="test-key-1"):
    n_bytes = _RSA_N.to_bytes((_RSA_N.bit_length() + 7) // 8, "big")
    e_bytes = _RSA_E.to_bytes((_RSA_E.bit_length() + 7) // 8, "big")
    return {"kty": "RSA", "kid": kid, "n": _b64url(n_bytes), "e": _b64url(e_bytes), "use": "sig", "alg": "RS256"}


def _sign_rs256(signing_input: bytes, n: int, e: int, d: int) -> bytes:
    """Produce a PKCS#1 v1.5 RS256 signature."""
    size = (n.bit_length() + 7) // 8
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(signing_input).digest()
    padding_length = size - len(digest_info) - 3
    padded = b"\x00\x01" + b"\xff" * padding_length + b"\x00" + digest_info
    sig_int = pow(int.from_bytes(padded, "big"), d, n)
    return sig_int.to_bytes(size, "big")


def _generate_test_rsa():
    """Generate a small RSA key pair for testing (deterministic seed)."""
    import random
    rng = random.Random(42)

    def is_prime_miller_rabin(n, k=20):
        if n < 2:
            return False
        if n < 4:
            return True
        if n % 2 == 0:
            return False
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        for _ in range(k):
            a = rng.randrange(2, n - 1)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def gen_prime(bits):
        while True:
            candidate = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
            if is_prime_miller_rabin(candidate):
                return candidate

    p = gen_prime(256)
    q = gen_prime(256)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi)
    return n, e, d


_TEST_N, _TEST_E, _TEST_D = _generate_test_rsa()


def _test_jwk(kid="test-key-1"):
    n_bytes = _TEST_N.to_bytes((_TEST_N.bit_length() + 7) // 8, "big")
    e_bytes = _TEST_E.to_bytes((_TEST_E.bit_length() + 7) // 8, "big")
    return {"kty": "RSA", "kid": kid, "n": _b64url(n_bytes), "e": _b64url(e_bytes)}


def _signed_jwt(claims: dict, kid="test-key-1"):
    header = {"alg": "RS256", "kid": kid, "typ": "JWT"}
    signing_input = f"{_b64url(json.dumps(header).encode())}.{_b64url(json.dumps(claims).encode())}".encode("ascii")
    sig = _sign_rs256(signing_input, _TEST_N, _TEST_E, _TEST_D)
    return f"{signing_input.decode()}.{_b64url(sig)}"


NOW = int(time.time())

BASE_PROVIDER = {
    "enabled": True,
    "issuer_url": "https://issuer.example.org",
    "jwks_url": None,
    "audience": ["kenning-trusted-agent"],
    "tenant_claim": "tenant_id",
    "subject_claim": "sub",
    "agent_claim": "agent_id",
    "scope_claim": "scope",
    "groups_claim": "groups",
    "allowed_subjects": [],
    "default_scopes": [],
    "principal_type": "user",
    "validation_mode": "jwt",
    "introspection_url": None,
    "client_id": None,
    "client_secret_arn": None,
}


# ---------------------------------------------------------------------------
# _secret_name_from_arn
# ---------------------------------------------------------------------------

class SecretNameFromArnTests(unittest.TestCase):
    def test_valid_arn(self):
        arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:kenning/tenants/demo/oauth/client"
        self.assertEqual(federation._secret_name_from_arn(arn), "kenning/tenants/demo/oauth/client")

    def test_invalid_arn_raises(self):
        with self.assertRaises(ValueError) as ctx:
            federation._secret_name_from_arn("not-an-arn")
        self.assertIn("Secrets Manager ARN", str(ctx.exception))

    def test_empty_arn_raises(self):
        with self.assertRaises(ValueError):
            federation._secret_name_from_arn("")

    def test_none_arn_raises(self):
        with self.assertRaises(ValueError):
            federation._secret_name_from_arn(None)


# ---------------------------------------------------------------------------
# _tenant_oauth_secret_prefix
# ---------------------------------------------------------------------------

class TenantOAuthSecretPrefixTests(unittest.TestCase):
    def test_valid_tenant(self):
        self.assertEqual(federation._tenant_oauth_secret_prefix("demo"), "kenning/tenants/demo/oauth/")

    def test_empty_tenant_raises(self):
        with self.assertRaises(ValueError):
            federation._tenant_oauth_secret_prefix("")

    def test_none_tenant_raises(self):
        with self.assertRaises(ValueError):
            federation._tenant_oauth_secret_prefix(None)

    def test_slash_in_tenant_raises(self):
        with self.assertRaises(ValueError):
            federation._tenant_oauth_secret_prefix("bad/tenant")

    def test_backslash_in_tenant_raises(self):
        with self.assertRaises(ValueError):
            federation._tenant_oauth_secret_prefix("bad\\tenant")


# ---------------------------------------------------------------------------
# _string_list
# ---------------------------------------------------------------------------

class StringListTests(unittest.TestCase):
    def test_string_input(self):
        self.assertEqual(federation._string_list("a b c"), ["a", "b", "c"])

    def test_list_input(self):
        self.assertEqual(federation._string_list(["x", "y"]), ["x", "y"])

    def test_non_list_non_string(self):
        self.assertEqual(federation._string_list(123), [])

    def test_none(self):
        self.assertEqual(federation._string_list(None), [])

    def test_empty_string_items_filtered(self):
        self.assertEqual(federation._string_list(["a", "", "  ", "b"]), ["a", "b"])


# ---------------------------------------------------------------------------
# _https_url
# ---------------------------------------------------------------------------

class HttpsUrlTests(unittest.TestCase):
    def test_valid_https(self):
        self.assertEqual(federation._https_url("https://example.org/path", "field"), "https://example.org/path")

    def test_http_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            federation._https_url("http://example.org", "field")
        self.assertIn("HTTPS", str(ctx.exception))

    def test_no_scheme_rejected(self):
        with self.assertRaises(ValueError):
            federation._https_url("example.org", "field")

    def test_embedded_credentials_rejected(self):
        with self.assertRaises(ValueError):
            federation._https_url("https://user:***@example.org", "field")

    def test_empty_rejected(self):
        with self.assertRaises(ValueError):
            federation._https_url("", "field")


# ---------------------------------------------------------------------------
# normalise_provider
# ---------------------------------------------------------------------------

class NormaliseProviderTests(unittest.TestCase):
    def test_disabled_provider(self):
        result = federation.normalise_provider({"enabled": False})
        self.assertEqual(result, {"enabled": False})

    def test_none_payload_uses_existing(self):
        existing = {"enabled": False}
        result = federation.normalise_provider(None, existing)
        self.assertEqual(result, {"enabled": False})

    def test_non_dict_raises(self):
        with self.assertRaises(ValueError) as ctx:
            federation.normalise_provider("not-a-dict")
        self.assertIn("must be an object", str(ctx.exception))

    def test_missing_audience_raises(self):
        with self.assertRaises(ValueError) as ctx:
            federation.normalise_provider({"enabled": True, "issuer_url": "https://x.org"})
        self.assertIn("audience", str(ctx.exception))

    def test_invalid_issuer_url_raises(self):
        with self.assertRaises(ValueError):
            federation.normalise_provider({"enabled": True, "issuer_url": "http://x.org", "audience": "a"})

    def test_invalid_jwks_url_raises(self):
        with self.assertRaises(ValueError):
            federation.normalise_provider({"enabled": True, "issuer_url": "https://x.org", "audience": "a", "jwks_url": "http://bad"})

    def test_invalid_claim_name_raises(self):
        with self.assertRaises(ValueError) as ctx:
            federation.normalise_provider({
                "enabled": True, "issuer_url": "https://x.org", "audience": "a",
                "tenant_claim": "bad claim!",
            })
        self.assertIn("claim names", str(ctx.exception))

    def test_unsupported_default_scopes_raises(self):
        with self.assertRaises(ValueError) as ctx:
            federation.normalise_provider({
                "enabled": True, "issuer_url": "https://x.org", "audience": "a",
                "default_scopes": ["guard:evaluate", "nonexistent:scope"],
            })
        self.assertIn("unsupported scopes", str(ctx.exception))

    def test_invalid_principal_type_raises(self):
        with self.assertRaises(ValueError) as ctx:
            federation.normalise_provider({
                "enabled": True, "issuer_url": "https://x.org", "audience": "a",
                "principal_type": "robot",
            })
        self.assertIn("principal_type", str(ctx.exception))

    def test_invalid_validation_mode_raises(self):
        with self.assertRaises(ValueError) as ctx:
            federation.normalise_provider({
                "enabled": True, "issuer_url": "https://x.org", "audience": "a",
                "validation_mode": "magic",
            })
        self.assertIn("validation_mode", str(ctx.exception))

    def test_introspection_missing_client_id_raises(self):
        with self.assertRaises(ValueError) as ctx:
            federation.normalise_provider({
                "enabled": True, "issuer_url": "https://x.org", "audience": "a",
                "validation_mode": "introspection",
                "introspection_url": "https://x.org/introspect",
                "client_secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:kenning/tenants/demo/oauth/c",
            })
        self.assertIn("client_id", str(ctx.exception))

    def test_introspection_bad_secret_arn_raises(self):
        with self.assertRaises(ValueError) as ctx:
            federation.normalise_provider({
                "enabled": True, "issuer_url": "https://x.org", "audience": "a",
                "validation_mode": "introspection",
                "introspection_url": "https://x.org/introspect",
                "client_id": "my-client",
                "client_secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:other/path",
            })
        self.assertIn("tenant-scoped", str(ctx.exception))

    def test_jwt_mode_with_introspection_fields_raises(self):
        with self.assertRaises(ValueError) as ctx:
            federation.normalise_provider({
                "enabled": True, "issuer_url": "https://x.org", "audience": "a",
                "validation_mode": "jwt",
                "introspection_url": "https://x.org/introspect",
            })
        self.assertIn("introspection", str(ctx.exception))

    def test_full_valid_jwt_provider(self):
        result = federation.normalise_provider({
            "enabled": True,
            "issuer_url": "https://issuer.example.org/",
            "audience": ["kenning"],
            "tenant_claim": "tid",
            "subject_claim": "sub",
            "agent_claim": "aid",
            "scope_claim": "scp",
            "groups_claim": "grp",
            "allowed_subjects": ["user@*"],
            "default_scopes": ["guard:evaluate"],
            "principal_type": "workload",
        })
        self.assertTrue(result["enabled"])
        self.assertEqual(result["issuer_url"], "https://issuer.example.org")
        self.assertEqual(result["audience"], ["kenning"])
        self.assertEqual(result["tenant_claim"], "tid")
        self.assertEqual(result["principal_type"], "workload")
        self.assertEqual(result["validation_mode"], "jwt")
        self.assertIsNone(result["introspection_url"])

    def test_full_valid_introspection_provider(self):
        result = federation.normalise_provider({
            "enabled": True,
            "issuer_url": "https://issuer.example.org",
            "audience": "kenning",
            "validation_mode": "introspection",
            "introspection_url": "https://issuer.example.org/oauth/introspect",
            "client_id": "my-client",
            "client_secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:kenning/tenants/demo/oauth/client",
        })
        self.assertEqual(result["validation_mode"], "introspection")
        self.assertEqual(result["client_id"], "my-client")
        self.assertIsNotNone(result["client_secret_arn"])


# ---------------------------------------------------------------------------
# decode_unverified
# ---------------------------------------------------------------------------

class DecodeUnverifiedTests(unittest.TestCase):
    def test_valid_jwt(self):
        token = _make_jwt({"alg": "RS256"}, {"sub": "user"})
        header, claims, sig, signing_input = federation.decode_unverified(token)
        self.assertEqual(header["alg"], "RS256")
        self.assertEqual(claims["sub"], "user")
        self.assertIsInstance(sig, bytes)
        self.assertIn(b".", signing_input)

    def test_not_three_parts_raises(self):
        with self.assertRaises(ValueError) as ctx:
            federation.decode_unverified("only.two")
        self.assertIn("compact JWT", str(ctx.exception))

    def test_invalid_base64_raises(self):
        with self.assertRaises(ValueError) as ctx:
            federation.decode_unverified("!!!.@@@.###")
        self.assertIn("not valid base64url", str(ctx.exception))

    def test_non_dict_header_raises(self):
        token = f"{_b64url(b'[1,2]')}.{_b64url(json.dumps({'sub': 'x'}).encode())}.{_b64url(b'sig')}"
        with self.assertRaises(ValueError) as ctx:
            federation.decode_unverified(token)
        self.assertIn("must be JSON objects", str(ctx.exception))

    def test_non_dict_claims_raises(self):
        token = f"{_b64url(json.dumps({'alg': 'RS256'}).encode())}.{_b64url(b'[1,2]')}.{_b64url(b'sig')}"
        with self.assertRaises(ValueError) as ctx:
            federation.decode_unverified(token)
        self.assertIn("must be JSON objects", str(ctx.exception))

    def test_empty_token_raises(self):
        with self.assertRaises(ValueError):
            federation.decode_unverified("")

    def test_none_token_raises(self):
        with self.assertRaises(ValueError):
            federation.decode_unverified(None)


# ---------------------------------------------------------------------------
# _fetch_json
# ---------------------------------------------------------------------------

class FetchJsonTests(unittest.TestCase):
    def test_valid_response(self):
        body = json.dumps({"keys": []}).encode()
        result = federation._fetch_json("https://example.org/jwks", _fake_opener(body))
        self.assertEqual(result, {"keys": []})

    def test_oversized_response_raises(self):
        body = b"x" * (1_048_577)
        with self.assertRaises(ValueError) as ctx:
            federation._fetch_json("https://example.org/jwks", _fake_opener(body))
        self.assertIn("too large", str(ctx.exception))

    def test_non_dict_response_raises(self):
        body = json.dumps([1, 2, 3]).encode()
        with self.assertRaises(ValueError) as ctx:
            federation._fetch_json("https://example.org/jwks", _fake_opener(body))
        self.assertIn("must be an object", str(ctx.exception))


# ---------------------------------------------------------------------------
# _jwks
# ---------------------------------------------------------------------------

class JwksTests(unittest.TestCase):
    def setUp(self):
        federation._JWKS_CACHE.clear()

    def tearDown(self):
        federation._JWKS_CACHE.clear()

    def test_fetches_from_jwks_url(self):
        keys = [_test_jwk()]
        body = json.dumps({"keys": keys}).encode()
        provider = {**BASE_PROVIDER, "jwks_url": "https://issuer.example.org/jwks"}
        result = federation._jwks(provider, _fake_opener(body), NOW)
        self.assertEqual(result, keys)

    def test_fetches_via_discovery_when_no_jwks_url(self):
        keys = [_test_jwk()]
        discovery_body = json.dumps({"jwks_uri": "https://issuer.example.org/.well-known/jwks.json"}).encode()
        jwks_body = json.dumps({"keys": keys}).encode()

        call_count = [0]
        def multi_opener(request, timeout=None):
            call_count[0] += 1
            body = discovery_body if call_count[0] == 1 else jwks_body
            return _fake_opener(body)(request, timeout)

        provider = {**BASE_PROVIDER, "jwks_url": None}
        result = federation._jwks(provider, multi_opener, NOW)
        self.assertEqual(result, keys)
        self.assertEqual(call_count[0], 2)

    def test_cache_hit(self):
        keys = [_test_jwk()]
        federation._JWKS_CACHE["https://issuer.example.org/jwks"] = {
            "expires_at": NOW + 300,
            "keys": keys,
        }
        provider = {**BASE_PROVIDER, "jwks_url": "https://issuer.example.org/jwks"}
        # Opener that would fail if called
        result = federation._jwks(provider, lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("should not call")), NOW)
        self.assertEqual(result, keys)

    def test_cache_expired_refetches(self):
        keys = [_test_jwk()]
        federation._JWKS_CACHE["https://issuer.example.org/jwks"] = {
            "expires_at": NOW - 1,
            "keys": [{"old": True}],
        }
        body = json.dumps({"keys": keys}).encode()
        provider = {**BASE_PROVIDER, "jwks_url": "https://issuer.example.org/jwks"}
        result = federation._jwks(provider, _fake_opener(body), NOW)
        self.assertEqual(result, keys)

    def test_no_keys_array_raises(self):
        body = json.dumps({"not_keys": []}).encode()
        provider = {**BASE_PROVIDER, "jwks_url": "https://issuer.example.org/jwks"}
        with self.assertRaises(ValueError) as ctx:
            federation._jwks(provider, _fake_opener(body), NOW)
        self.assertIn("keys array", str(ctx.exception))

    def test_discovery_bad_jwks_uri_raises(self):
        discovery_body = json.dumps({"jwks_uri": "http://insecure.example.org/jwks"}).encode()
        provider = {**BASE_PROVIDER, "jwks_url": None}
        with self.assertRaises(ValueError) as ctx:
            federation._jwks(provider, _fake_opener(discovery_body), NOW)
        self.assertIn("HTTPS", str(ctx.exception))


# ---------------------------------------------------------------------------
# _verify_rsa_sha256
# ---------------------------------------------------------------------------

class VerifyRsaSha256Tests(unittest.TestCase):
    def test_valid_signature(self):
        signing_input = b"test.payload"
        sig = _sign_rs256(signing_input, _TEST_N, _TEST_E, _TEST_D)
        key = _test_jwk()
        self.assertTrue(federation._verify_rsa_sha256(signing_input, sig, key))

    def test_invalid_signature(self):
        signing_input = b"test.payload"
        key = _test_jwk()
        bad_sig = b"\x00" * ((_TEST_N.bit_length() + 7) // 8)
        self.assertFalse(federation._verify_rsa_sha256(signing_input, bad_sig, key))

    def test_non_rsa_key(self):
        self.assertFalse(federation._verify_rsa_sha256(b"data", b"sig", {"kty": "EC"}))

    def test_missing_n_or_e(self):
        self.assertFalse(federation._verify_rsa_sha256(b"data", b"sig", {"kty": "RSA", "n": _b64url(b"\x01")}))
        self.assertFalse(federation._verify_rsa_sha256(b"data", b"sig", {"kty": "RSA", "e": _b64url(b"\x01")}))

    def test_zero_modulus(self):
        key = {"kty": "RSA", "n": _b64url(b"\x00"), "e": _b64url(b"\x01")}
        self.assertFalse(federation._verify_rsa_sha256(b"data", b"sig", key))

    def test_wrong_signature_length(self):
        signing_input = b"test.payload"
        key = _test_jwk()
        self.assertFalse(federation._verify_rsa_sha256(signing_input, b"short", key))

    def test_padding_too_small_returns_false(self):
        # A tiny modulus makes padding_length < 8, hitting the early-return branch
        tiny_n = 0xDEADBEEF  # 32-bit modulus — far too small for PKCS#1 v1.5
        tiny_e = 3
        n_bytes = tiny_n.to_bytes((tiny_n.bit_length() + 7) // 8, "big")
        e_bytes = tiny_e.to_bytes((tiny_e.bit_length() + 7) // 8, "big")
        key = {"kty": "RSA", "n": _b64url(n_bytes), "e": _b64url(e_bytes)}
        size = (tiny_n.bit_length() + 7) // 8
        sig = b"\x00" * size
        self.assertFalse(federation._verify_rsa_sha256(b"data", sig, key))


# ---------------------------------------------------------------------------
# _claims_to_auth_record
# ---------------------------------------------------------------------------

class ClaimsToAuthRecordTests(unittest.TestCase):
    def _claims(self, **overrides):
        claims = {
            "iss": "https://issuer.example.org",
            "aud": "kenning-trusted-agent",
            "exp": NOW + 3600,
            "sub": "user@example.org",
            "tenant_id": "demo",
            "scope": "guard:evaluate audit:read",
        }
        claims.update(overrides)
        return claims

    def _verify(self, claims, **kwargs):
        defaults = dict(
            now=NOW,
            auth_source="oidc",
            token_id_prefix="oidc",
            require_audience=True,
            require_issuer=True,
        )
        defaults.update(kwargs)
        return federation._claims_to_auth_record(claims, BASE_PROVIDER, **defaults)

    def test_happy_path(self):
        result = self._verify(self._claims())
        self.assertEqual(result["token_type"], "federated")
        self.assertEqual(result["auth_source"], "oidc")
        self.assertEqual(result["tenant_id"], "demo")
        self.assertEqual(result["subject"], "user@example.org")
        self.assertEqual(result["scopes"], ["audit:read", "guard:evaluate"])
        self.assertEqual(result["status"], "active")

    def test_missing_issuer_when_required_raises(self):
        claims = self._claims()
        del claims["iss"]
        with self.assertRaises(ValueError) as ctx:
            self._verify(claims)
        self.assertIn("issuer", str(ctx.exception))

    def test_issuer_mismatch_raises(self):
        with self.assertRaises(ValueError) as ctx:
            self._verify(self._claims(iss="https://evil.example.org"))
        self.assertIn("does not match", str(ctx.exception))

    def test_missing_audience_when_required_raises(self):
        claims = self._claims()
        del claims["aud"]
        with self.assertRaises(ValueError) as ctx:
            self._verify(claims)
        self.assertIn("audience", str(ctx.exception))

    def test_audience_not_authorised_raises(self):
        with self.assertRaises(ValueError) as ctx:
            self._verify(self._claims(aud="wrong-audience"))
        self.assertIn("not authorised", str(ctx.exception))

    def test_missing_exp_raises(self):
        claims = self._claims()
        del claims["exp"]
        with self.assertRaises(ValueError) as ctx:
            self._verify(claims)
        self.assertIn("exp", str(ctx.exception))

    def test_expired_token_raises(self):
        with self.assertRaises(ValueError) as ctx:
            self._verify(self._claims(exp=NOW - 100))
        self.assertIn("expired", str(ctx.exception))

    def test_nbf_in_future_raises(self):
        with self.assertRaises(ValueError) as ctx:
            self._verify(self._claims(nbf=NOW + 3600))
        self.assertIn("not active yet", str(ctx.exception))

    def test_nbf_within_skew_ok(self):
        result = self._verify(self._claims(nbf=NOW + 20))
        self.assertEqual(result["status"], "active")

    def test_missing_subject_raises(self):
        claims = self._claims()
        del claims["sub"]
        with self.assertRaises(ValueError) as ctx:
            self._verify(claims)
        self.assertIn("subject", str(ctx.exception))

    def test_subject_not_in_allowed_raises(self):
        provider = {**BASE_PROVIDER, "allowed_subjects": ["admin@*"]}
        claims = self._claims(sub="user@example.org")
        with self.assertRaises(ValueError) as ctx:
            federation._claims_to_auth_record(
                claims, provider, now=NOW, auth_source="oidc",
                token_id_prefix="oidc", require_audience=True, require_issuer=True,
            )
        self.assertIn("not authorised", str(ctx.exception))

    def test_subject_in_allowed_ok(self):
        provider = {**BASE_PROVIDER, "allowed_subjects": ["user@*"]}
        claims = self._claims(sub="user@example.org")
        result = federation._claims_to_auth_record(
            claims, provider, now=NOW, auth_source="oidc",
            token_id_prefix="oidc", require_audience=True, require_issuer=True,
        )
        self.assertEqual(result["subject"], "user@example.org")

    def test_missing_tenant_claim_raises(self):
        claims = self._claims()
        del claims["tenant_id"]
        with self.assertRaises(ValueError) as ctx:
            self._verify(claims)
        self.assertIn("tenant claim", str(ctx.exception))

    def test_missing_tenant_allowed_with_flag(self):
        provider = {**BASE_PROVIDER, "allow_missing_tenant_claim": True}
        claims = self._claims()
        del claims["tenant_id"]
        result = federation._claims_to_auth_record(
            claims, provider, now=NOW, auth_source="oidc",
            token_id_prefix="oidc", require_audience=True, require_issuer=True,
        )
        self.assertIsNone(result["tenant_id"])

    def test_scopes_fallback_to_default(self):
        provider = {**BASE_PROVIDER, "default_scopes": ["guard:evaluate", "audit:read"]}
        claims = self._claims()
        del claims["scope"]
        result = federation._claims_to_auth_record(
            claims, provider, now=NOW, auth_source="oidc",
            token_id_prefix="oidc", require_audience=True, require_issuer=True,
        )
        self.assertEqual(result["scopes"], ["audit:read", "guard:evaluate"])

    def test_scopes_filtered_to_federated_names(self):
        claims = self._claims(scope="guard:evaluate admin:everything")
        result = self._verify(claims)
        self.assertEqual(result["scopes"], ["guard:evaluate"])

    def test_groups_extracted(self):
        claims = self._claims(groups=["admins", "devs", "  "])
        result = self._verify(claims)
        self.assertEqual(result["groups"], ["admins", "devs"])

    def test_groups_capped_at_50(self):
        claims = self._claims(groups=[f"g{i}" for i in range(60)])
        result = self._verify(claims)
        self.assertEqual(len(result["groups"]), 50)

    def test_display_name_fallback_chain(self):
        # name > preferred_username > cognito:username > email > subject
        claims = self._claims(name="Full Name")
        self.assertEqual(self._verify(claims)["display_name"], "Full Name")

        claims = self._claims(preferred_username="prefuser")
        self.assertEqual(self._verify(claims)["display_name"], "prefuser")

        claims = self._claims()
        claims["cognito:username"] = "coguser"
        self.assertEqual(self._verify(claims)["display_name"], "coguser")

        claims = self._claims(email="user@example.org")
        self.assertEqual(self._verify(claims)["display_name"], "user@example.org")

    def test_email_lowercased(self):
        claims = self._claims(email="USER@EXAMPLE.ORG")
        self.assertEqual(self._verify(claims)["email"], "user@example.org")

    def test_agent_id_extracted(self):
        claims = self._claims(agent_id="agent-123")
        self.assertEqual(self._verify(claims)["agent_id"], "agent-123")

    def test_no_require_audience(self):
        claims = self._claims()
        del claims["aud"]
        result = self._verify(claims, require_audience=False)
        self.assertEqual(result["status"], "active")

    def test_no_require_issuer(self):
        claims = self._claims()
        del claims["iss"]
        result = self._verify(claims, require_issuer=False)
        self.assertEqual(result["status"], "active")


# ---------------------------------------------------------------------------
# verify_federated_token
# ---------------------------------------------------------------------------

class VerifyFederatedTokenTests(unittest.TestCase):
    def setUp(self):
        federation._JWKS_CACHE.clear()

    def tearDown(self):
        federation._JWKS_CACHE.clear()

    def _provider(self):
        return {**BASE_PROVIDER, "jwks_url": "https://issuer.example.org/jwks"}

    def _jwks_opener(self):
        keys = [_test_jwk()]
        body = json.dumps({"keys": keys}).encode()
        return _fake_opener(body)

    def test_valid_token(self):
        claims = {
            "iss": "https://issuer.example.org",
            "aud": "kenning-trusted-agent",
            "exp": NOW + 3600,
            "sub": "user@example.org",
            "tenant_id": "demo",
            "scope": "guard:evaluate",
        }
        token = _signed_jwt(claims)
        result = federation.verify_federated_token(token, self._provider(), self._jwks_opener(), NOW)
        self.assertEqual(result["auth_source"], "oidc")
        self.assertEqual(result["subject"], "user@example.org")
        self.assertEqual(result["tenant_id"], "demo")

    def test_wrong_algorithm_raises(self):
        header = {"alg": "HS256", "kid": "test-key-1"}
        claims = {"sub": "user", "exp": NOW + 3600}
        token = _make_jwt(header, claims)
        with self.assertRaises(ValueError) as ctx:
            federation.verify_federated_token(token, self._provider(), self._jwks_opener(), NOW)
        self.assertIn("RS256", str(ctx.exception))

    def test_missing_kid_raises(self):
        header = {"alg": "RS256"}
        claims = {"sub": "user", "exp": NOW + 3600}
        token = _make_jwt(header, claims)
        with self.assertRaises(ValueError) as ctx:
            federation.verify_federated_token(token, self._provider(), self._jwks_opener(), NOW)
        self.assertIn("RS256", str(ctx.exception))

    def test_unknown_kid_raises(self):
        claims = {
            "iss": "https://issuer.example.org",
            "aud": "kenning-trusted-agent",
            "exp": NOW + 3600,
            "sub": "user@example.org",
            "tenant_id": "demo",
        }
        token = _signed_jwt(claims, kid="unknown-key")
        with self.assertRaises(ValueError) as ctx:
            federation.verify_federated_token(token, self._provider(), self._jwks_opener(), NOW)
        self.assertIn("signature", str(ctx.exception))

    def test_tampered_signature_raises(self):
        claims = {
            "iss": "https://issuer.example.org",
            "aud": "kenning-trusted-agent",
            "exp": NOW + 3600,
            "sub": "user@example.org",
            "tenant_id": "demo",
        }
        token = _signed_jwt(claims)
        # Tamper with the payload
        parts = token.split(".")
        tampered_claims = {**claims, "sub": "evil@example.org"}
        parts[1] = _b64url(json.dumps(tampered_claims).encode())
        tampered_token = ".".join(parts)
        with self.assertRaises(ValueError) as ctx:
            federation.verify_federated_token(tampered_token, self._provider(), self._jwks_opener(), NOW)
        self.assertIn("signature", str(ctx.exception))

    def test_expired_token_raises(self):
        claims = {
            "iss": "https://issuer.example.org",
            "aud": "kenning-trusted-agent",
            "exp": NOW - 100,
            "sub": "user@example.org",
            "tenant_id": "demo",
        }
        token = _signed_jwt(claims)
        with self.assertRaises(ValueError) as ctx:
            federation.verify_federated_token(token, self._provider(), self._jwks_opener(), NOW)
        self.assertIn("expired", str(ctx.exception))


# ---------------------------------------------------------------------------
# _post_form_json
# ---------------------------------------------------------------------------

class PostFormJsonTests(unittest.TestCase):
    def test_valid_response(self):
        body = json.dumps({"active": True}).encode()
        result = federation._post_form_json(
            "https://example.org/introspect",
            {"token": "***"},
            "Basic dGVzdDp0ZXN0",
            _fake_opener(body),
        )
        self.assertEqual(result, {"active": True})

    def test_oversized_response_raises(self):
        body = b"x" * 1_048_577
        with self.assertRaises(ValueError) as ctx:
            federation._post_form_json("https://example.org/introspect", {}, "Basic x", _fake_opener(body))
        self.assertIn("too large", str(ctx.exception))

    def test_non_dict_response_raises(self):
        body = json.dumps([1]).encode()
        with self.assertRaises(ValueError) as ctx:
            federation._post_form_json("https://example.org/introspect", {}, "Basic x", _fake_opener(body))
        self.assertIn("must be an object", str(ctx.exception))


# ---------------------------------------------------------------------------
# verify_oauth2_token
# ---------------------------------------------------------------------------

class VerifyOAuth2TokenTests(unittest.TestCase):
    def _provider(self, **overrides):
        provider = {
            **BASE_PROVIDER,
            "validation_mode": "introspection",
            "introspection_url": "https://issuer.example.org/oauth/introspect",
            "client_id": "my-client",
            "client_secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:kenning/tenants/demo/oauth/client",
            "tenant_id": "demo",
        }
        provider.update(overrides)
        return provider

    def test_valid_introspection(self):
        introspection_response = json.dumps({
            "active": True,
            "sub": "service@example.org",
            "tenant_id": "demo",
            "scope": "guard:evaluate",
            "exp": NOW + 3600,
        }).encode()
        result = federation.verify_oauth2_token(
            "opaque-token",
            self._provider(),
            secret_getter=lambda arn: "s3cret",
            opener=_fake_opener(introspection_response),
            now=NOW,
        )
        self.assertEqual(result["auth_source"], "oauth2")
        self.assertEqual(result["subject"], "service@example.org")
        self.assertEqual(result["tenant_id"], "demo")

    def test_inactive_token_raises(self):
        introspection_response = json.dumps({"active": False}).encode()
        with self.assertRaises(ValueError) as ctx:
            federation.verify_oauth2_token(
                "opaque-token",
                self._provider(),
                secret_getter=lambda arn: "s3cret",
                opener=_fake_opener(introspection_response),
                now=NOW,
            )
        self.assertIn("inactive", str(ctx.exception))

    def test_secret_not_tenant_scoped_raises(self):
        provider = self._provider(
            client_secret_arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:other/path",
            tenant_id="demo",
        )
        with self.assertRaises(ValueError) as ctx:
            federation.verify_oauth2_token(
                "opaque-token", provider,
                secret_getter=lambda arn: "s3cret",
                opener=_fake_opener(b"{}"),
                now=NOW,
            )
        self.assertIn("scoped to the authenticating tenant", str(ctx.exception))

    def test_empty_secret_raises(self):
        with self.assertRaises(ValueError) as ctx:
            federation.verify_oauth2_token(
                "opaque-token", self._provider(),
                secret_getter=lambda arn: "",
                opener=_fake_opener(b"{}"),
                now=NOW,
            )
        self.assertIn("empty", str(ctx.exception))

    def test_missing_tenant_id_in_provider_raises(self):
        provider = self._provider(tenant_id="")
        with self.assertRaises(ValueError):
            federation.verify_oauth2_token(
                "opaque-token", provider,
                secret_getter=lambda arn: "s3cret",
                opener=_fake_opener(b"{}"),
                now=NOW,
            )


if __name__ == "__main__":
    unittest.main()
