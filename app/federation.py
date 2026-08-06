"""Dependency-free OIDC/JWT and OAuth 2.0 federation for API access.

This module validates signed RS256 bearer tokens or introspects opaque OAuth
2.0 access tokens against tenant-configured identity providers. Provider
client secrets are supplied by a caller-owned secret-manager callback and are
never part of the provider record or returned authentication context.
"""

from __future__ import annotations

import base64
import fnmatch
import hashlib
import json
import re
import time
from typing import Any, Callable
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen


FEDERATED_SCOPE_NAMES = {
    "guard:evaluate",
    "mcp:read",
    "audit:read",
    "audit:write",
    "approve:actions",
    "actions:write",
    "proof:read",
    "proof:write",
    "citation:verify",
    "identity:read",
    "identity:write",
    "model:read",
    "model:write",
    "policy:read",
    "policy:write",
    "policy:simulate",
    "tenant:read",
    "tenant:write",
    "tenant:retention",
}
_JWKS_CACHE: dict[str, dict[str, Any]] = {}
_TENANT_SECRET_PREFIX = "kenning/tenants/"
_SECRET_ARN_RE = re.compile(r"^arn:[^:]+:secretsmanager:[^:]+:[0-9]{12}:secret:([^\s]+)$")


def _secret_name_from_arn(secret_arn: str) -> str:
    match = _SECRET_ARN_RE.match(str(secret_arn or "").strip())
    if not match:
        raise ValueError("identity_provider.client_secret_arn must be a Secrets Manager ARN for introspection.")
    return match.group(1)


def _tenant_oauth_secret_prefix(tenant_id: str) -> str:
    tenant_id = str(tenant_id or "").strip()
    if not tenant_id or any(char in tenant_id for char in "/\\"):
        raise ValueError("OAuth introspection requires a valid tenant id before reading a client secret.")
    return f"{_TENANT_SECRET_PREFIX}{tenant_id}/oauth/"



def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [item for item in value.split() if item]
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


def _https_url(value: Any, field: str) -> str:
    value = str(value or "").strip()
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise ValueError(f"{field} must be an HTTPS URL without embedded credentials.")
    return value


def normalise_provider(payload: Any, existing: dict[str, Any] | None = None) -> dict[str, Any]:
    """Validate public OIDC provider metadata for a tenant."""

    if payload is None:
        payload = existing if isinstance(existing, dict) else {}
    if not isinstance(payload, dict):
        raise ValueError("identity_provider must be an object.")
    if not bool(payload.get("enabled", False)):
        return {"enabled": False}
    issuer_url = _https_url(payload.get("issuer_url"), "identity_provider.issuer_url").rstrip("/")
    jwks_url = payload.get("jwks_url")
    if jwks_url:
        jwks_url = _https_url(jwks_url, "identity_provider.jwks_url")
    audience = _string_list(payload.get("audience"))
    if not audience:
        raise ValueError("identity_provider.audience is required when federation is enabled.")
    tenant_claim = str(payload.get("tenant_claim") or "tenant_id").strip()
    subject_claim = str(payload.get("subject_claim") or "sub").strip()
    agent_claim = str(payload.get("agent_claim") or "agent_id").strip()
    scope_claim = str(payload.get("scope_claim") or "scope").strip()
    groups_claim = str(payload.get("groups_claim") or "groups").strip()
    if not all(1 <= len(value) <= 128 and all(char.isalnum() or char in "_-:" for char in value) for value in (tenant_claim, subject_claim, agent_claim, scope_claim, groups_claim)):
        raise ValueError("identity_provider claim names must contain only letters, numbers, underscore, hyphen, or colon.")
    allowed_subjects = _string_list(payload.get("allowed_subjects"))
    default_scopes = _string_list(payload.get("default_scopes"))
    unsupported = sorted(set(default_scopes) - FEDERATED_SCOPE_NAMES)
    if unsupported:
        raise ValueError(f"identity_provider.default_scopes contains unsupported scopes: {', '.join(unsupported)}.")
    principal_type = str(payload.get("principal_type") or "user").lower()
    if principal_type not in {"user", "workload"}:
        raise ValueError("identity_provider.principal_type must be user or workload.")
    validation_mode = str(payload.get("validation_mode") or payload.get("token_validation") or "jwt").lower().strip()
    if validation_mode not in {"jwt", "introspection"}:
        raise ValueError("identity_provider.validation_mode must be jwt or introspection.")
    introspection_url = payload.get("introspection_url")
    client_id = str(payload.get("client_id") or "").strip()
    client_secret_arn = str(payload.get("client_secret_arn") or "").strip()
    if validation_mode == "introspection":
        introspection_url = _https_url(introspection_url, "identity_provider.introspection_url")
        if not client_id or len(client_id) > 256:
            raise ValueError("identity_provider.client_id is required for introspection and must be no longer than 256 characters.")
        secret_name = _secret_name_from_arn(client_secret_arn)
        if len(client_secret_arn) > 2048 or not secret_name.startswith(_TENANT_SECRET_PREFIX):
            raise ValueError("identity_provider.client_secret_arn must be a tenant-scoped Secrets Manager ARN under kenning/tenants/{tenant_id}/oauth/.")
    elif introspection_url or client_id or client_secret_arn:
        raise ValueError("introspection_url, client_id, and client_secret_arn require validation_mode=introspection.")
    return {
        "enabled": True,
        "issuer_url": issuer_url,
        "jwks_url": jwks_url,
        "audience": audience,
        "tenant_claim": tenant_claim,
        "subject_claim": subject_claim,
        "agent_claim": agent_claim,
        "scope_claim": scope_claim,
        "groups_claim": groups_claim,
        "allowed_subjects": allowed_subjects,
        "default_scopes": default_scopes,
        "principal_type": principal_type,
        "validation_mode": validation_mode,
        "introspection_url": introspection_url,
        "client_id": client_id or None,
        "client_secret_arn": client_secret_arn or None,
    }


def decode_unverified(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    parts = str(token or "").split(".")
    if len(parts) != 3:
        raise ValueError("Federated bearer token must be a compact JWT.")
    try:
        header_bytes = _b64decode(parts[0])
        claims_bytes = _b64decode(parts[1])
        signature = _b64decode(parts[2])
        header = json.loads(header_bytes.decode("utf-8"))
        claims = json.loads(claims_bytes.decode("utf-8"))
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Federated bearer token is not valid base64url JSON.") from exc
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise ValueError("Federated bearer token header and claims must be JSON objects.")
    return header, claims, signature, f"{parts[0]}.{parts[1]}".encode("ascii")


def _fetch_json(url: str, opener: Callable[..., Any]) -> dict[str, Any]:
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "Kenning-Trusted-Agent-OIDC/0.1"})
    with opener(request, timeout=2) as response:
        raw = response.read(1_048_577)
    if len(raw) > 1_048_576:
        raise ValueError("OIDC metadata response is too large.")
    parsed = json.loads(raw.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("OIDC metadata response must be an object.")
    return parsed


def _jwks(provider: dict[str, Any], opener: Callable[..., Any], now: int) -> list[dict[str, Any]]:
    issuer = str(provider["issuer_url"])
    discovery_url = issuer + "/.well-known/openid-configuration"
    jwks_url = str(provider.get("jwks_url") or "")
    cache_key = jwks_url or discovery_url
    cached = _JWKS_CACHE.get(cache_key)
    if cached and int(cached.get("expires_at", 0)) > now:
        return cached["keys"]
    if not jwks_url:
        discovery = _fetch_json(discovery_url, opener)
        jwks_url = _https_url(discovery.get("jwks_uri"), "OIDC discovery jwks_uri")
    document = _fetch_json(jwks_url, opener)
    keys = document.get("keys")
    if not isinstance(keys, list):
        raise ValueError("JWKS response does not contain a keys array.")
    _JWKS_CACHE[cache_key] = {"expires_at": now + 300, "keys": keys}
    return keys


def _verify_rsa_sha256(signing_input: bytes, signature: bytes, key: dict[str, Any]) -> bool:
    if key.get("kty") != "RSA":
        return False
    try:
        modulus = int.from_bytes(_b64decode(str(key["n"])), "big")
        exponent = int.from_bytes(_b64decode(str(key["e"])), "big")
    except (KeyError, ValueError, TypeError):
        return False
    if modulus <= 0 or exponent <= 0:
        return False
    size = (modulus.bit_length() + 7) // 8
    if len(signature) != size:
        return False
    encoded = pow(int.from_bytes(signature, "big"), exponent, modulus).to_bytes(size, "big")
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(signing_input).digest()
    padding_length = size - len(digest_info) - 3
    if padding_length < 8:
        return False
    expected = b"\x00\x01" + b"\xff" * padding_length + b"\x00" + digest_info
    return encoded == expected


def _claims_to_auth_record(
    claims: dict[str, Any],
    provider: dict[str, Any],
    *,
    now: int,
    auth_source: str,
    token_id_prefix: str,
    require_audience: bool,
    require_issuer: bool,
) -> dict[str, Any]:
    if require_issuer and not claims.get("iss"):
        raise ValueError("Federated token must contain an issuer.")
    issuer = str(claims.get("iss") or provider["issuer_url"]).rstrip("/")
    if issuer != str(provider["issuer_url"]).rstrip("/"):
        raise ValueError("Federated token issuer does not match the configured provider.")
    audiences = _string_list(claims.get("aud"))
    if require_audience and not audiences:
        raise ValueError("Federated token must contain an audience.")
    if audiences and not set(audiences).intersection(set(provider["audience"])):
        raise ValueError("Federated token audience is not authorised.")
    try:
        expires_at = int(claims["exp"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Federated token must contain an exp claim.") from exc
    if expires_at <= now:
        raise ValueError("Federated token has expired.")
    if claims.get("nbf") is not None and int(claims["nbf"]) > now + 30:
        raise ValueError("Federated token is not active yet.")

    subject = str(claims.get(provider.get("subject_claim", "sub")) or "").strip()
    if not subject:
        raise ValueError("Federated token must contain a subject.")
    allowed_subjects = provider.get("allowed_subjects") or []
    if allowed_subjects and not any(fnmatch.fnmatchcase(subject, str(pattern)) for pattern in allowed_subjects):
        raise ValueError("Federated subject is not authorised for this tenant.")
    tenant_id = str(claims.get(provider.get("tenant_claim", "tenant_id")) or "").strip()
    if not tenant_id and not provider.get("allow_missing_tenant_claim"):
        raise ValueError("Federated token must contain a tenant claim.")
    scopes = _string_list(claims.get(provider.get("scope_claim", "scope")) or claims.get("scp"))
    scopes = sorted(set(scopes).intersection(FEDERATED_SCOPE_NAMES))
    if not scopes:
        scopes = sorted(set(provider.get("default_scopes") or []).intersection(FEDERATED_SCOPE_NAMES))
    groups = _string_list(claims.get(provider.get("groups_claim", "groups")))
    groups = sorted(set(group.strip() for group in groups if group.strip()))[:50]
    agent_id = str(claims.get(provider.get("agent_claim", "agent_id")) or "").strip()
    email = str(claims.get("email") or "").strip().lower() or None
    display_name = str(
        claims.get("name")
        or claims.get("preferred_username")
        or claims.get("cognito:username")
        or email
        or subject
    ).strip() or None
    return {
        "token_type": "federated",
        "auth_source": auth_source,
        "token_id": f"{token_id_prefix}:{provider['issuer_url']}:{subject}",
        "tenant_id": tenant_id or None,
        "subject": subject,
        "email": email,
        "display_name": display_name,
        "invoked_by": subject,
        "agent_id": agent_id or None,
        "principal_type": provider.get("principal_type", "user"),
        "issuer": provider["issuer_url"],
        "scopes": scopes,
        "groups": groups,
        "status": "active",
        "expires_at": expires_at,
    }


def verify_federated_token(
    token: str,
    provider: dict[str, Any],
    opener: Callable[..., Any] = urlopen,
    now: int | None = None,
) -> dict[str, Any]:
    """Validate a JWT and return an auth record compatible with PAT auth."""

    now = int(time.time()) if now is None else int(now)
    header, claims, signature, signing_input = decode_unverified(token)
    if header.get("alg") != "RS256" or not header.get("kid"):
        raise ValueError("Only RS256 JWTs with a key id are accepted.")
    keys = _jwks(provider, opener, now)
    key = next((item for item in keys if isinstance(item, dict) and item.get("kid") == header.get("kid")), None)
    if not key or not _verify_rsa_sha256(signing_input, signature, key):
        raise ValueError("Federated token signature could not be verified.")
    return _claims_to_auth_record(
        claims,
        provider,
        now=now,
        auth_source="oidc",
        token_id_prefix="oidc",
        require_audience=True,
        require_issuer=True,
    )


def _post_form_json(url: str, form: dict[str, str], authorization: str, opener: Callable[..., Any]) -> dict[str, Any]:
    request = Request(
        url,
        data=urlencode(form).encode("utf-8"),
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": authorization,
            "User-Agent": "Kenning-Trusted-Agent-OAuth2/0.1",
        },
    )
    with opener(request, timeout=2) as response:
        raw = response.read(1_048_577)
    if len(raw) > 1_048_576:
        raise ValueError("OAuth introspection response is too large.")
    parsed = json.loads(raw.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("OAuth introspection response must be an object.")
    return parsed


def verify_oauth2_token(
    token: str,
    provider: dict[str, Any],
    secret_getter: Callable[[str], str],
    opener: Callable[..., Any] = urlopen,
    now: int | None = None,
) -> dict[str, Any]:
    """Introspect an opaque OAuth 2.0 access token without storing its secret."""

    now = int(time.time()) if now is None else int(now)
    secret_arn = str(provider["client_secret_arn"])
    secret_name = _secret_name_from_arn(secret_arn)
    tenant_secret_prefix = _tenant_oauth_secret_prefix(str(provider.get("tenant_id") or ""))
    if not secret_name.startswith(tenant_secret_prefix):
        raise ValueError("OAuth introspection client secret must be scoped to the authenticating tenant.")
    client_secret = str(secret_getter(secret_arn))
    if not client_secret:
        raise ValueError("OAuth introspection client secret is empty.")
    basic = base64.b64encode(f"{provider['client_id']}:{client_secret}".encode("utf-8")).decode("ascii")
    claims = _post_form_json(
        str(provider["introspection_url"]),
        {"token": token, "token_type_hint": "access_token"},
        f"Basic {basic}",
        opener,
    )
    if claims.get("active") is not True:
        raise ValueError("OAuth access token is inactive.")
    return _claims_to_auth_record(
        claims,
        provider,
        now=now,
        auth_source="oauth2",
        token_id_prefix="oauth2",
        require_audience=False,
        require_issuer=False,
    )
