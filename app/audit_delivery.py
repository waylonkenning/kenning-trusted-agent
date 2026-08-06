"""Best-effort external audit event delivery.

The Guard decision remains durable in DynamoDB before delivery is attempted.
Sink credentials are referenced through Secrets Manager rather than stored in
tenant configuration.  Delivery status is recorded on the originating event
without retrying or duplicating the protected action.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


SUPPORTED_FORMATS = {"json", "ndjson"}
SECRET_ARN_PATTERN = re.compile(
    r"^arn:aws[a-zA-Z-]*:secretsmanager:(?P<region>[a-z0-9-]+):(?P<account>\d{12}):secret:(?P<name>[A-Za-z0-9/_+=.@-]+)$"
)


def _audit_secret_prefix(tenant_id: str) -> str:
    environment = str(os.environ.get("KENNING_ENV") or os.environ.get("KENNING_ENVIRONMENT") or "prototype").strip()
    return f"kenning/audit-sinks/{environment}/{tenant_id}/"


def validate_secret_arn(secret_arn: str, tenant_id: str | None = None) -> str:
    """Return a tenant-scoped Secrets Manager ARN or raise ValueError."""

    secret_arn = str(secret_arn or "").strip()
    match = SECRET_ARN_PATTERN.fullmatch(secret_arn)
    if not match:
        raise ValueError("audit_sink.secret_arn must be a Secrets Manager ARN.")
    expected_region = str(os.environ.get("AWS_REGION") or "").strip()
    if expected_region and match.group("region") != expected_region:
        raise ValueError("audit_sink.secret_arn must be in the current deployment region.")
    expected_account = str(os.environ.get("AWS_ACCOUNT_ID") or os.environ.get("KENNING_AWS_ACCOUNT_ID") or "").strip()
    if expected_account and match.group("account") != expected_account:
        raise ValueError("audit_sink.secret_arn must be in the current AWS account.")
    if tenant_id is not None:
        expected_prefix = _audit_secret_prefix(str(tenant_id))
        if not match.group("name").startswith(expected_prefix):
            raise ValueError(f"audit_sink.secret_arn must reference a tenant-owned secret under {expected_prefix}.")
    return secret_arn


def normalise_sink(payload: Any, existing: dict[str, Any] | None = None, tenant_id: str | None = None) -> dict[str, Any]:
    """Validate and redact a tenant audit sink configuration."""

    if payload is None:
        payload = existing if isinstance(existing, dict) else {}
    if not isinstance(payload, dict):
        raise ValueError("audit_sink must be an object.")
    enabled = bool(payload.get("enabled", False))
    if not enabled:
        return {"enabled": False, "format": "json", "timeout_ms": 1000}

    endpoint = str(payload.get("endpoint_url") or "").strip()
    parsed = urlparse(endpoint)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise ValueError("audit_sink.endpoint_url must be an HTTPS URL without embedded credentials.")
    output_format = str(payload.get("format") or "json").lower()
    if output_format not in SUPPORTED_FORMATS:
        raise ValueError(f"audit_sink.format must be one of: {', '.join(sorted(SUPPORTED_FORMATS))}.")
    try:
        timeout_ms = int(payload.get("timeout_ms") or 1000)
    except (TypeError, ValueError) as exc:
        raise ValueError("audit_sink.timeout_ms must be an integer between 250 and 2000.") from exc
    if timeout_ms < 250 or timeout_ms > 2000:
        raise ValueError("audit_sink.timeout_ms must be an integer between 250 and 2000.")
    secret_arn = str(payload.get("secret_arn") or "").strip()
    # Never accept raw bearer tokens or arbitrary authorization headers through
    # the tenant configuration API.
    forbidden = {"token", "bearer_token", "authorization", "headers", "secret"}
    if forbidden.intersection(payload):
        raise ValueError("Use secret_arn for sink credentials; raw tokens and headers are not accepted.")
    if not secret_arn:
        raise ValueError("audit_sink.secret_arn is required when the sink is enabled.")
    secret_arn = validate_secret_arn(secret_arn, tenant_id)
    return {
        "enabled": True,
        "endpoint_url": endpoint,
        "format": output_format,
        "timeout_ms": timeout_ms,
        "secret_arn": secret_arn,
        "auth_scheme": "Bearer",
    }


def _secret_token(secret_client: Any, secret_arn: str) -> str:
    if secret_client is None:
        raise RuntimeError("Secrets Manager is not configured for audit delivery.")
    result = secret_client.get_secret_value(SecretId=secret_arn)
    value = result.get("SecretString")
    if value is None and result.get("SecretBinary") is not None:
        value = result["SecretBinary"].decode("utf-8") if isinstance(result["SecretBinary"], bytes) else str(result["SecretBinary"])
    if not value:
        raise RuntimeError("The audit delivery secret is empty.")
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        parsed = None
    if isinstance(parsed, dict):
        value = parsed.get("token") or parsed.get("bearer_token") or parsed.get("value")
    if not value:
        raise RuntimeError("The audit delivery secret must contain token, bearer_token, value, or a raw secret string.")
    return str(value)


def deliver_event(
    event: dict[str, Any],
    sink: dict[str, Any] | None,
    secret_client: Any = None,
    opener: Callable[..., Any] = urlopen,
) -> dict[str, Any]:
    """Deliver one event and return a redacted operational status."""

    if not isinstance(sink, dict) or not sink.get("enabled"):
        return {"status": "disabled", "delivered": False}
    try:
        token = _secret_token(secret_client, str(sink["secret_arn"]))
        output_format = str(sink.get("format") or "json")
        if output_format == "ndjson":
            data = (json.dumps(event, default=str, sort_keys=True) + "\n").encode("utf-8")
            content_type = "application/x-ndjson"
        else:
            data = json.dumps(event, default=str, sort_keys=True).encode("utf-8")
            content_type = "application/json"
        request = Request(
            str(sink["endpoint_url"]),
            data=data,
            method="POST",
            headers={
                "Accept": "application/json",
                "Content-Type": content_type,
                "Authorization": f"Bearer {token}",
                "User-Agent": "Kenning-Trusted-Agent-Audit/0.1",
            },
        )
        with opener(request, timeout=int(sink.get("timeout_ms") or 1000) / 1000) as response:
            status_value = getattr(response, "status", None)
            status_code = int(status_value if status_value is not None else response.getcode())
        if 200 <= status_code < 300:
            return {"status": "delivered", "delivered": True, "http_status": status_code}
        return {"status": "rejected", "delivered": False, "http_status": status_code}
    except HTTPError as exc:
        return {"status": "rejected", "delivered": False, "http_status": int(exc.code)}
    except (URLError, TimeoutError, OSError, RuntimeError, ValueError) as exc:
        return {"status": "failed", "delivered": False, "error_code": type(exc).__name__}
    except Exception as exc:  # Provider client errors must not block Guard.
        return {"status": "failed", "delivered": False, "error_code": type(exc).__name__}
