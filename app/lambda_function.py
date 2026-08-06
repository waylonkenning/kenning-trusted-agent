"""AWS Lambda HTTP and MCP adapters for Kenning Agent Guard."""

from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import json
import os
import re
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

try:  # pragma: no cover
    from auth import (  # noqa: F401 — re-exported for backward compatibility
        authenticated_principal,
        configured_platform_admin_groups,
        has_scope,
        is_platform_admin_principal,
        is_platform_admin_session,
        is_session_auth,
        product_for_api_path,
        scope_error,
    )
except ImportError:  # pragma: no cover
    from .auth import (  # noqa: F401
        authenticated_principal,
        configured_platform_admin_groups,
        has_scope,
        is_platform_admin_principal,
        is_platform_admin_session,
        is_session_auth,
        product_for_api_path,
        scope_error,
    )

try:  # pragma: no cover
    import boto3
    from boto3.dynamodb.conditions import Attr, Key
    from botocore.exceptions import ClientError
except ModuleNotFoundError:  # Keep dependency-free unit tests importable locally.
    boto3 = None

    class _Condition:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.field = str(args[0]) if args else kwargs.get("field")
            self.operator = kwargs.get("operator")
            self.value = kwargs.get("value")
            self.clauses = kwargs.get("clauses")

        def eq(self, value: Any) -> "_Condition":
            return _Condition(field=self.field, operator="eq", value=value)

        def begins_with(self, value: Any) -> "_Condition":
            return _Condition(field=self.field, operator="begins_with", value=value)

        def between(self, start: Any, end: Any) -> "_Condition":
            return _Condition(field=self.field, operator="between", value=(start, end))

        def not_exists(self) -> "_Condition":
            return _Condition(field=self.field, operator="not_exists")

        def __and__(self, other: Any) -> "_Condition":
            return _Condition(clauses=[self, other])

    Attr = _Condition
    Key = _Condition

    class ClientError(Exception):
        pass

try:  # pragma: no cover
    from audit_delivery import deliver_event
    from audit import event_matches, normalise_filters
    from capture import capture_action, capture_policy_summary
    from citation import set_source_remote_retriever, verify_response
    from control_plane import (
        SESSION_COOKIE_NAME,
        clear_session_cookie,
        is_session_auth,
        membership_record,
        membership_summary,
        normalise_role,
        normalise_subject,
        parse_cookie,
        role_allows,
        role_scopes,
        session_hash,
        session_cookie,
        session_inactivity_ttl,
        session_ttl,
        portal_origin,
    )
    from federation import decode_unverified, verify_federated_token, verify_oauth2_token
    from governance import (
        documentation_metadata,
        normalise_concern,
        normalise_data_resource,
        normalise_documentation,
        normalise_nonconformity,
        normalise_supplier,
    )
    from guard import DECISION_RANK, action_hash, build_receipt, evaluate, normalise_action, receipt_public_key, utc_now, verify_receipt
    from identity import (
        MAX_DELEGATION_DEPTH,
        authorize_action,
        authority_rank,
        build_agent_record,
        check_approval_separation,
        normalise_authority_level,
        normalise_delegation_chain,
    )
    from metrics import aggregate, metric_updates
    from model_registry import model_risk_at_least, normalise_model_record
    from policy import apply_policies, build_policy_record, normalise_test_cases
    from proof import apply_capture, attach_outcome, attach_receipt, build_proof_record, render_report, verify_integrity
    from report import extract_report_citations
    from starter_rules import custom_starter_policy, default_starter_rules, normalise_starter_rules, starter_rule_summary
    from workload_identity import aws_iam_context, map_aws_iam_principal
    from tenant import (
        build_environment_config,
        build_tenant_config,
        default_tenant_config,
        enabled_products_for_config,
        environment_for,
        is_retained_item,
        iso_from_epoch,
        retention_cutoff,
        runtime_constraints,
        TENANT_STATUSES,
    )
except ModuleNotFoundError:  # Local package import during tests.
    from .audit_delivery import deliver_event
    from .audit import event_matches, normalise_filters
    from .capture import capture_action, capture_policy_summary
    from .citation import set_source_remote_retriever, verify_response
    from .control_plane import (
        SESSION_COOKIE_NAME,
        clear_session_cookie,
        is_session_auth,
        membership_record,
        membership_summary,
        normalise_role,
        normalise_subject,
        parse_cookie,
        role_allows,
        role_scopes,
        session_hash,
        session_cookie,
        session_inactivity_ttl,
        session_ttl,
        portal_origin,
    )
    from .federation import decode_unverified, verify_federated_token, verify_oauth2_token
    from .governance import (
        documentation_metadata,
        normalise_concern,
        normalise_data_resource,
        normalise_documentation,
        normalise_nonconformity,
        normalise_supplier,
    )
    from .guard import DECISION_RANK, action_hash, build_receipt, evaluate, normalise_action, receipt_public_key, utc_now, verify_receipt
    from .identity import (
        MAX_DELEGATION_DEPTH,
        authorize_action,
        authority_rank,
        build_agent_record,
        check_approval_separation,
        normalise_authority_level,
        normalise_delegation_chain,
    )
    from .metrics import aggregate, metric_updates
    from .model_registry import model_risk_at_least, normalise_model_record
    from .policy import apply_policies, build_policy_record, normalise_test_cases
    from .proof import apply_capture, attach_outcome, attach_receipt, build_proof_record, render_report, verify_integrity
    from .report import extract_report_citations
    from .starter_rules import custom_starter_policy, default_starter_rules, normalise_starter_rules, starter_rule_summary
    from .workload_identity import aws_iam_context, map_aws_iam_principal
    from .tenant import (
        build_environment_config,
        build_tenant_config,
        default_tenant_config,
        enabled_products_for_config,
        environment_for,
        is_retained_item,
        iso_from_epoch,
        retention_cutoff,
        runtime_constraints,
        TENANT_STATUSES,
    )


TABLE_NAME = os.environ.get("AUDIT_TABLE_NAME", "")
TOKEN_TABLE_NAME = os.environ.get("TOKEN_TABLE_NAME", "")
PASSKEY_FLOW_COOKIE_NAME = "kta_passkey_flow"
TOKEN_TENANT_INDEX_NAME = os.environ.get("TOKEN_TENANT_INDEX_NAME", "tenant-token-index")
TOKEN_AGENT_INDEX_NAME = os.environ.get("TOKEN_AGENT_INDEX_NAME", "agent-token-index")
ENVIRONMENT = os.environ.get("KENNING_ENV", "prototype")
RELEASE_ID = os.environ.get("RELEASE_ID", "")
RELEASE_SOURCE_COMMIT = os.environ.get("RELEASE_SOURCE_COMMIT", "")
PAT_TOKEN_SCAN_PAGE_SIZE = 1000
RELEASE_NAME = os.environ.get("RELEASE_NAME", "")
RELEASE_VERSION = os.environ.get("RELEASE_VERSION", "")
# A private deployment can pin every request to the one workspace provisioned
# for the customer.  Keep the default empty so the hosted multi-tenant service
# retains its existing routing behaviour.
SINGLE_TENANT_ID = os.environ.get("CONTROL_PLANE_SINGLE_TENANT_ID", "").strip()
PAT_SCOPES = {
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
    "token:admin",
    "session:create",
}
dynamodb = boto3.resource("dynamodb") if boto3 is not None else None
dynamodb_client = (
    boto3.client("dynamodb", region_name=os.environ.get("AWS_REGION", "us-east-1"))
    if boto3 is not None
    else None
)
secrets_client = boto3.client("secretsmanager") if boto3 is not None else None
cognito_idp = (
    boto3.client("cognito-idp", region_name=os.environ.get("AWS_REGION", "us-east-1"))
    if boto3 is not None
    else None
)
table = dynamodb.Table(TABLE_NAME) if TABLE_NAME and dynamodb is not None else None
token_table = dynamodb.Table(TOKEN_TABLE_NAME) if TOKEN_TABLE_NAME and dynamodb is not None else None
CITATION_FETCHER_FUNCTION_NAME = os.environ.get("CITATION_FETCHER_FUNCTION_NAME", "").strip()
CITATION_FETCHER_REGION = os.environ.get("CITATION_FETCHER_REGION", "us-east-1").strip() or "us-east-1"
lambda_client = (
    boto3.client("lambda", region_name=CITATION_FETCHER_REGION)
    if boto3 is not None and CITATION_FETCHER_FUNCTION_NAME
    else None
)
# Duration-based approval grants (#242). Allowed durations in seconds; a reviewer
# picks one when approving "for a while". The server-side maximum bounds the set.
GRANT_DURATION_OPTIONS_SECONDS = (15 * 60, 60 * 60, 4 * 60 * 60)
GRANT_MAX_DURATION_SECONDS = 4 * 60 * 60
GRANT_DEFAULT_DURATION_SECONDS = 60 * 60


def _fetch_citation_source_remotely(  # pragma: no cover
    url: str,
    max_source_bytes: int,
    timeout_seconds: float,
    user_agent: str,
) -> dict[str, Any]:
    """Invoke the private browser-compatible citation transport Lambda."""

    if lambda_client is None or not CITATION_FETCHER_FUNCTION_NAME:
        return {"retrieval_status": "transport_error", "error": "Citation fetcher is not configured."}
    payload = {
        "url": url,
        "max_source_bytes": int(max_source_bytes),
        "timeout_seconds": max(1.0, min(12.0, float(timeout_seconds))),
        "user_agent": user_agent,
    }
    try:
        invoked = lambda_client.invoke(
            FunctionName=CITATION_FETCHER_FUNCTION_NAME,
            InvocationType="RequestResponse",
            Payload=json.dumps(payload).encode("utf-8"),
        )
        raw_result = invoked.get("Payload")
        raw_body = raw_result.read() if raw_result is not None else b"{}"
        result = json.loads(raw_body.decode("utf-8") if isinstance(raw_body, bytes) else str(raw_body))
        if not isinstance(result, dict):
            return {"retrieval_status": "transport_error", "error": "Citation fetcher returned an invalid response."}
        if invoked.get("FunctionError"):
            return {
                "retrieval_status": "transport_error",
                "error": str(result.get("errorMessage") or "Citation fetcher failed.")[:512],
            }
        body_base64 = result.pop("body_base64", None)
        if body_base64:
            result["raw_bytes"] = base64.b64decode(body_base64, validate=True)
        return result
    except Exception as error:
        return {"retrieval_status": "transport_error", "error": str(error)[:512] or type(error).__name__}


if lambda_client is not None:  # pragma: no cover
    set_source_remote_retriever(_fetch_citation_source_remotely)


class ApiError(Exception):
    """Typed API error carrying status, code, and message (#252).

    Raise this instead of bare ValueError/PermissionError in handlers.
    The global exception handler in lambda_handler maps it to a response.
    """

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def response(status_code: int, body: Any, extra_headers: dict[str, str] | None = None) -> dict[str, Any]:
    headers = {
        "content-type": "application/json",
        "cache-control": "no-store",
    }
    if extra_headers:
        headers.update(extra_headers)
    result = {
        "statusCode": status_code,
        "headers": headers,
        "body": json.dumps(body, default=_json_default),
    }
    cookies = [value for key, value in headers.items() if key.lower() == "set-cookie"]
    if cookies:
        # API Gateway HTTP API and Lambda Function URL payload v2 integrations
        # forward cookies through the top-level cookies array. Keep the
        # header too so direct Lambda callers and existing adapters retain the
        # conventional response shape.
        result["cookies"] = cookies
    return result


def raw_response(status_code: int, body: str, content_type: str, extra_headers: dict[str, str] | None = None) -> dict[str, Any]:
    headers = {
        "content-type": content_type,
        "cache-control": "no-store",
    }
    if extra_headers:
        headers.update(extra_headers)
    result = {
        "statusCode": status_code,
        "headers": headers,
        "body": body,
    }
    cookies = [value for key, value in headers.items() if key.lower() == "set-cookie"]
    if cookies:
        result["cookies"] = cookies
    return result


def empty_response(status_code: int, extra_headers: dict[str, str] | None = None) -> dict[str, Any]:
    headers = extra_headers or {}
    result = {
        "statusCode": status_code,
        "headers": headers,
        "body": "",
    }
    cookies = [value for key, value in headers.items() if key.lower() == "set-cookie"]
    if cookies:
        result["cookies"] = cookies
    return result


def _json_default(value: Any) -> Any:
    if isinstance(value, Decimal):
        return int(value) if value % 1 == 0 else float(value)
    raise TypeError(f"Cannot serialise {type(value).__name__}")


def _dynamodb_safe(value: Any) -> Any:
    """Convert JSON floats to DynamoDB-safe Decimal values before persistence."""

    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, dict):
        return {key: _dynamodb_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_dynamodb_safe(item) for item in value]
    return value


def parse_body(event: dict[str, Any]) -> dict[str, Any]:
    raw_body = event.get("body") or "{}"
    if event.get("isBase64Encoded"):
        raw_body = base64.b64decode(raw_body).decode("utf-8")
    parsed = json.loads(raw_body)
    if not isinstance(parsed, dict):
        raise ValueError("Request body must be a JSON object.")
    return parsed


def path_and_method(event: dict[str, Any]) -> tuple[str, str]:
    request_context = event.get("requestContext") or {}
    http = request_context.get("http") or {}
    method = str(http.get("method") or event.get("httpMethod") or "GET").upper()
    path = str(event.get("rawPath") or event.get("path") or "/")
    return path.rstrip("/") or "/", method


def configured_single_tenant_id() -> str:
    """Return the optional workspace pin used by a single-tenant deployment."""

    return str(os.environ.get("CONTROL_PLANE_SINGLE_TENANT_ID") or SINGLE_TENANT_ID or "").strip()


def enforce_single_tenant(tenant_id: Any, *, allow_empty: bool = False) -> str:
    """Apply the deployment workspace boundary before normal tenant routing."""

    requested = str(tenant_id or "").strip()
    configured = configured_single_tenant_id()
    if configured:
        if requested and requested != configured:
            raise ApiError(403, "single_tenant_mismatch", "This deployment accepts only its configured workspace.")
        return configured
    if requested or allow_empty:
        return requested
    return ""


def tenant_from(event: dict[str, Any], body: dict[str, Any] | None = None, auth: dict[str, Any] | None = None) -> str:
    query = event.get("queryStringParameters") or {}
    if body:
        context = body.get("context") if isinstance(body.get("context"), dict) else {}
        requested = context.get("tenant_id") or body.get("tenant_id") or query.get("tenant_id") or (auth or {}).get("tenant_id") or "demo"
        return enforce_single_tenant(requested)
    requested = query.get("tenant_id") or (auth or {}).get("tenant_id") or "demo"
    return enforce_single_tenant(requested)


def request_headers(event: dict[str, Any]) -> dict[str, str]:
    headers = {str(key).lower(): str(value) for key, value in (event.get("headers") or {}).items()}
    # HTTP API payload v2 represents incoming Cookie headers as an array on
    # the event. Normalise it so the same session parser works for direct
    # Lambda tests, Function URLs, and API Gateway integrations.
    if "cookie" not in headers and event.get("cookies"):
        headers["cookie"] = "; ".join(str(value) for value in event.get("cookies") or [])
    return headers


def auth_error() -> dict[str, Any]:
    return response(401, {"error": "unauthorized", "message": "A valid Bearer credential or AWS IAM workload identity is required."}, {"www-authenticate": "Bearer"})


def session_authentication(event: dict[str, Any]) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Authenticate an opaque browser session without accepting its contents as claims."""

    if token_table is None:
        return None, None
    cookie_token = parse_cookie(request_headers(event).get("cookie"), SESSION_COOKIE_NAME)
    if not cookie_token:
        return None, None
    record = token_table.get_item(Key={"token_hash": session_hash(cookie_token)}).get("Item")
    if not record or record.get("token_type") != "session" or record.get("status") != "active":
        return None, auth_error()
    expires_at = record.get("expires_at")
    if expires_at is not None and int(expires_at) <= int(time.time()):
        return None, auth_error()
    now = int(time.time())
    last_activity_at = int(record.get("last_activity_at") or now)
    if now - last_activity_at > session_inactivity_ttl():
        try:
            token_table.update_item(
                Key={"token_hash": session_hash(cookie_token)},
                UpdateExpression="SET #status = :revoked, revoked_at = :now, revoke_reason = :reason",
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={":revoked": "revoked", ":now": utc_now(), ":reason": "inactivity_timeout"},
            )
        except Exception:
            pass
        return None, auth_error()
    if last_activity_at != now:
        try:
            token_table.update_item(
                Key={"token_hash": session_hash(cookie_token)},
                UpdateExpression="SET last_activity_at = :last_activity_at",
                ExpressionAttributeValues={":last_activity_at": now},
            )
        except Exception:
            pass
    auth = dict(record)
    configured_tenant = configured_single_tenant_id()
    record_tenant = str(auth.get("tenant_id") or "").strip()
    if configured_tenant and record_tenant and record_tenant != configured_tenant:
        return None, auth_error()
    if configured_tenant and not record_tenant:
        auth["tenant_id"] = configured_tenant
    auth["auth_source"] = "session"
    auth["token_type"] = "session"
    auth["session_id"] = record.get("token_id")
    auth["last_activity_at"] = now
    auth["scopes"] = list(record.get("session_scopes") or []) if record.get("platform_admin") else []
    return auth, None


def validate_session_csrf(event: dict[str, Any], auth: dict[str, Any], method: str) -> None:
    if not is_session_auth(auth) or method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return
    provided = request_headers(event).get("x-kenning-csrf", "")
    expected_hash = str(auth.get("csrf_hash") or "")
    if not provided or not expected_hash or not secrets.compare_digest(session_hash(provided), expected_hash):
        raise ApiError(403, "csrf_required", "A valid X-Kenning-CSRF header is required for browser session mutations.")


def record_auth_failure(event: dict[str, Any], reason: str, tenant_id: str | None = None, tenant_hint: str | None = None) -> None:
    """Best-effort audit of an authentication failure without storing bearer material."""

    if table is None:
        return
    event_context = event.get("requestContext") if isinstance(event.get("requestContext"), dict) else {}
    request_id = str(event_context.get("requestId") or event_context.get("request_id") or "")
    headers = request_headers(event)
    presented = headers.get("authorization", "")
    auth_method = "aws_iam" if aws_iam_context(event) is not None else "bearer_pat" if presented.lower().startswith("bearer kta_pat_") else "bearer_agent" if presented.lower().startswith("bearer kta_agent_") else "bearer_jwt" if presented.lower().startswith("bearer ") else "unknown"
    audit_event = {
        "event_type": "auth.failed",
        "tenant_id": str(tenant_id or "system"),
        "environment": "security",
        "run_id": "authentication",
        "action_id": request_id or f"auth-{uuid.uuid4().hex[:16]}",
        "agent_id": "authentication-gateway",
        "invoked_by": "unauthenticated",
        "created_at": utc_now(),
        "status": "denied",
        "auth_method": auth_method,
        "failure_reason": str(reason),
        "tenant_hint": str(tenant_hint or "")[:128] or None,
    }
    try:
        AuditStore(table, secrets_client).put_event(audit_event)
    except Exception as exc:
        # Authentication must remain fail-closed even if its audit record cannot
        # be written. CloudWatch still receives the non-secret failure class.
        print(f"authentication audit failed: {type(exc).__name__}")


def _oauth_client_secret(secret_arn: str) -> str:
    if secrets_client is None:
        raise RuntimeError("AWS Secrets Manager is unavailable.")
    result = secrets_client.get_secret_value(SecretId=secret_arn)
    secret_string = result.get("SecretString")
    if secret_string:
        try:
            parsed = json.loads(secret_string)
        except (TypeError, ValueError, json.JSONDecodeError):
            return str(secret_string)
        if isinstance(parsed, dict):
            for key in ("client_secret", "secret", "value", "password"):
                if parsed.get(key):
                    return str(parsed[key])
        raise ValueError("OAuth client secret must be a string or a supported JSON secret field.")
    secret_binary = result.get("SecretBinary")
    if secret_binary:
        return str(secret_binary)
    raise ValueError("OAuth client secret is empty.")


def _authenticate_workload_identity(
    event: dict[str, Any],
    body: dict[str, Any] | None,
    headers: dict[str, str],
    iam_context: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    if table is None:
        record_auth_failure(event, "workload_identity_store_unavailable")
        return None, auth_error()
    body_context = body.get("context") if isinstance(body, dict) and isinstance(body.get("context"), dict) else {}
    tenant_hint = str(
        headers.get("x-kenning-tenant-id")
        or body_context.get("tenant_id")
        or (body.get("tenant_id") if isinstance(body, dict) else "")
        or ((event.get("queryStringParameters") or {}).get("tenant_id") or "")
    ).strip()
    tenant_hint = tenant_hint or configured_single_tenant_id()
    if not tenant_hint:
        record_auth_failure(event, "workload_identity_missing_tenant")
        return None, auth_error()
    try:
        tenant_hint = enforce_single_tenant(tenant_hint)
    except ApiError:
        record_auth_failure(event, "workload_identity_single_tenant_mismatch", tenant_hint=tenant_hint)
        return None, auth_error()
    try:
        config_result = table.get_item(Key={"pk": f"TENANT#{tenant_hint}", "sk": "CONFIG"})
        config = config_result.get("Item") or {}
        record = map_aws_iam_principal(iam_context, tenant_hint, config.get("workload_identity"))
        registered_agent = AuditStore(table, secrets_client).get_agent(str(record["agent_id"]), tenant_hint)
        if not registered_agent or str(registered_agent.get("tenant_id")) != tenant_hint or registered_agent.get("status") == "revoked":
            raise ValueError("The mapped AWS IAM workload agent is not active and registered for this tenant.")
        return record, None
    except Exception:
        record_auth_failure(event, "workload_identity_invalid_or_unmapped", tenant_hint=tenant_hint)
        return None, auth_error()


def _authenticate_bearer_token(
    event: dict[str, Any],
    presented: str,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    if token_table is None:
        record_auth_failure(event, "token_store_unavailable")
        return None, auth_error()
    token_hash = hashlib.sha256(presented.encode("utf-8")).hexdigest()
    result = token_table.get_item(Key={"token_hash": token_hash})
    record = result.get("Item")
    if not record or record.get("status") != "active":
        record_auth_failure(event, "token_not_found_or_inactive")
        return None, auth_error()
    expires_at = record.get("expires_at")
    if expires_at is not None and int(expires_at) <= int(time.time()):
        record_auth_failure(event, "token_expired", tenant_id=str(record.get("tenant_id") or "system"))
        return None, auth_error()
    record = dict(record)
    try:
        configured_tenant = configured_single_tenant_id()
        if configured_tenant and str(record.get("tenant_id") or "") != configured_tenant:
            record_auth_failure(event, "token_single_tenant_mismatch", tenant_id=str(record.get("tenant_id") or "system"))
            return None, auth_error()
    except ApiError:
        record_auth_failure(event, "token_single_tenant_mismatch")
        return None, auth_error()
    record.setdefault("token_type", "pat")
    if record.get("token_type") == "agent" and not record.get("agent_id"):
        record_auth_failure(event, "agent_credential_missing_identity", tenant_id=str(record.get("tenant_id") or "system"))
        return None, auth_error()
    return record, None


def _authenticate_federated(
    event: dict[str, Any],
    body: dict[str, Any] | None,
    headers: dict[str, str],
    presented: str,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    if table is None:
        record_auth_failure(event, "unsupported_bearer_token")
        return None, auth_error()
    tenant_hint = ""
    headers_tenant_hint = str(headers.get("x-kenning-tenant-id") or "").strip()
    body_context = body.get("context") if isinstance(body, dict) and isinstance(body.get("context"), dict) else {}
    body_tenant_hint = ""
    if isinstance(body, dict):
        body_tenant_hint = str(body_context.get("tenant_id") or body.get("tenant_id") or "").strip()
    query_tenant_hint = str((event.get("queryStringParameters") or {}).get("tenant_id") or "").strip()
    explicit_tenant_hint = headers_tenant_hint or body_tenant_hint or query_tenant_hint
    try:
        if presented.count(".") == 2:
            _, unverified_claims, _, _ = decode_unverified(presented)
            claim_tenant_hint = str(
                unverified_claims.get("tenant_id")
                or unverified_claims.get("tenant")
                or unverified_claims.get("tid")
                or ""
            ).strip()
            if explicit_tenant_hint and claim_tenant_hint and explicit_tenant_hint != claim_tenant_hint:
                record_auth_failure(event, "federated_tenant_hint_mismatch", tenant_hint=explicit_tenant_hint)
                return None, auth_error()
            tenant_hint = claim_tenant_hint or explicit_tenant_hint
        else:
            tenant_hint = explicit_tenant_hint
        tenant_hint = tenant_hint or configured_single_tenant_id()
        if not tenant_hint:
            record_auth_failure(event, "federated_token_missing_tenant")
            return None, auth_error()
        try:
            tenant_hint = enforce_single_tenant(tenant_hint)
        except ApiError:
            record_auth_failure(event, "federated_single_tenant_mismatch", tenant_hint=tenant_hint)
            return None, auth_error()
        config_result = table.get_item(Key={"pk": f"TENANT#{tenant_hint}", "sk": "CONFIG"})
        config = config_result.get("Item") or {}
        provider = config.get("identity_provider") if isinstance(config.get("identity_provider"), dict) else {}
        if not provider.get("enabled"):
            record_auth_failure(event, "federation_not_configured", tenant_hint=tenant_hint)
            return None, auth_error()
        provider = dict(provider)
        provider["tenant_id"] = tenant_hint
        if provider.get("validation_mode") == "introspection":
            record = verify_oauth2_token(presented, provider, _oauth_client_secret)
        elif presented.count(".") == 2:
            record = verify_federated_token(presented, provider)
        else:
            record_auth_failure(event, "opaque_token_requires_introspection", tenant_hint=tenant_hint)
            return None, auth_error()
        if str(record.get("tenant_id")) != tenant_hint:
            record_auth_failure(event, "federated_tenant_mismatch", tenant_hint=tenant_hint)
            return None, auth_error()
        if configured_single_tenant_id() and str(record.get("tenant_id")) != configured_single_tenant_id():
            record_auth_failure(event, "federated_single_tenant_mismatch", tenant_hint=tenant_hint)
            return None, auth_error()
        return record, None
    except Exception:
        record_auth_failure(event, "federated_token_invalid", tenant_hint=tenant_hint)
        return None, auth_error()


def authenticate(event: dict[str, Any], body: dict[str, Any] | None = None) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    headers = request_headers(event)
    session, session_failure = session_authentication(event)
    if session:
        return session, None
    if session_failure:
        record_auth_failure(event, "session_not_found_or_expired")
        return None, session_failure
    iam_context = aws_iam_context(event)
    if iam_context is not None:
        return _authenticate_workload_identity(event, body, headers, iam_context)
    value = headers.get("authorization", "")
    # Some embedded browsers strip the standard Authorization header from a
    # cross-origin credential exchange even when the CORS preflight permits
    # it.  Keep the compatibility path narrowly scoped to browser-session
    # creation; all other API calls must continue to use Authorization.
    if not value and path_and_method(event) == ("/auth/session", "POST"):
        presented_pat = headers.get("x-kenning-pat", "").strip()
        if not presented_pat and isinstance(body, dict):
            presented_pat = str(body.get("personal_access_token") or "").strip()
        if presented_pat:
            value = f"Bearer {presented_pat}"
    scheme, separator, presented = value.partition(" ")
    if scheme.lower() != "bearer" or not separator or not presented:
        record_auth_failure(event, "missing_or_malformed_bearer")
        return None, auth_error()
    if presented.startswith(("kta_pat_", "kta_agent_")):
        return _authenticate_bearer_token(event, presented)
    return _authenticate_federated(event, body, headers, presented)


def product_access_error(product_id: str, auth: dict[str, Any], tenant_id: str | None = None) -> dict[str, Any] | None:
    """Return a stable authorization error when a workspace disabled a product."""

    target_tenant = str(tenant_id or auth.get("tenant_id") or "").strip()
    if not target_tenant:
        return response(403, {"error": "tenant_required"})
    try:
        config = store().get_tenant_config(target_tenant) or default_tenant_config(target_tenant)
    except Exception as exc:
        # Entitlement lookup is part of authorization. A store outage must not
        # turn a disabled product into an enabled product.
        print(f"Product entitlement lookup unavailable: {type(exc).__name__}")
        return response(
            503,
            {
                "error": "product_access_unavailable",
                "message": "Workspace product access could not be verified. Retry after the service recovers.",
                "retryable": True,
            },
            {"retry-after": "1"},
        )
    if product_id in enabled_products_for_config(config):
        return None
    return response(
        403,
        {
            "error": "product_disabled",
            "product_id": product_id,
            "message": f"The {product_id} product is disabled for this workspace.",
        },
    )


class GuardEvaluationError(RuntimeError):
    """Identify the evaluation phase that made fail-closed handling necessary."""

    def __init__(self, stage: str, cause: Exception) -> None:
        self.stage = str(stage)
        self.cause = cause
        super().__init__(f"Guard evaluation failed during {self.stage}.")


@contextmanager
def _guard_failure_stage(stage: str):
    try:
        yield
    except (ValueError, PermissionError, ApiError):
        raise
    except GuardEvaluationError:
        raise
    except Exception as exc:
        raise GuardEvaluationError(stage, exc) from exc


def _guard_failure_diagnostics(exc: Exception) -> dict[str, Any]:
    """Return safe details that let an operator correlate a fail-closed response."""

    stage = "unknown"
    error_type = type(exc).__name__
    error_code = ""
    request_id = ""
    error_message = ""
    current: BaseException | None = exc
    seen: set[int] = set()
    while isinstance(current, BaseException) and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, GuardEvaluationError):
            stage = current.stage
        else:
            error_type = type(current).__name__
        error_response = getattr(current, "response", None)
        if isinstance(error_response, dict):
            error_details = error_response.get("Error")
            if isinstance(error_details, dict):
                error_code = str(error_details.get("Code") or error_code)
                raw_message = str(error_details.get("Message") or "")
                if raw_message:
                    error_message = " ".join(raw_message.split())
            metadata = error_response.get("ResponseMetadata")
            if isinstance(metadata, dict):
                request_id = str(metadata.get("RequestId") or request_id)
        current = (
            getattr(current, "__cause__", None)
            or getattr(current, "cause", None)
            or getattr(current, "__context__", None)
        )
    diagnostics: dict[str, Any] = {
        "failure_stage": stage,
        "error_type": error_type,
    }
    if error_code:
        diagnostics["error_code"] = error_code
    if request_id:
        diagnostics["request_id"] = request_id
    if error_message:
        safe_message = re.sub(
            r"(?i)(authorization|token|secret|password)\s*[:=]\s*\S+",
            r"\1=<redacted>",
            error_message,
        )
        diagnostics["error_message"] = safe_message[:240]
    return diagnostics


def _guard_request_id(event: dict[str, Any] | None) -> str | None:
    request_context = event.get("requestContext") if isinstance(event, dict) else {}
    if not isinstance(request_context, dict):
        return None
    request_id = str(request_context.get("requestId") or request_context.get("extendedRequestId") or "").strip()
    return request_id[:128] or None


def guard_unavailable_payload(payload: dict[str, Any], auth: dict[str, Any], diagnostics: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the explicit fail-closed response used when Guard cannot finish."""

    context = payload.get("context") if isinstance(payload.get("context"), dict) else {}
    mode = str(payload.get("mode") or context.get("mode") or "enforce").lower()
    if mode not in {"observe", "enforce"}:
        mode = "enforce"
    result: dict[str, Any] = {
        "error": "guard_unavailable",
        "message": "Guard could not complete evaluation or durable recording. Do not execute the action; retry after the service recovers.",
        "decision": "deny",
        "mode": mode,
        "risk": "critical",
        "risk_score": 100,
        "reason_codes": ["GUARD_UNAVAILABLE"],
        "reasons": [
            {
                "code": "GUARD_UNAVAILABLE",
                "message": "The Guard evaluation or durable recording path is unavailable, so enforcement fails closed.",
                "decision": "deny",
            }
        ],
        "tenant_id": str(context.get("tenant_id") or auth.get("tenant_id") or "unknown-tenant"),
        "action_id": str(context.get("action_id") or payload.get("action_id") or "") or None,
        "enforcement": "fail_closed",
        "retryable": True,
    }
    if isinstance(diagnostics, dict):
        public_diagnostics = {
            key: diagnostics[key]
            for key in ("failure_stage", "error_type", "error_code", "request_id", "error_message")
            if diagnostics.get(key)
        }
        if public_diagnostics:
            result["diagnostics"] = public_diagnostics
    return result


def guard_unavailable_response(
    payload: dict[str, Any],
    auth: dict[str, Any],
    exc: Exception,
    event: dict[str, Any] | None = None,
) -> dict[str, Any]:
    diagnostics = _guard_failure_diagnostics(exc)
    request_id = _guard_request_id(event)
    if request_id and not diagnostics.get("request_id"):
        diagnostics["request_id"] = request_id
    print(f"Guard unavailable: {json.dumps(diagnostics, sort_keys=True)}")
    return response(503, guard_unavailable_payload(payload, auth, diagnostics), {"retry-after": "1"})


def bind_tenant(payload: dict[str, Any], auth: dict[str, Any], *, enforce_agent_binding: bool = True) -> dict[str, Any]:
    context = payload.get("context") if isinstance(payload.get("context"), dict) else {}
    requested = context.get("tenant_id") or payload.get("tenant_id")
    configured_tenant = configured_single_tenant_id()
    if configured_tenant:
        if str(auth.get("tenant_id") or "") != configured_tenant:
            raise ApiError(403, "single_tenant_mismatch", "The authenticated credential is not issued for this deployment workspace.")
        if requested and str(requested) != configured_tenant:
            raise ApiError(403, "single_tenant_mismatch", "This deployment accepts only its configured workspace.")
        context["tenant_id"] = configured_tenant
    else:
        context["tenant_id"] = str(requested or auth["tenant_id"])
    if requested and str(requested) != str(auth.get("tenant_id")) and not has_scope(auth, "admin"):
        raise ApiError(403, "tenant_mismatch", "The PAT is not authorised for the requested tenant.")
    bound_agent = str(auth.get("agent_id") or "")
    requested_agent = context.get("agent_id") or payload.get("agent_id")
    if enforce_agent_binding and bound_agent and requested_agent and str(requested_agent) != bound_agent:
        raise ApiError(403, "agent_credential_mismatch", "The agent credential is bound to a different agent identity.")
    if enforce_agent_binding and bound_agent:
        context["agent_id"] = bound_agent
    if auth.get("auth_source") in {"oidc", "oauth2", "aws_iam"}:
        subject = str(auth.get("subject") or "")
        requested_invoker = context.get("invoked_by") or payload.get("invoked_by")
        if requested_invoker and str(requested_invoker) != subject:
            raise ApiError(403, "subject_mismatch", "The federated identity cannot claim a different invoking subject.")
        if subject:
            context["invoked_by"] = subject
    payload["context"] = context
    return payload


def _is_conditional_check_failure(exc: Exception) -> bool:
    """Recognise DynamoDB conditional conflicts in AWS and dependency-free tests."""

    error = getattr(exc, "response", {})
    if isinstance(error, dict):
        code = error.get("Error", {}).get("Code")
        if code == "ConditionalCheckFailedException":
            return True
        if code == "TransactionCanceledException":
            # A transaction is cancelled when any item's condition fails.
            # Distinguish a rate-limit condition failure from an infrastructure
            # cancellation (e.g. item too large) by inspecting the reasons.
            reasons = error.get("CancellationReasons") or []
            return any(
                isinstance(reason, dict) and reason.get("Code") == "ConditionalCheckFailed"
                for reason in reasons
            )
    return boto3 is None and isinstance(exc, ClientError)


# AuditStore and its store() factory live in app/store.py (#249).
try:  # pragma: no cover
    from store import AuditStore, store
except ModuleNotFoundError:  # Local package import during tests.
    from .store import AuditStore, store


def tenant_target(tenant_id: str, auth: dict[str, Any]) -> tuple[str | None, dict[str, Any] | None]:
    tenant_id = str(tenant_id or auth.get("tenant_id") or "")
    configured_tenant = configured_single_tenant_id()
    if configured_tenant and (tenant_id != configured_tenant or str(auth.get("tenant_id") or "") != configured_tenant):
        return None, response(403, {"error": "single_tenant_mismatch"})
    if tenant_id != str(auth.get("tenant_id")) and not has_scope(auth, "admin"):
        return None, response(403, {"error": "tenant_mismatch"})
    return tenant_id, None


def control_plane_tenant_hint(event: dict[str, Any], body: dict[str, Any] | None, auth: dict[str, Any]) -> str:
    headers = request_headers(event)
    query = event.get("queryStringParameters") or {}
    context = body.get("context") if isinstance(body, dict) and isinstance(body.get("context"), dict) else {}
    requested = str(
        headers.get("x-kenning-tenant-id")
        or query.get("tenant_id")
        or context.get("tenant_id")
        or (body.get("tenant_id") if isinstance(body, dict) else "")
        or auth.get("tenant_id")
        or ""
    ).strip()
    return enforce_single_tenant(requested or configured_single_tenant_id())


def apply_control_plane_membership(event: dict[str, Any], body: dict[str, Any] | None, auth: dict[str, Any]) -> dict[str, Any]:
    """Resolve the active tenant from a verified session and its membership."""

    if not is_session_auth(auth):
        return auth
    subject = normalise_subject(auth.get("subject"))
    tenant_id = control_plane_tenant_hint(event, body, auth)
    if not tenant_id:
        raise ApiError(403, "membership_required", "Select a tenant membership before accessing tenant-scoped resources.")
    membership = store().get_membership(subject, tenant_id)
    if not membership or membership.get("status") != "active":
        raise ApiError(403, "membership_required", "The signed-in user is not an active member of the requested tenant.")
    auth.update({
        "tenant_id": tenant_id,
        "role": membership.get("role"),
        "membership": membership_summary(membership),
        "scopes": role_scopes(str(membership.get("role") or "viewer")),
        "email": membership.get("email"),
        "display_name": membership.get("display_name"),
    })
    return auth


def control_plane_admin(tenant_id: str, event: dict[str, Any], body: dict[str, Any] | None, auth: dict[str, Any]) -> dict[str, Any] | None:
    """Require a tenant owner/admin for membership administration.

    Machine PATs retain a deliberate POC administration path through their
    existing tenant:write scope. Browser sessions must have an
    active server-side owner or admin membership.
    """

    if is_session_auth(auth):
        apply_control_plane_membership(event, body, auth)
        if not role_allows(str(auth.get("role") or "viewer"), "admin"):
            return response(403, {"error": "membership_role_required", "required_role": "admin"})
        if str(auth.get("tenant_id")) != str(tenant_id):
            return response(403, {"error": "tenant_mismatch"})
        return None
    target, error = tenant_target(tenant_id, auth)
    if error:
        return error
    if not (has_scope(auth, "admin") or has_scope(auth, "tenant:write")):
        return response(403, {"error": "membership_role_required", "required_role": "admin"})
    return None


def control_plane_oidc_config() -> dict[str, str] | None:
    issuer = str(os.environ.get("CONTROL_PLANE_OIDC_ISSUER_URL") or "").strip().rstrip("/")
    client_id = str(os.environ.get("CONTROL_PLANE_OIDC_CLIENT_ID") or "").strip()
    redirect_uri = str(os.environ.get("CONTROL_PLANE_OIDC_REDIRECT_URI") or "").strip()
    authorization_url = str(os.environ.get("CONTROL_PLANE_OIDC_AUTHORIZATION_URL") or "").strip()
    token_url = str(os.environ.get("CONTROL_PLANE_OIDC_TOKEN_URL") or "").strip()
    if not all((issuer, client_id, redirect_uri, authorization_url, token_url)):
        return None
    for name, value in (
        ("issuer_url", issuer),
        ("redirect_uri", redirect_uri),
        ("authorization_url", authorization_url),
        ("token_url", token_url),
    ):
        parsed = urlparse(value)
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password or any(char.isspace() for char in value):
            raise ValueError(f"CONTROL_PLANE_OIDC_{name.upper()} must be an HTTPS URL.")
    jwks_url = str(os.environ.get("CONTROL_PLANE_OIDC_JWKS_URL") or "").strip()
    if jwks_url:
        parsed_jwks = urlparse(jwks_url)
        if parsed_jwks.scheme != "https" or not parsed_jwks.netloc or parsed_jwks.username or parsed_jwks.password or any(char.isspace() for char in jwks_url):
            raise ValueError("CONTROL_PLANE_OIDC_JWKS_URL must be an HTTPS URL.")
    return {
        "issuer_url": issuer,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "authorization_url": authorization_url,
        "token_url": token_url,
        "logout_url": str(os.environ.get("CONTROL_PLANE_OIDC_LOGOUT_URL") or "").strip(),
        "jwks_url": jwks_url,
        "scope": str(os.environ.get("CONTROL_PLANE_OIDC_SCOPES") or "openid profile email").strip(),
        "client_secret_arn": str(os.environ.get("CONTROL_PLANE_OIDC_CLIENT_SECRET_ARN") or "").strip(),
        "tenant_claim": str(os.environ.get("CONTROL_PLANE_OIDC_TENANT_CLAIM") or "tenant_id").strip(),
        "subject_claim": str(os.environ.get("CONTROL_PLANE_OIDC_SUBJECT_CLAIM") or "sub").strip(),
        "scope_claim": str(os.environ.get("CONTROL_PLANE_OIDC_SCOPE_CLAIM") or "scope").strip(),
        "groups_claim": str(os.environ.get("CONTROL_PLANE_OIDC_GROUPS_CLAIM") or "groups").strip(),
        "agent_claim": str(os.environ.get("CONTROL_PLANE_OIDC_AGENT_CLAIM") or "agent_id").strip(),
        "passkeys_url": str(os.environ.get("CONTROL_PLANE_OIDC_PASSKEYS_URL") or "").strip(),
        "passkeys_redirect_uri": str(os.environ.get("CONTROL_PLANE_OIDC_PASSKEYS_REDIRECT_URI") or "").strip(),
    }


def control_plane_oidc_logout_url(config: dict[str, str]) -> str:
    """Return the managed-login logout endpoint for the configured provider."""

    configured = str(config.get("logout_url") or "").strip().rstrip("/")
    if configured:
        parsed = urlparse(configured)
        if parsed.scheme != "https" or not parsed.netloc or parsed.fragment:
            raise ValueError("CONTROL_PLANE_OIDC_LOGOUT_URL must be an HTTPS URL without a fragment.")
        return configured
    authorization = urlparse(config["authorization_url"])
    return f"{authorization.scheme}://{authorization.netloc}/logout"


def control_plane_oidc_logout_uri(config: dict[str, str]) -> str:
    """Return the fixed post-logout portal URL registered with the client."""

    origin = portal_origin()
    if not origin:
        redirect = urlparse(config["redirect_uri"])
        origin = f"{redirect.scheme}://{redirect.netloc}"
    return f"{origin}/app"


def handle_auth_logout_redirect() -> dict[str, Any]:
    """Clear the local session cookie and terminate the provider web session."""

    config = control_plane_oidc_config()
    if not config:
        return raw_response(
            302,
            "",
            "text/plain",
            {"location": "/app", "set-cookie": clear_session_cookie(), "cache-control": "no-store"},
        )
    logout_url = control_plane_oidc_logout_url(config)
    logout_uri = control_plane_oidc_logout_uri(config)
    query = urlencode({"client_id": config["client_id"], "logout_uri": logout_uri})
    separator = "&" if "?" in logout_url else "?"
    return raw_response(
        302,
        "",
        "text/plain",
        {
            "location": f"{logout_url}{separator}{query}",
            "set-cookie": clear_session_cookie(),
            "cache-control": "no-store",
        },
    )


def control_plane_provider(config: dict[str, str]) -> dict[str, Any]:
    return {
        "issuer_url": config["issuer_url"],
        "jwks_url": config.get("jwks_url") or None,
        "audience": [config["client_id"]],
        "tenant_claim": config.get("tenant_claim") or "tenant_id",
        "subject_claim": config.get("subject_claim") or "sub",
        "agent_claim": config.get("agent_claim") or "agent_id",
        "scope_claim": config.get("scope_claim") or "scope",
        "groups_claim": config.get("groups_claim") or "groups",
        "allowed_subjects": [],
        "default_scopes": [],
        "principal_type": "user",
        "validation_mode": "jwt",
        # Human directory tokens identify a person, not a single workspace.
        # Workspace membership is resolved from Kenning's server-side records
        # after the OIDC session is established.
        "allow_missing_tenant_claim": True,
    }


def create_browser_session(auth: dict[str, Any], event: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    if token_table is None:
        raise RuntimeError("TOKEN_TABLE_NAME is not configured.")
    subject = normalise_subject(auth.get("subject"))
    session_token = "kta_session_" + secrets.token_urlsafe(48)
    created_at = utc_now()
    expires_at = int(time.time()) + session_ttl()
    session_tenant = str(auth.get("tenant_id") or configured_single_tenant_id() or "").strip()
    session_record: dict[str, Any] = {
        "token_hash": session_hash(session_token),
        "token_id": "session-" + uuid.uuid4().hex[:16],
        "token_type": "session",
        "subject": subject,
        "tenant_id": session_tenant or None,
        "email": auth.get("email"),
        "display_name": auth.get("display_name"),
        "status": "active",
        "created_at": created_at,
        "created_by": subject,
        "expires_at": expires_at,
        "last_activity_at": int(time.time()),
        "platform_admin": is_platform_admin_principal(auth),
        "session_scopes": ["admin"] if is_platform_admin_principal(auth) else [],
        "user_agent_hash": hashlib.sha256(request_headers(event).get("user-agent", "").encode("utf-8")).hexdigest(),
    }
    # The token table has tenant and agent global secondary indexes. DynamoDB
    # rejects NULL values for index keys, and human OIDC identities are
    # deliberately tenant-less until membership resolution selects a workspace.
    if not session_record.get("tenant_id"):
        session_record.pop("tenant_id", None)
    token_table.put_item(Item=_dynamodb_safe(session_record), ConditionExpression=Attr("token_hash").not_exists())
    return session_token, session_record


def handle_auth_config() -> dict[str, Any]:
    try:
        oidc_enabled = control_plane_oidc_config() is not None
    except ValueError:
        # An invalid OIDC URL must not surface as an unhandled API failure or
        # leak internal configuration details. Report a safe, controlled error
        # so the portal can render a stable failure state. See issue #200.
        return response(
            500,
            {
                "error": "auth_configuration_unavailable",
                "message": "Authentication configuration is unavailable. Try again later.",
            },
        )
    passkeys_enabled = str(os.environ.get("CONTROL_PLANE_OIDC_PASSKEYS_ENABLED") or "false").lower() in {"1", "true", "yes"}
    return response(
        200,
        {
            "oidc_enabled": oidc_enabled,
            "passkeys_enabled": passkeys_enabled,
            "session_cookie": SESSION_COOKIE_NAME,
            "session_ttl_seconds": session_ttl(),
            "session_inactivity_seconds": session_inactivity_ttl(),
            "reauth_enabled": oidc_enabled,
            "pat_bootstrap_enabled": str(os.environ.get("CONTROL_PLANE_ALLOW_PAT_BOOTSTRAP") or "false").lower() in {"1", "true", "yes"},
        },
    )


def _confirmation_error(exc: Exception) -> dict[str, Any]:
    """Return a stable, user-safe response for Cognito confirmation errors."""

    error_response = getattr(exc, "response", {}) or {}
    error_code = str((error_response.get("Error") or {}).get("Code") or "")
    mapped = {
        "CodeMismatchException": (400, "invalid_confirmation_code", "That confirmation code is not valid."),
        "ExpiredCodeException": (400, "confirmation_code_expired", "That confirmation code has expired. Request a new code."),
        "NotAuthorizedException": (400, "account_already_confirmed", "This account is already confirmed. Sign in instead."),
        "UserNotFoundException": (404, "account_not_found", "We could not find an account for that email address."),
        "TooManyRequestsException": (429, "confirmation_rate_limited", "Too many requests. Wait a moment and try again."),
        "LimitExceededException": (429, "confirmation_rate_limited", "Too many requests. Wait a moment and try again."),
    }
    status_code, public_code, message = mapped.get(
        error_code,
        (400, "confirmation_failed", "We could not confirm that account. Check the details and try again."),
    )
    return response(status_code, {"error": public_code, "message": message})


def _confirmation_values(body: dict[str, Any], *, require_code: bool) -> tuple[str, str | None, dict[str, Any] | None]:
    username = str(body.get("username") or body.get("email") or "").strip()
    if not username or len(username) > 320 or any(ord(char) < 32 for char in username):
        return "", None, response(400, {"error": "invalid_username", "message": "Enter the email address used to create the account."})
    if not require_code:
        return username, None, None
    code = str(body.get("confirmation_code") or body.get("code") or "").strip()
    if not re.fullmatch(r"[0-9]{4,12}", code):
        return username, None, response(400, {"error": "invalid_confirmation_code", "message": "Enter the numeric confirmation code from your email."})
    return username, code, None


def _confirmation_client() -> tuple[dict[str, str] | None, dict[str, Any] | None]:
    config = control_plane_oidc_config()
    if not config:
        return None, response(503, {"error": "identity_provider_unavailable", "message": "Account confirmation is not configured yet."})
    if cognito_idp is None:
        return None, response(503, {"error": "identity_provider_unavailable", "message": "Account confirmation is temporarily unavailable."})
    return config, None


def handle_auth_confirm(body: dict[str, Any]) -> dict[str, Any]:
    """Confirm a Cognito account from the portal recovery page."""

    username, code, validation_error = _confirmation_values(body, require_code=True)
    if validation_error:
        return validation_error
    config, client_error = _confirmation_client()
    if client_error:
        return client_error
    try:
        cognito_idp.confirm_sign_up(
            ClientId=config["client_id"],
            Username=username,
            ConfirmationCode=code,
        )
    except ClientError as exc:
        return _confirmation_error(exc)
    except Exception as exc:
        print(f"account confirmation failed: {type(exc).__name__}")
        return response(503, {"error": "identity_provider_unavailable", "message": "Account confirmation is temporarily unavailable."})
    return response(200, {"confirmed": True, "message": "Account confirmed. You can now sign in."})


def handle_auth_confirm_resend(body: dict[str, Any]) -> dict[str, Any]:
    """Request a new Cognito confirmation code without requiring a session."""

    username, _, validation_error = _confirmation_values(body, require_code=False)
    if validation_error:
        return validation_error
    config, client_error = _confirmation_client()
    if client_error:
        return client_error
    try:
        result = cognito_idp.resend_confirmation_code(ClientId=config["client_id"], Username=username)
    except ClientError as exc:
        return _confirmation_error(exc)
    except Exception as exc:
        print(f"confirmation resend failed: {type(exc).__name__}")
        return response(503, {"error": "identity_provider_unavailable", "message": "A new confirmation code could not be sent."})
    delivery = result.get("CodeDeliveryDetails") or {}
    return response(
        200,
        {
            "resent": True,
            "message": "A new confirmation code has been sent.",
            "code_delivery_details": {
                "delivery_medium": delivery.get("DeliveryMedium"),
                "destination": delivery.get("Destination"),
            },
        },
    )


def handle_auth_login(event: dict[str, Any], *, force_reauth: bool = False) -> dict[str, Any]:
    config = control_plane_oidc_config()
    if not config:
        return response(404, {"error": "oidc_not_configured"})
    if token_table is None:
        return response(503, {"error": "session_store_unavailable"})
    query = event.get("queryStringParameters") or {}
    return_to = str(query.get("return_to") or "/app").strip()
    reauth_requested = force_reauth or str(query.get("reauth") or "").lower() in {"1", "true", "yes"}
    current_session, session_error = session_authentication(event) if reauth_requested else (None, None)
    if reauth_requested and (session_error or not current_session):
        return auth_error()
    parsed_return = urlparse(return_to)
    if not return_to.startswith("/") or return_to.startswith("//") or parsed_return.scheme or parsed_return.netloc:
        return_to = "/app"
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    invite_token = str(query.get("invite") or "").strip()
    if invite_token and not invite_token.startswith("kta_invite_"):
        invite_token = ""
    state_item: dict[str, Any] = {
        "token_hash": session_hash(state),
        "token_id": "oidc-state-" + uuid.uuid4().hex[:16],
        "token_type": "oidc_state",
        "status": "active",
        "state": state,
        "nonce": nonce,
        "code_verifier": code_verifier,
        "return_to": return_to,
        "reauth_session_hash": current_session.get("token_hash") if current_session else None,
        # A fresh sign-up plus email confirmation can take longer than a plain
        # login, so give invite flows a longer window to reach the callback.
        "expires_at": int(time.time()) + (3600 if invite_token else 600),
    }
    if invite_token:
        state_item["invite_token"] = invite_token
    token_table.put_item(
        Item=state_item,
        ConditionExpression=Attr("token_hash").not_exists(),
    )
    query_string = urlencode({
        "response_type": "code",
        "client_id": config["client_id"],
        "redirect_uri": config["redirect_uri"],
        "scope": config["scope"],
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    if reauth_requested:
        query_string += "&prompt=login&max_age=0"
    return raw_response(302, "", "text/plain", {"location": f"{config['authorization_url']}?{query_string}", "cache-control": "no-store"})


def handle_auth_passkeys(event: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    """Start Cognito Managed Login's authenticated passkey registration flow."""

    config = control_plane_oidc_config()
    if not config:
        return response(404, {"error": "oidc_not_configured"})
    if str(os.environ.get("CONTROL_PLANE_OIDC_PASSKEYS_ENABLED") or "false").lower() not in {"1", "true", "yes"}:
        return response(404, {"error": "passkeys_not_configured"})
    if not is_session_auth(auth):
        return response(403, {"error": "interactive_user_authentication_required"})
    if token_table is None:
        return response(503, {"error": "session_store_unavailable"})

    flow_id = secrets.token_urlsafe(32)
    token_table.put_item(
        Item={
            "token_hash": session_hash(f"passkey-flow:{flow_id}"),
            "token_id": "oidc-state-" + uuid.uuid4().hex[:16],
            "token_type": "passkey_flow",
            "status": "active",
            "flow": "passkey_add",
            "session_hash": auth.get("token_hash"),
            "expires_at": int(time.time()) + 600,
        },
        ConditionExpression=Attr("token_hash").not_exists(),
    )

    configured_url = str(config.get("passkeys_url") or "").strip()
    if configured_url:
        passkeys_url = configured_url
    else:
        authorization = urlparse(config["authorization_url"])
        passkeys_url = f"{authorization.scheme}://{authorization.netloc}/passkeys/add"
    configured_redirect_uri = str(config.get("passkeys_redirect_uri") or "").strip()
    if configured_redirect_uri:
        passkeys_redirect_uri = configured_redirect_uri
    else:
        origin = portal_origin()
        if not origin:
            redirect = urlparse(config["redirect_uri"])
            origin = f"{redirect.scheme}://{redirect.netloc}"
        passkeys_redirect_uri = f"{origin}/auth/passkeys/callback"
    query_string = urlencode({
        "client_id": config["client_id"],
        "redirect_uri": passkeys_redirect_uri,
    })
    flow_cookie = f"{PASSKEY_FLOW_COOKIE_NAME}={flow_id}; Max-Age=600; Path=/auth; HttpOnly; Secure; SameSite=Lax"
    return raw_response(
        302,
        "",
        "text/plain",
        {"location": f"{passkeys_url}?{query_string}", "set-cookie": flow_cookie, "cache-control": "no-store"},
    )


def handle_auth_passkeys_callback(event: dict[str, Any]) -> dict[str, Any]:
    """Complete passkey registration without treating it as an OAuth callback."""

    result = str((event.get("queryStringParameters") or {}).get("result") or "").strip().lower()
    if result and result not in {"success", "added", "registered"}:
        return response(400, {"error": "passkey_registration_failed", "result": result})
    auth, authentication_failure = session_authentication(event)
    if authentication_failure:
        return authentication_failure
    if not auth or not is_session_auth(auth) or token_table is None:
        return auth_error()
    flow_id = parse_cookie(request_headers(event).get("cookie"), PASSKEY_FLOW_COOKIE_NAME)
    if not flow_id:
        return response(400, {"error": "invalid_passkey_callback"})
    flow_hash = session_hash(f"passkey-flow:{flow_id}")
    flow = token_table.get_item(
        Key={"token_hash": flow_hash},
        ConsistentRead=True,
    ).get("Item")
    if (
        not flow
        or flow.get("token_type") != "passkey_flow"
        or flow.get("status") != "active"
        or flow.get("session_hash") != auth.get("token_hash")
    ):
        return response(400, {"error": "invalid_passkey_callback"})
    if int(flow.get("expires_at") or 0) <= int(time.time()):
        return response(400, {"error": "expired_passkey_callback"})
    token_table.update_item(
        Key={"token_hash": flow_hash},
        UpdateExpression="SET #status = :consumed, consumed_at = :now",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={":consumed": "consumed", ":now": utc_now()},
    )
    clear_flow_cookie = f"{PASSKEY_FLOW_COOKIE_NAME}=; Max-Age=0; Path=/auth; HttpOnly; Secure; SameSite=Lax"
    return raw_response(
        302,
        "",
        "text/plain",
        {
            "location": f"{portal_origin()}/app?passkey=added",
            "set-cookie": clear_flow_cookie,
            "cache-control": "no-store",
        },
    )


OIDC_CALLBACK_ERROR_CODES = {
    "invalid_auth_configuration",
    "invalid_oidc_callback",
    "invalid_oidc_state",
    "expired_oidc_state",
    "oidc_authentication_failed",
    "oidc_provider_error",
}


def oidc_callback_error_response(
    error_code: str,
    config: dict[str, str] | None = None,
    *,
    status_code: int = 400,
) -> dict[str, Any]:
    """Return a safe browser recovery response for an OIDC callback failure."""

    safe_code = error_code if error_code in OIDC_CALLBACK_ERROR_CODES else "oidc_authentication_failed"
    print(f"OIDC callback recovery: error={safe_code}")

    origin = ""
    try:
        origin = portal_origin()
    except ValueError:
        # The callback must not surface configuration details to the browser.
        pass
    if not origin and config:
        redirect = urlparse(str(config.get("redirect_uri") or ""))
        if redirect.scheme == "https" and redirect.netloc:
            origin = f"{redirect.scheme}://{redirect.netloc}"
    if origin:
        query = urlencode({"auth_error": safe_code})
        return raw_response(
            302,
            "",
            "text/plain",
            {"location": f"{origin}/app?{query}", "cache-control": "no-store"},
        )
    return response(status_code, {"error": safe_code})


def handle_auth_callback(event: dict[str, Any]) -> dict[str, Any]:
    try:
        config = control_plane_oidc_config()
    except ValueError as exc:
        print(f"OIDC callback rejected invalid configuration: {exc}")
        return oidc_callback_error_response("invalid_auth_configuration", status_code=503)
    if not config or token_table is None:
        return response(404, {"error": "oidc_not_configured"})
    query = event.get("queryStringParameters") or {}
    provider_error = str(query.get("error") or "").strip()
    state = str(query.get("state") or "").strip()
    code = str(query.get("code") or "").strip()
    if provider_error:
        return oidc_callback_error_response("oidc_provider_error", config)
    if not state or not code:
        return oidc_callback_error_response("invalid_oidc_callback", config)
    try:
        state_record = token_table.get_item(
            Key={"token_hash": session_hash(state)},
            ConsistentRead=True,
        ).get("Item")
        if not state_record or state_record.get("token_type") != "oidc_state" or state_record.get("status") != "active":
            return oidc_callback_error_response("invalid_oidc_state", config)
        if int(state_record.get("expires_at") or 0) <= int(time.time()):
            return oidc_callback_error_response("expired_oidc_state", config)
        token_table.update_item(
            Key={"token_hash": session_hash(state)},
            UpdateExpression="SET #status = :revoked, consumed_at = :now",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={":revoked": "consumed", ":now": utc_now()},
        )
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": config["redirect_uri"],
            "client_id": config["client_id"],
            "code_verifier": str(state_record.get("code_verifier") or ""),
        }
        secret_arn = config.get("client_secret_arn") or ""
        if secret_arn:
            form["client_secret"] = _oauth_client_secret(secret_arn)
        request = Request(
            config["token_url"],
            data=urlencode(form).encode("utf-8"),
            method="POST",
            headers={"accept": "application/json", "content-type": "application/x-www-form-urlencoded"},
        )
        with urlopen(request, timeout=5) as upstream:
            token_document = json.loads(upstream.read(1_048_577).decode("utf-8"))
        if not isinstance(token_document, dict) or not token_document.get("id_token"):
            raise ValueError("OIDC token response did not contain an id_token.")
        provider = control_plane_provider(config)
        verified = verify_federated_token(str(token_document["id_token"]), provider)
        _, claims, _, _ = decode_unverified(str(token_document["id_token"]))
        if str(claims.get("nonce") or "") != str(state_record.get("nonce") or ""):
            raise ValueError("OIDC nonce validation failed.")
        session_token, session_record = create_browser_session(verified, event)
        old_session_hash = str(state_record.get("reauth_session_hash") or "")
        if old_session_hash and old_session_hash != session_record.get("token_hash"):
            token_table.update_item(
                Key={"token_hash": old_session_hash},
                UpdateExpression="SET #status = :revoked, revoked_at = :now, revoke_reason = :reason",
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={":revoked": "revoked", ":now": utc_now(), ":reason": "reauthenticated"},
            )
        invite_token = str(state_record.get("invite_token") or "").strip()
        if invite_token:
            invited_subject = str(session_record.get("subject") or "")
            if invited_subject:
                # Redeem the invitation now that the recipient has a verified
                # identity. A failed redemption (expired or already-used token)
                # must not fail the login itself; the portal can offer
                # acceptance again from the no-workspace screen.
                try:
                    _, redeem_error = redeem_invitation(invite_token, invited_subject)
                    if redeem_error:
                        print(f"invitation redemption skipped during callback: {redeem_error}")
                except Exception as redeem_exc:
                    print(f"invitation redemption failed during callback: {type(redeem_exc).__name__}")
        return_to = str(state_record.get("return_to") or "/app")
        if invite_token and "invite=" not in return_to:
            separator = "&" if "?" in return_to else "?"
            return_to = f"{return_to}{separator}{urlencode({'invite': invite_token})}"
    except ClientError as exc:
        error_response = getattr(exc, "response", {}) or {}
        error_code = str((error_response.get("Error") or {}).get("Code") or "unknown")
        operation = str(getattr(exc, "operation_name", "unknown"))
        print(f"OIDC callback failed: ClientError code={error_code} operation={operation}")
        return oidc_callback_error_response("oidc_authentication_failed", config, status_code=503)
    except Exception as exc:
        print(f"OIDC callback failed: {type(exc).__name__}")
        return oidc_callback_error_response("oidc_authentication_failed", config, status_code=503)
    return raw_response(
        302,
        "",
        "text/plain",
        {"location": f"{portal_origin()}{return_to}", "set-cookie": session_cookie(session_token), "cache-control": "no-store"},
    )


def handle_create_session(event: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    if is_session_auth(auth):
        return response(200, {"user": {"subject": auth.get("subject")}, "session": "active"})
    if auth.get("token_type") not in {"pat", "federated"} or auth.get("principal_type") == "workload":
        return response(403, {"error": "interactive_user_authentication_required"})
    if not auth.get("subject") or not has_scope(auth, "session:create"):
        return response(403, {"error": "interactive_session_scope_required", "required_scope": "session:create"})
    session_token, session_record = create_browser_session(auth, event)
    subject = str(session_record["subject"])
    memberships = store().list_memberships(subject)
    allow_bootstrap = str(os.environ.get("CONTROL_PLANE_ALLOW_PAT_BOOTSTRAP") or "false").lower() in {"1", "true", "yes"}
    if allow_bootstrap and not memberships and auth.get("tenant_id"):
        bootstrap = membership_record(str(auth["tenant_id"]), subject, {"role": "owner", "status": "active", "email": auth.get("email")}, actor=subject)
        store().put_membership(bootstrap)
        memberships = [bootstrap]
    for membership in memberships:
        try:
            store().put_event({
                "event_type": "auth.session.created",
                "tenant_id": membership["tenant_id"],
                "environment": "security",
                "run_id": "authentication",
                "action_id": session_record["token_id"],
                "agent_id": "control-plane",
                "invoked_by": subject,
                "created_at": utc_now(),
                "status": "accepted",
                "auth_source": str(auth.get("auth_source") or "unknown"),
            })
        except Exception:
            pass
    return response(
        201,
        {
            "user": {"subject": subject, "email": session_record.get("email"), "display_name": session_record.get("display_name")},
            "memberships": [membership_with_entitlements(item) for item in memberships],
            "expires_at": session_record["expires_at"],
            "inactivity_timeout_seconds": session_inactivity_ttl(),
            "message": "Browser session created. The session cookie is HttpOnly and is not returned as a bearer token.",
        },
        {"set-cookie": session_cookie(session_token)},
    )


def handle_csrf(auth: dict[str, Any]) -> dict[str, Any]:
    if not is_session_auth(auth) or token_table is None:
        return response(403, {"error": "session_required"})
    token = secrets.token_urlsafe(32)
    token_table.update_item(
        Key={"token_hash": auth["token_hash"]},
        UpdateExpression="SET csrf_hash = :csrf_hash, csrf_issued_at = :now",
        ExpressionAttributeValues={":csrf_hash": session_hash(token), ":now": utc_now()},
    )
    return response(200, {"csrf_token": token})


def handle_logout(auth: dict[str, Any]) -> dict[str, Any]:
    if is_session_auth(auth) and token_table is not None:
        token_table.update_item(
            Key={"token_hash": auth["token_hash"]},
            UpdateExpression="SET #status = :revoked, revoked_at = :now",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={":revoked": "revoked", ":now": utc_now()},
        )
        if auth.get("tenant_id"):
            try:
                store().put_event({
                    "event_type": "auth.session.revoked",
                    "tenant_id": str(auth["tenant_id"]),
                    "environment": "security",
                    "run_id": "authentication",
                    "action_id": str(auth.get("session_id") or auth.get("token_id")),
                    "agent_id": "control-plane",
                    "invoked_by": authenticated_principal(auth),
                    "created_at": utc_now(),
                    "status": "accepted",
                    "reason": "logout",
                })
            except Exception:
                pass
    return empty_response(204, {"set-cookie": clear_session_cookie(), "cache-control": "no-store"})


def handle_me(auth: dict[str, Any]) -> dict[str, Any]:
    if not is_session_auth(auth):
        return response(403, {"error": "session_required"})
    subject = normalise_subject(auth.get("subject"))
    memberships = store().list_memberships(subject)
    return response(
        200,
        {
            "user": {"subject": subject, "email": auth.get("email"), "display_name": auth.get("display_name")},
            "memberships": [membership_with_entitlements(item) for item in memberships if item.get("status") == "active"],
            "active_tenant_id": auth.get("tenant_id"),
            "platform_admin": bool(auth.get("platform_admin")),
            "session_expires_at": auth.get("expires_at"),
            "session_last_activity_at": auth.get("last_activity_at"),
            "session_inactivity_timeout_seconds": session_inactivity_ttl(),
        },
    )


def membership_config(tenant_id: str) -> dict[str, Any]:
    return store().get_tenant_config(tenant_id) or default_tenant_config(tenant_id)


def membership_with_entitlements(record: dict[str, Any]) -> dict[str, Any]:
    tenant_id = str(record.get("tenant_id") or "")
    return membership_summary(record, enabled_products_for_config(membership_config(tenant_id)))


def handle_list_members(tenant_id: str, event: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    error = control_plane_admin(tenant_id, event, {}, auth)
    if error:
        return error
    memberships = store().list_tenant_memberships(tenant_id)
    return response(200, {"tenant_id": tenant_id, "count": len(memberships), "memberships": [membership_summary(item) for item in memberships]})


def handle_create_member(tenant_id: str, body: dict[str, Any], event: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    error = control_plane_admin(tenant_id, event, body, auth)
    if error:
        return error
    subject = normalise_subject(body.get("subject"))
    requested_role = normalise_role(body.get("role") or "viewer")
    if requested_role == "owner" and not (auth.get("role") == "owner" or has_scope(auth, "admin")):
        return response(403, {"error": "owner_role_requires_owner"})
    existing = store().get_membership(subject, tenant_id)
    membership = membership_record(tenant_id, subject, body, existing, actor=authenticated_principal(auth))
    store().put_membership(membership)
    store().put_event(tenant_admin_event("tenant.membership.updated", membership_config(tenant_id), auth, subject=subject, role=membership["role"], status=membership["status"], previous_role=(existing or {}).get("role"), previous_status=(existing or {}).get("status")))
    return response(200 if existing else 201, membership_summary(membership))


def handle_update_member(tenant_id: str, subject: str, body: dict[str, Any], event: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    error = control_plane_admin(tenant_id, event, body, auth)
    if error:
        return error
    existing = store().get_membership(normalise_subject(subject), tenant_id)
    if not existing:
        return response(404, {"error": "membership_not_found", "subject": subject, "tenant_id": tenant_id})
    requested_role = normalise_role(body.get("role") if "role" in body else existing.get("role"))
    if requested_role == "owner" and existing.get("role") != "owner" and not (auth.get("role") == "owner" or has_scope(auth, "admin")):
        return response(403, {"error": "owner_role_requires_owner"})
    if existing.get("role") == "owner" and requested_role != "owner" and not (auth.get("role") == "owner" or has_scope(auth, "admin")):
        return response(403, {"error": "owner_role_requires_owner"})
    next_membership = membership_record(tenant_id, subject, body, existing, actor=authenticated_principal(auth))
    if existing.get("role") == "owner" and next_membership.get("status") != "active":
        active_owners = [item for item in store().list_tenant_memberships(tenant_id) if item.get("role") == "owner" and item.get("status") == "active" and item.get("subject") != subject]
        if not active_owners:
            return response(409, {"error": "last_owner_cannot_be_removed"})
    store().put_membership(next_membership)
    store().put_event(tenant_admin_event("tenant.membership.updated", membership_config(tenant_id), auth, subject=subject, role=next_membership["role"], status=next_membership["status"], previous_role=existing.get("role"), previous_status=existing.get("status")))
    return response(200, membership_summary(next_membership))


def invitation_link(token: str) -> str:
    return f"{portal_origin()}/app?invite={token}"


def invitation_summary(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "invitation_id": record.get("invitation_id"),
        "tenant_id": record.get("tenant_id"),
        "role": record.get("role"),
        "status": record.get("status"),
        "created_by": record.get("created_by"),
        "created_at": record.get("created_at"),
        "expires_at": record.get("expires_at"),
        "max_uses": record.get("max_uses"),
        "use_count": record.get("use_count"),
    }


def handle_create_invitation(tenant_id: str, body: dict[str, Any], event: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    error = control_plane_admin(tenant_id, event, body, auth)
    if error:
        return error
    try:
        role = normalise_role(body.get("role") or "viewer")
    except ValueError as exc:
        return response(400, {"error": "invalid_role", "message": str(exc)})
    if role == "owner" and not (auth.get("role") == "owner" or has_scope(auth, "admin")):
        return response(403, {"error": "owner_role_requires_owner"})
    raw_expires_in_days = body.get("expires_in_days")
    if raw_expires_in_days is None:
        expires_in_days = 7
    else:
        try:
            expires_in_days = int(raw_expires_in_days)
        except (TypeError, ValueError):
            return response(400, {"error": "invalid_expires_in_days", "message": "expires_in_days must be an integer between 1 and 90."})
    if expires_in_days < 1 or expires_in_days > 90:
        return response(400, {"error": "invalid_expires_in_days", "message": "expires_in_days must be between 1 and 90."})
    raw_max_uses = body.get("max_uses")
    if raw_max_uses is None:
        max_uses = 1
    else:
        try:
            max_uses = int(raw_max_uses)
        except (TypeError, ValueError):
            return response(400, {"error": "invalid_max_uses", "message": "max_uses must be an integer between 1 and 1000."})
    if max_uses < 1 or max_uses > 1000:
        return response(400, {"error": "invalid_max_uses", "message": "max_uses must be between 1 and 1000."})
    token = "kta_invite_" + secrets.token_urlsafe(32)
    invitation = {
        "item_type": "tenant_invitation",
        "invitation_id": "inv-" + uuid.uuid4().hex[:16],
        "tenant_id": tenant_id,
        "role": role,
        "status": "active",
        "token_hash": hashlib.sha256(token.encode("utf-8")).hexdigest(),
        "created_by": authenticated_principal(auth),
        "created_at": utc_now(),
        "expires_at": int(time.time()) + expires_in_days * 86400,
        "max_uses": max_uses,
        "use_count": 0,
    }
    store().put_invitation(invitation)
    store().put_event(tenant_admin_event("tenant.invitation.created", membership_config(tenant_id), auth, invitation_id=invitation["invitation_id"], role=role, max_uses=max_uses, expires_at=invitation["expires_at"]))
    summary = invitation_summary(invitation)
    summary["token"] = token
    summary["link"] = invitation_link(token)
    return response(201, summary)


def handle_list_invitations(tenant_id: str, event: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    error = control_plane_admin(tenant_id, event, {}, auth)
    if error:
        return error
    invitations = store().list_tenant_invitations(tenant_id)
    return response(200, {"tenant_id": tenant_id, "count": len(invitations), "invitations": [invitation_summary(item) for item in invitations]})


def handle_revoke_invitation(tenant_id: str, invitation_id: str, body: dict[str, Any], event: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    error = control_plane_admin(tenant_id, event, body, auth)
    if error:
        return error
    index = store().get_invitation_index(invitation_id, tenant_id)
    if not index:
        return response(404, {"error": "invitation_not_found", "invitation_id": invitation_id})
    record = store().get_invitation_by_token_hash(str(index.get("token_hash") or ""))
    if not record:
        return response(404, {"error": "invitation_not_found", "invitation_id": invitation_id})
    if record.get("status") == "revoked":
        return response(200, invitation_summary(record))
    record["status"] = "revoked"
    record["revoked_at"] = utc_now()
    store().put_invitation(record)
    store().put_event(tenant_admin_event("tenant.invitation.revoked", membership_config(tenant_id), auth, invitation_id=invitation_id))
    return response(200, invitation_summary(record))


def redeem_invitation(token: str, subject: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Activate a membership from a valid invitation token.

    Returns ``(membership, None)`` on success or ``(None, error_response)`` on
    failure. The token is the capability: possession of a valid, unexpired,
    unexhausted invitation token authorises creation of the membership for
    ``subject``. The self-registration flow calls this once the recipient has
    authenticated with the identity provider.
    """

    token = str(token or "").strip()
    if not token:
        return None, response(400, {"error": "invitation_token_required"})
    record = store().get_invitation_by_token_hash(hashlib.sha256(token.encode("utf-8")).hexdigest())
    if not record:
        return None, response(404, {"error": "invitation_not_found"})
    if record.get("status") != "active":
        return None, response(409, {"error": "invitation_not_active", "status": record.get("status")})
    expires_at = record.get("expires_at")
    if expires_at is not None and int(time.time()) >= int(expires_at):
        return None, response(410, {"error": "invitation_expired"})
    use_count = int(record.get("use_count") or 0)
    max_uses = int(record.get("max_uses") or 1)
    if use_count >= max_uses:
        return None, response(409, {"error": "invitation_fully_used"})
    tenant_id = str(record["tenant_id"])
    try:
        subject = normalise_subject(subject)
    except ValueError as exc:
        return None, response(400, {"error": "invalid_subject", "message": str(exc)})
    existing = store().get_membership(subject, tenant_id)
    membership = membership_record(tenant_id, subject, {"role": record.get("role") or "viewer", "status": "active"}, existing, actor="invitation-redemption")
    store().put_membership(membership)
    record["use_count"] = use_count + 1
    if record["use_count"] >= max_uses:
        record["status"] = "redeemed"
    record["redeemed_at"] = utc_now()
    store().put_invitation(record)
    store().put_event(tenant_admin_event("tenant.invitation.redeemed", membership_config(tenant_id), {"auth_source": "session", "subject": subject}, invitation_id=record.get("invitation_id"), subject=subject, role=membership["role"]))
    return membership, None


def handle_redeem_invitation(body: dict[str, Any], event: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    token = str(body.get("token") or "").strip()
    if not token:
        return response(400, {"error": "invitation_token_required"})
    record = store().get_invitation_by_token_hash(hashlib.sha256(token.encode("utf-8")).hexdigest())
    if not record:
        return response(404, {"error": "invitation_not_found"})
    error = control_plane_admin(str(record["tenant_id"]), event, body, auth)
    if error:
        return error
    subject = str(body.get("subject") or "").strip()
    if not subject:
        return response(400, {"error": "subject_required", "message": "subject is required to redeem an invitation."})
    membership, redeem_error = redeem_invitation(token, subject)
    if redeem_error:
        return redeem_error
    return response(200, {"redeemed": True, "membership": membership_summary(membership)})


def handle_accept_invitation(body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    """Self-service acceptance by a signed-in recipient.

    Unlike ``handle_redeem_invitation`` (admin-gated, with the subject supplied
    by the admin), this redeems against the caller's own authenticated subject,
    so a brand-new recipient who has no membership yet can activate the
    membership an invitation grants them.
    """

    if not is_session_auth(auth):
        return response(403, {"error": "interactive_user_authentication_required"})
    token = str(body.get("token") or "").strip()
    if not token:
        return response(400, {"error": "invitation_token_required"})
    subject = str(auth.get("subject") or "").strip()
    if not subject:
        return response(400, {"error": "subject_required"})
    membership, redeem_error = redeem_invitation(token, subject)
    if redeem_error:
        return redeem_error
    return response(200, {"accepted": True, "membership": membership_summary(membership)})


def handle_platform_access_grant(body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    """Create an audited, time-limited grant for privileged support work.

    This capability is intentionally separate from tenant membership. A
    platform operator must use a platform-admin session or non-browser
    principal with the explicit admin scope and provide a bounded reason and
    operation before any support workflow can be built on top of the grant.
    """

    error = require_platform_operator(auth)
    if error:
        return error
    tenant_id = str(body.get("tenant_id") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}", tenant_id):
        raise ValueError("tenant_id is required and must be a bounded identifier.")
    reason = str(body.get("reason") or "").strip()
    if len(reason) < 10 or len(reason) > 512:
        raise ValueError("reason must be between 10 and 512 characters.")
    operation = str(body.get("operation") or "support").strip().lower()
    if operation not in {"read", "support", "export", "configuration"}:
        raise ValueError("operation must be one of: read, support, export, configuration.")
    try:
        expires_in_seconds = int(body.get("expires_in_seconds") or 3600)
    except (TypeError, ValueError) as exc:
        raise ValueError("expires_in_seconds must be an integer between 300 and 28800.") from exc
    if expires_in_seconds < 300 or expires_in_seconds > 8 * 60 * 60:
        raise ValueError("expires_in_seconds must be an integer between 300 and 28800.")
    now = int(time.time())
    created_at = utc_now()
    grant_id = "support-grant-" + uuid.uuid4().hex[:16]
    grant = {
        "item_type": "platform_access_grant",
        "grant_id": grant_id,
        "tenant_id": tenant_id,
        "operation": operation,
        "reason": reason,
        "status": "active",
        "invoked_by": authenticated_principal(auth),
        "created_at": created_at,
        "expires_at": now + expires_in_seconds,
        "expires_in_seconds": expires_in_seconds,
    }
    grant["grant_hash"] = hashlib.sha256(
        json.dumps(grant, sort_keys=True, separators=(",", ":"), default=_json_default).encode("utf-8")
    ).hexdigest()
    audit_store = store()
    audit_store.put_platform_access_grant(grant)
    audit_store.put_event({
        "event_type": "platform.support.access_granted",
        "tenant_id": tenant_id,
        "environment": "platform",
        "run_id": "platform-support",
        "action_id": grant_id,
        "agent_id": "platform-support",
        "invoked_by": grant["invoked_by"],
        "created_at": created_at,
        "operation": operation,
        "reason": reason,
        "grant_hash": grant["grant_hash"],
        "grant_expires_at": grant["expires_at"],
    })
    return response(201, grant)


def require_platform_operator(auth: dict[str, Any]) -> dict[str, Any] | None:
    if is_session_auth(auth):
        if is_platform_admin_session(auth):
            return None
    elif has_scope(auth, "admin"):
        return None
    return response(
        403,
        {
            "error": "platform_admin_required",
            "message": "A platform-admin session or non-browser administrator is required.",
        },
    )
    return None


def load_platform_grant(body: dict[str, Any], auth: dict[str, Any], *, required_operation: str = "read") -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Validate a reason-bound grant before a support operation can read tenant data."""

    error = require_platform_operator(auth)
    if error:
        return None, error
    grant_id = str(body.get("grant_id") or "").strip()
    tenant_id = str(body.get("tenant_id") or "").strip()
    if not grant_id or not tenant_id:
        return None, response(400, {"error": "grant_id_and_tenant_id_required"})
    grant = store().get_platform_access_grant(grant_id)
    now = int(time.time())
    if not grant or str(grant.get("tenant_id")) != tenant_id:
        return None, response(404, {"error": "platform_access_grant_not_found"})
    if grant.get("status") != "active" or int(grant.get("expires_at") or 0) <= now:
        return None, response(403, {"error": "platform_access_grant_inactive"})
    operation = str(grant.get("operation") or "")
    allowed_operations = {
        "read": {"read", "support", "export", "configuration"},
        "export": {"export", "support"},
        "configuration": {"configuration", "support"},
    }.get(required_operation, {"support"})
    if operation not in allowed_operations:
        return None, response(403, {"error": "platform_access_operation_not_granted", "required_operation": required_operation})
    return grant, None


def handle_list_platform_access_grants(event: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    error = require_platform_operator(auth)
    if error:
        return error
    query = event.get("queryStringParameters") or {}
    tenant_id = str(query.get("tenant_id") or "").strip() or None
    try:
        limit = int(query.get("limit") or 100)
    except (TypeError, ValueError) as exc:
        raise ValueError("limit must be an integer between 1 and 100") from exc
    if limit < 1 or limit > 100:
        raise ValueError("limit must be an integer between 1 and 100")
    grants = store().list_platform_access_grants(tenant_id=tenant_id, limit=limit)
    return response(200, {"count": len(grants), "grants": grants})


def handle_revoke_platform_access_grant(grant_id: str, body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    error = require_platform_operator(auth)
    if error:
        return error
    grant = store().get_platform_access_grant(str(grant_id).strip())
    if not grant:
        return response(404, {"error": "platform_access_grant_not_found"})
    if grant.get("status") != "active":
        return response(409, {"error": "platform_access_grant_not_active", "status": grant.get("status")})
    reason = str(body.get("reason") or "Operator revoked support access").strip()
    if len(reason) < 10 or len(reason) > 512:
        raise ValueError("reason must be between 10 and 512 characters.")
    now = utc_now()
    store().table.update_item(
        Key={"pk": f"PLATFORM_ACCESS#{grant_id}", "sk": "METADATA"},
        UpdateExpression="SET #status = :status, revoked_at = :revoked_at, revoked_by = :revoked_by, revoke_reason = :reason",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":status": "revoked",
            ":revoked_at": now,
            ":revoked_by": authenticated_principal(auth),
            ":reason": reason,
        },
    )
    store().put_event({
        "event_type": "platform.support.access_revoked",
        "tenant_id": str(grant["tenant_id"]),
        "environment": "platform",
        "run_id": "platform-support",
        "action_id": str(grant_id),
        "agent_id": "platform-support",
        "invoked_by": authenticated_principal(auth),
        "created_at": now,
        "reason": reason,
        "grant_hash": grant.get("grant_hash"),
    })
    return response(200, {**grant, "status": "revoked", "revoked_at": now, "revoked_by": authenticated_principal(auth), "revoke_reason": reason})


def handle_platform_support_read(body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    grant, error = load_platform_grant(body, auth, required_operation="read")
    if error:
        return error
    tenant_id = str(body["tenant_id"])
    resource = str(body.get("resource") or "tenant").strip().lower()
    if resource not in {"tenant", "members", "audit", "metrics"}:
        raise ValueError("resource must be one of: tenant, members, audit, metrics.")
    try:
        limit = int(body.get("limit") or 50)
    except (TypeError, ValueError) as exc:
        raise ValueError("limit must be an integer between 1 and 100") from exc
    if limit < 1 or limit > 100:
        raise ValueError("limit must be an integer between 1 and 100")
    if resource == "tenant":
        config = store().get_tenant_config(tenant_id) or default_tenant_config(tenant_id)
        result = tenant_summary(config)
        result["environments"] = config.get("environments") or []
    elif resource == "members":
        result = {"tenant_id": tenant_id, "memberships": [membership_summary(item) for item in store().list_tenant_memberships(tenant_id)]}
    elif resource == "metrics":
        result = {"tenant_id": tenant_id, "metrics": store().get_metrics(tenant_id)}
    else:
        result = {"tenant_id": tenant_id, "events": store().list_events(tenant_id, filters={"limit": limit})}
    store().put_event({
        "event_type": "platform.support.operation",
        "tenant_id": tenant_id,
        "environment": "platform",
        "run_id": "platform-support",
        "action_id": f"support-read-{uuid.uuid4().hex[:16]}",
        "agent_id": "platform-support",
        "invoked_by": authenticated_principal(auth),
        "created_at": utc_now(),
        "grant_id": grant.get("grant_id"),
        "grant_hash": grant.get("grant_hash"),
        "resource": resource,
        "operation": "read",
    })
    return response(200, {"grant_id": grant.get("grant_id"), "grant_expires_at": grant.get("expires_at"), **result})


def token_target(body: dict[str, Any], auth: dict[str, Any]) -> tuple[str | None, dict[str, Any] | None]:
    context = body.get("context") if isinstance(body.get("context"), dict) else {}
    requested = str(context.get("tenant_id") or body.get("tenant_id") or auth.get("tenant_id") or "")
    return tenant_target(requested, auth)


def token_metadata(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "token_id": record.get("token_id"),
        "name": record.get("name"),
        "tenant_id": record.get("tenant_id"),
        "token_type": "pat",
        "scopes": sorted(str(scope) for scope in (record.get("scopes") or [])),
        "groups": sorted((str(group) for group in (record.get("groups") or [])), key=str.casefold),
        "status": record.get("status"),
        "created_at": record.get("created_at"),
        "created_by": record.get("created_by"),
        "expires_at": record.get("expires_at"),
        "revoked_at": record.get("revoked_at"),
    }


def _query_token_index(index_name: str, key_name: str, key_value: str) -> tuple[list[dict[str, Any]], bool]:
    """Read token records through a configured GSI.

    The boolean indicates whether the query itself succeeded. A false value
    lets older deployments use the bounded scan migration path without
    confusing an empty tenant result with an unavailable index.
    """

    if token_table is None:
        raise RuntimeError("TOKEN_TABLE_NAME is not configured.")
    records: list[dict[str, Any]] = []
    query_kwargs: dict[str, Any] = {
        "IndexName": index_name,
        "KeyConditionExpression": Key(key_name).eq(key_value),
        "Limit": 100,
        "ScanIndexForward": False,
    }
    try:
        pages = 0
        while pages < 10 and len(records) < 100:
            result = token_table.query(**query_kwargs)
            records.extend(dict(item) for item in result.get("Items", []))
            last_key = result.get("LastEvaluatedKey")
            pages += 1
            if not last_key:
                break
            query_kwargs["ExclusiveStartKey"] = last_key
        return records[:100], True
    except Exception:
        return [], False


def _scan_pat_records(tenant_id: str, expected_token_id: str | None = None) -> list[dict[str, Any]]:
    if token_table is None:
        raise RuntimeError("TOKEN_TABLE_NAME is not configured.")
    filtered: list[dict[str, Any]] = []
    scan_kwargs: dict[str, Any] = {"Limit": PAT_TOKEN_SCAN_PAGE_SIZE, "ConsistentRead": True}
    pages = 0
    # Scan enough bounded pages to cover a large token table when a caller
    # needs a strong read for a just-created record. The result is capped
    # after tenant filtering, not before, so the first page cannot hide a
    # valid tenant record.
    while pages < 50:
        result = token_table.scan(**scan_kwargs)
        for item in result.get("Items", []):
            if str(item.get("tenant_id") or "") != tenant_id:
                continue
            if str(item.get("token_type") or "pat") != "pat":
                continue
            if expected_token_id and str(item.get("token_id") or "") != expected_token_id:
                continue
            filtered.append(dict(item))
            if expected_token_id:
                return filtered
        last_key = result.get("LastEvaluatedKey")
        pages += 1
        if not last_key:
            break
        scan_kwargs["ExclusiveStartKey"] = last_key
    return filtered[:100]


def list_pat_records(tenant_id: str, expected_token_id: str | None = None) -> list[dict[str, Any]]:
    if token_table is None:
        raise RuntimeError("TOKEN_TABLE_NAME is not configured.")

    def matching(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            item for item in records
            if str(item.get("tenant_id") or "") == tenant_id
            and str(item.get("token_type") or "pat") == "pat"
        ]

    records, indexed = _query_token_index(TOKEN_TENANT_INDEX_NAME, "tenant_id", tenant_id)
    filtered = matching(records) if indexed else []
    if expected_token_id:
        indexed_record = next(
            (item for item in filtered if str(item.get("token_id") or "") == expected_token_id),
            None,
        )
        if indexed_record:
            # The GSI can contain the token while still serving its previous
            # status after a revoke. Reconcile a known token ID with a strong
            # base-table read before returning it to the console.
            strong_record = None
            token_hash = str(indexed_record.get("token_hash") or "")
            if token_hash:
                try:
                    strong_record = token_table.get_item(
                        Key={"token_hash": token_hash},
                        ConsistentRead=True,
                    ).get("Item")
                except Exception:
                    strong_record = None
            if (
                strong_record
                and str(strong_record.get("tenant_id") or "") == tenant_id
                and str(strong_record.get("token_id") or "") == expected_token_id
                and str(strong_record.get("token_type") or "pat") == "pat"
            ):
                filtered = [
                    strong_record if str(item.get("token_id") or "") == expected_token_id else item
                    for item in filtered
                ]
            return filtered[:100]
        # A GSI is eventually consistent. Use a bounded strong read when the
        # caller has the token ID returned by the create operation, so the
        # access-token screen and revoke action do not miss a fresh token.
        recent = _scan_pat_records(tenant_id, expected_token_id)
        if recent:
            filtered.extend(recent)
        return filtered[:100]
    if not filtered:
        filtered = _scan_pat_records(tenant_id)
    return filtered[:100]


def handle_create_token(body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    tenant_id, error = token_target(body, auth)
    if error:
        return error
    name = str(body.get("name") or "").strip()
    if not name or len(name) > 128:
        raise ValueError("name is required and must be no longer than 128 characters.")
    try:
        expires_in_days = int(body.get("expires_in_days") or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("expires_in_days must be an integer between 0 and 3650.") from exc
    if expires_in_days < 0 or expires_in_days > 3650:
        raise ValueError("expires_in_days must be an integer between 0 and 3650.")

    caller_scopes = {str(scope) for scope in (auth.get("scopes") or []) if str(scope) in PAT_SCOPES}
    requested_scopes = body.get("scopes")
    if requested_scopes is None:
        scopes = set(PAT_SCOPES) if has_scope(auth, "admin") else caller_scopes
    else:
        scopes = {str(scope).strip() for scope in requested_scopes if str(scope).strip()} if isinstance(requested_scopes, list) else set()
    if not scopes or not scopes.issubset(PAT_SCOPES):
        return response(400, {"error": "unsupported_token_scope", "allowed_scopes": sorted(PAT_SCOPES)})
    if not has_scope(auth, "admin") and not scopes.issubset(caller_scopes):
        return response(403, {"error": "token_scope_escalation", "message": "A token may not delegate scopes its issuer does not possess."})

    caller_groups = {str(group).strip() for group in (auth.get("groups") or []) if str(group).strip()}
    requested_groups = body.get("groups")
    if requested_groups is None:
        groups = caller_groups
    elif isinstance(requested_groups, list):
        groups = {str(group).strip() for group in requested_groups if str(group).strip()}
    else:
        return response(400, {"error": "invalid_token_groups", "message": "groups must be an array of strings."})
    if len(groups) > 50 or any(len(group) > 128 for group in groups):
        return response(400, {"error": "invalid_token_groups", "message": "A token may contain at most 50 groups of 128 characters each."})
    if not has_scope(auth, "admin") and not groups.issubset(caller_groups):
        return response(403, {"error": "token_group_escalation", "message": "A token may not delegate groups its issuer does not possess."})

    token_id = "pat-" + uuid.uuid4().hex[:16]
    token = "kta_pat_" + secrets.token_urlsafe(32)
    now = int(time.time())
    created_at = utc_now()
    record: dict[str, Any] = {
        "token_hash": hashlib.sha256(token.encode("utf-8")).hexdigest(),
        "token_id": token_id,
        "name": name,
        "tenant_id": tenant_id,
        "token_type": "pat",
        "scopes": sorted(scopes),
        "groups": sorted(groups, key=str.casefold),
        "status": "active",
        "created_at": created_at,
        "created_by": str(auth.get("subject") or auth.get("token_id") or "token-administrator"),
    }
    if expires_in_days:
        record["expires_at"] = now + expires_in_days * 86400
    if token_table is None:
        raise RuntimeError("TOKEN_TABLE_NAME is not configured.")
    token_table.put_item(Item=record, ConditionExpression=Attr("token_hash").not_exists())
    store().put_event(
        {
            "event_type": "token.created",
            "tenant_id": tenant_id,
            "run_id": "token-management",
            "action_id": token_id,
            "agent_id": "token-management",
            "invoked_by": record["created_by"],
            "created_at": created_at,
            "token_id": token_id,
            "token_name": name,
            "token_scopes": record["scopes"],
            "token_groups": record["groups"],
            "token_expires_at": record.get("expires_at"),
        }
    )
    return response(201, {"token": token, "token_metadata": token_metadata(record)})


def handle_list_tokens(event: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    query = event.get("queryStringParameters") or {}
    requested_tenant = str(query.get("tenant_id") or auth.get("tenant_id") or "")
    tenant_id, error = tenant_target(requested_tenant, auth)
    if error:
        return error
    expected_token_id = str(query.get("token_id") or "").strip() or None
    records = list_pat_records(tenant_id, expected_token_id)
    return response(200, {"tenant_id": tenant_id, "tokens": [token_metadata(record) for record in records]})


def handle_revoke_token(token_id: str, body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    tenant_id, error = token_target(body, auth)
    if error:
        return error
    records = [record for record in list_pat_records(tenant_id, token_id) if str(record.get("token_id") or "") == token_id]
    if not records:
        return response(404, {"error": "token_not_found", "token_id": token_id})
    record = records[0]
    if record.get("status") == "revoked":
        return response(200, {"token_metadata": token_metadata(record)})
    now = utc_now()
    token_table.update_item(
        Key={"token_hash": record["token_hash"]},
        UpdateExpression="SET #status = :revoked, revoked_at = :now",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={":revoked": "revoked", ":now": now},
    )
    record["status"] = "revoked"
    record["revoked_at"] = now
    store().put_event(
        {
            "event_type": "token.revoked",
            "tenant_id": tenant_id,
            "run_id": "token-management",
            "action_id": token_id,
            "agent_id": "token-management",
            "invoked_by": str(auth.get("subject") or auth.get("token_id") or "token-administrator"),
            "created_at": now,
            "token_id": token_id,
        }
    )
    return response(200, {"token_metadata": token_metadata(record)})


def tenant_admin_event(event_type: str, config: dict[str, Any], auth: dict[str, Any], **fields: Any) -> dict[str, Any]:
    return {
        "event_type": event_type,
        "tenant_id": config["tenant_id"],
        "environment": "administration",
        "run_id": "tenant-management",
        "action_id": config["tenant_id"],
        "agent_id": "platform-administrator",
        "invoked_by": authenticated_principal(auth),
        "created_at": utc_now(),
        "tenant_config_version": config.get("config_version"),
        **fields,
    }


def apply_tenant_runtime(payload: dict[str, Any], auth: dict[str, Any], audit_store: AuditStore) -> dict[str, Any]:
    """Attach tenant runtime constraints before Guard normalises an action."""

    bind_tenant(payload, auth)
    context = payload.get("context") if isinstance(payload.get("context"), dict) else {}
    tenant_id = str(context.get("tenant_id") or auth["tenant_id"])
    config = audit_store.get_tenant_config(tenant_id) or default_tenant_config(tenant_id)
    starter_rules = normalise_starter_rules(config.get("starter_rules"))
    environment = str(context.get("environment") or payload.get("environment") or "development")
    raw_action = payload.get("action") if isinstance(payload.get("action"), dict) else payload
    tool = str(raw_action.get("tool") or raw_action.get("type") or "").lower()
    constraints = runtime_constraints(config, environment, tool)
    tenant_mode = str(constraints.get("mode") or "enforce").lower()
    if tenant_mode not in {"observe", "enforce"}:
        tenant_mode = "enforce"
    payload["mode"] = tenant_mode
    payload["_tenant_runtime"] = {
        "configured": bool(config.get("configured")),
        "config_version": config.get("config_version"),
        "policy_bundle_revision": config.get("policy_bundle_revision") or 0,
        "environment": environment,
        "mode": tenant_mode,
        "reasons": constraints.get("reasons") or [],
        "allowed_tools": (environment_for(config, environment) or {}).get("allowed_tools") or [],
        "retention_enabled": bool(config.get("retention_enabled")),
        "capture_policy": config.get("capture_policy") or default_tenant_config(tenant_id)["capture_policy"],
        "starter_rules": starter_rules,
        "starter_rule_summary": starter_rule_summary(starter_rules),
    }
    if auth.get("token_type") == "workload":
        payload["_tenant_runtime"]["workload_authority_ceiling"] = normalise_authority_level(
            auth.get("maximum_authority"), "workload_identity.maximum_authority"
        )
    return payload


def _triggering_rule_summary(decision: dict[str, Any]) -> dict[str, Any] | None:
    """Build a compact summary of the rule that triggered an approval.

    Returns the selected (winning) rule from policy resolution plus the list of
    all matched rules, so the portal can show what triggered the approval and
    what else matched.
    """
    resolution = decision.get("policy_resolution") if isinstance(decision.get("policy_resolution"), dict) else {}
    selected = resolution.get("selected_match")
    evaluated = resolution.get("evaluated_matches") or []
    matched_rules = [
        {
            "policy_id": match.get("policy_id"),
            "policy_version": match.get("policy_version"),
            "rule_id": match.get("rule_id"),
            "decision": match.get("decision"),
            "applied": match.get("applied", False),
        }
        for match in evaluated
        if isinstance(match, dict)
    ]

    # Built-in detector matches are applied before versioned workspace
    # policies. They do not pass through policy.apply_policies(), so include
    # them explicitly in the approval provenance instead of leaving the
    # reviewer with "Rule information not recorded".
    starter_matches = [
        match for match in (decision.get("starter_rule_matches") or [])
        if isinstance(match, dict) and (match.get("rule_id") or match.get("reason_code"))
    ]
    starter_version = 1
    tenant_policy = decision.get("tenant_policy")
    if isinstance(tenant_policy, dict):
        try:
            starter_version = int(tenant_policy.get("config_version") or 1)
        except (TypeError, ValueError):
            starter_version = 1
    if starter_matches:
        starter_decisions = [str(match.get("decision") or "allow") for match in starter_matches]
        starter_rank = max((DECISION_RANK.get(value, 0) for value in starter_decisions), default=0)
        starter_rules = []
        for match in starter_matches:
            rule_id = str(match.get("rule_id") or match.get("reason_code"))
            reason_code = str(match.get("reason_code") or rule_id).upper()
            rule_decision = str(match.get("decision") or "allow")
            starter_rules.append(
                {
                    "policy_id": "kenning-starter-rules",
                    "policy_version": starter_version,
                    "rule_id": rule_id,
                    "reason_code": reason_code,
                    "decision": rule_decision,
                    "applied": DECISION_RANK.get(rule_decision, 0) == starter_rank,
                }
            )
        matched_rules = starter_rules + matched_rules

        # A workspace policy is selected only when it is at least as
        # restrictive as the built-in baseline. Otherwise the winning rule is
        # the most restrictive built-in starter check.
        if not isinstance(selected, dict):
            selected = max(starter_rules, key=lambda item: DECISION_RANK.get(str(item.get("decision") or "allow"), 0))

    if not selected and not matched_rules:
        return None
    summary: dict[str, Any] = {"matched_rules": matched_rules}
    if isinstance(selected, dict):
        summary["selected_rule"] = {
            "policy_id": selected.get("policy_id"),
            "policy_version": selected.get("policy_version"),
            "rule_id": selected.get("rule_id"),
            "reason_code": selected.get("reason_code"),
            "decision": selected.get("decision"),
            "mode": selected.get("mode"),
        }
    # Distinguish Kenning built-in rules from workspace policies by policy_id prefix.
    policy_id = str((selected or {}).get("policy_id") or "")
    summary["rule_source"] = "kenning" if policy_id.startswith("kenning-") else "workspace"
    return summary


def _normalise_grant_duration(value: Any) -> int | None:
    """Return a valid grant duration in seconds, or None if not requested/invalid."""
    if value is None or value == "":
        return None
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        return None
    if seconds <= 0:
        return None
    if seconds > GRANT_MAX_DURATION_SECONDS:
        return None
    return seconds


def create_approval_grant(
    approval: dict[str, Any],
    duration_seconds: int,
    reviewer: str,
    reviewer_principal: str,
    audit_store: AuditStore,
) -> dict[str, Any]:
    """Create a duration-based grant bound to the approved action's semantic hash."""
    now = int(time.time())
    grant_id = f"grant-{uuid.uuid4().hex[:16]}"
    grant = {
        "grant_id": grant_id,
        "tenant_id": approval["tenant_id"],
        "action_hash": approval["action_hash"],
        "agent_id": approval.get("agent_id"),
        "environment": approval.get("environment"),
        "source_approval_id": approval.get("approval_id"),
        "action": approval.get("action"),
        "status": "active",
        "created_by": reviewer,
        "created_by_principal": reviewer_principal,
        "duration_seconds": duration_seconds,
        "expires_at": now + duration_seconds,
        "created_at": utc_now(),
        "use_count": 0,
    }
    audit_store.put_grant(grant)
    audit_store.put_event(
        {
            "event_type": "approval.grant_created",
            "tenant_id": approval["tenant_id"],
            "run_id": approval.get("run_id"),
            "action_id": approval.get("action_id"),
            "agent_id": approval.get("agent_id"),
            "created_at": grant["created_at"],
            "grant_id": grant_id,
            "source_approval_id": approval.get("approval_id"),
            "action_hash": approval["action_hash"],
            "duration_seconds": duration_seconds,
            "expires_at": grant["expires_at"],
            "created_by": reviewer,
            "created_by_principal": reviewer_principal,
            "status": "active",
        }
    )
    return grant


def _apply_model_context(action: dict[str, Any], audit_store: AuditStore) -> None:
    """Attach the bound model metadata used by policy and audit evaluation."""
    agent_id = str(action.get("agent_id") or "")
    tenant_id = str(action.get("tenant_id") or "")
    agent = audit_store.get_agent(agent_id, tenant_id) if agent_id and tenant_id else None
    # Preserve the legacy action hash for unregistered callers. Registered
    # agents always get explicit nullable model fields, including an unbound
    # agent, so the model context is durable and approval retries remain
    # deterministic.
    if not agent:
        return
    action["model_id"] = None
    action["model_version"] = None
    action["model_risk_tier"] = None
    model_id = str(agent.get("model_id") or "") if agent else ""
    if not model_id:
        return
    requested_version = str(agent.get("model_version") or "").strip() or None
    model = audit_store.get_model(model_id, tenant_id, requested_version)
    action["model_id"] = model_id
    action["model_version"] = str(model.get("version") or requested_version or "") if model else requested_version
    if model:
        action["model_risk_tier"] = model.get("risk_tier")


def _apply_identity_authorization(decision: dict[str, Any], action: dict[str, Any], audit_store: AuditStore, tenant_runtime: dict[str, Any]) -> None:
    """Check registered-agent identity authorization and mutate decision in place (#253)."""
    registered_agent = audit_store.get_agent(action["agent_id"], action["tenant_id"])
    if not registered_agent or registered_agent.get("tenant_id") != action["tenant_id"]:
        return
    identity_agent = dict(registered_agent)
    workload_ceiling = tenant_runtime.get("workload_authority_ceiling")
    if workload_ceiling:
        registered_authority = normalise_authority_level(identity_agent.get("maximum_authority") or identity_agent.get("authority_level"))
        if authority_rank(workload_ceiling) < authority_rank(registered_authority):
            identity_agent["maximum_authority"] = workload_ceiling
    identity_result = authorize_action(identity_agent, action)
    decision["identity"] = identity_result
    if not identity_result["authorized"]:
        decision["decision"] = "deny"
        decision["risk"] = "critical"
        decision["risk_score"] = 100
        for reason in identity_result["reasons"]:
            decision["reason_codes"].append(reason["code"])
            decision["reasons"].append({**reason, "decision": "deny"})
    elif identity_result["decision"] == "require_approval" and decision["decision"] in {"allow", "warn"}:
        decision["decision"] = "require_approval"
        decision["risk"] = "high"
        decision["risk_score"] = max(decision["risk_score"], 80)
        decision["reason_codes"].append("IDENTITY_APPROVAL_REQUIRED")
        decision["reasons"].append(
            {
                "code": "IDENTITY_APPROVAL_REQUIRED",
                "message": "Registered agent delegation requires human approval before this action.",
                "decision": "require_approval",
            }
        )


def _check_grant_auto_approval(decision: dict[str, Any], action: dict[str, Any], audit_store: AuditStore, audit_event: dict[str, Any], created_at: str) -> None:
    """If a duration grant matches, auto-approve instead of creating a new approval (#253)."""
    if decision["decision"] != "require_approval":
        return
    matched_grant = audit_store.find_active_grant(action["tenant_id"], decision["action_hash"])
    if matched_grant is None:
        return
    decision["decision"] = "allow"
    decision["auto_approved"] = True
    decision["grant_id"] = matched_grant["grant_id"]
    decision["grant"] = {
        "grant_id": matched_grant["grant_id"],
        "created_by": matched_grant.get("created_by"),
        "created_by_principal": matched_grant.get("created_by_principal"),
        "expires_at": matched_grant.get("expires_at"),
        "source_approval_id": matched_grant.get("source_approval_id"),
    }
    decision["reason_codes"].append("AUTO_APPROVED_BY_GRANT")
    decision["reasons"].append(
        {
            "code": "AUTO_APPROVED_BY_GRANT",
            "message": f"Auto-approved under grant {matched_grant['grant_id']} created by {matched_grant.get('created_by') or 'a reviewer'}.",
            "decision": "allow",
        }
    )
    audit_event["decision"] = "allow"
    audit_event["auto_approved"] = True
    audit_event["grant_id"] = matched_grant["grant_id"]
    try:
        audit_store.table.update_item(
            Key={"pk": f"GRANT#{matched_grant['grant_id']}", "sk": "METADATA"},
            UpdateExpression="SET use_count = if_not_exists(use_count, :zero) + :one, last_used_at = :now",
            ExpressionAttributeValues={":zero": 0, ":one": 1, ":now": created_at},
        )
    except Exception:
        pass


def _build_proof_and_receipt(payload: dict[str, Any], action: dict[str, Any], decision: dict[str, Any], audit_store: AuditStore, audit_event: dict[str, Any], capture_policy: dict[str, Any] | None) -> None:
    """Build the proof record, attach receipt, persist, and update audit event (#253)."""
    phase_timings = decision.setdefault("evaluation_phases_ms", {})
    proof_started = time.perf_counter()
    phase_started = proof_started
    proof_input = payload.get("proof") if isinstance(payload.get("proof"), dict) else {}
    captured_action = decision["action"]
    proof = apply_capture(build_proof_record(proof_input, action=captured_action, decision=decision), capture_policy)
    phase_timings["proof_build_ms"] = round((time.perf_counter() - phase_started) * 1000, 3)
    decision["proof_id"] = proof["proof_id"]
    decision["proof_uri"] = proof["proof_uri"]
    decision["evidence_status"] = proof["evidence_status"]
    decision["evidence_gaps"] = proof["evidence_gaps"]
    if decision.get("approval"):
        decision["approval"]["proof_id"] = proof["proof_id"]
        decision["approval"]["proof_uri"] = proof["proof_uri"]
        decision["approval"]["evidence"] = proof["evidence"]
        phase_started = time.perf_counter()
        with _guard_failure_stage("approval_persistence"):
            audit_store.put_approval(decision["approval"])
        phase_timings["approval_persistence_ms"] = round((time.perf_counter() - phase_started) * 1000, 3)
        decision["approval_creation_latency_ms"] = round((time.perf_counter() - decision.get("_approval_started", time.perf_counter())) * 1000, 3)
        audit_event["approval_creation_latency_ms"] = decision["approval_creation_latency_ms"]
    phase_started = time.perf_counter()
    decision["receipt"] = build_receipt(
        action,
        decision["decision"],
        decision.get("approval"),
        result="awaiting_approval" if decision["decision"] == "require_approval" else "not_executed",
        proof_record=proof["proof_uri"],
    )
    phase_timings["receipt_signing_ms"] = round((time.perf_counter() - phase_started) * 1000, 3)
    proof = attach_receipt(proof, decision["receipt"])
    phase_started = time.perf_counter()
    with _guard_failure_stage("proof_persistence"):
        audit_store.put_proof(proof, create_only=True)
    phase_timings["proof_persistence_ms"] = round((time.perf_counter() - phase_started) * 1000, 3)
    audit_event["proof_id"] = proof["proof_id"]
    audit_event["proof_uri"] = proof["proof_uri"]
    audit_event["evidence_status"] = proof["evidence_status"]
    audit_event["evidence_gaps"] = proof["evidence_gaps"]
    audit_event["receipt"] = decision["receipt"]
    phase_timings["proof_and_receipt_ms"] = round((time.perf_counter() - proof_started) * 1000, 3)


def _apply_tenant_runtime_policy(
    decision: dict[str, Any],
    action: dict[str, Any],
    tenant_runtime: dict[str, Any],
    mode: str,
    starter_rules: list[dict[str, Any]],
    audit_store: AuditStore,
) -> dict[str, Any]:
    """Apply tenant runtime policy reasons, tenant_policy summary, and capture policy."""

    runtime_reasons = tenant_runtime.get("reasons") if isinstance(tenant_runtime.get("reasons"), list) else []
    if runtime_reasons:
        decision["decision"] = "deny"
        decision["risk"] = "critical"
        decision["risk_score"] = 100
        for reason in runtime_reasons:
            reason = {"code": str(reason.get("code") or "TENANT_RUNTIME_POLICY"), "message": str(reason.get("message") or "Tenant runtime policy denied the action."), "decision": "deny"}
            decision["reason_codes"].append(reason["code"])
            decision["reasons"].append(reason)
    decision["tenant_policy"] = {
        "configured": bool(tenant_runtime.get("configured")),
        "config_version": tenant_runtime.get("config_version"),
        "environment": tenant_runtime.get("environment") or action["environment"],
        "mode": tenant_runtime.get("mode") or mode,
        "allowed_tools": tenant_runtime.get("allowed_tools") or [],
        "retention_enabled": bool(tenant_runtime.get("retention_enabled")),
        "policy_bundle_revision": tenant_runtime.get("policy_bundle_revision") or 0,
        "starter_rules": tenant_runtime.get("starter_rule_summary") or starter_rule_summary(starter_rules),
    }
    capture_policy = tenant_runtime.get("capture_policy")
    if not isinstance(capture_policy, dict):
        tenant_config = audit_store.get_tenant_config(action["tenant_id"]) or default_tenant_config(action["tenant_id"])
        capture_policy = tenant_config.get("capture_policy")
    decision["capture_policy"] = capture_policy_summary(capture_policy)
    decision["tenant_policy"]["capture_policy"] = decision["capture_policy"]
    return capture_policy


def _select_and_apply_policies(
    decision: dict[str, Any],
    action: dict[str, Any],
    payload: dict[str, Any],
    context: dict[str, Any],
    tenant_runtime: dict[str, Any],
    starter_rules: list[dict[str, Any]],
    mode: str,
    audit_store: AuditStore,
) -> dict[str, Any]:
    """Select tenant policies and apply them to the decision."""

    requested_policy_id = str(payload.get("policy_id") or context.get("policy_id") or "")
    requested_policy_version = payload.get("policy_version") or context.get("policy_version")
    if requested_policy_id:
        selected_policy = audit_store.get_policy(requested_policy_id, int(requested_policy_version) if requested_policy_version is not None else None, action["tenant_id"])
        policies = [selected_policy] if selected_policy and selected_policy.get("tenant_id") == action["tenant_id"] and selected_policy.get("status") == "published" else []
    else:
        bundle = audit_store.get_policy_bundle(
            action["tenant_id"],
            {
                "config_version": tenant_runtime.get("config_version") or 1,
                "policy_bundle_revision": tenant_runtime.get("policy_bundle_revision") or 0,
            },
        )
        policies = bundle.get("policies") if isinstance(bundle.get("policies"), list) else []
        decision["policy_bundle_id"] = bundle.get("bundle_id")
        decision["policy_bundle_hash"] = bundle.get("bundle_hash")
    custom_policy = custom_starter_policy(
        starter_rules,
        action["tenant_id"],
        int(tenant_runtime.get("config_version") or 1),
        mode=mode,
    )
    return _impact_assessment_policy_context(
        decision,
        action,
        ([custom_policy] if custom_policy else []) + policies,
        audit_store,
    )


def _build_approval_record(
    decision: dict[str, Any],
    action: dict[str, Any],
    captured_action: dict[str, Any],
    created_at: str,
) -> None:
    """Create a pending approval record when the decision requires approval."""

    approval_started = time.perf_counter()
    approval_id = f"approval-{uuid.uuid4().hex[:16]}"
    approval = {
        "approval_id": approval_id,
        "tenant_id": action["tenant_id"],
        "run_id": action["run_id"],
        "action_id": action["action_id"],
        "action_hash": decision["action_hash"],
        "status": "pending",
        "requested_by": action["invoked_by"],
        "agent_id": action["agent_id"],
        "environment": action["environment"],
        "target": captured_action["target"],
        "intent": captured_action["intent"],
        "requested_scope": (captured_action.get("parameters") or {}).get("requested_scope"),
        "action": captured_action,
        "risk": decision["risk"],
        "reason_codes": decision["reason_codes"],
        "reasons": decision["reasons"],
        "triggering_rule": _triggering_rule_summary(decision),
        "approval_requirements": decision.get("approval_requirements", []),
        "expires_at": int((datetime.now(timezone.utc) + timedelta(minutes=15)).timestamp()),
        "created_at": created_at,
    }
    # Multi-step approval chain (#245): persist the chain definition plus a
    # per-step status list. Step 1 is actionable; later steps stay pending
    # until the preceding step is approved.
    chain_definition = decision.get("approval_chain")
    if isinstance(chain_definition, dict) and chain_definition.get("steps"):
        approval["approval_chain"] = chain_definition
        approval["chain_steps"] = [
            {
                "step": step["step"],
                "label": step.get("label") or f"Step {step['step']}",
                "approver_groups": step.get("approver_groups", []),
                "separation_of_duties": step.get("separation_of_duties", True),
                "status": "pending",
                "approver": None,
                "approver_principal": None,
                "decided_at": None,
            }
            for step in chain_definition["steps"]
        ]
        approval["current_step"] = 1
        approval["total_steps"] = len(approval["chain_steps"])
    decision["approval"] = approval
    decision["_approval_started"] = approval_started


def evaluate_and_record(
    payload: dict[str, Any],
    audit_store: AuditStore,
    prepared_action: dict[str, Any] | None = None,
    prepared_phase_timings: dict[str, float] | None = None,
) -> dict[str, Any]:
    evaluation_started = time.perf_counter()
    phase_timings: dict[str, float] = dict(prepared_phase_timings or {})
    if prepared_action is None:
        phase_started = evaluation_started
        with _guard_failure_stage("action_normalization"):
            action = normalise_action(payload)
        phase_timings["normalise_action_ms"] = round((time.perf_counter() - phase_started) * 1000, 3)
        phase_started = time.perf_counter()
        with _guard_failure_stage("model_context"):
            _apply_model_context(action, audit_store)
        phase_timings["model_context_ms"] = round((time.perf_counter() - phase_started) * 1000, 3)
    else:
        action = prepared_action
    context = payload.get("context") if isinstance(payload.get("context"), dict) else {}
    tenant_runtime = payload.get("_tenant_runtime") if isinstance(payload.get("_tenant_runtime"), dict) else {}
    mode = str(tenant_runtime.get("mode") or "enforce")
    starter_rules = tenant_runtime.get("starter_rules") if isinstance(tenant_runtime.get("starter_rules"), list) else default_starter_rules()
    phase_started = time.perf_counter()
    with _guard_failure_stage("built_in_rules"):
        decision = evaluate(action, mode=mode, starter_rules=starter_rules)
    phase_timings["builtin_rules_ms"] = round((time.perf_counter() - phase_started) * 1000, 3)
    decision["policy_id"] = "kenning-agent-guard-mvp"
    decision["policy_version"] = 1

    phase_started = time.perf_counter()
    with _guard_failure_stage("tenant_runtime_policy"):
        capture_policy = _apply_tenant_runtime_policy(decision, action, tenant_runtime, mode, starter_rules, audit_store)
    phase_timings["tenant_runtime_policy_ms"] = round((time.perf_counter() - phase_started) * 1000, 3)
    phase_started = time.perf_counter()
    with _guard_failure_stage("policy_resolution"):
        decision = _select_and_apply_policies(decision, action, payload, context, tenant_runtime, starter_rules, mode, audit_store)
    phase_timings["policy_resolution_ms"] = round((time.perf_counter() - phase_started) * 1000, 3)

    phase_started = time.perf_counter()
    with _guard_failure_stage("identity_authorization"):
        _apply_identity_authorization(decision, action, audit_store, tenant_runtime)
    phase_timings["identity_authorization_ms"] = round((time.perf_counter() - phase_started) * 1000, 3)

    decision["evaluation_phases_ms"] = phase_timings
    decision["evaluation_latency_ms"] = round((time.perf_counter() - evaluation_started) * 1000, 3)
    phase_started = time.perf_counter()
    captured_action = capture_action(action, capture_policy)
    phase_timings["capture_action_ms"] = round((time.perf_counter() - phase_started) * 1000, 3)
    decision["action"] = captured_action
    created_at = utc_now()
    audit_event = {
        "event_type": "action.evaluated",
        "tenant_id": action["tenant_id"],
        "environment": action["environment"],
        "run_id": action["run_id"],
        "action_id": action["action_id"],
        "agent_id": action["agent_id"],
        "action_classification": action["classification"],
        "model_id": action.get("model_id"),
        "model_version": action.get("model_version"),
        "invoked_by": action["invoked_by"],
        "created_at": created_at,
        "decision": decision["decision"],
        "would_decision": decision.get("would_decision"),
        "risk": decision["risk"],
        "risk_score": decision["risk_score"],
        "reason_codes": decision["reason_codes"],
        "action_hash": decision["action_hash"],
        "action": captured_action,
        "policy_id": decision["policy_id"],
        "policy_version": decision["policy_version"],
        "policy_matches": decision.get("policy_matches", []),
        "policy_resolution": decision.get("policy_resolution"),
        "policy_bundle_id": decision.get("policy_bundle_id"),
        "policy_bundle_hash": decision.get("policy_bundle_hash"),
        "evaluation_phases_ms": decision.get("evaluation_phases_ms"),
        "impact_assessment": decision.get("impact_assessment"),
        "tenant_policy": decision["tenant_policy"],
        "evaluation_latency_ms": decision["evaluation_latency_ms"],
    }
    if decision.get("identity"):
        audit_event["identity"] = decision["identity"]

    phase_started = time.perf_counter()
    _check_grant_auto_approval(decision, action, audit_store, audit_event, created_at)
    phase_timings["grant_lookup_ms"] = round((time.perf_counter() - phase_started) * 1000, 3)

    if decision["decision"] == "require_approval":
        _build_approval_record(decision, action, captured_action, created_at)
        audit_event["approval_id"] = decision["approval"]["approval_id"]

    _build_proof_and_receipt(payload, action, decision, audit_store, audit_event, capture_policy)

    audit_started = time.perf_counter()
    with _guard_failure_stage("audit_persistence"):
        decision["audit_delivery"] = audit_store.put_event(audit_event)
    decision["audit_acceptance_latency_ms"] = round((time.perf_counter() - audit_started) * 1000, 3)
    phase_timings["audit_persistence_ms"] = decision["audit_acceptance_latency_ms"]
    return decision


def replay_action_evaluation(existing: dict[str, Any], audit_store: AuditStore) -> dict[str, Any]:
    """Return the durable decision for a retry of the same semantic action."""

    proof = audit_store.get_proof(str(existing.get("proof_id") or ""), str(existing.get("tenant_id") or "")) if existing.get("proof_id") else None
    decision: dict[str, Any] = {
        key: existing.get(key)
        for key in (
            "decision",
            "would_decision",
            "mode",
            "risk",
            "risk_score",
            "action_classification",
            "reason_codes",
            "reasons",
            "recommended_action",
            "action",
            "action_hash",
            "identity",
            "policy_id",
            "policy_version",
            "policy_matches",
            "policy_resolution",
            "policy_bundle_id",
            "policy_bundle_hash",
            "evaluation_phases_ms",
            "impact_assessment",
            "tenant_policy",
            "evaluated_at",
            "evaluation_latency_ms",
            "approval_creation_latency_ms",
            "audit_acceptance_latency_ms",
        )
        if existing.get(key) is not None
    }
    decision["action_id"] = existing.get("action_id")
    decision["run_id"] = existing.get("run_id")
    decision["proof_id"] = existing.get("proof_id")
    decision["proof_uri"] = existing.get("proof_uri")
    if isinstance(proof, dict):
        decision["evidence_status"] = proof.get("evidence_status")
        decision["evidence_gaps"] = proof.get("evidence_gaps") or []
        decision["receipt"] = proof.get("trusted_action_receipt")
    approval_id = existing.get("approval_id")
    if approval_id:
        approval = audit_store.get_approval(str(approval_id))
        if approval:
            decision["approval"] = approval
    decision["idempotent"] = True
    decision["audit_delivery"] = {"status": "already_recorded", "delivered": False, "idempotent": True}
    return decision


def approval_action_core(action: Any) -> dict[str, Any]:
    """Return the execution fields used to validate an approval continuation."""

    if not isinstance(action, dict):
        return {}
    return {
        key: action.get(key)
        for key in (
            "tenant_id",
            "environment",
            "agent_id",
            "classification",
            "purpose",
            "data_scope",
            "tool",
            "operation",
            "target",
            "parameters",
            "shell_context",
        )
        if key in action
    }


def approval_action_matches(approval: dict[str, Any], action: dict[str, Any]) -> bool:
    """Require the resumed request to describe the same executable action.

    Natural-language intent and generated correlation fields are deliberately
    excluded. The command, target, tool, operation, tenant, environment, and
    agent identity remain bound to the human-approved action.
    """

    approved_action = approval.get("action") if isinstance(approval.get("action"), dict) else {}
    return approval_action_core(approved_action) == approval_action_core(action)


def approved_replay_decision(existing: dict[str, Any], approval: dict[str, Any], audit_store: AuditStore) -> dict[str, Any]:
    """Return an allow response for a consumed, exact approved retry."""

    decision = replay_action_evaluation(existing, audit_store)
    decision["decision"] = "allow"
    decision["approval"] = approval
    decision["approval_id"] = approval.get("approval_id")
    decision["approval_status"] = approval.get("status")
    decision["approved_action_id"] = approval.get("action_id")
    decision["approved_action_hash"] = approval.get("action_hash")
    decision["approval_resume"] = True
    return decision


def handle_approved_evaluation(
    body: dict[str, Any],
    action: dict[str, Any],
    audit_store: AuditStore,
    approval_id: str,
    auth: dict[str, Any],
) -> dict[str, Any]:
    """Verify and consume an approval continuation before returning an allow decision."""

    _apply_model_context(action, audit_store)
    approval = audit_store.get_approval(approval_id)
    if not approval:
        return response(404, {"error": "approval_not_found", "approval_id": approval_id})
    if approval.get("tenant_id") != action.get("tenant_id"):
        return response(403, {"error": "approval_tenant_mismatch", "approval_id": approval_id})
    if approval.get("status") != "approved":
        return response(
            409,
            {
                "error": "approval_not_approved",
                "approval_id": approval_id,
                "status": approval.get("status"),
            },
        )
    requested_hash = str(body.get("action_hash") or (body.get("context") or {}).get("action_hash") or "")
    if not requested_hash:
        return response(409, {"error": "approval_action_hash_required", "approval_id": approval_id})
    if requested_hash != str(approval.get("action_hash") or ""):
        return response(409, {"error": "approval_action_mismatch", "approval_id": approval_id})
    if action.get("action_id") != approval.get("action_id"):
        return response(
            409,
            {
                "error": "approval_action_id_mismatch",
                "approval_id": approval_id,
                "expected_action_id": approval.get("action_id"),
                "requested_action_id": action.get("action_id"),
            },
        )
    if not approval_action_matches(approval, action):
        return response(409, {"error": "approval_action_mismatch", "approval_id": approval_id})
    if action_hash(action) != str(approval.get("action_hash") or ""):
        return response(409, {"error": "approval_action_mismatch", "approval_id": approval_id})
    existing = audit_store.get_action_evaluation(str(action["tenant_id"]), str(action["action_id"]))
    if not existing or str(existing.get("action_hash") or "") != str(approval.get("action_hash") or ""):
        return response(409, {"error": "approval_evaluation_not_found", "approval_id": approval_id})
    consumed = audit_store.consume_approval(
        approval_id,
        consumed_by=str(auth.get("subject") or auth.get("token_id") or "action-executor"),
        consumed_at=utc_now(),
        action_id=str(action["action_id"]),
        action_hash=str(approval.get("action_hash") or ""),
    )
    if not consumed:
        return response(409, {"error": "approval_already_consumed_or_revoked", "approval_id": approval_id})
    return response(200, approved_replay_decision(existing, consumed, audit_store))


def handle_evaluate(event: dict[str, Any], body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    with _guard_failure_stage("tenant_runtime_resolution"):
        audit_store = store()
        apply_tenant_runtime(body, auth, audit_store)
    context = body.get("context") if isinstance(body.get("context"), dict) else {}
    context["invoked_by"] = authenticated_principal(auth)
    body["context"] = context
    preparation_timings: dict[str, float] = {}
    phase_started = time.perf_counter()
    with _guard_failure_stage("action_normalization"):
        action = normalise_action(body)
    preparation_timings["normalise_action_ms"] = round((time.perf_counter() - phase_started) * 1000, 3)
    phase_started = time.perf_counter()
    with _guard_failure_stage("model_context"):
        _apply_model_context(action, audit_store)
    preparation_timings["model_context_ms"] = round((time.perf_counter() - phase_started) * 1000, 3)
    approval_id = str(body.get("approval_id") or (body.get("context") or {}).get("approval_id") or "")
    if approval_id:
        with _guard_failure_stage("approved_evaluation"):
            return handle_approved_evaluation(body, action, audit_store, approval_id, auth)
    with _guard_failure_stage("existing_evaluation_lookup"):
        existing = audit_store.get_action_evaluation(action["tenant_id"], action["action_id"])
    if existing:
        requested_hash = action_hash(action)
        recorded_hash = str(existing.get("action_hash") or "")
        if recorded_hash != requested_hash:
            return response(
                409,
                {
                    "error": "action_id_reuse",
                    "message": "The action_id is already bound to a different semantic action.",
                    "action_id": action["action_id"],
                    "recorded_action_hash": recorded_hash,
                    "requested_action_hash": requested_hash,
                },
            )
        return response(200, replay_action_evaluation(existing, audit_store))
    return response(
        200,
        evaluate_and_record(
            body,
            audit_store,
            prepared_action=action,
            prepared_phase_timings=preparation_timings,
        ),
    )



MANAGEMENT_REVIEW_EVENT_TYPE = "management_review.created"
_MANAGEMENT_REVIEW_POLICY_EVENTS = {
    "policy.created",
    "policy.updated",
    "policy.published",
    "policy.suspended",
    "policy.reactivated",
    "policy.deleted",
    "policy.reviewed",
}


def _management_review_date(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field} is required.")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO-8601 date.") from exc
    return parsed.date().isoformat()


def _management_review_text(value: Any, field: str, maximum: int = 10_000) -> str:
    if value in (None, ""):
        return ""
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string.")
    text = value.strip()
    if len(text) > maximum:
        raise ValueError(f"{field} must be no longer than {maximum} characters.")
    return text


def _management_review_metrics(tenant_id: str, period_start: str, period_end: str) -> dict[str, int]:
    events = store().list_events(
        tenant_id,
        limit=100,
        filters={
            "start_time": f"{period_start}T00:00:00Z",
            "end_time": f"{period_end}T23:59:59.999999Z",
            "limit": 100,
        },
    )
    action_events = [event for event in events if str(event.get("event_type") or "") == "action.evaluated"]
    raised_nonconformities = sum(
        1 for event in events if str(event.get("event_type") or "") in {"nonconformity.raised", "nonconformity.opened"}
    )
    closed_nonconformities = sum(
        1
        for event in events
        if str(event.get("event_type") or "") in {
            "nonconformity.closed",
            "nonconformity.corrected",
            "nonconformity.resolved",
        }
    )
    return {
        "total_actions": len(action_events),
        "approvals_required": sum(1 for event in action_events if event.get("decision") == "require_approval"),
        "denials": sum(1 for event in action_events if event.get("decision") == "deny"),
        "policies_changed": sum(1 for event in events if event.get("event_type") in _MANAGEMENT_REVIEW_POLICY_EVENTS),
        "agents_registered": sum(1 for event in events if event.get("event_type") == "agent.registered"),
        "nonconformities_open": max(0, raised_nonconformities - closed_nonconformities),
    }


def _management_review_from_event(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "review_id": event.get("management_review_id") or event.get("action_id"),
        "tenant_id": event.get("tenant_id"),
        "period_start": event.get("period_start"),
        "period_end": event.get("period_end"),
        "attendees": event.get("attendees") or "",
        "decisions": event.get("decisions") or "",
        "action_items": event.get("action_items") or "",
        "metrics": event.get("metrics") if isinstance(event.get("metrics"), dict) else {},
        "created_at": event.get("created_at"),
        "created_by": event.get("created_by") or event.get("invoked_by"),
    }


def handle_create_management_review(body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    bind_tenant(body, auth)
    tenant_id = tenant_from({}, body, auth)
    period_start = _management_review_date(body.get("period_start"), "period_start")
    period_end = _management_review_date(body.get("period_end"), "period_end")
    if period_start > period_end:
        raise ValueError("period_start must not be after period_end.")
    created_by = authenticated_principal(auth)
    created_at = utc_now()
    review = {
        "review_id": f"management-review-{uuid.uuid4().hex[:16]}",
        "tenant_id": tenant_id,
        "period_start": period_start,
        "period_end": period_end,
        "attendees": _management_review_text(body.get("attendees"), "attendees"),
        "decisions": _management_review_text(body.get("decisions"), "decisions"),
        "action_items": _management_review_text(body.get("action_items"), "action_items"),
        "metrics": _management_review_metrics(tenant_id, period_start, period_end),
        "created_at": created_at,
        "created_by": created_by,
    }
    store().put_event(
        {
            "event_type": MANAGEMENT_REVIEW_EVENT_TYPE,
            "tenant_id": tenant_id,
            "environment": "governance",
            "run_id": "management-review",
            "action_id": review["review_id"],
            "agent_id": "management-review",
            "invoked_by": created_by,
            "created_at": created_at,
            "management_review_id": review["review_id"],
            **review,
        }
    )
    return response(201, review)


def handle_list_management_reviews(event: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    query = event.get("queryStringParameters") or {}
    requested_tenant = query.get("tenant_id")
    if requested_tenant and requested_tenant != auth.get("tenant_id") and not has_scope(auth, "admin"):
        return response(403, {"error": "tenant_mismatch"})
    tenant_id = str(requested_tenant or auth["tenant_id"])
    review_events = store().list_events(
        tenant_id,
        limit=100,
        filters={"event_type": MANAGEMENT_REVIEW_EVENT_TYPE, "limit": 100},
    )
    reviews = [
        _management_review_from_event(item)
        for item in review_events
        if item.get("source") != "external"
    ]
    return response(200, {"tenant_id": tenant_id, "reviews": reviews})


def _tenant_for_governance_query(event: dict[str, Any], auth: dict[str, Any]) -> tuple[str | None, dict[str, Any] | None]:
    query = event.get("queryStringParameters") or {}
    requested_tenant = query.get("tenant_id")
    if requested_tenant and requested_tenant != auth.get("tenant_id") and not has_scope(auth, "admin"):
        return None, response(403, {"error": "tenant_mismatch"})
    return str(requested_tenant or auth["tenant_id"]), None


def _nonconformity_records(tenant_id: str, audit_store: "AuditStore") -> list[dict[str, Any]]:
    events = audit_store.list_events(
        tenant_id,
        limit=100,
        filters={"event_type": "nonconformity.raised", "limit": 100},
    )
    resolved_events = audit_store.list_events(
        tenant_id,
        limit=100,
        filters={"event_type": "nonconformity.resolved", "limit": 100},
    )
    records: dict[str, dict[str, Any]] = {}
    for event in sorted(events, key=lambda item: str(item.get("created_at") or "")):
        nc_id = str(event.get("nc_id") or event.get("action_id") or "").strip()
        if not nc_id:
            continue
        records[nc_id] = {
            "nc_id": nc_id,
            "tenant_id": tenant_id,
            "title": event.get("title") or "",
            "description": event.get("description") or "",
            "severity": event.get("severity") or "",
            "source_event_id": event.get("source_event_id") or "",
            "status": "open",
            "created_at": event.get("created_at"),
        }
    for event in sorted(resolved_events, key=lambda item: str(item.get("created_at") or "")):
        nc_id = str(event.get("nc_id") or event.get("action_id") or "").strip()
        if not nc_id:
            continue
        record = records.get(nc_id)
        if record is None:
            record = {"nc_id": nc_id, "tenant_id": tenant_id, "status": "open"}
            records[nc_id] = record
        record.update(
            {
                "status": "resolved",
                "corrective_action": event.get("corrective_action") or "",
                "resolved_by": event.get("resolved_by") or event.get("invoked_by") or "",
                "resolved_at": event.get("created_at"),
            }
        )
    return sorted(records.values(), key=lambda item: str(item.get("created_at") or ""), reverse=True)


def handle_create_nonconformity(body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    bind_tenant(body, auth)
    tenant_id = tenant_from({}, body, auth)
    record = normalise_nonconformity(body, tenant_id)
    store().put_event(
        {
            "event_type": "nonconformity.raised",
            "tenant_id": tenant_id,
            "environment": "governance",
            "run_id": "nonconformity-tracker",
            "action_id": record["nc_id"],
            "agent_id": "nonconformity-tracker",
            "invoked_by": authenticated_principal(auth),
            **record,
        }
    )
    return response(201, record)


def handle_list_nonconformities(event: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    tenant_id, error = _tenant_for_governance_query(event, auth)
    if error:
        return error
    query = event.get("queryStringParameters") or {}
    status = str(query.get("status") or "all").strip().lower()
    if status not in {"all", "open", "resolved"}:
        return response(400, {"error": "status_must_be_open_resolved_or_all"})
    records = _nonconformity_records(str(tenant_id), store())
    if status != "all":
        records = [record for record in records if record.get("status") == status]
    return response(200, {"tenant_id": tenant_id, "status": status, "nonconformities": records})


def handle_resolve_nonconformity(nc_id: str, body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    bind_tenant(body, auth)
    tenant_id = tenant_from({}, body, auth)
    records = _nonconformity_records(tenant_id, store())
    record = next((item for item in records if str(item.get("nc_id") or "") == nc_id), None)
    if record is None:
        return response(404, {"error": "nonconformity_not_found", "nc_id": nc_id})
    if record.get("status") == "resolved":
        return response(200, record)
    corrective_action = body.get("corrective_action")
    if not isinstance(corrective_action, str) or not corrective_action.strip():
        return response(400, {"error": "corrective_action_required"})
    if len(corrective_action.strip()) > 10_000:
        return response(400, {"error": "corrective_action_too_long"})
    resolved_by = str(body.get("resolved_by") or authenticated_principal(auth)).strip()
    if not resolved_by:
        return response(400, {"error": "resolved_by_required"})
    resolved_at = utc_now()
    store().put_event(
        {
            "event_type": "nonconformity.resolved",
            "tenant_id": tenant_id,
            "environment": "governance",
            "run_id": "nonconformity-tracker",
            "action_id": nc_id,
            "agent_id": "nonconformity-tracker",
            "invoked_by": authenticated_principal(auth),
            "created_at": resolved_at,
            "nc_id": nc_id,
            "corrective_action": corrective_action.strip(),
            "resolved_by": resolved_by,
        }
    )
    return response(
        200,
        {
            **record,
            "status": "resolved",
            "corrective_action": corrective_action.strip(),
            "resolved_by": resolved_by,
            "resolved_at": resolved_at,
        },
    )


def handle_report_concern(body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    bind_tenant(body, auth)
    tenant_id = tenant_from({}, body, auth)
    record = normalise_concern(body, tenant_id)
    store().put_event(
        {
            "event_type": "concern.reported",
            "tenant_id": tenant_id,
            "environment": "governance",
            "run_id": "concerns-reporting",
            "action_id": record["concern_id"],
            "agent_id": "concerns-reporting",
            "invoked_by": "anonymous" if record["anonymous"] else authenticated_principal(auth),
            **record,
        }
    )
    return response(201, record)


def _data_resource_records(tenant_id: str, model_id: str, audit_store: "AuditStore") -> list[dict[str, Any]]:
    events = audit_store.list_events(
        tenant_id,
        limit=100,
        filters={"event_type": "data_resource.registered", "limit": 100},
    )
    resources = [
        {
            key: event.get(key)
            for key in (
                "data_resource_id",
                "tenant_id",
                "model_id",
                "name",
                "source",
                "category",
                "acquisition_date",
                "provenance",
                "preparation_notes",
                "created_at",
            )
        }
        for event in events
        if str(event.get("model_id") or "") == model_id
    ]
    return sorted(resources, key=lambda item: str(item.get("created_at") or ""), reverse=True)


def handle_register_data_resource(model_id: str, body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    bind_tenant(body, auth)
    tenant_id = tenant_from({}, body, auth)
    model_store = store()
    if not model_store.get_model(model_id, tenant_id):
        return response(404, {"error": "model_not_found", "model_id": model_id})
    resource = normalise_data_resource(body, tenant_id, model_id)
    model_store.put_event(
        {
            "event_type": "data_resource.registered",
            "tenant_id": tenant_id,
            "environment": "governance",
            "run_id": "data-governance",
            "action_id": resource["data_resource_id"],
            "agent_id": "data-governance",
            "invoked_by": authenticated_principal(auth),
            **resource,
        }
    )
    return response(201, resource)


def handle_list_data_resources(model_id: str, auth: dict[str, Any]) -> dict[str, Any]:
    tenant_id = str(auth.get("tenant_id") or "")
    model_store = store()
    if not model_store.get_model(model_id, tenant_id):
        return response(404, {"error": "model_not_found", "model_id": model_id})
    return response(
        200,
        {
            "tenant_id": tenant_id,
            "model_id": model_id,
            "data_resources": _data_resource_records(tenant_id, model_id, model_store),
        },
    )


def _supplier_with_binding_count(supplier: dict[str, Any], models: list[dict[str, Any]]) -> dict[str, Any]:
    supplier_id = str(supplier.get("supplier_id") or "")
    return {
        **supplier,
        "bound_model_count": sum(1 for model in models if str(model.get("supplier_id") or "") == supplier_id),
    }


def handle_register_supplier(body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    bind_tenant(body, auth)
    tenant_id = tenant_from({}, body, auth)
    supplier = normalise_supplier(body, tenant_id)
    supplier_store = store()
    try:
        supplier_store.put_supplier(supplier, require_absent=True)
    except Exception as exc:
        if _is_conditional_check_failure(exc):
            return response(409, {"error": "supplier_already_registered", "supplier_id": supplier["supplier_id"]})
        raise
    supplier_store.put_event(
        {
            "event_type": "supplier.registered",
            "tenant_id": tenant_id,
            "environment": "governance",
            "run_id": "supplier-registry",
            "action_id": supplier["supplier_id"],
            "agent_id": "supplier-registry",
            "invoked_by": authenticated_principal(auth),
            **supplier,
        }
    )
    return response(201, _supplier_with_binding_count(supplier, []))


def handle_list_suppliers(auth: dict[str, Any]) -> dict[str, Any]:
    supplier_store = store()
    models = supplier_store.list_models(str(auth["tenant_id"]))
    suppliers = [
        _supplier_with_binding_count(supplier, models)
        for supplier in supplier_store.list_suppliers(str(auth["tenant_id"]))
    ]
    return response(200, {"tenant_id": auth["tenant_id"], "suppliers": suppliers})


def handle_audit(event: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    query = event.get("queryStringParameters") or {}
    requested_tenant = query.get("tenant_id")
    if requested_tenant and requested_tenant != auth.get("tenant_id") and not has_scope(auth, "admin"):
        return response(403, {"error": "tenant_mismatch"})
    tenant_id = str(requested_tenant or auth["tenant_id"])
    filters = normalise_filters(query)
    return response(200, {"tenant_id": tenant_id, "filters": filters, "events": store().list_events(tenant_id, filters=filters)})


def handle_security_events(event: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    """Return tenant-scoped security and administration events for monitoring."""

    query = event.get("queryStringParameters") or {}
    requested_tenant = query.get("tenant_id")
    if requested_tenant and requested_tenant != auth.get("tenant_id") and not has_scope(auth, "admin"):
        return response(403, {"error": "tenant_mismatch"})
    tenant_id = str(requested_tenant or auth["tenant_id"])
    filters = normalise_filters(query)
    events = store().list_events(tenant_id, filters=filters)
    security_events = [
        item for item in events
        if str(item.get("event_type") or "").startswith(("auth.", "platform.", "tenant.", "environment.", "audit."))
        or item.get("status") == "denied"
    ]
    return response(200, {"tenant_id": tenant_id, "events": security_events[:int(filters.get("limit") or 50)], "monitoring": {"source": "tenant-audit-stream", "filters": filters}})


CONSENT_EVENT_TYPES = ("consent.granted", "consent.revoked")
CONSENT_STATUSES = {"active", "expired", "revoked"}
CONSENT_MAX_TEXT_LENGTH = 256


def _consent_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required.")
    text = value.strip()
    if len(text) > CONSENT_MAX_TEXT_LENGTH:
        raise ValueError(f"{field} must be no longer than {CONSENT_MAX_TEXT_LENGTH} characters.")
    return text


def _consent_expiry(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise ValueError("expires_at must be an ISO-8601 timestamp.")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("expires_at must be an ISO-8601 timestamp.") from exc
    if parsed.tzinfo is None:
        raise ValueError("expires_at must include a timezone.")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _consent_record(event: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    """Return a consent summary with status derived from its latest event."""

    event_type = str(event.get("event_type") or "")
    status = "revoked" if event_type == "consent.revoked" else "active"
    expires_at = event.get("expires_at")
    if status == "active" and expires_at:
        try:
            expiry = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
            if expiry.tzinfo is not None and expiry <= (now or datetime.now(timezone.utc)):
                status = "expired"
        except ValueError:
            status = "expired"
    return {
        "consent_id": event.get("consent_id") or event.get("action_id"),
        "tenant_id": event.get("tenant_id"),
        "subject": event.get("subject") or "",
        "purpose": event.get("purpose") or "",
        "data_scope": event.get("data_scope") or "",
        "granted_at": event.get("granted_at") or event.get("created_at"),
        "expires_at": expires_at,
        "status": status,
        "created_at": event.get("created_at"),
        "revoked_at": event.get("revoked_at") if status == "revoked" else None,
        "revoked_by": event.get("revoked_by") if status == "revoked" else None,
    }


def _list_consents(
    tenant_id: str,
    audit_store: AuditStore | None = None,
    filters: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Build tenant-scoped consent records from append-only audit events."""

    audit_store = audit_store or store()
    filters = dict(filters or {})
    events: list[dict[str, Any]] = []
    for event_type in CONSENT_EVENT_TYPES:
        events.extend(
            audit_store.list_events(
                tenant_id,
                filters={"event_type": event_type, "limit": 100},
            )
        )

    latest: dict[str, dict[str, Any]] = {}
    for event in events:
        if event.get("source") == "external":
            continue
        consent_id = str(event.get("consent_id") or event.get("action_id") or "").strip()
        if not consent_id:
            continue
        current = latest.get(consent_id)
        event_key = (
            str(event.get("created_at") or ""),
            1 if str(event.get("event_type") or "") == "consent.revoked" else 0,
        )
        current_key = (
            str(current.get("created_at") or ""),
            1 if str(current.get("event_type") or "") == "consent.revoked" else 0,
        ) if current else ("", -1)
        if current is None or event_key >= current_key:
            latest[consent_id] = event

    records = [_consent_record(event) for event in latest.values()]
    consent_id = str(filters.get("consent_id") or "").strip()
    subject = str(filters.get("subject") or "").strip()
    purpose = str(filters.get("purpose") or "").strip()
    status = str(filters.get("status") or "").strip().lower()
    if consent_id:
        records = [record for record in records if str(record.get("consent_id") or "") == consent_id]
    if subject:
        records = [record for record in records if str(record.get("subject") or "") == subject]
    if purpose:
        records = [record for record in records if str(record.get("purpose") or "") == purpose]
    if status:
        records = [record for record in records if record.get("status") == status]
    records.sort(key=lambda record: str(record.get("created_at") or ""), reverse=True)
    try:
        limit = max(1, min(int(filters.get("limit") or 50), 100))
    except (TypeError, ValueError) as exc:
        raise ValueError("limit must be an integer between 1 and 100") from exc
    return records[:limit]


def handle_create_consent(body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    bind_tenant(body, auth)
    tenant_id = tenant_from({}, body, auth)
    subject = _consent_text(body.get("subject"), "subject")
    purpose = _consent_text(body.get("purpose"), "purpose")
    data_scope = _consent_text(body.get("data_scope"), "data_scope")
    expires_at = _consent_expiry(body.get("expires_at"))
    consent_id = f"consent-{uuid.uuid4().hex[:16]}"
    created_at = utc_now()
    event = {
        "event_type": "consent.granted",
        "tenant_id": tenant_id,
        "environment": "governance",
        "run_id": "consent-management",
        "action_id": consent_id,
        "agent_id": "consent-management",
        "invoked_by": authenticated_principal(auth),
        "created_at": created_at,
        "source": "internal",
        "consent_id": consent_id,
        "granted_at": created_at,
        "subject": subject,
        "purpose": purpose,
        "data_scope": data_scope,
        "expires_at": expires_at,
        "status": "active",
    }
    store().put_event(event)
    return response(201, _consent_record(event))


def handle_list_consents(event: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    query = event.get("queryStringParameters") or {}
    tenant_id, error = tenant_target(str(query.get("tenant_id") or auth.get("tenant_id") or ""), auth)
    if error:
        return error
    status = str(query.get("status") or "").strip().lower()
    if status and status not in CONSENT_STATUSES:
        return response(400, {"error": "invalid_consent_status", "allowed_statuses": sorted(CONSENT_STATUSES)})
    filters = {
        "consent_id": query.get("consent_id"),
        "subject": query.get("subject"),
        "purpose": query.get("purpose"),
        "status": status,
        "limit": query.get("limit"),
    }
    consents = _list_consents(str(tenant_id), filters=filters)
    return response(200, {"tenant_id": tenant_id, "count": len(consents), "consents": consents})


def handle_revoke_consent(consent_id: str, body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    bind_tenant(body, auth)
    consent_id = str(consent_id or "").strip()
    if not consent_id:
        return response(404, {"error": "consent_not_found", "consent_id": consent_id})
    audit_store = store()
    current_records = _list_consents(
        str(auth.get("tenant_id") or ""),
        audit_store=audit_store,
        filters={"consent_id": consent_id, "limit": 100},
    )
    if not current_records:
        return response(404, {"error": "consent_not_found", "consent_id": consent_id})
    current = current_records[0]
    if current.get("status") == "revoked":
        return response(200, {**current, "idempotent": True})
    revoked_at = utc_now()
    event = {
        "event_type": "consent.revoked",
        "tenant_id": str(auth.get("tenant_id") or ""),
        "environment": "governance",
        "run_id": "consent-management",
        "action_id": consent_id,
        "agent_id": "consent-management",
        "invoked_by": authenticated_principal(auth),
        "created_at": revoked_at,
        "source": "internal",
        "consent_id": consent_id,
        "granted_at": current.get("granted_at") or current.get("created_at"),
        "subject": current.get("subject"),
        "purpose": current.get("purpose"),
        "data_scope": current.get("data_scope"),
        "expires_at": current.get("expires_at"),
        "status": "revoked",
        "revoked_at": revoked_at,
        "revoked_by": authenticated_principal(auth),
    }
    audit_store.put_event(event)
    return response(200, {**_consent_record(event), "idempotent": False})


AUDIT_EVENT_TYPE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,99}$")
AUDIT_EVENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
AUDIT_IDEMPOTENCY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
AUDIT_INGEST_FIELDS = {
    "event_type",
    "environment",
    "run_id",
    "action_id",
    "agent_id",
    "invoked_by",
    "decision",
    "risk",
    "risk_score",
    "action_classification",
    "reason_codes",
    "reasons",
    "action_hash",
    "policy_id",
    "policy_version",
    "approval_id",
    "proof_id",
    "receipt",
    "action",
    "evidence",
    "status",
    "result",
    "metadata",
}
AUDIT_INGEST_CONTROL_FIELDS = {"context", "tenant_id", "event_id", "idempotency_key", "created_at"}
AUDIT_INGEST_RESERVED_EVENT_TYPES = {
    "action.evaluated",
    "action.outcome",
    "consent.granted",
    "consent.revoked",
    "compliance.evidence_exported",
    MANAGEMENT_REVIEW_EVENT_TYPE,
}


def _bounded_identifier(value: Any, field: str, pattern: re.Pattern[str], maximum: int) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    if not pattern.fullmatch(text):
        raise ValueError(f"{field} must match {pattern.pattern}.")
    return text[:maximum]


def handle_ingest_audit_event(event: dict[str, Any], body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    """Accept one external, append-only audit event without executing anything."""

    bind_tenant(body, auth)
    unsupported_fields = set(body) - AUDIT_INGEST_FIELDS - AUDIT_INGEST_CONTROL_FIELDS
    if unsupported_fields:
        raise ValueError(f"Unsupported audit event fields: {', '.join(sorted(unsupported_fields))}.")
    context = body.get("context") if isinstance(body.get("context"), dict) else {}
    tenant_id = str(context.get("tenant_id") or body.get("tenant_id") or auth["tenant_id"])
    event_type = str(body.get("event_type") or "").strip().lower()
    if not AUDIT_EVENT_TYPE_PATTERN.fullmatch(event_type):
        raise ValueError("event_type must contain 1-100 lowercase letters, numbers, dots, underscores, or hyphens.")
    if event_type in AUDIT_INGEST_RESERVED_EVENT_TYPES:
        raise ValueError("event_type is reserved for internally generated Guard events.")

    event_id = _bounded_identifier(body.get("event_id"), "event_id", AUDIT_EVENT_ID_PATTERN, 128)
    headers = request_headers(event)
    header_idempotency = str(headers.get("idempotency-key") or "").strip()
    body_idempotency = str(body.get("idempotency_key") or "").strip()
    if header_idempotency and body_idempotency and header_idempotency != body_idempotency:
        raise ValueError("The Idempotency-Key header and idempotency_key body field must match.")
    idempotency_key = _bounded_identifier(
        header_idempotency or body_idempotency,
        "idempotency_key",
        AUDIT_IDEMPOTENCY_PATTERN,
        256,
    )

    created_at = str(body.get("created_at") or utc_now()).strip()
    try:
        datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("created_at must be an ISO-8601 timestamp.") from exc

    audit_store = store()
    tenant_config = audit_store.get_tenant_config(tenant_id) or default_tenant_config(tenant_id)
    ingested = {
        key: body[key]
        for key in AUDIT_INGEST_FIELDS
        if key in body and key not in {"event_type", "action"}
    }
    ingested.update(
        {
            "event_type": event_type,
            "tenant_id": tenant_id,
            "created_at": created_at,
            "event_id": event_id or f"evt-{uuid.uuid4().hex[:16]}",
            "source": "external",
            "ingested_by": str(auth.get("subject") or auth.get("token_id") or "authenticated-principal"),
            "auth_source": str(auth.get("auth_source") or "pat"),
        }
    )
    if isinstance(context, dict):
        for field in ("environment", "run_id", "action_id", "agent_id", "invoked_by"):
            if field not in ingested and context.get(field) not in (None, ""):
                ingested[field] = str(context[field])
    if isinstance(body.get("action"), dict):
        ingested["action"] = capture_action(body["action"], tenant_config.get("capture_policy"))
    if idempotency_key:
        ingested["idempotency_key"] = f"audit-ingest:{tenant_id}:{idempotency_key}"

    try:
        encoded_size = len(json.dumps(ingested, default=_json_default, ensure_ascii=False).encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise ValueError("Audit event fields must be JSON serialisable.") from exc
    if encoded_size > 300_000:
        raise ValueError("Audit event payload must be no larger than 300 KB.")

    delivery = audit_store.put_event(ingested)
    duplicate = delivery.get("status") == "duplicate"
    return response(
        200 if duplicate else 201,
        {
            "status": "duplicate" if duplicate else "accepted",
            "tenant_id": tenant_id,
            "event_id": ingested["event_id"],
            "event_type": event_type,
            "idempotency_key": idempotency_key,
            "delivery": delivery,
        },
    )


def handle_audit_export(event: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    query = event.get("queryStringParameters") or {}
    requested_tenant = query.get("tenant_id")
    if requested_tenant and requested_tenant != auth.get("tenant_id") and not has_scope(auth, "admin"):
        return response(403, {"error": "tenant_mismatch"})
    tenant_id = str(requested_tenant or auth["tenant_id"])
    filters = normalise_filters(query)
    audit_store = store()
    events = audit_store.list_events(tenant_id, filters=filters)
    export_format = str(query.get("format") or "json").lower()
    audit_store.put_event(
        {
            "event_type": "audit.exported",
            "tenant_id": tenant_id,
            "environment": "audit",
            "run_id": "audit-management",
            "action_id": f"audit-export-{uuid.uuid4().hex[:16]}",
            "agent_id": "audit-client",
            "invoked_by": str(auth.get("subject") or auth.get("token_id") or "authenticated-principal"),
            "created_at": utc_now(),
            "status": "accepted",
            "export_format": export_format,
            "event_count": len(events),
            "filter_fields": sorted(filters),
        }
    )
    if export_format == "jsonl":
        lines = "\n".join(json.dumps(event, default=_json_default, sort_keys=True) for event in events)
        if lines:
            lines += "\n"
        return raw_response(
            200,
            lines,
            "application/x-ndjson",
            {"x-kenning-tenant-id": tenant_id, "x-kenning-export-filters": json.dumps(filters, sort_keys=True)},
        )
    return response(200, {"tenant_id": tenant_id, "format": "json", "filters": filters, "events": events})


def handle_metrics(event: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    query = event.get("queryStringParameters") or {}
    requested_tenant = query.get("tenant_id")
    if requested_tenant and requested_tenant != auth.get("tenant_id") and not has_scope(auth, "admin"):
        return response(403, {"error": "tenant_mismatch"})
    tenant_id = str(requested_tenant or auth["tenant_id"])

    def metric_day(value: Any) -> str | None:
        if value in (None, ""):
            return None
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00")).date().isoformat()
        except ValueError as exc:
            raise ValueError("start_time and end_time must be ISO-8601 timestamps") from exc

    start_day = metric_day(query.get("start_time"))
    end_day = metric_day(query.get("end_time"))
    if start_day and end_day and start_day > end_day:
        raise ValueError("start_time must not be after end_time")
    return response(
        200,
        {
            "tenant_id": tenant_id,
            "period": {"start": start_day, "end": end_day, "granularity": "day"},
            "metrics": store().get_metrics(tenant_id, start_day=start_day, end_day=end_day),
        },
    )


def handle_get_tenant(tenant_id: str, auth: dict[str, Any]) -> dict[str, Any]:
    tenant_id, error = tenant_target(tenant_id, auth)
    if error:
        return error
    config = store().get_tenant_config(tenant_id) or default_tenant_config(tenant_id)
    defaults = default_tenant_config(tenant_id)
    if any(field not in config for field in ("capture_policy", "citation_policy", "audit_sink", "legal_hold_enabled", "data_residency_region", "workload_identity", "starter_rules", "enabled_products")):
        config = {
            **config,
            "capture_policy": config.get("capture_policy") or defaults["capture_policy"],
            "citation_policy": config.get("citation_policy") or defaults["citation_policy"],
            "audit_sink": config.get("audit_sink") or defaults["audit_sink"],
            "legal_hold_enabled": config.get("legal_hold_enabled", defaults["legal_hold_enabled"]),
            "legal_hold_reason": config.get("legal_hold_reason", defaults["legal_hold_reason"]),
            "legal_hold_set_by": config.get("legal_hold_set_by", defaults["legal_hold_set_by"]),
            "legal_hold_updated_at": config.get("legal_hold_updated_at", defaults["legal_hold_updated_at"]),
            "data_residency_region": config.get("data_residency_region", defaults["data_residency_region"]),
            "workload_identity": config.get("workload_identity", defaults["workload_identity"]),
            "starter_rules": normalise_starter_rules(config.get("starter_rules")),
            "enabled_products": enabled_products_for_config(config),
        }
    summary = tenant_summary(config)
    return response(
        200,
        {
            **config,
            "environment_ids": summary["environment_ids"],
            "environment_count": summary["environment_count"],
        },
    )


def tenant_summary(config: dict[str, Any]) -> dict[str, Any]:
    environments = [
        item for item in (config.get("environments") or [])
        if isinstance(item, dict) and item.get("environment_id")
    ]
    return {
        "tenant_id": config.get("tenant_id"),
        "name": config.get("name"),
        "status": config.get("status"),
        "configured": bool(config.get("configured")),
        "default_environment": config.get("default_environment"),
        "environment_ids": sorted(str(item["environment_id"]) for item in environments),
        "environment_count": len(environments),
        "retention_enabled": bool(config.get("retention_enabled")),
        "retention_days": config.get("retention_days"),
        "legal_hold_enabled": bool(config.get("legal_hold_enabled")),
        "data_residency_region": config.get("data_residency_region"),
        "starter_rule_count": len(normalise_starter_rules(config.get("starter_rules"))),
        "starter_rule_enabled_count": sum(1 for rule in normalise_starter_rules(config.get("starter_rules")) if rule.get("enabled")),
        "enabled_products": enabled_products_for_config(config),
        "config_version": config.get("config_version"),
        "created_at": config.get("created_at"),
        "updated_at": config.get("updated_at"),
    }


def handle_list_tenants(event: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    query = event.get("queryStringParameters") or {}
    requested_tenant = str(query.get("tenant_id") or "").strip()
    if requested_tenant and requested_tenant != str(auth.get("tenant_id")) and not has_scope(auth, "admin"):
        return response(403, {"error": "tenant_mismatch"})
    status = str(query.get("status") or "").strip().lower()
    if status and status not in TENANT_STATUSES:
        return response(400, {"error": "invalid_tenant_status", "allowed_statuses": sorted(TENANT_STATUSES)})
    try:
        limit = int(query.get("limit") or 100)
    except (TypeError, ValueError) as exc:
        raise ValueError("limit must be an integer between 1 and 100") from exc
    if limit < 1 or limit > 100:
        raise ValueError("limit must be an integer between 1 and 100")

    tenant_id = requested_tenant or (None if has_scope(auth, "admin") else str(auth.get("tenant_id") or ""))
    configs = store().list_tenant_configs(tenant_id=tenant_id, status=status, limit=limit)
    if not configs and not status and (
        not has_scope(auth, "admin") or requested_tenant == str(auth.get("tenant_id"))
    ):
        configs = [default_tenant_config(str(auth.get("tenant_id")))]
    return response(
        200,
        {
            "tenant_id": requested_tenant or (str(auth.get("tenant_id")) if not has_scope(auth, "admin") else None),
            "count": len(configs),
            "tenants": [tenant_summary(config) for config in configs[:limit]],
        },
    )


def handle_put_tenant(tenant_id: str, body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    tenant_id, error = tenant_target(tenant_id, auth)
    if error:
        return error
    if "enabled_products" in body and is_session_auth(auth) and not role_allows(str(auth.get("role") or ""), "admin"):
        return response(
            403,
            {
                "error": "membership_role_required",
                "required_role": "admin",
                "message": "Only workspace owners and administrators can change product access.",
            },
        )
    config_store = store()
    existing = config_store.get_tenant_config(tenant_id)
    config = build_tenant_config(tenant_id, body, existing)
    legal_hold_changed = bool(config.get("legal_hold_enabled")) != bool((existing or {}).get("legal_hold_enabled"))
    cleared_ttl_count = config_store.clear_retention_expiry(tenant_id) if config.get("legal_hold_enabled") else 0
    if legal_hold_changed:
        config["legal_hold_set_by"] = str(auth.get("subject") or auth.get("token_id") or "tenant-administrator")
        config["legal_hold_updated_at"] = utc_now()
    config_store.put_tenant_config(config)
    config_store.put_event(tenant_admin_event(
        "tenant.config.updated",
        config,
        auth,
        previous_status=(existing or {}).get("status"),
        status=config["status"],
        retention_enabled=config["retention_enabled"],
        retention_days=config["retention_days"],
        legal_hold_enabled=config["legal_hold_enabled"],
        legal_hold_changed=legal_hold_changed,
        cleared_retention_ttl_count=cleared_ttl_count,
        data_residency_region=config["data_residency_region"],
        previous_enabled_products=enabled_products_for_config(existing),
        enabled_products=config["enabled_products"],
    ))
    return response(200 if existing else 201, config)


def handle_get_starter_rules(tenant_id: str, auth: dict[str, Any]) -> dict[str, Any]:
    tenant_id, error = tenant_target(tenant_id, auth)
    if error:
        return error
    config = store().get_tenant_config(tenant_id) or default_tenant_config(tenant_id)
    rules = normalise_starter_rules(config.get("starter_rules"))
    return response(
        200,
        {
            "tenant_id": tenant_id,
            "config_version": config.get("config_version"),
            "rules": rules,
            "summary": starter_rule_summary(rules),
            "available_defaults": default_starter_rules(),
        },
    )


def handle_put_starter_rules(tenant_id: str, body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    tenant_id, error = tenant_target(tenant_id, auth)
    if error:
        return error
    if "rules" not in body:
        return response(400, {"error": "starter_rules_required", "message": "rules must be provided as an array."})
    config_store = store()
    existing = config_store.get_tenant_config(tenant_id)
    config = build_tenant_config(tenant_id, {"starter_rules": body.get("rules")}, existing)
    config_store.put_tenant_config(config)
    config_store.put_event(
        tenant_admin_event(
            "starter_rules.updated",
            config,
            auth,
            previous_config_version=(existing or {}).get("config_version"),
            starter_rule_summary=starter_rule_summary(config["starter_rules"]),
        )
    )
    return response(
        200 if existing else 201,
        {
            "tenant_id": tenant_id,
            "config_version": config.get("config_version"),
            "rules": config["starter_rules"],
            "summary": starter_rule_summary(config["starter_rules"]),
        },
    )


def handle_simulate_starter_rule(tenant_id: str, body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    """Evaluate one configured starter rule without creating an action record."""

    tenant_id, error = tenant_target(tenant_id, auth)
    if error:
        return error
    rule_id = str(body.get("rule_id") or "").strip()
    config = store().get_tenant_config(tenant_id) or default_tenant_config(tenant_id)
    rules = normalise_starter_rules(config.get("starter_rules"))
    rule = next((item for item in rules if str(item.get("rule_id") or "") == rule_id), None)
    if not rule:
        return response(404, {"error": "starter_rule_not_found", "rule_id": rule_id})
    context = body.get("context") if isinstance(body.get("context"), dict) else {}
    payload = {**body, "context": {**context, "tenant_id": tenant_id}}
    action = normalise_action(payload)
    mode = str(body.get("mode") or action.get("mode") or "enforce")
    decision = evaluate(action, mode=mode, starter_rules=rules)
    decision["policy_id"] = "kenning-agent-guard-mvp"
    decision["policy_version"] = 1
    custom_policy = custom_starter_policy(rules, tenant_id, int(config.get("config_version") or 1), mode=mode)
    decision = _impact_assessment_policy_context(decision, action, [custom_policy] if custom_policy else [], store())
    decision["capture_policy"] = capture_policy_summary(config.get("capture_policy"))
    decision["action"] = capture_action(action, config.get("capture_policy"))
    decision["simulation"] = True
    decision["simulated_rule_id"] = rule_id
    decision["simulated_rule_source"] = rule.get("source") or ("kenning-default" if rule.get("kind") == "builtin" else "tenant")
    store().put_event(
        {
            "event_type": "starter_rule.simulated",
            "tenant_id": tenant_id,
            "environment": action["environment"],
            "run_id": action["run_id"],
            "action_id": action["action_id"],
            "agent_id": action["agent_id"],
            "invoked_by": action["invoked_by"],
            "created_at": decision["evaluated_at"],
            "rule_id": rule_id,
            "rule_source": decision["simulated_rule_source"],
            "decision": decision["decision"],
            "reason_codes": decision.get("reason_codes") or [],
            "action_hash": decision["action_hash"],
        }
    )
    return response(200, decision)


def handle_list_environments(tenant_id: str, auth: dict[str, Any]) -> dict[str, Any]:
    tenant_id, error = tenant_target(tenant_id, auth)
    if error:
        return error
    config = store().get_tenant_config(tenant_id) or default_tenant_config(tenant_id)
    return response(
        200,
        {
            "tenant_id": tenant_id,
            "default_environment": config.get("default_environment"),
            "environments": config.get("environments") or [],
            "configured": bool(config.get("configured")),
        },
    )


def handle_put_environment(tenant_id: str, environment_id: str, body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    tenant_id, error = tenant_target(tenant_id, auth)
    if error:
        return error
    config_store = store()
    existing_config = config_store.get_tenant_config(tenant_id) or default_tenant_config(tenant_id)
    old_environment = environment_for(existing_config, environment_id)
    environment = build_environment_config(tenant_id, environment_id, body, old_environment)
    environments = [
        item for item in (existing_config.get("environments") or [])
        if isinstance(item, dict) and item.get("environment_id") != environment["environment_id"]
    ]
    environments.append(environment)
    next_payload = {
        "name": existing_config.get("name"),
        "status": existing_config.get("status", "active"),
        "default_environment": body.get("default_environment") or existing_config.get("default_environment", "development"),
        "environments": environments,
        "retention_enabled": existing_config.get("retention_enabled", False),
        "retention_days": existing_config.get("retention_days"),
        "legal_hold_enabled": existing_config.get("legal_hold_enabled", False),
        "legal_hold_reason": existing_config.get("legal_hold_reason", ""),
        "legal_hold_set_by": existing_config.get("legal_hold_set_by", ""),
        "legal_hold_updated_at": existing_config.get("legal_hold_updated_at"),
        "data_residency_region": existing_config.get("data_residency_region"),
        "audit_sink": existing_config.get("audit_sink"),
        "identity_provider": existing_config.get("identity_provider"),
        "workload_identity": existing_config.get("workload_identity"),
        "capture_policy": existing_config.get("capture_policy"),
        "citation_policy": existing_config.get("citation_policy"),
        "enabled_products": existing_config.get("enabled_products"),
    }
    config = build_tenant_config(tenant_id, next_payload, existing_config)
    config_store.put_tenant_config(config)
    config_store.put_event(tenant_admin_event(
        "environment.config.updated",
        config,
        auth,
        environment_id=environment["environment_id"],
        environment_status=environment["status"],
        environment_mode=environment["mode"],
        previous_environment_status=(old_environment or {}).get("status"),
    ))
    return response(200, environment)


def handle_retention_run(tenant_id: str, body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    tenant_id, error = tenant_target(tenant_id, auth)
    if error:
        return error
    config_store = store()
    config = config_store.get_tenant_config(tenant_id) or default_tenant_config(tenant_id)
    cutoff = retention_cutoff(config)
    if cutoff is None:
        return response(409, {"error": "retention_not_configured", "tenant_id": tenant_id})
    candidates = config_store.list_retention_candidates(tenant_id, cutoff)
    execute = bool(body.get("execute", False))
    result = {
        "tenant_id": tenant_id,
        "dry_run": not execute,
        "retention_days": config["retention_days"],
        "cutoff_epoch": cutoff,
        "cutoff": iso_from_epoch(cutoff),
        "candidate_count": len(candidates),
        "deleted_count": 0,
        "deleted_item_types": sorted({
            "event" if item.get("event_type") else "proof" if item.get("proof_id") else "approval"
            for item in candidates
        }),
        "legal_hold_enabled": bool(config.get("legal_hold_enabled")),
        "data_residency_region": config.get("data_residency_region"),
    }
    if execute and config.get("legal_hold_enabled"):
        result["error"] = "legal_hold_active"
        config_store.put_event(tenant_admin_event(
            "tenant.retention.blocked",
            config,
            auth,
            dry_run=False,
            candidate_count=result["candidate_count"],
            deleted_count=0,
            reason=config.get("legal_hold_reason") or "Tenant legal hold is active.",
        ))
        return response(409, result)
    if execute:
        for item in candidates:
            config_store.delete_record(item)
        result["deleted_count"] = len(candidates)
    config_store.put_event(tenant_admin_event(
        "tenant.retention.executed" if execute else "tenant.retention.previewed",
        config,
        auth,
        dry_run=not execute,
        candidate_count=result["candidate_count"],
        deleted_count=result["deleted_count"],
        cutoff=result["cutoff"],
    ))
    return response(200, result)



POLICY_REVIEW_INTERVAL = timedelta(days=365)


def _normalise_policy_review_timestamp(value: Any) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("last_reviewed_at must be an ISO-8601 timestamp.") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _policy_review_overdue(policy: dict[str, Any]) -> bool:
    value = policy.get("last_reviewed_at")
    if not value:
        return True
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return True
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - parsed > POLICY_REVIEW_INTERVAL


def _policy_with_review_status(policy: dict[str, Any]) -> dict[str, Any]:
    result = dict(policy)
    result["review_overdue"] = _policy_review_overdue(result)
    return result


def handle_create_policy(body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    if "last_reviewed_at" in body:
        body["last_reviewed_at"] = _normalise_policy_review_timestamp(body.get("last_reviewed_at"))
    bind_tenant(body, auth)
    tenant_id = tenant_from({}, body, auth)
    policy_id = str(body.get("policy_id") or "")
    versions = store().list_policy_versions(policy_id, tenant_id) if policy_id else []
    requested_version = body.get("version")
    version = int(requested_version) if requested_version is not None else (max((int(item.get("version", 0)) for item in versions), default=0) + 1)
    if any(int(item.get("version", 0)) == version for item in versions):
        return response(409, {"error": "policy_version_already_exists", "policy_id": policy_id, "version": version})
    policy = build_policy_record(body, tenant_id, version)
    store().put_policy(policy)
    store().put_event(
        {
            "event_type": "policy.created",
            "tenant_id": tenant_id,
            "run_id": "policy-management",
            "action_id": policy["policy_id"],
            "agent_id": "policy-administrator",
            "invoked_by": policy["created_by"],
            "created_at": policy["created_at"],
            "policy_id": policy["policy_id"],
            "policy_version": policy["version"],
            "policy_status": policy["status"],
        }
    )
    return response(201, policy)


def _policy_version_from_body(body: dict[str, Any]) -> tuple[int | None, dict[str, Any] | None]:
    try:
        version = int(body["version"])
    except (KeyError, TypeError, ValueError):
        return None, response(400, {"error": "policy_version_required"})
    if version < 1:
        return None, response(400, {"error": "policy_version_invalid"})
    return version, None


def handle_update_policy(policy_id: str, body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    version, error = _policy_version_from_body(body)
    if error:
        return error
    policy, error = _policy_for_tenant(policy_id, version, auth)
    if error:
        return error
    if policy.get("status") != "draft":
        review_only_fields = {"version", "last_reviewed_at", "updated_by"}
        if policy.get("status") not in {"published", "suspended"} or "last_reviewed_at" not in body or set(body) - review_only_fields:
            return response(409, {"error": "policy_not_editable", "policy_id": policy_id, "version": version, "status": policy.get("status")})
        reviewed_at = _normalise_policy_review_timestamp(body.get("last_reviewed_at"))
        updated = dict(policy)
        updated["last_reviewed_at"] = reviewed_at
        updated["updated_at"] = utc_now()
        updated["updated_by"] = str(body.get("updated_by") or auth.get("token_id") or "policy-administrator")
        store().put_policy(updated)
        store().put_event(
            {
                "event_type": "policy.reviewed",
                "tenant_id": updated["tenant_id"],
                "run_id": "policy-management",
                "action_id": policy_id,
                "agent_id": "policy-administrator",
                "invoked_by": updated["updated_by"],
                "created_at": updated["updated_at"],
                "policy_id": policy_id,
                "policy_version": version,
                "policy_status": updated["status"],
                "last_reviewed_at": reviewed_at,
            }
        )
        return response(200, _policy_with_review_status(updated))

    updated_payload = dict(policy)
    updated_payload.update(body)
    updated_payload["policy_id"] = policy_id
    updated_payload["created_by"] = policy.get("created_by")
    updated_payload["last_reviewed_at"] = _normalise_policy_review_timestamp(updated_payload.get("last_reviewed_at"))
    updated = build_policy_record(updated_payload, str(policy["tenant_id"]), int(version))
    updated["created_at"] = policy.get("created_at") or updated["created_at"]
    updated["updated_by"] = str(body.get("updated_by") or auth.get("token_id") or "policy-administrator")
    store().put_policy(updated)
    store().put_event(
        {
            "event_type": "policy.updated",
            "tenant_id": updated["tenant_id"],
            "run_id": "policy-management",
            "action_id": policy_id,
            "agent_id": "policy-administrator",
            "invoked_by": updated["updated_by"],
            "created_at": updated["updated_at"],
            "policy_id": policy_id,
            "policy_version": version,
            "policy_status": updated["status"],
            "last_reviewed_at": updated.get("last_reviewed_at"),
        }
    )
    return response(200, _policy_with_review_status(updated))

def handle_list_policies(auth: dict[str, Any]) -> dict[str, Any]:
    policies = store().list_policies(str(auth["tenant_id"]))
    latest: dict[str, dict[str, Any]] = {}
    for policy in policies:
        policy_id = str(policy.get("policy_id"))
        if policy_id not in latest or int(policy.get("version", 0)) > int(latest[policy_id].get("version", 0)):
            latest[policy_id] = policy
    return response(
        200,
        {
            "tenant_id": auth["tenant_id"],
            "policies": [_policy_with_review_status(policy) for policy in latest.values()],
        },
    )


def handle_get_compliance_coverage(auth: dict[str, Any]) -> dict[str, Any]:
    """Summarise the compliance labels on the tenant's latest policies."""

    return response(200, _compliance_policy_coverage(str(auth["tenant_id"])))


def _compliance_policy_coverage(tenant_id: str) -> dict[str, Any]:
    """Return the latest policy compliance labels and the untagged gaps."""

    policies = store().list_policies(tenant_id)
    latest: dict[str, dict[str, Any]] = {}
    for policy in policies:
        policy_id = str(policy.get("policy_id") or "")
        if not policy_id:
            continue
        if policy_id not in latest or int(policy.get("version", 0)) > int(latest[policy_id].get("version", 0)):
            latest[policy_id] = policy

    tag_policies: dict[str, set[str]] = {}
    tagged_policy_ids: list[str] = []
    for policy_id, policy in latest.items():
        tags = policy.get("compliance_tags") if isinstance(policy.get("compliance_tags"), list) else []
        if tags:
            tagged_policy_ids.append(policy_id)
        for tag in tags:
            normalised_tag = str(tag).strip()
            if normalised_tag:
                tag_policies.setdefault(normalised_tag, set()).add(policy_id)

    untagged_policy_ids = sorted(set(latest) - set(tagged_policy_ids))
    return {
        "tenant_id": tenant_id,
        "total_policies": len(latest),
        "tagged_policies": len(tagged_policy_ids),
        "untagged_policies": len(untagged_policy_ids),
        "policies_without_compliance_tags": untagged_policy_ids,
        "tags": [
            {
                "tag": tag,
                "policy_count": len(policy_ids),
                "policy_ids": sorted(policy_ids),
            }
            for tag, policy_ids in sorted(tag_policies.items(), key=lambda item: item[0].casefold())
        ],
    }


COMPLIANCE_EVIDENCE_TYPES = {"actions", "coverage", "consents"}
COMPLIANCE_EVIDENCE_DEFAULT_PERIOD_DAYS = 90
COMPLIANCE_EVIDENCE_MAX_PERIOD_DAYS = 3650


def _compliance_period(query: dict[str, Any]) -> dict[str, Any]:
    """Validate and return a bounded UTC period for action evidence."""

    try:
        period_days = int(query.get("period_days") or COMPLIANCE_EVIDENCE_DEFAULT_PERIOD_DAYS)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"period_days must be an integer between 1 and {COMPLIANCE_EVIDENCE_MAX_PERIOD_DAYS}."
        ) from exc
    if period_days < 1 or period_days > COMPLIANCE_EVIDENCE_MAX_PERIOD_DAYS:
        raise ValueError(f"period_days must be an integer between 1 and {COMPLIANCE_EVIDENCE_MAX_PERIOD_DAYS}.")
    end = datetime.fromisoformat(utc_now().replace("Z", "+00:00"))
    start = end - timedelta(days=period_days)
    return {
        "days": period_days,
        "start": start.isoformat().replace("+00:00", "Z"),
        "end": end.isoformat().replace("+00:00", "Z"),
    }


def _compliance_events(tenant_id: str, event_type: str, period: dict[str, Any]) -> list[dict[str, Any]]:
    """Read bounded, tenant-scoped audit events for one evidence export."""

    return [
        event
        for event in store().list_events(
            tenant_id,
            filters={
                "event_type": event_type,
                "start_time": period["start"],
                "end_time": period["end"],
                "limit": 100,
            },
        )
        if event.get("source") != "external"
    ]


def _compliance_action_evidence(tenant_id: str, period: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    evaluations = _compliance_events(tenant_id, "action.evaluated", period)
    outcomes = _compliance_events(tenant_id, "action.outcome", period)
    outcomes_by_action: dict[str, dict[str, Any]] = {}
    for outcome in outcomes:
        action_id = str(outcome.get("action_id") or "")
        if action_id and action_id not in outcomes_by_action:
            outcomes_by_action[action_id] = outcome

    records: list[dict[str, Any]] = []
    for evaluation in evaluations:
        action_id = str(evaluation.get("action_id") or "")
        action = evaluation.get("action") if isinstance(evaluation.get("action"), dict) else {}
        outcome = outcomes_by_action.get(action_id)
        classification = evaluation.get("action_classification") or action.get("classification")
        records.append(
            {
                "action_id": action_id,
                "timestamp": evaluation.get("created_at"),
                "agent_id": evaluation.get("agent_id"),
                "decision": evaluation.get("decision"),
                "risk_score": evaluation.get("risk_score"),
                "approval_id": evaluation.get("approval_id"),
                "outcome_status": outcome.get("status") if outcome else None,
                "classification": classification,
            }
        )
    records.sort(key=lambda item: str(item.get("timestamp") or ""), reverse=True)
    return records, {
        "total_actions": len(records),
        "approvals_required": sum(1 for item in records if item.get("decision") == "require_approval"),
        "denials": sum(1 for item in records if item.get("decision") == "deny"),
        "auto_approved": sum(1 for event in evaluations if event.get("auto_approved") is True),
    }


def _compliance_consent_evidence(tenant_id: str) -> tuple[list[dict[str, Any]], dict[str, int]]:
    records = [
        {
            "consent_id": consent.get("consent_id"),
            "subject": consent.get("subject"),
            "purpose": consent.get("purpose"),
            "data_scope": consent.get("data_scope"),
            "granted_at": consent.get("granted_at") or consent.get("created_at"),
            "expires_at": consent.get("expires_at"),
            "status": consent.get("status"),
        }
        for consent in _list_consents(tenant_id, filters={"limit": 100})
    ]
    records.sort(key=lambda item: str(item.get("granted_at") or ""), reverse=True)
    return records, {
        "total_consents": len(records),
        "active": sum(1 for item in records if item.get("status") == "active"),
        "expired": sum(1 for item in records if item.get("status") == "expired"),
        "revoked": sum(1 for item in records if item.get("status") == "revoked"),
    }


def handle_compliance_evidence(event: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    """Export bounded compliance evidence and audit the export itself."""

    query = event.get("queryStringParameters") or {}
    requested_tenant = str(query.get("tenant_id") or auth.get("tenant_id") or "")
    tenant_id, error = tenant_target(requested_tenant, auth)
    if error:
        return error
    evidence_type = str(query.get("type") or "").strip().lower()
    if evidence_type not in COMPLIANCE_EVIDENCE_TYPES:
        raise ValueError("type must be one of: actions, coverage, consents.")

    period = _compliance_period(query) if evidence_type == "actions" else {"scope": "all"}
    body: dict[str, Any] = {
        "tenant_id": tenant_id,
        "type": evidence_type,
        "evidence_type": evidence_type,
        "period": period,
    }
    if evidence_type == "actions":
        records, summary = _compliance_action_evidence(str(tenant_id), period)
        body.update({"actions": records, "records": records, "summary": summary})
    elif evidence_type == "coverage":
        coverage = _compliance_policy_coverage(str(tenant_id))
        body.update({"coverage": coverage, "records": coverage["tags"], "summary": coverage})
        records = coverage["tags"]
    else:
        records, summary = _compliance_consent_evidence(str(tenant_id))
        body.update({"consents": records, "records": records, "summary": summary})

    exported_by = authenticated_principal(auth)
    store().put_event(
        {
            "event_type": "compliance.evidence_exported",
            "tenant_id": str(tenant_id),
            "environment": "governance",
            "run_id": "compliance-evidence",
            "action_id": f"compliance-export-{uuid.uuid4().hex[:16]}",
            "agent_id": "compliance-evidence",
            "invoked_by": exported_by,
            "created_at": utc_now(),
            "status": "accepted",
            "source": "internal",
            "exported_by": exported_by,
            "evidence_type": evidence_type,
            "period": period,
            "record_count": len(records),
        }
    )
    return response(200, body)


def _policy_for_tenant(policy_id: str, version: int | None, auth: dict[str, Any]) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    policy = store().get_policy(policy_id, version, str(auth.get("tenant_id") or ""))
    if not policy:
        return None, response(404, {"error": "policy_not_found", "policy_id": policy_id, "version": version})
    if policy.get("tenant_id") != auth.get("tenant_id") and not has_scope(auth, "admin"):
        return None, response(403, {"error": "tenant_mismatch"})
    return policy, None


def handle_get_policy(policy_id: str, event: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    query = event.get("queryStringParameters") or {}
    version = int(query["version"]) if query.get("version") else None
    policy, error = _policy_for_tenant(policy_id, version, auth)
    if error:
        return error
    return response(200, _policy_with_review_status(policy))


def handle_publish_policy(policy_id: str, body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    version = int(body.get("version")) if body.get("version") is not None else None
    if version is None:
        policy = store().get_policy(policy_id, tenant_id=str(auth["tenant_id"]))
        version = int(policy["version"]) if policy else 0
    policy, error = _policy_for_tenant(policy_id, version, auth)
    if error:
        return error
    published = store().publish_policy(policy_id, version, str(policy["tenant_id"]))
    store().put_event(
        {
            "event_type": "policy.published",
            "tenant_id": published["tenant_id"],
            "run_id": "policy-management",
            "action_id": policy_id,
            "agent_id": "policy-administrator",
            "invoked_by": str(body.get("published_by") or auth.get("token_id") or "policy-administrator"),
            "created_at": published["published_at"],
            "policy_id": policy_id,
            "policy_version": version,
            "policy_status": published["status"],
        }
    )
    return response(200, published)


def _policy_transition(policy_id: str, body: dict[str, Any], auth: dict[str, Any], expected_status: str, next_status: str, event_type: str) -> dict[str, Any]:
    version = int(body.get("version")) if body.get("version") is not None else None
    policy, error = _policy_for_tenant(policy_id, version, auth)
    if error:
        return error
    if policy.get("status") != expected_status:
        return response(409, {"error": "policy_invalid_status", "expected_status": expected_status, "status": policy.get("status")})
    if body.get("confirm") is not True:
        return response(400, {"error": "policy_confirmation_required", "message": f"Set confirm=true to {event_type.removeprefix('policy.')} this policy."})
    changed_at = utc_now()
    previous_status = policy.get("status")
    policy["status"] = next_status
    policy["updated_at"] = changed_at
    if next_status == "suspended":
        policy["suspended_at"] = changed_at
    elif next_status == "published":
        policy["reactivated_at"] = changed_at
    store().put_policy(policy)
    store().put_event(
        {
            "event_type": event_type,
            "tenant_id": policy["tenant_id"],
            "run_id": "policy-management",
            "action_id": policy_id,
            "agent_id": "policy-administrator",
            "invoked_by": str(body.get("changed_by") or auth.get("token_id") or "policy-administrator"),
            "created_at": changed_at,
            "policy_id": policy_id,
            "policy_version": policy["version"],
            "policy_status": next_status,
            "previous_policy_status": previous_status,
        }
    )
    return response(200, policy)


def handle_suspend_policy(policy_id: str, body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    return _policy_transition(policy_id, body, auth, "published", "suspended", "policy.suspended")


def handle_reactivate_policy(policy_id: str, body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    return _policy_transition(policy_id, body, auth, "suspended", "published", "policy.reactivated")


def handle_delete_policy(policy_id: str, body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    version = int(body.get("version")) if body.get("version") is not None else None
    policy, error = _policy_for_tenant(policy_id, version, auth)
    if error:
        return error
    if policy.get("status") == "draft":
        store().delete_policy_version(policy_id, int(policy["version"]), str(policy["tenant_id"]))
        deleted_at = utc_now()
        store().put_event(
            {
                "event_type": "policy.deleted",
                "tenant_id": policy["tenant_id"],
                "run_id": "policy-management",
                "action_id": policy_id,
                "agent_id": "policy-administrator",
                "invoked_by": str(body.get("deleted_by") or auth.get("token_id") or "policy-administrator"),
                "created_at": deleted_at,
                "policy_id": policy_id,
                "policy_version": int(policy["version"]),
                "policy_status": "deleted",
            }
        )
        return response(200, {"policy_id": policy_id, "version": int(policy["version"]), "status": "deleted"})
    if policy.get("status") != "published":
        return response(409, {"error": "policy_invalid_status", "expected_status": "published", "status": policy.get("status")})
    if body.get("confirm") is not True:
        return response(400, {"error": "policy_confirmation_required", "message": "Set confirm=true to delete this policy permanently."})
    deleted_versions = store().delete_policy(policy_id, str(policy["tenant_id"]))
    deleted_at = utc_now()
    store().put_event(
        {
            "event_type": "policy.deleted",
            "tenant_id": policy["tenant_id"],
            "run_id": "policy-management",
            "action_id": policy_id,
            "agent_id": "policy-administrator",
            "invoked_by": str(body.get("deleted_by") or auth.get("token_id") or "policy-administrator"),
            "created_at": deleted_at,
            "policy_id": policy_id,
            "policy_version": policy["version"],
            "policy_status": "deleted",
            "deleted_versions": deleted_versions,
        }
    )
    return response(200, {"deleted": True, "policy_id": policy_id, "deleted_versions": deleted_versions})


def handle_simulate_policy(policy_id: str, body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    bind_tenant(body, auth)
    version = int(body.get("version")) if body.get("version") is not None else None
    policy, error = _policy_for_tenant(policy_id, version, auth)
    if error:
        return error
    source_action_id = str(body.get("source_action_id") or body.get("historical_action_id") or "").strip()
    if len(source_action_id) > 128:
        raise ValueError("source_action_id must be no longer than 128 characters.")
    if source_action_id:
        source_event = store().get_action_evaluation(str(auth["tenant_id"]), source_action_id)
        if not source_event:
            return response(404, {"error": "historical_action_not_found", "action_id": source_action_id})
        source_action = source_event.get("action") if isinstance(source_event.get("action"), dict) else None
        if not source_action:
            return response(422, {"error": "historical_action_unavailable", "action_id": source_action_id})
        source_context = {
            "tenant_id": auth["tenant_id"],
            "environment": source_action.get("environment") or source_event.get("environment") or "development",
            "agent_id": source_action.get("agent_id") or source_event.get("agent_id") or "unregistered-agent",
            "invoked_by": source_action.get("invoked_by") or source_event.get("invoked_by") or "unknown-user",
        }
        for key in ("run_id", "action_id", "requested_at"):
            if source_action.get(key) is not None:
                source_context[key] = source_action[key]
        action = normalise_action(
            {
                "context": source_context,
                "action": source_action,
                "intent": source_action.get("intent"),
                "requested_at": source_action.get("requested_at"),
            }
        )
        simulation_source = {
            "type": "historical_action",
            "action_id": source_action_id,
            "source_action_hash": source_event.get("action_hash"),
            "source_evaluated_at": source_event.get("created_at"),
            "captured_action": True,
        }
    else:
        action = normalise_action(body)
        simulation_source = {"type": "supplied_action"}
    context = body.get("context") if isinstance(body.get("context"), dict) else {}
    mode = str(body.get("mode") or context.get("mode") or "enforce")
    tenant_config = store().get_tenant_config(action["tenant_id"]) or default_tenant_config(action["tenant_id"])
    starter_rules = normalise_starter_rules(tenant_config.get("starter_rules"))
    decision = evaluate(action, mode=mode, starter_rules=starter_rules)
    decision["policy_id"] = "kenning-agent-guard-mvp"
    decision["policy_version"] = 1
    custom_policy = custom_starter_policy(starter_rules, action["tenant_id"], int(tenant_config.get("config_version") or 1), mode=mode)
    decision = _impact_assessment_policy_context(
        decision,
        action,
        ([custom_policy] if custom_policy else []) + [policy],
        store(),
    )
    capture_policy = tenant_config.get("capture_policy")
    decision["capture_policy"] = capture_policy_summary(capture_policy)
    decision["action"] = capture_action(action, capture_policy)
    decision["simulation"] = True
    decision["simulated_policy_id"] = policy["policy_id"]
    decision["simulated_policy_version"] = policy["version"]
    decision["simulation_source"] = simulation_source
    store().put_event(
        {
            "event_type": "policy.simulated",
            "tenant_id": action["tenant_id"],
            "environment": action["environment"],
            "run_id": action["run_id"],
            "action_id": action["action_id"],
            "agent_id": action["agent_id"],
            "invoked_by": action["invoked_by"],
            "created_at": decision["evaluated_at"],
            "policy_id": policy["policy_id"],
            "policy_version": policy["version"],
            "decision": decision["decision"],
            "reason_codes": decision["reason_codes"],
            "policy_resolution": decision.get("policy_resolution"),
            "action_hash": decision["action_hash"],
            "simulation_source": simulation_source,
            "source_action_id": source_action_id or None,
        }
    )
    return response(200, decision)


def handle_test_policy(policy_id: str, body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    """Run stored or supplied policy test cases without creating side effects."""

    bind_tenant(body, auth)
    version = int(body.get("version")) if body.get("version") is not None else None
    policy, error = _policy_for_tenant(policy_id, version, auth)
    if error:
        return error
    raw_cases = body["test_cases"] if "test_cases" in body else policy.get("test_cases")
    cases = normalise_test_cases(raw_cases)
    if not cases:
        return response(400, {"error": "policy_test_cases_required", "policy_id": policy_id, "version": policy["version"]})

    results: list[dict[str, Any]] = []
    for case in cases:
        case_context = dict(case.get("context") if isinstance(case.get("context"), dict) else {})
        case_context.setdefault("tenant_id", auth["tenant_id"])
        case_payload: dict[str, Any] = {
            "context": case_context,
            "action": case["action"],
            "intent": case.get("intent") or "",
        }
        bind_tenant(case_payload, auth)
        action = normalise_action(case_payload)
        mode = str(case_context.get("mode") or policy.get("mode") or "enforce")
        tenant_config = store().get_tenant_config(action["tenant_id"]) or default_tenant_config(action["tenant_id"])
        starter_rules = normalise_starter_rules(tenant_config.get("starter_rules"))
        decision = evaluate(action, mode=mode, starter_rules=starter_rules)
        decision["policy_id"] = "kenning-agent-guard-mvp"
        decision["policy_version"] = 1
        custom_policy = custom_starter_policy(starter_rules, action["tenant_id"], int(tenant_config.get("config_version") or 1), mode=mode)
        decision = _impact_assessment_policy_context(
            decision,
            action,
            ([custom_policy] if custom_policy else []) + [policy],
            store(),
        )
        expected_codes = set(case.get("expected_reason_codes") or [])
        actual_codes = set(decision.get("reason_codes") or [])
        results.append(
            {
                "case_id": case["case_id"],
                "name": case["name"],
                "expected_decision": case["expected_decision"],
                "actual_decision": decision["decision"],
                "expected_reason_codes": sorted(expected_codes),
                "reason_codes": decision.get("reason_codes") or [],
                "policy_resolution": decision.get("policy_resolution"),
                "action_hash": decision["action_hash"],
                "passed": decision["decision"] == case["expected_decision"] and expected_codes.issubset(actual_codes),
            }
        )

    passed = sum(1 for result in results if result["passed"])
    failed = len(results) - passed
    now = utc_now()
    store().put_event(
        {
            "event_type": "policy.tested",
            "tenant_id": auth["tenant_id"],
            "run_id": "policy-management",
            "action_id": policy_id,
            "agent_id": "policy-administrator",
            "invoked_by": str(body.get("tested_by") or auth.get("token_id") or "policy-administrator"),
            "created_at": now,
            "policy_id": policy_id,
            "policy_version": policy["version"],
            "test_count": len(results),
            "passed_count": passed,
            "failed_count": failed,
            "all_passed": failed == 0,
        }
    )
    return response(
        200,
        {
            "policy_id": policy_id,
            "version": policy["version"],
            "test_count": len(results),
            "passed_count": passed,
            "failed_count": failed,
            "all_passed": failed == 0,
            "results": results,
            "tested_at": now,
        },
    )


def handle_create_proof(body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    bind_tenant(body, auth)
    proof = build_proof_record(body)
    proof_store = store()
    tenant_config = proof_store.get_tenant_config(str(proof["tenant_id"])) or default_tenant_config(str(proof["tenant_id"]))
    proof = apply_capture(proof, tenant_config.get("capture_policy"))
    try:
        proof_store.put_proof(proof, create_only=True)
    except Exception as exc:
        if _is_conditional_check_failure(exc):
            return response(409, {"error": "proof_id_conflict", "proof_id": proof["proof_id"]})
        raise
    proof_store.put_event(
        {
            "event_type": "proof.created",
            "tenant_id": proof["tenant_id"],
            "run_id": proof["run_id"],
            "action_id": proof["action_id"],
            "agent_id": proof["agent"].get("id", "unregistered-agent"),
            "invoked_by": str((body.get("context") or {}).get("invoked_by") or "unknown-user"),
            "created_at": proof["created_at"],
            "proof_id": proof["proof_id"],
            "proof_uri": proof["proof_uri"],
            "evidence_status": proof["evidence_status"],
            "evidence_gaps": proof["evidence_gaps"],
        }
    )
    return response(201, proof)


def _agent_id_from_proof(proof: dict[str, Any]) -> str:
    agent = proof.get("agent") if isinstance(proof.get("agent"), dict) else {}
    return str(agent.get("id") or proof.get("agent_id") or "")


def _bound_agent_mismatch(resource_agent_id: Any, auth: dict[str, Any]) -> bool:
    bound_agent = str(auth.get("agent_id") or "").strip()
    return bool(bound_agent and str(resource_agent_id or "").strip() != bound_agent)


def _proof_for_tenant(proof_id: str, auth: dict[str, Any]) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    proof = store().get_proof(proof_id, str(auth.get("tenant_id") or ""))
    if not proof:
        return None, response(404, {"error": "proof_not_found", "proof_id": proof_id})
    if proof.get("tenant_id") != auth.get("tenant_id") and not has_scope(auth, "admin"):
        return None, response(403, {"error": "tenant_mismatch"})
    if _bound_agent_mismatch(_agent_id_from_proof(proof), auth):
        return None, response(403, {"error": "agent_credential_mismatch"})
    return proof, None


def handle_get_proof(proof_id: str, auth: dict[str, Any], report: bool = False) -> dict[str, Any]:
    proof, error = _proof_for_tenant(proof_id, auth)
    if error:
        return error
    if report:
        return response(200, {"proof_id": proof_id, "format": "markdown", "report": render_report(proof)})
    return response(200, proof)


def handle_verify_proof(proof_id: str, auth: dict[str, Any]) -> dict[str, Any]:
    proof, error = _proof_for_tenant(proof_id, auth)
    if error:
        return error
    proof_integrity = verify_integrity(proof)
    receipt_integrity = verify_receipt(proof.get("trusted_action_receipt"))
    return response(
        200,
        {
            "proof_id": proof_id,
            "valid": bool(proof_integrity.get("valid") and receipt_integrity.get("valid")),
            "proof_integrity": proof_integrity,
            "receipt_integrity": receipt_integrity,
            "checked_at": utc_now(),
        },
    )


def handle_receipt_public_key(auth: dict[str, Any]) -> dict[str, Any]:
    try:
        return response(200, receipt_public_key())
    except (RuntimeError, ValueError) as exc:
        return response(503, {"error": "receipt_signing_unavailable", "message": str(exc)})


def citation_verify_and_record(body: dict[str, Any], auth: dict[str, Any], audit_store: AuditStore) -> dict[str, Any]:
    bind_tenant(body, auth)
    context = body.get("context") if isinstance(body.get("context"), dict) else {}
    tenant_id = str(context.get("tenant_id") or auth["tenant_id"])
    config = audit_store.get_tenant_config(tenant_id) or default_tenant_config(tenant_id)
    result = verify_response(body, policy=config.get("citation_policy"))
    result["tenant_id"] = tenant_id
    result["response_id"] = str(body.get("response_id") or f"response-{uuid.uuid4().hex[:16]}")
    audit_store.put_event(
        {
            "event_type": "citation.verified",
            "tenant_id": result["tenant_id"],
            "environment": str(context.get("environment") or ENVIRONMENT),
            "run_id": str(context.get("run_id") or body.get("run_id") or "unknown-run"),
            "action_id": str(context.get("action_id") or body.get("action_id") or result["response_id"]),
            "agent_id": str(context.get("agent_id") or body.get("agent_id") or "unknown-agent"),
            "invoked_by": str(context.get("invoked_by") or body.get("invoked_by") or "unknown-user"),
            "created_at": result["checked_at"],
            "response_id": result["response_id"],
            "status": result["status"],
            "trust_score": result["trust_score"],
            "citation_count": len(result["citations"]),
        }
    )
    return result


def handle_citation_verify(body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    return response(200, citation_verify_and_record(body, auth, store()))


def handle_citation_report_extract(body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    """Extract report citations without persisting the uploaded report.

    PDF parsing happens in the browser for the POC. The API receives the
    deterministic extracted text, validates its content hash, and returns a
    bounded citation manifest for the portal or an integration to verify one
    citation at a time through Citation Trust MCP.
    """

    try:
        result = extract_report_citations(
            str(body.get("report_text") or ""),
            str(body.get("report_name") or "uploaded-report"),
        )
    except ValueError as exc:
        return response(400, {"error": "invalid_report", "message": str(exc)})

    supplied_hash = str(body.get("content_sha256") or "").strip().lower()
    if supplied_hash and supplied_hash != result["content_sha256"]:
        return response(
            400,
            {
                "error": "content_hash_mismatch",
                "expected": result["content_sha256"],
                "provided": supplied_hash,
            },
        )
    result["tenant_id"] = str(auth.get("tenant_id") or "")
    result["stored"] = False
    return response(200, result)


def _prepare_agent_registration(body: dict[str, Any], auth: dict[str, Any], agent_store: "AuditStore") -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Bind agent registration to an authenticated human or parent agent."""

    registration = dict(body)
    principal = authenticated_principal(auth)
    requested_parent = str(body.get("parent_agent_id") or "").strip()
    requested_authority = normalise_authority_level(body.get("maximum_authority") or body.get("authority_level"))
    caller_agent_id = str(auth.get("agent_id") or "").strip() if auth.get("token_type") == "agent" else ""

    if caller_agent_id:
        if requested_parent and requested_parent != caller_agent_id:
            return None, response(403, {"error": "agent_delegation_parent_mismatch"})
        parent = agent_store.get_agent(caller_agent_id, str(auth.get("tenant_id") or ""))
        if not parent or parent.get("tenant_id") != auth.get("tenant_id"):
            return None, response(403, {"error": "delegating_agent_not_found"})
        if parent.get("status") != "active":
            return None, response(409, {"error": "delegating_agent_not_active", "agent_id": caller_agent_id})
        conditions = parent.get("conditions") if isinstance(parent.get("conditions"), dict) else {}
        if conditions.get("can_delegate_agents") is not True and conditions.get("can_delegate") is not True:
            return None, response(403, {"error": "agent_delegation_not_permitted", "agent_id": caller_agent_id})
        parent_authority = normalise_authority_level(parent.get("maximum_authority") or parent.get("authority_level"))
        if authority_rank(requested_authority) > authority_rank(parent_authority):
            return None, response(
                403,
                {
                    "error": "agent_authority_escalation",
                    "parent_authority": parent_authority,
                    "requested_authority": requested_authority,
                },
            )
        chain = normalise_delegation_chain(parent.get("delegation_chain"))
        if caller_agent_id in chain:
            return None, response(409, {"error": "agent_delegation_cycle"})
        chain.append(caller_agent_id)
        if len(chain) > MAX_DELEGATION_DEPTH:
            return None, response(403, {"error": "agent_delegation_depth_exceeded", "maximum_depth": MAX_DELEGATION_DEPTH})
        delegated_by = caller_agent_id
        parent_agent_id = caller_agent_id
    elif requested_parent:
        if not has_scope(auth, "admin"):
            return None, response(403, {"error": "parent_delegation_requires_admin"})
        parent = agent_store.get_agent(requested_parent, str(auth.get("tenant_id") or ""))
        if not parent or parent.get("tenant_id") != auth.get("tenant_id"):
            return None, response(404, {"error": "parent_agent_not_found", "agent_id": requested_parent})
        if parent.get("status") != "active":
            return None, response(409, {"error": "parent_agent_not_active", "agent_id": requested_parent})
        parent_authority = normalise_authority_level(parent.get("maximum_authority") or parent.get("authority_level"))
        if authority_rank(requested_authority) > authority_rank(parent_authority):
            return None, response(
                403,
                {
                    "error": "agent_authority_escalation",
                    "parent_authority": parent_authority,
                    "requested_authority": requested_authority,
                },
            )
        chain = normalise_delegation_chain(parent.get("delegation_chain"))
        if requested_parent in chain:
            return None, response(409, {"error": "agent_delegation_cycle"})
        chain.append(requested_parent)
        if len(chain) > MAX_DELEGATION_DEPTH:
            return None, response(403, {"error": "agent_delegation_depth_exceeded", "maximum_depth": MAX_DELEGATION_DEPTH})
        delegated_by = principal
        parent_agent_id = requested_parent
    else:
        if requested_authority == "admin" and not has_scope(auth, "admin"):
            return None, response(403, {"error": "agent_authority_requires_admin"})
        chain = [principal]
        delegated_by = principal
        parent_agent_id = ""

    registration["delegated_by"] = delegated_by
    registration["delegation_chain"] = chain
    registration["delegation_root"] = chain[0]
    registration["delegation_depth"] = max(0, len(chain) - 1)
    registration["parent_agent_id"] = parent_agent_id
    registration["maximum_authority"] = requested_authority
    return registration, None


def handle_register_agent(body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    # The registration's agent_id is the new child identity, not the identity
    # making the request. _prepare_agent_registration enforces the authenticated
    # parent-agent relationship separately.
    bind_tenant(body, auth, enforce_agent_binding=False)
    tenant_id = tenant_from({}, body, auth)
    agent_store = store()
    registration, error = _prepare_agent_registration(body, auth, agent_store)
    if error:
        return error
    agent = build_agent_record(registration or body, tenant_id)
    model_id = str(agent.get("model_id") or "").strip()
    model_version = str(agent.get("model_version") or "").strip()
    if model_id:
        model = agent_store.get_model(model_id, tenant_id, model_version or None)
        if not model:
            return response(404, {"error": "model_not_found", "model_id": model_id, "version": model_version or None})
        agent["model_version"] = str(model["version"])
    elif model_version:
        return response(400, {"error": "model_id_required_for_version"})
    try:
        agent_store.put_agent(agent, require_absent=True)
    except Exception as exc:
        if _is_conditional_check_failure(exc):
            return response(409, {"error": "agent_already_registered", "agent_id": agent["agent_id"]})
        raise
    agent_store.put_event(
        {
            "event_type": "agent.registered",
            "tenant_id": tenant_id,
            "run_id": "identity-management",
            "action_id": agent["agent_id"],
            "agent_id": agent["agent_id"],
            "invoked_by": agent["owner"],
            "created_at": agent["created_at"],
            "identity_status": agent["status"],
            "model_id": agent.get("model_id"),
            "model_version": agent.get("model_version"),
        }
    )
    return response(201, {**agent, **documentation_metadata(agent.get("documentation"))})


def handle_list_agents(auth: dict[str, Any]) -> dict[str, Any]:
    audit_store = store()
    agents = [
        {
            **agent,
            **documentation_metadata(agent.get("documentation")),
            **_agent_impact_assessment_metadata(str(auth["tenant_id"]), str(agent.get("agent_id") or ""), audit_store),
        }
        for agent in audit_store.list_agents(str(auth["tenant_id"]))
    ]
    return response(200, {"tenant_id": auth["tenant_id"], "agents": agents})


def _model_with_binding_count(model: dict[str, Any], agents: list[dict[str, Any]]) -> dict[str, Any]:
    model_id = str(model.get("model_id") or "")
    version = str(model.get("version") or "")
    bound_agent_count = sum(
        1
        for agent in agents
        if str(agent.get("model_id") or "") == model_id
        and str(agent.get("model_version") or "") == version
    )
    return {**model, "bound_agent_count": bound_agent_count}


def _model_with_governance_metadata(
    model: dict[str, Any],
    agents: list[dict[str, Any]],
    suppliers: list[dict[str, Any]],
) -> dict[str, Any]:
    supplier_id = str(model.get("supplier_id") or "")
    supplier = next(
        (item for item in suppliers if str(item.get("supplier_id") or "") == supplier_id),
        None,
    )
    result = _model_with_binding_count(model, agents)
    result["supplier_name"] = supplier.get("name") if supplier else None
    result["supplier_risk_rating"] = supplier.get("risk_rating") if supplier else None
    return result


def handle_register_model(body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    bind_tenant(body, auth)
    tenant_id = tenant_from({}, body, auth)
    model = normalise_model_record(body, tenant_id)
    model_store = store()
    supplier_id = str(model.get("supplier_id") or "")
    if supplier_id and not model_store.get_supplier(supplier_id, tenant_id):
        return response(404, {"error": "supplier_not_found", "supplier_id": supplier_id})
    try:
        model_store.put_model(model, require_absent=True)
    except Exception as exc:
        if _is_conditional_check_failure(exc):
            return response(
                409,
                {
                    "error": "model_version_already_registered",
                    "model_id": model["model_id"],
                    "version": model["version"],
                },
            )
        raise
    model_store.put_event(
        {
            "event_type": "ai_model.registered",
            "tenant_id": tenant_id,
            "run_id": "model-governance",
            "action_id": f"{model['model_id']}:{model['version']}",
            "agent_id": "model-registry",
            "invoked_by": authenticated_principal(auth),
            "created_at": model["created_at"],
            "model_id": model["model_id"],
            "model_version": model["version"],
            "risk_tier": model["risk_tier"],
            "supplier_id": model.get("supplier_id"),
        }
    )
    return response(
        201,
        _model_with_governance_metadata(model, [], model_store.list_suppliers(tenant_id)),
    )


def handle_list_models(auth: dict[str, Any]) -> dict[str, Any]:
    model_store = store()
    agents = model_store.list_agents(str(auth["tenant_id"]))
    suppliers = model_store.list_suppliers(str(auth["tenant_id"]))
    models = [
        _model_with_governance_metadata(model, agents, suppliers)
        for model in model_store.list_models(str(auth["tenant_id"]))
    ]
    return response(200, {"tenant_id": auth["tenant_id"], "models": models})


def handle_update_model(model_id: str, body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    """Update governance metadata for one registered model version."""

    bind_tenant(body, auth)
    tenant_id = tenant_from({}, body, auth)
    model_store = store()
    version = str(body.get("version") or "").strip() or None
    model = model_store.get_model(model_id, tenant_id, version)
    if not model:
        return response(404, {"error": "model_not_found", "model_id": model_id, "version": version})
    if "supplier_id" not in body:
        return response(400, {"error": "supplier_id_required"})
    supplier_id = str(body.get("supplier_id") or "").strip()
    if supplier_id and not model_store.get_supplier(supplier_id, tenant_id):
        return response(404, {"error": "supplier_not_found", "supplier_id": supplier_id})
    model["supplier_id"] = supplier_id or None
    model["updated_at"] = utc_now()
    model_store.put_model(model)
    model_store.put_event(
        {
            "event_type": "ai_model.updated",
            "tenant_id": tenant_id,
            "run_id": "model-governance",
            "action_id": f"{model['model_id']}:{model['version']}",
            "agent_id": "model-registry",
            "invoked_by": authenticated_principal(auth),
            "created_at": model["updated_at"],
            "model_id": model["model_id"],
            "model_version": model["version"],
            "supplier_id": model.get("supplier_id"),
        }
    )
    agents = model_store.list_agents(tenant_id)
    return response(200, _model_with_governance_metadata(model, agents, model_store.list_suppliers(tenant_id)))


IMPACT_ASSESSMENT_MAX_AGE_DAYS = 365
IMPACT_ASSESSMENT_MAX_TEXT_LENGTH = 10_000
IMPACT_ASSESSMENT_FIELDS = (
    "summary",
    "impacts_on_individuals",
    "impacts_on_society",
    "mitigations",
    "assessor",
)


def _impact_assessment_time(value: Any) -> datetime | None:
    """Parse an assessment timestamp as an aware UTC datetime."""

    try:
        parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _impact_assessment_is_current(record: dict[str, Any] | None, *, now: datetime | None = None) -> bool:
    if not record:
        return False
    created_at = _impact_assessment_time(record.get("created_at"))
    if created_at is None:
        return False
    current_time = now or datetime.now(timezone.utc)
    age = current_time - created_at
    return timedelta(0) <= age <= timedelta(days=IMPACT_ASSESSMENT_MAX_AGE_DAYS)


def _impact_assessment_record(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "assessment_id": event.get("assessment_id") or event.get("event_id"),
        "tenant_id": event.get("tenant_id"),
        "agent_id": event.get("agent_id"),
        "summary": event.get("summary") or "",
        "impacts_on_individuals": event.get("impacts_on_individuals") or "",
        "impacts_on_society": event.get("impacts_on_society") or "",
        "mitigations": event.get("mitigations") or "",
        "assessor": event.get("assessor") or event.get("invoked_by") or "",
        "status": event.get("status") or "completed",
        "created_at": event.get("created_at"),
    }


def _list_impact_assessments(tenant_id: str, agent_id: str, audit_store: AuditStore) -> list[dict[str, Any]]:
    events = audit_store.list_events(
        tenant_id,
        filters={
            "event_type": "impact_assessment.created",
            "agent_id": agent_id,
            "limit": 100,
        },
    )
    # External audit ingestion must not be able to manufacture governance
    # evidence that satisfies the policy reminder.
    return [
        _impact_assessment_record(event)
        for event in events
        if event.get("source") != "external" and str(event.get("event_type") or "") == "impact_assessment.created"
    ]


def _latest_impact_assessment(tenant_id: str, agent_id: str, audit_store: AuditStore) -> dict[str, Any] | None:
    records = _list_impact_assessments(tenant_id, agent_id, audit_store)
    return max(records, key=lambda record: str(record.get("created_at") or ""), default=None)


def _agent_impact_assessment_metadata(tenant_id: str, agent_id: str, audit_store: AuditStore) -> dict[str, Any]:
    latest = _latest_impact_assessment(tenant_id, agent_id, audit_store)
    return {
        "impact_assessment_status": "assessed" if _impact_assessment_is_current(latest) else "assessment overdue",
        "impact_assessment_updated_at": latest.get("created_at") if latest else None,
    }


def _impact_assessment_policy_context(
    decision: dict[str, Any],
    action: dict[str, Any],
    policies: list[dict[str, Any]],
    audit_store: AuditStore,
) -> dict[str, Any]:
    """Apply policies with transient, audit-backed governance context."""

    latest = _latest_impact_assessment(str(action["tenant_id"]), str(action.get("agent_id") or ""), audit_store)
    current = _impact_assessment_is_current(latest)
    action["_impact_assessment_current"] = current
    needs_consent_context = any(
        isinstance(policy, dict)
        and any(
            isinstance(rule, dict)
            and isinstance(rule.get("conditions"), dict)
            and "requires_consent" in rule["conditions"]
            for rule in (policy.get("rules") or [])
        )
        for policy in policies
    )
    action["_active_consents"] = (
        _list_consents(str(action["tenant_id"]), audit_store=audit_store, filters={"status": "active", "limit": 100})
        if needs_consent_context
        else []
    )
    try:
        result = apply_policies(decision, action, policies)
        result["impact_assessment"] = {
            "status": "assessed" if current else "assessment overdue",
            "current": current,
            "last_assessed_at": latest.get("created_at") if latest else None,
        }
        return result
    finally:
        action.pop("_impact_assessment_current", None)
        action.pop("_active_consents", None)


def _validated_impact_assessment_field(body: dict[str, Any], field: str) -> str:
    value = body.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required.")
    value = value.strip()
    if len(value) > IMPACT_ASSESSMENT_MAX_TEXT_LENGTH:
        raise ValueError(f"{field} must be no longer than {IMPACT_ASSESSMENT_MAX_TEXT_LENGTH} characters.")
    return value


def handle_create_impact_assessment(agent_id: str, body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    bind_tenant(body, auth)
    agent, error = _agent_for_tenant(agent_id, auth)
    if error:
        return error
    fields = {field: _validated_impact_assessment_field(body, field) for field in IMPACT_ASSESSMENT_FIELDS}
    created_at = utc_now()
    assessment_id = f"assessment-{uuid.uuid4().hex[:16]}"
    record = {
        "assessment_id": assessment_id,
        "tenant_id": agent["tenant_id"],
        "agent_id": agent_id,
        **fields,
        "status": "completed",
        "created_at": created_at,
    }
    store().put_event(
        {
            "event_type": "impact_assessment.created",
            "tenant_id": agent["tenant_id"],
            "run_id": "impact-assessment-management",
            "action_id": assessment_id,
            "agent_id": agent_id,
            "invoked_by": str(auth.get("subject") or auth.get("token_id") or "impact-assessment-administrator"),
            "created_at": created_at,
            "source": "internal",
            **record,
        }
    )
    return response(201, record)


def handle_list_impact_assessments(agent_id: str, auth: dict[str, Any]) -> dict[str, Any]:
    agent, error = _agent_for_tenant(agent_id, auth)
    if error:
        return error
    assessments = _list_impact_assessments(str(agent["tenant_id"]), agent_id, store())
    latest = max(assessments, key=lambda record: str(record.get("created_at") or ""), default=None)
    return response(
        200,
        {
            "tenant_id": agent["tenant_id"],
            "agent_id": agent_id,
            "assessments": assessments,
            "assessment_status": "assessed" if _impact_assessment_is_current(latest) else "assessment overdue",
        },
    )


def _agent_for_tenant(agent_id: str, auth: dict[str, Any]) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    agent = store().get_agent(agent_id, str(auth.get("tenant_id") or ""))
    if not agent:
        return None, response(404, {"error": "agent_not_found", "agent_id": agent_id})
    if agent.get("tenant_id") != auth.get("tenant_id") and not has_scope(auth, "admin"):
        return None, response(403, {"error": "tenant_mismatch"})
    if auth.get("token_type") in {"agent", "workload"} and str(auth.get("agent_id") or "") != str(agent_id):
        return None, response(403, {"error": "agent_credential_mismatch"})
    return agent, None


def handle_update_agent(agent_id: str, body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    """Update the optional model binding and life-cycle documentation."""
    bind_tenant(body, auth, enforce_agent_binding=False)
    agent, error = _agent_for_tenant(agent_id, auth)
    if error:
        return error
    if agent.get("status") != "active":
        return response(409, {"error": "agent_not_active", "agent_id": agent_id})
    has_model_update = "model_id" in body or "model_version" in body
    has_documentation_update = "documentation" in body
    if not has_model_update and not has_documentation_update:
        return response(400, {"error": "model_binding_or_documentation_required"})
    model_id = str(body.get("model_id") or "").strip()
    model_version = str(body.get("model_version") or "").strip()
    model_store = store()
    if has_model_update and model_id:
        model = model_store.get_model(model_id, str(agent["tenant_id"]), model_version or None)
        if not model:
            return response(404, {"error": "model_not_found", "model_id": model_id, "version": model_version or None})
        model_version = str(model["version"])
    elif has_model_update and model_version:
        return response(400, {"error": "model_id_required_for_version"})
    if has_model_update:
        agent["model_id"] = model_id or None
        agent["model_version"] = model_version or None
    if has_documentation_update:
        agent["documentation"] = normalise_documentation(body.get("documentation"))
    agent["updated_at"] = utc_now()
    model_store.put_agent(agent)
    if has_model_update:
        model_store.put_event(
            {
                "event_type": "agent.model_binding.updated",
                "tenant_id": agent["tenant_id"],
                "run_id": "identity-management",
                "action_id": agent_id,
                "agent_id": agent_id,
                "invoked_by": authenticated_principal(auth),
                "created_at": agent["updated_at"],
                "model_id": agent.get("model_id"),
                "model_version": agent.get("model_version"),
            }
        )
    if has_documentation_update:
        model_store.put_event(
            {
                "event_type": "agent.documentation.updated",
                "tenant_id": agent["tenant_id"],
                "run_id": "identity-management",
                "action_id": agent_id,
                "agent_id": agent_id,
                "invoked_by": authenticated_principal(auth),
                "created_at": agent["updated_at"],
                "documentation": agent.get("documentation"),
            }
        )
    return response(200, {**agent, **documentation_metadata(agent.get("documentation"))})


def handle_get_agent(agent_id: str, auth: dict[str, Any]) -> dict[str, Any]:
    agent, error = _agent_for_tenant(agent_id, auth)
    if error:
        return error
    return response(
        200,
        {
            **agent,
            **documentation_metadata(agent.get("documentation")),
            **_agent_impact_assessment_metadata(str(agent["tenant_id"]), agent_id, store()),
        },
    )


def handle_revoke_agent(agent_id: str, auth: dict[str, Any]) -> dict[str, Any]:
    agent, error = _agent_for_tenant(agent_id, auth)
    if error:
        return error
    agent["status"] = "revoked"
    agent["updated_at"] = utc_now()
    agent["revoked_at"] = agent["updated_at"]
    agent_store = store()
    agent_store.put_agent(agent)
    agent_store.put_event(
        {
            "event_type": "agent.revoked",
            "tenant_id": agent["tenant_id"],
            "run_id": "identity-management",
            "action_id": agent_id,
            "agent_id": agent_id,
            "invoked_by": agent.get("owner", "unknown-owner"),
            "created_at": agent["updated_at"],
            "identity_status": agent["status"],
        }
    )
    return response(200, agent)


AGENT_CREDENTIAL_DEFAULT_SCOPES = {"guard:evaluate", "actions:write", "mcp:read"}
AGENT_CREDENTIAL_ALLOWED_SCOPES = AGENT_CREDENTIAL_DEFAULT_SCOPES | {
    "proof:read",
    "citation:verify",
    "audit:write",
    "identity:read",
    "identity:write",
    "model:read",
    "model:write",
}
AGENT_CREDENTIAL_SCAN_PAGE_SIZE = 1000


def credential_metadata(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "credential_id": record.get("credential_id"),
        "tenant_id": record.get("tenant_id"),
        "agent_id": record.get("agent_id"),
        "token_type": "agent",
        "scopes": record.get("scopes") or [],
        "status": record.get("status"),
        "created_at": record.get("created_at"),
        "expires_at": record.get("expires_at"),
        "revoked_at": record.get("revoked_at"),
    }


def list_agent_credentials(agent_id: str, tenant_id: str) -> list[dict[str, Any]]:
    if token_table is None:
        raise RuntimeError("TOKEN_TABLE_NAME is not configured.")
    def matching(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            item for item in records
            if str(item.get("token_type") or "") == "agent"
            and str(item.get("agent_id") or "") == agent_id
            and str(item.get("tenant_id") or "") == tenant_id
        ]

    items: list[dict[str, Any]] = []
    indexed = False
    filtered: list[dict[str, Any]] = []
    for attempt in range(5):
        items, indexed = _query_token_index(TOKEN_AGENT_INDEX_NAME, "agent_id", agent_id)
        filtered = matching(items) if indexed else []
        if filtered or not indexed or attempt == 4:
            break
        # A newly issued credential may take a short time to appear in the GSI.
        time.sleep(0.1)
    # GSI reads are eventually consistent. A credential issued immediately
    # before this read may not be visible on the index yet, or the index may
    # return a record that does not belong to this tenant. Fall back to a
    # bounded strongly consistent base-table scan and retry briefly.
    if not filtered:
        for attempt in range(3):
            items = []
            scan_kwargs: dict[str, Any] = {
                "FilterExpression": Attr("token_type").eq("agent") & Attr("agent_id").eq(agent_id) & Attr("tenant_id").eq(tenant_id),
                "Limit": AGENT_CREDENTIAL_SCAN_PAGE_SIZE,
                "ConsistentRead": True,
            }
            pages = 0
            # As with PAT listing, keep the bounded scan page limit independent
            # of the result cap so eventual GSI lag cannot hide a valid
            # credential.
            while pages < 50:
                result = token_table.scan(**scan_kwargs)
                items.extend(result.get("Items", []))
                last_key = result.get("LastEvaluatedKey")
                pages += 1
                if not last_key:
                    break
                scan_kwargs["ExclusiveStartKey"] = last_key
            filtered = matching(items)
            if filtered or attempt == 2:
                break
            time.sleep(0.05)
    return filtered[:100]


def handle_issue_agent_credential(agent_id: str, body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    bind_tenant(body, auth)
    agent, error = _agent_for_tenant(agent_id, auth)
    if error:
        return error
    if agent.get("status") != "active":
        return response(409, {"error": "agent_not_active", "agent_id": agent_id})
    try:
        lifetime = int(body.get("expires_in_seconds") or 900)
    except (TypeError, ValueError) as exc:
        raise ValueError("expires_in_seconds must be an integer between 60 and 3600") from exc
    if lifetime < 60 or lifetime > 3600:
        raise ValueError("expires_in_seconds must be between 60 and 3600")
    requested_scopes = body.get("scopes")
    scopes = {str(item) for item in requested_scopes} if isinstance(requested_scopes, list) else set(AGENT_CREDENTIAL_DEFAULT_SCOPES)
    if not scopes or not scopes.issubset(AGENT_CREDENTIAL_ALLOWED_SCOPES):
        return response(400, {"error": "unsupported_agent_credential_scope", "allowed_scopes": sorted(AGENT_CREDENTIAL_ALLOWED_SCOPES)})
    if auth.get("token_type") == "agent" and not scopes.issubset({str(scope) for scope in (auth.get("scopes") or [])}):
        return response(403, {"error": "agent_credential_scope_escalation"})
    credential_id = f"cred-{uuid.uuid4().hex[:16]}"
    token = f"kta_agent_{secrets.token_urlsafe(32)}"
    now = int(time.time())
    record = {
        "token_hash": hashlib.sha256(token.encode("utf-8")).hexdigest(),
        "token_id": credential_id,
        "credential_id": credential_id,
        "token_type": "agent",
        "name": str(body.get("name") or f"{agent_id}-credential"),
        "tenant_id": agent["tenant_id"],
        "agent_id": agent_id,
        "scopes": sorted(scopes),
        "status": "active",
        "created_at": utc_now(),
        "expires_at": now + lifetime,
        "issued_by": str(auth.get("token_id") or auth.get("agent_id") or "identity-administrator"),
    }
    if token_table is None:
        raise RuntimeError("TOKEN_TABLE_NAME is not configured.")
    token_table.put_item(Item=record, ConditionExpression=Attr("token_hash").not_exists())
    store().put_event(
        {
            "event_type": "agent.credential.issued",
            "tenant_id": agent["tenant_id"],
            "run_id": "identity-management",
            "action_id": credential_id,
            "agent_id": agent_id,
            "invoked_by": record["issued_by"],
            "created_at": record["created_at"],
            "credential_id": credential_id,
            "credential_expires_at": record["expires_at"],
            "credential_scopes": record["scopes"],
        }
    )
    return response(201, {"token": token, "credential": credential_metadata(record)})


def handle_list_agent_credentials(agent_id: str, auth: dict[str, Any]) -> dict[str, Any]:
    agent, error = _agent_for_tenant(agent_id, auth)
    if error:
        return error
    credentials = [credential_metadata(item) for item in list_agent_credentials(agent_id, agent["tenant_id"])]
    return response(200, {"agent_id": agent_id, "tenant_id": agent["tenant_id"], "credentials": credentials})


def handle_get_agent_credential(agent_id: str, credential_id: str, auth: dict[str, Any]) -> dict[str, Any]:
    agent, error = _agent_for_tenant(agent_id, auth)
    if error:
        return error
    for record in list_agent_credentials(agent_id, agent["tenant_id"]):
        if record.get("credential_id") == credential_id:
            return response(200, {"credential": credential_metadata(record)})
    return response(404, {"error": "credential_not_found", "credential_id": credential_id})


def handle_revoke_agent_credential(agent_id: str, credential_id: str, auth: dict[str, Any]) -> dict[str, Any]:
    agent, error = _agent_for_tenant(agent_id, auth)
    if error:
        return error
    records = list_agent_credentials(agent_id, agent["tenant_id"])
    record = next((item for item in records if item.get("credential_id") == credential_id), None)
    if not record:
        return response(404, {"error": "credential_not_found", "credential_id": credential_id})
    if record.get("status") == "revoked":
        return response(200, {"credential": credential_metadata(record)})
    now = utc_now()
    token_table.update_item(
        Key={"token_hash": record["token_hash"]},
        UpdateExpression="SET #status = :revoked, revoked_at = :now",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={":revoked": "revoked", ":now": now},
    )
    record["status"] = "revoked"
    record["revoked_at"] = now
    store().put_event(
        {
            "event_type": "agent.credential.revoked",
            "tenant_id": agent["tenant_id"],
            "run_id": "identity-management",
            "action_id": credential_id,
            "agent_id": agent_id,
            "invoked_by": str(auth.get("token_id") or "identity-administrator"),
            "created_at": now,
            "credential_id": credential_id,
        }
    )
    return response(200, {"credential": credential_metadata(record)})


def handle_list_approvals(event: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    query = event.get("queryStringParameters") or {}
    requested_tenant = str(query.get("tenant_id") or auth.get("tenant_id") or "")
    tenant_id, error = tenant_target(requested_tenant, auth)
    if error:
        return error
    status = str(query.get("status") or "").strip().lower()
    allowed_statuses = {"pending", "approved", "denied", "expired", "revoked", "consumed"}
    if status and status not in allowed_statuses:
        return response(400, {"error": "invalid_approval_status", "allowed_statuses": sorted(allowed_statuses)})
    try:
        limit = int(query.get("limit") or 50)
    except (TypeError, ValueError) as exc:
        raise ValueError("limit must be an integer between 1 and 100") from exc
    if limit < 1 or limit > 100:
        raise ValueError("limit must be an integer between 1 and 100")
    statuses = {status} if status else {"pending", "approved"}
    approvals = store().list_approvals(
        tenant_id,
        statuses=statuses,
        agent_id=str(query.get("agent_id") or "").strip() or None,
        environment=str(query.get("environment") or "").strip() or None,
        limit=limit,
    )
    return response(
        200,
        {
            "tenant_id": tenant_id,
            "statuses": sorted(statuses),
            "count": len(approvals),
            "approvals": approvals,
        },
    )


def handle_get_approval(approval_id: str, auth: dict[str, Any]) -> dict[str, Any]:
    approval = store().get_approval(approval_id)
    if not approval:
        return response(404, {"error": "approval_not_found", "approval_id": approval_id})
    if approval.get("tenant_id") != auth.get("tenant_id") and not has_scope(auth, "admin"):
        return response(403, {"error": "tenant_mismatch"})
    return response(200, {"approval": approval})


def handle_list_grants(event: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    query = event.get("queryStringParameters") or {}
    requested_tenant = str(query.get("tenant_id") or auth.get("tenant_id") or "")
    tenant_id, error = tenant_target(requested_tenant, auth)
    if error:
        return error
    try:
        limit = int(query.get("limit") or 50)
    except (TypeError, ValueError) as exc:
        raise ValueError("limit must be an integer between 1 and 100") from exc
    if limit < 1 or limit > 100:
        raise ValueError("limit must be an integer between 1 and 100")
    now = int(time.time())
    grants = store().list_grants(tenant_id, limit=limit)
    for grant in grants:
        if str(grant.get("status") or "active") == "active" and int(grant.get("expires_at", 0)) <= now:
            grant["status"] = "expired"
    return response(200, {"tenant_id": tenant_id, "count": len(grants), "grants": grants})


def handle_revoke_grant(event: dict[str, Any], body: dict[str, Any], grant_id: str, auth: dict[str, Any]) -> dict[str, Any]:
    bind_tenant(body, auth)
    grant_store = store()
    grant = grant_store.get_grant(grant_id)
    if not grant:
        return response(404, {"error": "grant_not_found", "grant_id": grant_id})
    if grant.get("tenant_id") != tenant_from(event, body, auth):
        return response(403, {"error": "tenant_mismatch"})
    if str(grant.get("status") or "active") != "active":
        return response(409, {"error": "grant_not_active", "grant_id": grant_id, "status": grant.get("status")})
    revoked_by = authenticated_principal(auth)
    updated = grant_store.revoke_grant(grant_id, revoked_by=revoked_by, revoked_at=utc_now())
    if not updated:
        return response(409, {"error": "grant_not_active", "grant_id": grant_id})
    grant_store.put_event(
        {
            "event_type": "approval.grant_revoked",
            "tenant_id": updated["tenant_id"],
            "created_at": utc_now(),
            "grant_id": grant_id,
            "action_hash": updated.get("action_hash"),
            "revoked_by": revoked_by,
            "status": "revoked",
        }
    )
    return response(200, {"grant": updated})


def _chain_step_context(
    approval: dict[str, Any],
    approval_id: str,
    body: dict[str, Any],
) -> tuple[list[dict[str, Any]], int, dict[str, Any] | None, dict[str, Any] | None]:
    """Return the current chain step or a stable validation response."""
    chain_steps = [dict(step) for step in approval.get("chain_steps") or []]
    current_step = int(approval.get("current_step") or 1)
    total_steps = len(chain_steps)
    requested_step = body.get("step")
    if requested_step is not None:
        try:
            requested_step = int(requested_step)
        except (TypeError, ValueError):
            return chain_steps, current_step, None, response(400, {"error": "step_must_be_an_integer", "approval_id": approval_id})
        if requested_step != current_step:
            return chain_steps, current_step, None, response(
                409,
                {
                    "error": "approval_step_not_actionable",
                    "approval_id": approval_id,
                    "current_step": current_step,
                    "requested_step": requested_step,
                },
            )
    if current_step < 1 or current_step > total_steps:
        return chain_steps, current_step, None, response(409, {"error": "approval_chain_invalid_state", "approval_id": approval_id})
    return chain_steps, current_step, chain_steps[current_step - 1], None


def _validate_chain_approval(
    approval: dict[str, Any],
    approval_id: str,
    step: dict[str, Any],
    chain_steps: list[dict[str, Any]],
    current_step: int,
    approver_principal: str,
    auth: dict[str, Any],
) -> dict[str, Any] | None:
    """Validate group membership and separation of duties for a chain step."""
    reviewer_groups = {str(group).strip().casefold() for group in (auth.get("groups") or []) if str(group).strip()}
    required_groups = [str(group).strip().casefold() for group in (step.get("approver_groups") or []) if str(group).strip()]
    if required_groups and not reviewer_groups.intersection(required_groups):
        return response(
            403,
            {
                "error": "approver_group_required",
                "approval_id": approval_id,
                "step": current_step,
                "required_groups": [step.get("approver_groups", [])],
            },
        )
    if step.get("separation_of_duties", True):
        if approver_principal and approver_principal == str(approval.get("requested_by") or ""):
            return response(
                403,
                {
                    "error": "separation_of_duties_violation",
                    "approval_id": approval_id,
                    "step": current_step,
                    "reasons": [{"code": "SELF_APPROVAL", "message": "The requester cannot approve their own action."}],
                },
            )
        prior_approvers = {str(prior.get("approver_principal") or "") for prior in chain_steps if prior.get("status") == "approved"}
        if approver_principal and approver_principal in prior_approvers:
            return response(
                403,
                {
                    "error": "separation_of_duties_violation",
                    "approval_id": approval_id,
                    "step": current_step,
                    "reasons": [{"code": "REPEAT_APPROVER", "message": "Each chain step must be approved by a different person."}],
                },
            )
    return None


def _deny_chain_step(
    approval_store: AuditStore,
    approval: dict[str, Any],
    approval_id: str,
    chain_steps: list[dict[str, Any]],
    current_step: int,
    step: dict[str, Any],
    approver: str,
    approver_principal: str,
    decided_at: str,
) -> dict[str, Any]:
    step.update({"status": "denied", "approver": approver, "approver_principal": approver_principal, "decided_at": decided_at})
    updated = approval_store.update_approval_chain(
        approval_id, chain_steps, current_step, "denied",
        decided_at=decided_at, approver=approver, approver_principal=approver_principal,
    )
    if not updated:
        return response(409, {"error": "approval_expired_or_already_decided", "approval_id": approval_id})
    approval_store.put_event(
        {
            "event_type": "approval.step_decided",
            "tenant_id": approval["tenant_id"],
            "run_id": approval.get("run_id"),
            "action_id": approval.get("action_id"),
            "agent_id": approval.get("agent_id"),
            "created_at": decided_at,
            "approval_id": approval_id,
            "step": current_step,
            "step_label": step.get("label"),
            "status": "denied",
            "approver": approver,
            "approver_principal": approver_principal,
        }
    )
    return response(200, {"approval": updated})


def _approve_chain_step(
    approval_store: AuditStore,
    approval: dict[str, Any],
    approval_id: str,
    body: dict[str, Any],
    chain_steps: list[dict[str, Any]],
    current_step: int,
    step: dict[str, Any],
    approver: str,
    approver_principal: str,
    decided_at: str,
) -> dict[str, Any]:
    step.update({"status": "approved", "approver": approver, "approver_principal": approver_principal, "decided_at": decided_at})
    total_steps = len(chain_steps)
    is_final = current_step >= total_steps
    updated = approval_store.update_approval_chain(
        approval_id, chain_steps, current_step if is_final else current_step + 1, "approved" if is_final else "pending",
        decided_at=decided_at if is_final else None,
        approver=approver if is_final else None,
        approver_principal=approver_principal if is_final else None,
    )
    if not updated:
        return response(409, {"error": "approval_expired_or_already_decided", "approval_id": approval_id})
    approval_store.put_event(
        {
            "event_type": "approval.step_decided",
            "tenant_id": approval["tenant_id"],
            "run_id": approval.get("run_id"),
            "action_id": approval.get("action_id"),
            "agent_id": approval.get("agent_id"),
            "created_at": decided_at,
            "approval_id": approval_id,
            "step": current_step,
            "step_label": step.get("label"),
            "status": "approved",
            "approver": approver,
            "approver_principal": approver_principal,
            "chain_complete": is_final,
        }
    )
    result_payload: dict[str, Any] = {"approval": updated, "step": current_step, "total_steps": total_steps, "chain_complete": is_final}
    if is_final:
        duration_seconds = _normalise_grant_duration(body.get("grant_duration"))
        if duration_seconds is not None:
            result_payload["grant"] = create_approval_grant(updated, duration_seconds, approver, approver_principal, approval_store)
    return response(200, result_payload)


def _handle_chain_decision(
    approval_store: AuditStore,
    approval: dict[str, Any],
    approval_id: str,
    body: dict[str, Any],
    requested_decision: str,
    approver: str,
    approver_principal: str,
    approver_auth_source: str,
    auth: dict[str, Any],
) -> dict[str, Any]:
    """Apply a decision to the current step of a multi-step approval chain (#245)."""
    del approver_auth_source
    chain_steps, current_step, step, validation_error = _chain_step_context(approval, approval_id, body)
    if validation_error:
        return validation_error
    assert step is not None
    decided_at = utc_now()
    if requested_decision == "deny":
        return _deny_chain_step(approval_store, approval, approval_id, chain_steps, current_step, step, approver, approver_principal, decided_at)
    validation_error = _validate_chain_approval(approval, approval_id, step, chain_steps, current_step, approver_principal, auth)
    if validation_error:
        return validation_error
    return _approve_chain_step(approval_store, approval, approval_id, body, chain_steps, current_step, step, approver, approver_principal, decided_at)


def _validate_single_step_approval(
    approval_store: AuditStore,
    approval: dict[str, Any],
    approval_id: str,
    auth: dict[str, Any],
    approver: str,
    approver_principal: str,
) -> dict[str, Any] | None:
    """Validate group membership and separation for a single-step approval."""
    approval_requirements = approval.get("approval_requirements") if isinstance(approval.get("approval_requirements"), list) else []
    reviewer_groups = {str(group).strip().casefold() for group in (auth.get("groups") or []) if str(group).strip()}
    missing_group_requirements = [
        requirement
        for requirement in approval_requirements
        if isinstance(requirement, dict)
        and (groups := [str(group).strip().casefold() for group in (requirement.get("groups") or []) if str(group).strip()])
        and not reviewer_groups.intersection(groups)
    ]
    if missing_group_requirements:
        approval_store.put_event(
            {
                "event_type": "approval.blocked",
                "tenant_id": approval["tenant_id"],
                "run_id": approval["run_id"],
                "action_id": approval["action_id"],
                "agent_id": approval["agent_id"],
                "created_at": utc_now(),
                "approval_id": approval_id,
                "status": "blocked",
                "approver": approver,
                "approver_principal": approver_principal,
                "reason_codes": ["APPROVER_GROUP_REQUIRED"],
                "reasons": [
                    {
                        "code": "APPROVER_GROUP_REQUIRED",
                        "message": "The approver is not a member of every group required by the approval policy.",
                    }
                ],
                "approval_requirements": missing_group_requirements,
            }
        )
        return response(
            403,
            {
                "error": "approver_group_required",
                "approval_id": approval_id,
                "required_groups": [requirement.get("groups", []) for requirement in missing_group_requirements],
            },
        )
    agent = approval_store.get_agent(str(approval.get("agent_id") or ""), str(approval.get("tenant_id") or ""))
    separation = check_approval_separation(agent, approval, approver, auth, approver_principal=approver_principal)
    if separation["allowed"]:
        return None
    approval_store.put_event(
        {
            "event_type": "approval.blocked",
            "tenant_id": approval["tenant_id"],
            "run_id": approval["run_id"],
            "action_id": approval["action_id"],
            "agent_id": approval["agent_id"],
            "created_at": separation["checked_at"],
            "approval_id": approval_id,
            "status": "blocked",
            "approver": approver,
            "approver_principal": approver_principal,
            "reason_codes": [reason["code"] for reason in separation["reasons"]],
            "reasons": separation["reasons"],
        }
    )
    return response(403, {"error": "separation_of_duties_violation", "approval_id": approval_id, "reasons": separation["reasons"]})


def handle_approval(event: dict[str, Any], body: dict[str, Any], approval_id: str, auth: dict[str, Any]) -> dict[str, Any]:
    bind_tenant(body, auth)
    approval_store = store()
    approval = approval_store.get_approval(approval_id)
    if not approval:
        return response(404, {"error": "approval_not_found", "approval_id": approval_id})
    if approval["tenant_id"] != tenant_from(event, body, auth):
        return response(403, {"error": "tenant_mismatch"})
    requested_hash = str(body.get("action_hash") or "")
    if requested_hash and requested_hash != str(approval.get("action_hash") or ""):
        return response(409, {"error": "approval_action_mismatch", "approval_id": approval_id})
    requested_decision = str(body.get("decision") or "").lower()
    if requested_decision not in {"approve", "deny"}:
        return response(400, {"error": "decision_must_be_approve_or_deny"})
    approver_principal = authenticated_principal(auth)
    requested_approver = str(body.get("approver") or "").strip()
    if auth.get("auth_source") in {"oidc", "oauth2"} and requested_approver and requested_approver != approver_principal:
        return response(
            403,
            {
                "error": "approver_identity_mismatch",
                "message": "The federated identity must approve using its verified subject.",
            },
        )
    approver = requested_approver or approver_principal
    approver_auth_source = str(auth.get("auth_source") or auth.get("token_type") or "pat")
    status = "approved" if requested_decision == "approve" else "denied"
    if approval.get("status") != "pending":
        if (
            approval.get("status") == status
            and str(approval.get("approver") or "") == approver
            and (not approval.get("approver_principal") or str(approval.get("approver_principal")) == approver_principal)
        ):
            return response(200, {"approval": approval})
        return response(409, {"error": "approval_expired_or_already_decided", "approval_id": approval_id})
    # Multi-step approval chain (#245): route the decision through the chain
    # handler when the approval carries a step list.
    if isinstance(approval.get("chain_steps"), list) and approval["chain_steps"]:
        return _handle_chain_decision(approval_store, approval, approval_id, body, requested_decision, approver, approver_principal, approver_auth_source, auth)
    if requested_decision == "approve":
        validation_error = _validate_single_step_approval(approval_store, approval, approval_id, auth, approver, approver_principal)
        if validation_error:
            return validation_error
    try:
        updated = approval_store.update_approval(
            approval_id,
            status,
            approver,
            utc_now(),
            approver_principal=approver_principal,
            approver_auth_source=approver_auth_source,
        )
    except Exception as exc:
        if _is_conditional_check_failure(exc):
            return response(409, {"error": "approval_expired_or_already_decided", "approval_id": approval_id})
        raise
    approval_store.put_event(
        {
            "event_type": "approval.decided",
            "tenant_id": updated["tenant_id"],
            "run_id": updated["run_id"],
            "action_id": updated["action_id"],
            "agent_id": updated["agent_id"],
            "created_at": updated["decided_at"],
            "approval_id": approval_id,
            "status": status,
            "approver": approver,
            "approver_principal": approver_principal,
            "approver_auth_source": approver_auth_source,
            "action_hash": updated["action_hash"],
        }
    )
    # Duration-based grant (#242): on approval, a reviewer may extend the decision
    # to all identical actions for a bounded time window.
    grant = None
    if requested_decision == "approve":
        duration_seconds = _normalise_grant_duration(body.get("grant_duration"))
        if duration_seconds is not None:
            grant = create_approval_grant(updated, duration_seconds, approver, approver_principal, approval_store)
    result_payload: dict[str, Any] = {"approval": updated}
    if grant is not None:
        result_payload["grant"] = grant
    return response(200, result_payload)


def handle_revoke_approval(event: dict[str, Any], body: dict[str, Any], approval_id: str, auth: dict[str, Any]) -> dict[str, Any]:
    bind_tenant(body, auth)
    approval_store = store()
    approval = approval_store.get_approval(approval_id)
    if not approval:
        return response(404, {"error": "approval_not_found", "approval_id": approval_id})
    if approval.get("tenant_id") != tenant_from(event, body, auth):
        return response(403, {"error": "tenant_mismatch"})
    revoked_by = str(body.get("revoked_by") or auth.get("subject") or auth.get("token_id") or "unknown-revoker")
    revoked, changed = approval_store.revoke_approval(
        approval_id,
        revoked_by=revoked_by,
        revoked_at=utc_now(),
        reason=str(body.get("reason") or "").strip(),
    )
    if not revoked:
        return response(404, {"error": "approval_not_found", "approval_id": approval_id})
    if not changed:
        if revoked.get("status") == "revoked" and str(revoked.get("revoked_by") or "") == revoked_by:
            return response(200, {"approval": revoked, "idempotent": True})
        return response(409, {"error": "approval_not_revivable", "approval_id": approval_id, "status": revoked.get("status")})
    approval_store.put_event(
        {
            "event_type": "approval.revoked",
            "tenant_id": revoked["tenant_id"],
            "run_id": revoked["run_id"],
            "action_id": revoked["action_id"],
            "agent_id": revoked["agent_id"],
            "created_at": revoked["revoked_at"],
            "approval_id": approval_id,
            "status": "revoked",
            "revoked_by": revoked_by,
            "reason": revoked.get("revocation_reason"),
            "action_hash": revoked.get("action_hash"),
        }
    )
    return response(200, {"approval": revoked})


def handle_outcome(event: dict[str, Any], body: dict[str, Any], action_id: str, auth: dict[str, Any]) -> dict[str, Any]:
    bind_tenant(body, auth)
    action = body.get("action") if isinstance(body.get("action"), dict) else {}
    context = body.get("context") if isinstance(body.get("context"), dict) else {}
    tenant_id = tenant_from(event, body, auth)
    proof_store = store()
    evaluation = proof_store.get_action_evaluation(tenant_id, action_id)
    if not evaluation:
        return response(404, {"error": "action_not_found", "action_id": action_id})
    if _bound_agent_mismatch(evaluation.get("agent_id"), auth):
        return response(403, {"error": "agent_credential_mismatch"})
    expected_hash = str(evaluation.get("action_hash") or "")
    supplied_hash = str(body.get("action_hash") or "")
    if supplied_hash and supplied_hash != expected_hash:
        return response(409, {"error": "action_hash_mismatch", "action_id": action_id})
    action_hash_value = supplied_hash or expected_hash
    approval_id = str(body.get("approval_id") or "")
    requested_status = str(body.get("status") or "unknown")
    existing_outcome = proof_store.get_action_outcome(tenant_id, action_id)
    if existing_outcome:
        same_hash = str(existing_outcome.get("action_hash") or "") == action_hash_value
        same_status = str(existing_outcome.get("status") or "") == requested_status
        same_approval = str(existing_outcome.get("approval_id") or "") == (approval_id or "")
        if same_hash and same_status and same_approval:
            return response(202, {**existing_outcome, "idempotent": True})
        return response(409, {"error": "action_outcome_already_recorded", "action_id": action_id})
    approval = None
    if evaluation.get("decision") == "require_approval":
        if not approval_id:
            return response(409, {"error": "approved_action_required", "action_id": action_id})
        approval = proof_store.get_approval(approval_id)
        if not approval or approval.get("tenant_id") != tenant_id:
            return response(403, {"error": "approval_not_found_or_tenant_mismatch", "approval_id": approval_id})
        if approval.get("status") not in {"approved", "consumed"}:
            return response(409, {"error": "approval_not_approved", "approval_id": approval_id})
        if approval.get("action_id") != action_id or approval.get("action_hash") != action_hash_value:
            return response(409, {"error": "approval_action_mismatch", "approval_id": approval_id})
        if approval.get("status") == "consumed" and (
            str(approval.get("consumed_action_id") or "") != action_id
            or str(approval.get("consumed_action_hash") or "") != action_hash_value
        ):
            return response(409, {"error": "approval_already_consumed_or_revoked", "approval_id": approval_id})
    elif approval_id:
        approval = proof_store.get_approval(approval_id)
        if not approval or approval.get("tenant_id") != tenant_id:
            return response(403, {"error": "approval_not_found_or_tenant_mismatch", "approval_id": approval_id})
        if approval.get("status") not in {"approved", "consumed"} or approval.get("action_id") != action_id or approval.get("action_hash") != action_hash_value:
            return response(409, {"error": "approval_action_mismatch", "approval_id": approval_id})
        if approval.get("status") == "consumed" and (
            str(approval.get("consumed_action_id") or "") != action_id
            or str(approval.get("consumed_action_hash") or "") != action_hash_value
        ):
            return response(409, {"error": "approval_already_consumed_or_revoked", "approval_id": approval_id})
    outcome = {
        "event_type": "action.outcome",
        "tenant_id": tenant_id,
        "environment": str(context.get("environment") or body.get("environment") or ENVIRONMENT),
        "run_id": str(context.get("run_id") or body.get("run_id") or "unknown-run"),
        "action_id": action_id,
        "agent_id": str(context.get("agent_id") or body.get("agent_id") or "unknown-agent"),
        "invoked_by": str(context.get("invoked_by") or body.get("invoked_by") or "unknown-user"),
        "created_at": utc_now(),
        "status": requested_status,
        "result": body.get("result"),
        "action_hash": action_hash_value,
        "approval_id": approval_id or None,
        "action": action,
        "idempotency_key": f"action-outcome:{tenant_id}:{action_id}",
    }
    proof_id = str(body.get("proof_id") or "")
    if proof_id:
        proof, proof_error = _proof_for_tenant(proof_id, auth)
        if proof_error:
            return proof_error
        outcome["proof_id"] = proof_id
        outcome["proof_uri"] = proof.get("proof_uri")
        proof_store.put_proof(attach_outcome(proof, outcome))
    if approval_id and approval and approval.get("status") == "approved":
        consumed = proof_store.consume_approval(
            approval_id,
            consumed_by=str(auth.get("subject") or auth.get("token_id") or "action-executor"),
            consumed_at=outcome["created_at"],
            action_id=action_id,
            action_hash=action_hash_value,
        )
        if not consumed:
            existing_outcome = proof_store.get_action_outcome(tenant_id, action_id)
            if existing_outcome:
                return response(202, {**existing_outcome, "idempotent": True})
            return response(409, {"error": "approval_already_consumed_or_revoked", "approval_id": approval_id})
        outcome["approval_status"] = "consumed"
    delivery = proof_store.put_event(outcome)
    if delivery.get("status") == "duplicate":
        existing_outcome = proof_store.get_action_outcome(tenant_id, action_id)
        if existing_outcome:
            return response(202, {**existing_outcome, "idempotent": True})
    return response(202, outcome)


MCP_PROTOCOL_VERSIONS = {"2025-06-18", "2025-11-25"}

MCP_TOOL_SCOPES = {
    "evaluate_action": "guard:evaluate",
    "verify_citations": "citation:verify",
    "create_proof": "proof:write",
    "verify_proof": "proof:read",
    "get_receipt_public_key": "proof:read",
    "register_agent": "identity:write",
    "list_agents": "identity:read",
    "get_agent": "identity:read",
    "revoke_agent": "identity:write",
    "issue_agent_credential": "identity:write",
    "list_agent_credentials": "identity:read",
    "get_agent_credential": "identity:read",
    "revoke_agent_credential": "identity:write",
}

MCP_TOOL_PRODUCTS = {
    "evaluate_action": "agent-guard",
    "verify_citations": "citation-trust",
    "create_proof": "agent-proof",
    "verify_proof": "agent-proof",
    "get_receipt_public_key": "agent-proof",
    "register_agent": "agent-identity",
    "list_agents": "agent-identity",
    "get_agent": "agent-identity",
    "revoke_agent": "agent-identity",
    "issue_agent_credential": "agent-identity",
    "list_agent_credentials": "agent-identity",
    "get_agent_credential": "agent-identity",
    "revoke_agent_credential": "agent-identity",
}

MCP_PROFILES = {
    "suite": {
        "server_name": "kenning-trusted-agent",
        "instructions": "Use the product-specific MCP server when possible. This compatibility endpoint exposes Guard, Citation Trust, Proof, and Identity tools.",
        "tools": ("evaluate_action", "verify_citations", "create_proof", "verify_proof", "get_receipt_public_key"),
    },
    "agent-guard": {
        "server_name": "kenning-agent-guard",
        "instructions": "This server provides Kenning Agent Guard only. Call evaluate_action before an agent executes an explicit action. A require_approval or deny result must not be executed automatically.",
        "tools": ("evaluate_action",),
    },
    "citation-trust": {
        "server_name": "kenning-citation-trust",
        "instructions": "This server provides Kenning Citation Trust only. Use verify_citations to check cited sources. The tenant is derived from the PAT; do not provide tenant or environment fields.",
        "tools": ("verify_citations",),
    },
    "agent-proof": {
        "server_name": "kenning-agent-proof",
        "instructions": "This server provides Kenning Agent Proof only. Use create_proof to record structured provenance, verify_proof to validate a record, and get_receipt_public_key for independent receipt verification.",
        "tools": ("create_proof", "verify_proof", "get_receipt_public_key"),
    },
    "agent-identity": {
        "server_name": "kenning-agent-identity",
        "instructions": "This server provides Kenning Agent Identity only. The tenant is derived from the PAT; use the identity tools to manage agents and their short-lived credentials.",
        "tools": (
            "register_agent",
            "list_agents",
            "get_agent",
            "revoke_agent",
            "issue_agent_credential",
            "list_agent_credentials",
            "get_agent_credential",
            "revoke_agent_credential",
        ),
    },
}

MCP_PATH_PROFILES = {
    "/mcp": "suite",
    "/mcp/agent-guard": "agent-guard",
    "/mcp/citation-trust": "citation-trust",
    "/mcp/agent-proof": "agent-proof",
    "/mcp/agent-identity": "agent-identity",
}


def mcp_profile_for_path(path: str) -> dict[str, Any] | None:
    profile_name = MCP_PATH_PROFILES.get(path)
    return MCP_PROFILES.get(profile_name) if profile_name else None


def mcp_error(request_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def mcp_tool_definition() -> dict[str, Any]:
    return {
        "name": "evaluate_action",
        "title": "Evaluate an agent action",
        "description": "Evaluate and record an agent tool call before execution. Returns an allow, warn, require_approval, observe, rewrite, or deny decision. For an operator-approved retry, include the original approval_id and action_hash; do not change the approved command, target, tool, operation, tenant, environment, or agent.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "context": {
                    "type": "object",
                    "description": "Tenant, environment, agent, user, and run context.",
                    "properties": {
                        "tenant_id": {"type": "string"},
                        "environment": {"type": "string", "enum": ["development", "staging", "production"]},
                        "agent_id": {"type": "string"},
                        "invoked_by": {"type": "string"},
                        "run_id": {"type": "string"},
                    },
                    "additionalProperties": True,
                },
                "intent": {"type": "string", "description": "The user or system intent the agent is trying to fulfil."},
                "approval_id": {"type": "string", "description": "Original operator approval ID when resuming an approved action."},
                "action_hash": {"type": "string", "description": "Original semantic action hash returned by Guard when resuming an approved action."},
                "action": {
                    "type": "object",
                    "description": "The proposed action to evaluate.",
                    "properties": {
                        "tool": {"type": "string", "enum": ["shell", "sql", "file", "aws", "azure", "cloud"]},
                        "operation": {"type": "string"},
                        "classification": {"type": "string", "enum": ["unclassified", "in_confidence", "sensitive", "restricted", "confidential", "secret"]},
                        "target": {},
                        "parameters": {"type": "object"},
                    },
                    "required": ["tool"],
                    "additionalProperties": True,
                },
            },
            "required": ["action"],
            "additionalProperties": False,
        },
    }


def mcp_citation_tool_definition(*, product_specific: bool = False) -> dict[str, Any]:
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "response": {"type": "string", "description": "The agent response containing citations."},
            "response_id": {"type": "string"},
            "citations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "claim": {"type": "string"},
                        "claim_support_required": {
                            "type": "boolean",
                            "description": "Set false for bibliography, data, licence, and other source-only URLs that have no claim to compare.",
                        },
                        "reference_metadata": {
                            "type": "object",
                            "description": "Bibliographic metadata extracted from the report entry. The verifier compares available title, author, year, and publisher fields with the retrieved source.",
                            "additionalProperties": True,
                        },
                    },
                    "required": ["url"],
                    "additionalProperties": True,
                },
            },
        },
        "required": ["response"],
        "additionalProperties": not product_specific,
    }
    description = "Verify that cited sources exist, are accessible, authentic, and support the associated claims. Bibliography URLs can be sent as source-only checks with reference_metadata so the URL and bibliographic record are verified separately. Returns separate source, bibliography-metadata, and claim-support results; source quality is reported as policy metadata rather than included in the default score."
    if product_specific:
        description += " This Citation Trust server is read-only; the tenant is derived from the PAT and must not be supplied by the client."
    return {
        "name": "verify_citations",
        "title": "Verify cited evidence",
        "description": description,
        "annotations": {
            "title": "Verify cited evidence",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": True,
        },
        "inputSchema": input_schema,
        "outputSchema": {
            "type": "object",
            "properties": {
                "status": {"type": "string", "enum": ["pass", "warning", "fail"]},
                "trust_score": {"type": "integer", "minimum": 0, "maximum": 100},
                "citations": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "source_verified": {"type": "boolean"},
                            "source_score": {"type": "integer", "minimum": 0, "maximum": 100},
                            "claim_support_score": {"type": "integer", "minimum": 0, "maximum": 100},
                            "claim_support_required": {"type": "boolean"},
                            "verification_scope": {"type": "string", "enum": ["claim_support", "source_only"]},
                            "reference_verified": {"type": "boolean", "nullable": True},
                            "reference_metadata_score": {"type": "integer", "minimum": 0, "maximum": 100, "nullable": True},
                            "reference_metadata_findings": {"type": "object", "additionalProperties": {"type": "boolean"}},
                            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                        },
                        "additionalProperties": True,
                    },
                },
                "reference_findings": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
                "extracted_references": {"type": "object", "additionalProperties": True},
                "checked_at": {"type": "string"},
                "summary": {"type": "string"},
                "citation_policy": {"type": "object", "additionalProperties": True},
                "tenant_id": {"type": "string"},
                "response_id": {"type": "string"},
            },
            "required": ["status", "trust_score", "citations", "reference_findings", "checked_at", "summary", "citation_policy"],
            "additionalProperties": True,
        },
    }


def mcp_proof_tool_definition() -> dict[str, Any]:
    return {
        "name": "create_proof",
        "title": "Create an Agent Proof record",
        "description": "Record structured decision provenance, evidence, limitations, model metadata, approvals, and outcomes without capturing hidden chain-of-thought.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "context": {"type": "object", "additionalProperties": True},
                "request": {"type": "object", "additionalProperties": True},
                "inputs": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
                "evidence": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
                "decision_factors": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
                "recommendation": {},
                "limitations": {"type": "array", "items": {"type": "string"}},
                "model": {"type": "object", "additionalProperties": True},
                "tools_used": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
                "approvals": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
            },
            "required": ["request"],
            "additionalProperties": True,
        },
    }


def mcp_verify_proof_tool_definition() -> dict[str, Any]:
    return {
        "name": "verify_proof",
        "title": "Verify a Proof and receipt",
        "description": "Recompute a stored Proof record and its Trusted Action Receipt, including the deployed KMS signature.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "proof_id": {"type": "string", "description": "The Proof ID returned by evaluation or create_proof."},
            },
            "required": ["proof_id"],
            "additionalProperties": False,
        },
    }


def mcp_receipt_key_tool_definition() -> dict[str, Any]:
    return {
        "name": "get_receipt_public_key",
        "title": "Get receipt verification key",
        "description": "Return the public key metadata needed to independently verify Trusted Action Receipt signatures.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
        },
    }


def mcp_identity_tool_definitions() -> list[dict[str, Any]]:
    registration_properties = {
        "agent_id": {"type": "string"},
        "owner": {"type": "string"},
        "purpose": {"type": "string"},
        "version": {"type": "string"},
        "allowed_environments": {"type": "array", "items": {"type": "string"}},
        "approved_tools": {"type": "array", "items": {"type": "string"}},
        "may": {"type": "array", "items": {"type": "string"}},
        "may_not": {"type": "array", "items": {"type": "string"}},
        "conditions": {"type": "object", "additionalProperties": True},
        "maximum_authority": {"type": "string", "enum": ["read", "standard", "high", "admin"]},
        "parent_agent_id": {"type": "string"},
    }
    return [
        {
            "name": "register_agent",
            "title": "Register an agent identity",
            "description": "Register a tenant-bound agent identity. The tenant is derived from the PAT.",
            "inputSchema": {"type": "object", "properties": registration_properties, "required": ["agent_id"], "additionalProperties": False},
        },
        {
            "name": "list_agents",
            "title": "List agent identities",
            "description": "List active and revoked agent identities in the PAT's tenant.",
            "inputSchema": {"type": "object", "additionalProperties": False},
        },
        {
            "name": "get_agent",
            "title": "Get an agent identity",
            "description": "Retrieve one agent identity in the PAT's tenant.",
            "inputSchema": {"type": "object", "properties": {"agent_id": {"type": "string"}}, "required": ["agent_id"], "additionalProperties": False},
        },
        {
            "name": "revoke_agent",
            "title": "Revoke an agent identity",
            "description": "Revoke one agent identity in the PAT's tenant.",
            "inputSchema": {"type": "object", "properties": {"agent_id": {"type": "string"}}, "required": ["agent_id"], "additionalProperties": False},
        },
        {
            "name": "issue_agent_credential",
            "title": "Issue an agent credential",
            "description": "Issue a short-lived, least-privilege credential for an active agent in the PAT's tenant.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string"},
                    "name": {"type": "string"},
                    "expires_in_seconds": {"type": "integer", "minimum": 60, "maximum": 3600},
                    "scopes": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["agent_id"],
                "additionalProperties": False,
            },
        },
        {
            "name": "list_agent_credentials",
            "title": "List agent credentials",
            "description": "List credential metadata for an agent in the PAT's tenant without returning secret values.",
            "inputSchema": {"type": "object", "properties": {"agent_id": {"type": "string"}}, "required": ["agent_id"], "additionalProperties": False},
        },
        {
            "name": "get_agent_credential",
            "title": "Get agent credential metadata",
            "description": "Retrieve non-secret metadata for one agent credential.",
            "inputSchema": {
                "type": "object",
                "properties": {"agent_id": {"type": "string"}, "credential_id": {"type": "string"}},
                "required": ["agent_id", "credential_id"],
                "additionalProperties": False,
            },
        },
        {
            "name": "revoke_agent_credential",
            "title": "Revoke an agent credential",
            "description": "Revoke one agent credential in the PAT's tenant.",
            "inputSchema": {
                "type": "object",
                "properties": {"agent_id": {"type": "string"}, "credential_id": {"type": "string"}},
                "required": ["agent_id", "credential_id"],
                "additionalProperties": False,
            },
        },
    ]


def mcp_headers(event: dict[str, Any]) -> dict[str, str]:
    return {str(key).lower(): str(value) for key, value in (event.get("headers") or {}).items()}


def mcp_tool_definitions(profile: dict[str, Any], enabled_products: list[str] | None = None) -> list[dict[str, Any]]:
    definitions = {
        "evaluate_action": mcp_tool_definition,
        "verify_citations": lambda: mcp_citation_tool_definition(product_specific=profile["server_name"] == "kenning-citation-trust"),
        "create_proof": mcp_proof_tool_definition,
        "verify_proof": mcp_verify_proof_tool_definition,
        "get_receipt_public_key": mcp_receipt_key_tool_definition,
    }
    enabled = set(enabled_products or [])
    names = [
        name for name in profile["tools"]
        if name in definitions and (not enabled or MCP_TOOL_PRODUCTS.get(name) in enabled)
    ]
    result = [definitions[name]() for name in names]
    if "register_agent" not in profile["tools"]:
        return result
    identity_tools = [
        item for item in mcp_identity_tool_definitions()
        if not enabled or MCP_TOOL_PRODUCTS.get(item.get("name")) in enabled
    ]
    return result + identity_tools


def mcp_argument_error(profile: dict[str, Any], tool_name: str, arguments: dict[str, Any]) -> dict[str, Any] | None:
    if profile.get("server_name") == "kenning-citation-trust" and tool_name == "verify_citations":
        allowed = {"response", "response_id", "citations"}
        unexpected = sorted(set(arguments) - allowed)
        if unexpected:
            return mcp_error(
                None,
                -32602,
                "Citation Trust derives tenant and environment from the PAT; remove unsupported fields: " + ", ".join(unexpected),
            )
    return None


APPROVAL_REFERENCE_PATTERN = re.compile(r"\bapproval-[A-Za-z0-9]+\b")


def mcp_approval_reference(arguments: dict[str, Any]) -> str:
    explicit = str(arguments.get("approval_id") or "").strip()
    if explicit:
        return explicit
    intent = str(arguments.get("intent") or "")
    if "approv" not in intent.lower():
        return ""
    match = APPROVAL_REFERENCE_PATTERN.search(intent)
    return match.group(0) if match else ""


def handle_mcp_approved_retry(
    event: dict[str, Any],
    request_id: Any,
    arguments: dict[str, Any],
    approval_id: str,
    auth: dict[str, Any],
) -> dict[str, Any]:
    """Resume an exact action after the operator approved it in the UI."""

    mcp_store = store()
    approval = mcp_store.get_approval(approval_id)
    if not approval:
        return mcp_tool_response(request_id, {"error": "approval_not_found", "approval_id": approval_id}, is_error=True)
    if approval.get("status") != "approved":
        return mcp_tool_response(
            request_id,
            {"error": "approval_not_approved", "approval_id": approval_id, "status": approval.get("status")},
            is_error=True,
        )

    candidate = dict(arguments)
    apply_tenant_runtime(candidate, auth, mcp_store)
    candidate_action = normalise_action(candidate)
    if not approval_action_matches(approval, candidate_action):
        return mcp_tool_response(
            request_id,
            {
                "error": "approval_action_mismatch",
                "approval_id": approval_id,
                "message": "The resumed tool, operation, target, parameters, tenant, environment, or agent differs from the approved action.",
            },
            is_error=True,
        )

    retry = dict(arguments)
    retry_context = dict(arguments.get("context") if isinstance(arguments.get("context"), dict) else {})
    retry_context.update(
        {
            "tenant_id": approval["tenant_id"],
            "environment": approval["environment"],
            "agent_id": approval["agent_id"],
            "invoked_by": approval.get("requested_by") or retry_context.get("invoked_by") or "unknown-user",
            "run_id": approval["run_id"],
            "action_id": approval["action_id"],
        }
    )
    retry["context"] = retry_context
    retry["intent"] = approval["intent"] if "intent" in approval else retry.get("intent") or ""
    retry["approval_id"] = approval_id
    retry["action_hash"] = approval["action_hash"]
    # Call handle_approved_evaluation directly rather than handle_evaluate.
    # handle_evaluate overwrites invoked_by with the current authenticated
    # principal, which would change the action hash and break the exact-replay
    # guarantee.  The retry handler has already bound invoked_by to the
    # original requester stored in the approval record.
    retry_action = normalise_action(retry)
    approved = handle_approved_evaluation(retry, retry_action, mcp_store, approval_id, auth)
    result = json.loads(approved.get("body") or "{}")
    return mcp_tool_response(
        request_id,
        result,
        is_error=approved.get("statusCode", 500) >= 400 or result.get("decision") in {"require_approval", "deny"},
    )


def mcp_tool_response(request_id: Any, result: dict[str, Any], is_error: bool = False) -> dict[str, Any]:
    return response(
        200,
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [{"type": "text", "text": json.dumps(result, default=_json_default)}],
                "structuredContent": result,
                "isError": is_error,
            },
        },
    )


def _handle_mcp_non_evaluation_tool_call(
    request_id: Any,
    name: str,
    arguments: dict[str, Any],
    auth: dict[str, Any],
) -> dict[str, Any] | None:
    """Handle MCP tools that do not evaluate an action."""
    if name == "verify_citations":
        result = citation_verify_and_record(arguments, auth, store())
        return mcp_tool_response(request_id, result, is_error=result["status"] == "fail")
    if name == "create_proof":
        created = handle_create_proof(arguments, auth)
        result = json.loads(created["body"])
        return mcp_tool_response(request_id, result, is_error=created["statusCode"] >= 400)
    if name == "verify_proof":
        proof_id = str(arguments.get("proof_id") or "")
        if not proof_id:
            return response(200, mcp_error(request_id, -32602, "proof_id is required."))
        verified = handle_verify_proof(proof_id, auth)
        result = json.loads(verified["body"])
        return mcp_tool_response(request_id, result, is_error=verified["statusCode"] >= 400 or not result.get("valid", False))
    if name == "get_receipt_public_key":
        key_response = handle_receipt_public_key(auth)
        result = json.loads(key_response["body"])
        return mcp_tool_response(request_id, result, is_error=key_response["statusCode"] >= 400)
    if name == "register_agent":
        created = handle_register_agent(arguments, auth)
        result = json.loads(created["body"])
        return mcp_tool_response(request_id, result, is_error=created["statusCode"] >= 400)
    if name == "list_agents":
        listed = handle_list_agents(auth)
        result = json.loads(listed["body"])
        return mcp_tool_response(request_id, result, is_error=listed["statusCode"] >= 400)
    if name == "get_agent":
        result_response = handle_get_agent(str(arguments.get("agent_id") or ""), auth)
        result = json.loads(result_response["body"])
        return mcp_tool_response(request_id, result, is_error=result_response["statusCode"] >= 400)
    if name == "revoke_agent":
        result_response = handle_revoke_agent(str(arguments.get("agent_id") or ""), auth)
        result = json.loads(result_response["body"])
        return mcp_tool_response(request_id, result, is_error=result_response["statusCode"] >= 400)
    if name == "issue_agent_credential":
        result_response = handle_issue_agent_credential(str(arguments.get("agent_id") or ""), arguments, auth)
        result = json.loads(result_response["body"])
        return mcp_tool_response(request_id, result, is_error=result_response["statusCode"] >= 400)
    if name == "list_agent_credentials":
        result_response = handle_list_agent_credentials(str(arguments.get("agent_id") or ""), auth)
        result = json.loads(result_response["body"])
        return mcp_tool_response(request_id, result, is_error=result_response["statusCode"] >= 400)
    if name == "get_agent_credential":
        result_response = handle_get_agent_credential(
            str(arguments.get("agent_id") or ""), str(arguments.get("credential_id") or ""), auth
        )
        result = json.loads(result_response["body"])
        return mcp_tool_response(request_id, result, is_error=result_response["statusCode"] >= 400)
    if name == "revoke_agent_credential":
        result_response = handle_revoke_agent_credential(
            str(arguments.get("agent_id") or ""), str(arguments.get("credential_id") or ""), auth
        )
        result = json.loads(result_response["body"])
        return mcp_tool_response(request_id, result, is_error=result_response["statusCode"] >= 400)
    return None


def _handle_mcp_tool_call(
    request_id: Any,
    params: dict[str, Any],
    arguments: dict[str, Any],
    auth: dict[str, Any],
    event: dict[str, Any],
    profile: dict[str, Any],
) -> dict[str, Any]:
    """Route an MCP tools/call request to the appropriate handler."""

    argument_error = mcp_argument_error(profile, str(params.get("name") or ""), arguments)
    if argument_error:
        argument_error["id"] = request_id
        return response(200, argument_error)
    non_evaluation_response = _handle_mcp_non_evaluation_tool_call(request_id, str(params.get("name") or ""), arguments, auth)
    if non_evaluation_response is not None:
        return non_evaluation_response
    if params.get("name") != "evaluate_action":
        return response(200, mcp_error(request_id, -32601, "Unknown MCP tool."))
    try:
        approval_id = mcp_approval_reference(arguments)
        if approval_id:
            return handle_mcp_approved_retry(event, request_id, arguments, approval_id, auth)
        mcp_store = store()
        apply_tenant_runtime(arguments, auth, mcp_store)
        result = evaluate_and_record(arguments, mcp_store)
    except (ValueError, PermissionError):
        raise
    except Exception as exc:
        diagnostics = _guard_failure_diagnostics(exc)
        transport_request_id = _guard_request_id(event)
        if transport_request_id and not diagnostics.get("request_id"):
            diagnostics["request_id"] = transport_request_id
        unavailable = guard_unavailable_payload(arguments, auth, diagnostics)
        print(f"MCP Guard unavailable: {json.dumps(diagnostics, sort_keys=True)}")
        return response(
            503,
            mcp_error(
                request_id,
                -32002,
                "Guard unavailable. Do not execute the action; retry after the service recovers.",
                data=unavailable,
            ),
            {"retry-after": "1"},
        )
    return response(
        200,
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(result, default=_json_default),
                    }
                ],
                "structuredContent": result,
                "isError": result["decision"] in {"require_approval", "deny"},
            },
        },
    )


def handle_mcp(
    event: dict[str, Any],
    body: dict[str, Any],
    http_method: str,
    auth: dict[str, Any],
    profile: dict[str, Any] | None = None,
) -> dict[str, Any]:
    profile = profile or MCP_PROFILES["suite"]
    if http_method == "GET":
        return response(405, {"error": "method_not_allowed", "allow": "POST"})
    if http_method != "POST":
        return response(405, {"error": "method_not_allowed", "allow": "POST"})

    headers = mcp_headers(event)
    requested_header_version = headers.get("mcp-protocol-version")
    if requested_header_version and requested_header_version not in MCP_PROTOCOL_VERSIONS:
        return response(400, mcp_error(None, -32602, f"Unsupported MCP protocol version: {requested_header_version}"))

    request_id = body.get("id")
    if body.get("jsonrpc") != "2.0":
        return response(400, mcp_error(request_id, -32600, "MCP requests must use JSON-RPC 2.0."))

    method = body.get("method")
    params = body.get("params") if isinstance(body.get("params"), dict) else {}
    tool_name = params.get("name")
    if method == "tools/call" and tool_name not in profile["tools"]:
        return response(200, mcp_error(request_id, -32601, f"Tool '{tool_name}' is not available on {profile['server_name']} MCP server."))
    required_product = MCP_TOOL_PRODUCTS.get(str(tool_name)) if method == "tools/call" else None
    if required_product:
        product_error = product_access_error(required_product, auth)
        if product_error:
            payload = json.loads(product_error["body"])
            return response(200, mcp_error(request_id, -32003, payload.get("message", "Product is disabled."), payload))
    required_scope = MCP_TOOL_SCOPES.get(tool_name, "mcp:read") if method == "tools/call" else "mcp:read"
    if not has_scope(auth, required_scope):
        return scope_error(required_scope)
    if isinstance(method, str) and method.startswith("notifications/"):
        return empty_response(202)

    if method == "initialize":
        params = body.get("params") if isinstance(body.get("params"), dict) else {}
        requested_version = str(params.get("protocolVersion") or "2025-06-18")
        negotiated_version = requested_version if requested_version in MCP_PROTOCOL_VERSIONS else "2025-06-18"
        return response(
            200,
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": negotiated_version,
                    "capabilities": {
                        "tools": {
                            "listChanged": False,
                        }
                    },
                    "serverInfo": {
                        "name": profile["server_name"],
                        "version": "0.2.0",
                    },
                    "instructions": profile["instructions"],
                },
            },
        )
    if method == "ping":
        return response(200, {"jsonrpc": "2.0", "id": request_id, "result": {}})
    if method == "tools/list":
        return response(
            200,
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "tools": mcp_tool_definitions(profile, enabled_products_for_config(membership_config(str(auth.get("tenant_id") or "")))),
                },
            },
        )
    if method == "tools/call":
        arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        return _handle_mcp_tool_call(request_id, params, arguments, auth, event, profile)
    return response(200, mcp_error(request_id, -32601, f"Unsupported MCP method: {method}"))


def _route_tenant_subresource(tenant_path: str, method: str, body: dict[str, Any], event: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any] | None:
    """Route /v1/tenants/{id}/... sub-resources. Returns None if no match (#251)."""
    tenant_parts = [part for part in tenant_path.split("/") if part]
    if len(tenant_parts) == 2 and tenant_parts[1] == "members" and method == "GET":
        return handle_list_members(tenant_parts[0], event, auth)
    if len(tenant_parts) == 2 and tenant_parts[1] == "members" and method == "POST":
        return handle_create_member(tenant_parts[0], body, event, auth)
    if len(tenant_parts) == 3 and tenant_parts[1] == "members" and method in {"PATCH", "PUT"}:
        return handle_update_member(tenant_parts[0], tenant_parts[2], body, event, auth)
    if len(tenant_parts) == 3 and tenant_parts[1] == "members" and method == "DELETE":
        return handle_update_member(tenant_parts[0], tenant_parts[2], {"status": "revoked"}, event, auth)
    if len(tenant_parts) == 2 and tenant_parts[1] == "invitations" and method == "GET":
        return handle_list_invitations(tenant_parts[0], event, auth)
    if len(tenant_parts) == 2 and tenant_parts[1] == "invitations" and method == "POST":
        return handle_create_invitation(tenant_parts[0], body, event, auth)
    if len(tenant_parts) == 4 and tenant_parts[1] == "invitations" and tenant_parts[3] == "revoke" and method == "POST":
        return handle_revoke_invitation(tenant_parts[0], tenant_parts[2], body, event, auth)
    if len(tenant_parts) == 1 and method == "GET":
        if not has_scope(auth, "tenant:read"):
            return scope_error("tenant:read")
        return handle_get_tenant(tenant_parts[0], auth)
    if len(tenant_parts) == 1 and method == "PUT":
        if not has_scope(auth, "tenant:write"):
            return scope_error("tenant:write")
        return handle_put_tenant(tenant_parts[0], body, auth)
    if len(tenant_parts) == 2 and tenant_parts[1] == "starter-rules" and method == "GET":
        if not has_scope(auth, "tenant:read"):
            return scope_error("tenant:read")
        return handle_get_starter_rules(tenant_parts[0], auth)
    if len(tenant_parts) == 2 and tenant_parts[1] == "starter-rules" and method == "PUT":
        if not has_scope(auth, "tenant:write"):
            return scope_error("tenant:write")
        return handle_put_starter_rules(tenant_parts[0], body, auth)
    if len(tenant_parts) == 3 and tenant_parts[1] == "starter-rules" and tenant_parts[2] == "simulate" and method == "POST":
        if not has_scope(auth, "policy:simulate"):
            return scope_error("policy:simulate")
        return handle_simulate_starter_rule(tenant_parts[0], body, auth)
    if len(tenant_parts) == 2 and tenant_parts[1] == "environments" and method == "GET":
        if not has_scope(auth, "tenant:read"):
            return scope_error("tenant:read")
        return handle_list_environments(tenant_parts[0], auth)
    if len(tenant_parts) == 3 and tenant_parts[1] == "environments" and method == "PUT":
        if not has_scope(auth, "tenant:write"):
            return scope_error("tenant:write")
        return handle_put_environment(tenant_parts[0], tenant_parts[2], body, auth)
    if len(tenant_parts) == 3 and tenant_parts[1] == "retention" and tenant_parts[2] == "run" and method == "POST":
        if not has_scope(auth, "tenant:retention"):
            return scope_error("tenant:retention")
        return handle_retention_run(tenant_parts[0], body, auth)
    return None


def _route_policy_subresource(policy_path: str, method: str, body: dict[str, Any], event: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any] | None:
    """Route /v1/policies/{id}/... sub-resources. Returns None if no match (#251)."""
    if method == "PUT":
        if not has_scope(auth, "policy:write"):
            return scope_error("policy:write")
        return handle_update_policy(policy_path.strip("/"), body, auth)
    if method == "DELETE":
        if not has_scope(auth, "policy:write"):
            return scope_error("policy:write")
        return handle_delete_policy(policy_path.strip("/"), body, auth)
    if policy_path.endswith("/publish") and method == "POST":
        if not has_scope(auth, "policy:write"):
            return scope_error("policy:write")
        return handle_publish_policy(policy_path.removesuffix("/publish").strip("/"), body, auth)
    if policy_path.endswith("/suspend") and method == "POST":
        if not has_scope(auth, "policy:write"):
            return scope_error("policy:write")
        return handle_suspend_policy(policy_path.removesuffix("/suspend").strip("/"), body, auth)
    if policy_path.endswith("/reactivate") and method == "POST":
        if not has_scope(auth, "policy:write"):
            return scope_error("policy:write")
        return handle_reactivate_policy(policy_path.removesuffix("/reactivate").strip("/"), body, auth)
    if policy_path.endswith("/test") and method == "POST":
        if not has_scope(auth, "policy:simulate"):
            return scope_error("policy:simulate")
        return handle_test_policy(policy_path.removesuffix("/test").strip("/"), body, auth)
    if policy_path.endswith("/simulate") and method == "POST":
        if not has_scope(auth, "policy:simulate"):
            return scope_error("policy:simulate")
        return handle_simulate_policy(policy_path.removesuffix("/simulate").strip("/"), body, auth)
    if method == "GET":
        if not has_scope(auth, "policy:read"):
            return scope_error("policy:read")
        return handle_get_policy(policy_path, event, auth)
    return None


def _route_agent_subresource(agent_path: str, method: str, body: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any] | None:
    """Route /v1/agents/{id}/... sub-resources. Returns None if no match (#251)."""
    agent_parts = [part for part in agent_path.split("/") if part]
    if len(agent_parts) == 2 and agent_parts[1] == "impact-assessments":
        agent_id = agent_parts[0]
        if method == "POST":
            if not has_scope(auth, "identity:write"):
                return scope_error("identity:write")
            return handle_create_impact_assessment(agent_id, body, auth)
        if method == "GET":
            if not has_scope(auth, "identity:read"):
                return scope_error("identity:read")
            return handle_list_impact_assessments(agent_id, auth)
    if len(agent_parts) >= 2 and agent_parts[1] == "credentials":
        agent_id = agent_parts[0]
        if len(agent_parts) == 2 and method == "POST":
            if not has_scope(auth, "identity:write"):
                return scope_error("identity:write")
            return handle_issue_agent_credential(agent_id, body, auth)
        if len(agent_parts) == 2 and method == "GET":
            if not has_scope(auth, "identity:read"):
                return scope_error("identity:read")
            return handle_list_agent_credentials(agent_id, auth)
        if len(agent_parts) == 3 and method == "GET":
            if not has_scope(auth, "identity:read"):
                return scope_error("identity:read")
            return handle_get_agent_credential(agent_id, agent_parts[2], auth)
        if len(agent_parts) == 4 and agent_parts[3] == "revoke" and method == "POST":
            if not has_scope(auth, "identity:write"):
                return scope_error("identity:write")
            return handle_revoke_agent_credential(agent_id, agent_parts[2], auth)
    if agent_path.endswith("/revoke") and method == "POST":
        if not has_scope(auth, "identity:write"):
            return scope_error("identity:write")
        agent_id = agent_path.removesuffix("/revoke").strip("/")
        return handle_revoke_agent(agent_id, auth)
    if len(agent_parts) == 1 and method == "PUT":
        if not has_scope(auth, "identity:write"):
            return scope_error("identity:write")
        return handle_update_agent(agent_parts[0], body, auth)
    if method == "GET":
        if not has_scope(auth, "identity:read"):
            return scope_error("identity:read")
        return handle_get_agent(agent_path, auth)
    return None


# Declarative route table for exact-match authenticated endpoints (#251).
#
# Each entry is (path, method, required_scope_or_None, handler, args) where
# args is one of "auth", "body_auth", or "event_auth" and selects how the
# handler is invoked. Routes with bespoke logic (action evaluation, prefix
# subresource routers, the invitation-accept pre-membership path) stay inline
# in lambda_handler. Matching is first-match-wins on exact (path, method).
ROUTE_TABLE: tuple[tuple[str, str, str | None, str, str], ...] = (
    ("/v1/tokens", "GET", "token:admin", "handle_list_tokens", "event_auth"),
    ("/v1/tokens", "POST", "token:admin", "handle_create_token", "body_auth"),
    ("/v1/invitations/redeem", "POST", None, "handle_redeem_invitation", "body_event_auth"),
    ("/v1/tenants", "GET", "tenant:read", "handle_list_tenants", "event_auth"),
    ("/v1/audit", "GET", "audit:read", "handle_audit", "event_auth"),
    ("/v1/consents", "GET", "audit:read", "handle_list_consents", "event_auth"),
    ("/v1/consents", "POST", "audit:write", "handle_create_consent", "body_auth"),
    ("/v1/compliance/evidence", "GET", "audit:read", "handle_compliance_evidence", "event_auth"),
    ("/v1/security/events", "GET", "audit:read", "handle_security_events", "event_auth"),
    ("/v1/audit/events", "POST", "audit:write", "handle_ingest_audit_event", "event_body_auth"),
    ("/v1/audit/export", "GET", "audit:read", "handle_audit_export", "event_auth"),
    ("/v1/metrics", "GET", "audit:read", "handle_metrics", "event_auth"),
    ("/v1/management-reviews", "GET", "audit:read", "handle_list_management_reviews", "event_auth"),
    ("/v1/management-reviews", "POST", "audit:write", "handle_create_management_review", "body_auth"),
    ("/v1/nonconformities", "GET", "audit:read", "handle_list_nonconformities", "event_auth"),
    ("/v1/nonconformities", "POST", "audit:write", "handle_create_nonconformity", "body_auth"),
    ("/v1/concerns", "POST", "audit:write", "handle_report_concern", "body_auth"),
    ("/v1/policies", "GET", "policy:read", "handle_list_policies", "auth"),
    ("/v1/policies", "POST", "policy:write", "handle_create_policy", "body_auth"),
    ("/v1/compliance/coverage", "GET", "policy:read", "handle_get_compliance_coverage", "auth"),
    ("/v1/citations/verify", "POST", "citation:verify", "handle_citation_verify", "body_auth"),
    ("/v1/citation-reports/extract", "POST", "citation:verify", "handle_citation_report_extract", "body_auth"),
    ("/v1/agents", "POST", "identity:write", "handle_register_agent", "body_auth"),
    ("/v1/agents", "GET", "identity:read", "handle_list_agents", "auth"),
    ("/v1/models", "POST", "model:write", "handle_register_model", "body_auth"),
    ("/v1/models", "GET", "model:read", "handle_list_models", "auth"),
    ("/v1/suppliers", "POST", "model:write", "handle_register_supplier", "body_auth"),
    ("/v1/suppliers", "GET", "model:read", "handle_list_suppliers", "auth"),
    ("/v1/proofs", "POST", "proof:write", "handle_create_proof", "body_auth"),
    ("/v1/receipts/public-key", "GET", "proof:read", "handle_receipt_public_key", "auth"),
    ("/v1/approvals", "GET", "approve:actions", "handle_list_approvals", "event_auth"),
    ("/v1/grants", "GET", "approve:actions", "handle_list_grants", "event_auth"),
)


def _dispatch_route_table(
    path: str,
    method: str,
    event: dict[str, Any],
    body: dict[str, Any],
    auth: dict[str, Any],
) -> dict[str, Any] | None:
    """Return a response for the first exact-match route, or None to fall through."""

    for route_path, route_method, required_scope, handler_name, args in ROUTE_TABLE:
        if route_path != path or route_method != method:
            continue
        if required_scope and not has_scope(auth, required_scope):
            return scope_error(required_scope)
        handler = globals()[handler_name]
        if args == "auth":
            return handler(auth)
        if args == "body_auth":
            return handler(body, auth)
        if args == "event_auth":
            return handler(event, auth)
        if args == "body_event_auth":
            return handler(body, event, auth)
        if args == "event_body_auth":
            return handler(event, body, auth)
        raise ValueError(f"unknown route arg style: {args}")
    return None


def _dispatch_control_plane_request(
    path: str,
    method: str,
    event: dict[str, Any],
    body: dict[str, Any],
    auth: dict[str, Any],
) -> dict[str, Any] | None:
    """Dispatch authenticated session and control-plane routes."""
    if path == "/auth/session" and method == "POST":
        return handle_create_session(event, auth)
    if path == "/auth/passkeys" and method == "GET":
        return handle_auth_passkeys(event, auth)
    if path == "/auth/csrf" and method == "GET":
        return handle_csrf(auth)
    if path == "/auth/logout" and method == "POST":
        return handle_logout(auth)
    if path == "/v1/me" and method == "GET":
        return handle_me(auth)
    if path == "/v1/platform/access-grants" and method == "POST":
        return handle_platform_access_grant(body, auth)
    if path == "/v1/platform/access-grants" and method == "GET":
        return handle_list_platform_access_grants(event, auth)
    if path.startswith("/v1/platform/access-grants/") and path.endswith("/revoke") and method == "POST":
        grant_id = path.removeprefix("/v1/platform/access-grants/").removesuffix("/revoke").strip("/")
        return handle_revoke_platform_access_grant(grant_id, body, auth)
    if path == "/v1/platform/support/read" and method == "POST":
        return handle_platform_support_read(body, auth)
    if path == "/v1/invitations/accept" and method == "POST":
        # Membership-independent: this is how a recipient with no membership
        # yet activates the membership an invitation grants them, so it must
        # run before apply_control_plane_membership (which rejects members
        # with no active membership).
        return handle_accept_invitation(body, auth)
    return None


def _dispatch_api_request(
    path: str,
    method: str,
    event: dict[str, Any],
    body: dict[str, Any],
    auth: dict[str, Any],
) -> dict[str, Any]:
    """Dispatch product, resource, MCP, and approval API routes."""
    required_product = product_for_api_path(path)
    if required_product:
        product_error = product_access_error(required_product, auth)
        if product_error:
            return product_error
    if path == "/v1/actions/evaluate" and method == "POST":
        if not has_scope(auth, "guard:evaluate"):
            return scope_error("guard:evaluate")
        try:
            return handle_evaluate(event, body, auth)
        except (ValueError, PermissionError, ApiError):
            raise
        except Exception as exc:
            return guard_unavailable_response(body, auth, exc, event)
    table_result = _dispatch_route_table(path, method, event, body, auth)
    if table_result is not None:
        return table_result
    if path.startswith("/v1/tokens/") and path.endswith("/revoke") and method == "POST":
        if not has_scope(auth, "token:admin"):
            return scope_error("token:admin")
        token_id = path.removeprefix("/v1/tokens/").removesuffix("/revoke").strip("/")
        return handle_revoke_token(token_id, body, auth)
    if path.startswith("/v1/consents/") and path.endswith("/revoke") and method == "POST":
        if not has_scope(auth, "audit:write"):
            return scope_error("audit:write")
        consent_id = path.removeprefix("/v1/consents/").removesuffix("/revoke").strip("/")
        return handle_revoke_consent(consent_id, body, auth)
    if path.startswith("/v1/tenants/"):
        tenant_result = _route_tenant_subresource(path.removeprefix("/v1/tenants/"), method, body, event, auth)
        if tenant_result is not None:
            return tenant_result
    if path.startswith("/v1/policies/"):
        policy_result = _route_policy_subresource(path.removeprefix("/v1/policies/"), method, body, event, auth)
        if policy_result is not None:
            return policy_result
    if path.startswith("/v1/nonconformities/") and path.endswith("/resolve") and method == "POST":
        if not has_scope(auth, "audit:write"):
            return scope_error("audit:write")
        nc_id = path.removeprefix("/v1/nonconformities/").removesuffix("/resolve").strip("/")
        if not nc_id:
            return response(404, {"error": "nonconformity_not_found"})
        return handle_resolve_nonconformity(nc_id, body, auth)
    if path.startswith("/v1/models/"):
        model_path = path.removeprefix("/v1/models/").strip("/")
        model_parts = [part for part in model_path.split("/") if part]
        if len(model_parts) == 2 and model_parts[1] == "data-resources":
            if method == "POST":
                if not has_scope(auth, "model:write"):
                    return scope_error("model:write")
                return handle_register_data_resource(model_parts[0], body, auth)
            if method == "GET":
                if not has_scope(auth, "model:read"):
                    return scope_error("model:read")
                return handle_list_data_resources(model_parts[0], auth)
        if len(model_parts) == 1 and method == "PUT":
            if not has_scope(auth, "model:write"):
                return scope_error("model:write")
            return handle_update_model(model_parts[0], body, auth)
    if path.startswith("/v1/agents/"):
        agent_result = _route_agent_subresource(path.removeprefix("/v1/agents/"), method, body, auth)
        if agent_result is not None:
            return agent_result
    if path.startswith("/v1/proofs/") and method == "GET":
        proof_path = path.removeprefix("/v1/proofs/")
        if proof_path.endswith("/verify"):
            proof_id = proof_path.removesuffix("/verify").strip("/")
            if not proof_id:
                return response(404, {"error": "proof_not_found"})
            if not has_scope(auth, "proof:read"):
                return scope_error("proof:read")
            return handle_verify_proof(proof_id, auth)
        if proof_path.endswith("/report"):
            proof_id = proof_path.removesuffix("/report").strip("/")
            if not proof_id:
                return response(404, {"error": "proof_not_found"})
            if not has_scope(auth, "proof:read"):
                return scope_error("proof:read")
            return handle_get_proof(proof_id, auth, report=True)
        if not has_scope(auth, "proof:read"):
            return scope_error("proof:read")
        return handle_get_proof(proof_path, auth)
    if path in MCP_PATH_PROFILES and method in {"GET", "POST"}:
        if not has_scope(auth, "mcp:read"):
            return scope_error("mcp:read")
        return handle_mcp(event, body, method, auth, mcp_profile_for_path(path))
    if path.startswith("/v1/grants/") and path.endswith("/revoke") and method == "POST":
        if not has_scope(auth, "approve:actions"):
            return scope_error("approve:actions")
        grant_id = path.split("/")[3]
        return handle_revoke_grant(event, body, grant_id, auth)
    if path.startswith("/v1/approvals/") and method == "GET":
        if not has_scope(auth, "approve:actions"):
            return scope_error("approve:actions")
        approval_id = path.removeprefix("/v1/approvals/").strip("/")
        return handle_get_approval(approval_id, auth)
    if path.startswith("/v1/approvals/") and path.endswith("/revoke") and method == "POST":
        if not has_scope(auth, "approve:actions"):
            return scope_error("approve:actions")
        approval_id = path.split("/")[3]
        return handle_revoke_approval(event, body, approval_id, auth)
    if path.startswith("/v1/approvals/") and path.endswith("/decision") and method == "POST":
        if not has_scope(auth, "approve:actions"):
            return scope_error("approve:actions")
        approval_id = path.split("/")[3]
        return handle_approval(event, body, approval_id, auth)
    if path.startswith("/v1/actions/") and path.endswith("/outcome") and method == "POST":
        if not has_scope(auth, "actions:write"):
            return scope_error("actions:write")
        action_id = path.split("/")[3]
        return handle_outcome(event, body, action_id, auth)
    return response(404, {"error": "not_found", "path": path})


def _dispatch_authenticated_request(
    path: str,
    method: str,
    event: dict[str, Any],
    body: dict[str, Any],
    auth: dict[str, Any],
) -> dict[str, Any]:
    """Apply authenticated request policy, then dispatch the API route."""
    validate_session_csrf(event, auth, method)
    control_plane_result = _dispatch_control_plane_request(path, method, event, body, auth)
    if control_plane_result is not None:
        return control_plane_result
    if is_session_auth(auth):
        apply_control_plane_membership(event, body, auth)
    return _dispatch_api_request(path, method, event, body, auth)


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    path, method = path_and_method(event)
    if method == "OPTIONS":
        return {"statusCode": 204, "headers": {}, "body": ""}
    if path == "/health" and method == "GET":
        return response(
            200,
            {
                "status": "ok",
                "service": "kenning-agent-guard",
                "environment": ENVIRONMENT,
                "release_id": RELEASE_ID,
                "source_commit": RELEASE_SOURCE_COMMIT,
                "release_name": RELEASE_NAME,
                "release_version": RELEASE_VERSION,
            },
        )
    if path == "/auth/config" and method == "GET":
        return handle_auth_config()
    if path == "/auth/login" and method == "GET":
        try:
            return handle_auth_login(event)
        except ValueError as exc:
            return response(400, {"error": "invalid_auth_configuration", "message": str(exc)})
    if path == "/auth/reauth" and method == "GET":
        try:
            return handle_auth_login(event, force_reauth=True)
        except ValueError as exc:
            return response(400, {"error": "invalid_auth_configuration", "message": str(exc)})
    if path == "/auth/logout" and method == "GET":
        try:
            return handle_auth_logout_redirect()
        except ValueError as exc:
            return response(400, {"error": "invalid_auth_configuration", "message": str(exc)})
    if path == "/auth/callback" and method == "GET":
        return handle_auth_callback(event)
    if path == "/auth/passkeys/callback" and method == "GET":
        return handle_auth_passkeys_callback(event)

    try:
        body = parse_body(event) if method in {"POST", "PUT", "PATCH", "DELETE"} else {}
        if path == "/auth/confirm" and method == "POST":
            return handle_auth_confirm(body)
        if path == "/auth/confirm/resend" and method == "POST":
            return handle_auth_confirm_resend(body)
        auth, authentication_failure = authenticate(event, body)
        if authentication_failure:
            return authentication_failure
        return _dispatch_authenticated_request(path, method, event, body, auth)
    except json.JSONDecodeError:
        return response(400, {"error": "invalid_json"})
    except ApiError as exc:
        return response(exc.status, {"error": exc.code, "message": exc.message})
    except ValueError as exc:
        return response(400, {"error": "invalid_request", "message": str(exc)})
    except PermissionError as exc:
        # Legacy fallback — new code should raise ApiError instead (#252).
        return response(403, {"error": "forbidden", "message": str(exc)})
    except Exception as exc:
        print(f"request failed: {type(exc).__name__}: {exc}")
        return response(500, {"error": "internal_error", "message": "The request could not be evaluated or recorded."})
