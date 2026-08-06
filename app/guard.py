"""Core Agent Guard policy evaluation.

This module is intentionally dependency-free so the rules can be tested locally
and reused by the Lambda HTTP and MCP adapters.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shlex
import base64
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

try:
    import boto3
except ModuleNotFoundError:  # Keep the core and unit tests dependency-free.
    boto3 = None

try:
    from aws_adapter import aws_operation, is_mutating_operation, normalise_aws_action
    from integration_adapters import normalise_integration_action  # pragma: no cover
except ModuleNotFoundError:  # Local package import during tests.
    from .aws_adapter import aws_operation, is_mutating_operation, normalise_aws_action
    from .integration_adapters import normalise_integration_action


DECISIONS = {"allow", "observe", "warn", "require_approval", "rewrite", "deny"}
DECISION_RANK = {"allow": 0, "warn": 1, "rewrite": 2, "require_approval": 3, "deny": 4}
CLASSIFICATION_LEVELS = (
    "unclassified",
    "in_confidence",
    "sensitive",
    "restricted",
    "confidential",
    "secret",
)
CLASSIFICATION_RANK = {level: rank for rank, level in enumerate(CLASSIFICATION_LEVELS)}
KMS_RAW_MESSAGE_LIMIT = 4096
SHELL_DATABASE_CLIENTS = {
    "clickhouse-client",
    "duckdb",
    "isql",
    "mariadb",
    "mysql",
    "pgcli",
    "psql",
    "sqlcmd",
    "sqlite",
    "sqlite3",
    "sqlplus",
}


def _canonical_default(value: Any) -> Any:
    if isinstance(value, Decimal):
        return int(value) if value % 1 == 0 else float(value)
    raise TypeError(f"Cannot serialise {type(value).__name__}")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]"
            if re.search(r"(password|secret|token|api[_-]?key|credential|private[_-]?key)", str(key), re.I)
            else _redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, str) and len(value) > 4096:
        return value[:4096] + "...[TRUNCATED]"
    return value


def _normalise_shell_context(parameters: dict[str, Any]) -> dict[str, Any]:
    """Extract inspectable shell execution context without exposing secrets."""

    context: dict[str, Any] = {}
    arguments = parameters.get("arguments")
    if arguments is None:
        arguments = parameters.get("args")
    if arguments is not None:
        context["arguments"] = _redact(arguments)

    working_directory = parameters.get("working_directory")
    if working_directory is None:
        working_directory = parameters.get("cwd")
    if working_directory is None:
        working_directory = parameters.get("workdir")
    if working_directory is not None:
        context["working_directory"] = _redact(working_directory)

    environment_variables = parameters.get("environment_variables")
    if environment_variables is None:
        environment_variables = parameters.get("env_vars")
    if environment_variables is None:
        environment_variables = parameters.get("env")
    if environment_variables is not None:
        context["environment_variables"] = _redact(environment_variables)

    execution_context = parameters.get("execution_context")
    if execution_context is None:
        execution_context = parameters.get("execution")
    if execution_context is not None:
        context["execution_context"] = _redact(execution_context)
    return context


def _shell_database_command(command: str) -> bool:
    """Return whether a shell command invokes a recognised database client."""

    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>")
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return False

    for token in tokens:
        executable = token.rsplit("/", 1)[-1].lower()
        if executable not in SHELL_DATABASE_CLIENTS:
            continue
        return True
    return False


def normalise_classification(value: Any) -> str:
    """Return the bounded action sensitivity label used by Guard policies."""

    classification = str(value or "unclassified").strip().lower()
    if classification not in CLASSIFICATION_RANK:
        allowed = ", ".join(CLASSIFICATION_LEVELS)
        raise ValueError(f"classification must be one of: {allowed}.")
    return classification


def normalise_action(payload: dict[str, Any]) -> dict[str, Any]:
    raw = payload.get("action") if isinstance(payload.get("action"), dict) else payload
    context = payload.get("context") if isinstance(payload.get("context"), dict) else {}
    parameters = raw.get("parameters") if isinstance(raw.get("parameters"), dict) else {}

    tool = str(raw.get("tool") or raw.get("type") or "").strip().lower()
    operation = str(raw.get("operation") or raw.get("action_type") or raw.get("verb") or "execute").strip().lower()
    target = raw.get("target")
    if target is None:
        target = parameters.get("path") or parameters.get("resource") or parameters.get("database")
    provider = context.get("provider") or raw.get("provider") or payload.get("provider") or parameters.get("provider")

    action = {
        "tenant_id": str(context.get("tenant_id") or payload.get("tenant_id") or "demo"),
        "environment": str(context.get("environment") or payload.get("environment") or "development"),
        "run_id": str(context.get("run_id") or payload.get("run_id") or f"run-{hashlib.sha256(utc_now().encode()).hexdigest()[:12]}"),
        # Correlation IDs must remain unique when several requests arrive in
        # the same second. A timestamp-derived ID caused legitimate local and
        # low-latency API requests to collide and be rejected as action reuse.
        "action_id": str(context.get("action_id") or payload.get("action_id") or f"action-{uuid.uuid4().hex[:12]}"),
        "agent_id": str(context.get("agent_id") or payload.get("agent_id") or "unregistered-agent"),
        "invoked_by": str(context.get("invoked_by") or payload.get("invoked_by") or "unknown-user"),
        "tool": tool,
        "operation": operation,
        "classification": normalise_classification(raw.get("classification")),
        "target": _redact(target),
        "parameters": _redact(parameters),
        "intent": str(payload.get("intent") or raw.get("intent") or ""),
        "original_action": _redact(raw),
        "requested_at": str(payload.get("requested_at") or utc_now()),
    }
    for field in ("purpose", "data_scope"):
        value = raw.get(field)
        if value in (None, ""):
            value = payload.get(field)
        if value in (None, ""):
            value = parameters.get(field)
        if value not in (None, ""):
            text = str(value).strip()
            if text:
                action[field] = text
    if provider not in (None, ""):
        action["provider"] = str(provider).strip().lower()
    if tool in {"shell", "command", "terminal"}:
        shell_context = _normalise_shell_context(parameters)
        if shell_context:
            action["shell_context"] = shell_context
    return normalise_integration_action(normalise_aws_action(action))


def action_hash(action: dict[str, Any]) -> str:
    """Hash the semantic action while excluding generated correlation metadata.

    Run IDs, action IDs, and request timestamps identify an invocation but do
    not change what the tool call would do. Keeping them out of this hash makes
    retries and policy simulation deterministic without weakening approval
    binding: approvals still carry and validate the exact action ID and tenant.
    """

    hashable = {
        key: value
        for key, value in action.items()
        if key not in {"run_id", "action_id", "requested_at"} and not key.startswith("_")
    }
    canonical = json.dumps(hashable, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=_canonical_default)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_receipt(
    action: dict[str, Any],
    guard_decision: str,
    approval: dict[str, Any] | None = None,
    result: str = "not_executed",
    proof_record: str | None = None,
    signing_secret: str | None = None,
) -> dict[str, Any]:
    receipt = {
        "receipt_id": f"receipt-{hashlib.sha256((action['action_id'] + utc_now()).encode()).hexdigest()[:16]}",
        "action": f"{action['tool']}:{action['operation']}",
        "agent_identity": action["agent_id"],
        "invoked_by": action["invoked_by"],
        "authorised": guard_decision in {"allow", "warn"},
        "guard_decision": guard_decision,
        "approval": approval,
        "evidence_verified": None,
        "proof_record": proof_record or f"proof://{action['run_id']}/{action['action_id']}",
        "result": result,
        "action_hash": action_hash(action),
        "created_at": utc_now(),
    }
    return _seal_receipt(receipt, signing_secret=signing_secret)


def refresh_receipt(
    receipt: dict[str, Any],
    *,
    signing_secret: str | None = None,
    **updates: Any,
) -> dict[str, Any]:
    """Update a receipt and reseal its integrity hash."""

    refreshed = dict(receipt)
    refreshed.update(updates)
    return _seal_receipt(refreshed, signing_secret=signing_secret)


def _receipt_signing_secret(signing_secret: str | None) -> str:
    if signing_secret is not None:
        return str(signing_secret)
    return str(os.environ.get("RECEIPT_SIGNING_SECRET") or "")


def _receipt_unsigned(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in receipt.items()
        if key not in {"integrity", "signature"}
    }


def _receipt_signature(receipt: dict[str, Any], secret: str) -> str:
    canonical = _receipt_canonical_bytes(receipt)
    digest = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


_kms_client_instance: Any = None


def _receipt_canonical_bytes(receipt: dict[str, Any]) -> bytes:
    return json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=_canonical_default).encode("utf-8")


def _receipt_signing_mode() -> str:
    return str(os.environ.get("RECEIPT_SIGNING_MODE") or "hmac").strip().lower()


def _receipt_kms_key_id() -> str:
    return str(os.environ.get("RECEIPT_KMS_KEY_ID") or "").strip()


def _receipt_kms_algorithm() -> str:
    return str(os.environ.get("RECEIPT_KMS_SIGNING_ALGORITHM") or "RSASSA_PSS_SHA_256").strip()


def _kms_client() -> Any:
    global _kms_client_instance
    if _kms_client_instance is None:
        if boto3 is None:
            raise RuntimeError("boto3 is required for KMS receipt signing.")
        _kms_client_instance = boto3.client("kms")
    return _kms_client_instance


def _kms_message_type(message: bytes) -> str:
    """Choose a KMS message mode that supports the complete receipt payload."""

    return "RAW" if len(message) <= KMS_RAW_MESSAGE_LIMIT else "DIGEST"


def _kms_message_payload(message: bytes, message_type: str) -> bytes:
    """Return the bytes KMS expects for the selected message mode."""

    if message_type == "RAW":
        return message
    if message_type == "DIGEST":
        return hashlib.sha256(message).digest()
    raise ValueError(f"Unsupported KMS message type: {message_type}")


def _kms_sign(message: bytes, key_id: str, algorithm: str, message_type: str = "RAW") -> bytes:
    message_type = str(message_type).upper()
    result = _kms_client().sign(
        KeyId=key_id,
        Message=_kms_message_payload(message, message_type),
        MessageType=message_type,
        SigningAlgorithm=algorithm,
    )
    return bytes(result["Signature"])


def _kms_verify(message: bytes, signature: bytes, key_id: str, algorithm: str, message_type: str = "RAW") -> bool:
    message_type = str(message_type).upper()
    result = _kms_client().verify(
        KeyId=key_id,
        Message=_kms_message_payload(message, message_type),
        MessageType=message_type,
        Signature=signature,
        SigningAlgorithm=algorithm,
    )
    return bool(result.get("SignatureValid"))


def receipt_public_key() -> dict[str, Any]:
    """Return the KMS public key needed for independent receipt verification."""

    key_id = _receipt_kms_key_id()
    if _receipt_signing_mode() != "kms" or not key_id:
        raise RuntimeError("KMS receipt signing is not configured.")
    result = _kms_client().get_public_key(KeyId=key_id)
    return {
        "key_id": key_id,
        "key_spec": str(result.get("KeySpec") or "RSA_2048"),
        "key_usage": str(result.get("KeyUsage") or "SIGN_VERIFY"),
        "signing_algorithm": _receipt_kms_algorithm(),
        "public_key_format": "DER SubjectPublicKeyInfo",
        "public_key_der_base64": base64.b64encode(bytes(result["PublicKey"])).decode("ascii"),
    }


def _seal_receipt(receipt: dict[str, Any], signing_secret: str | None = None) -> dict[str, Any]:
    sealed = dict(receipt)
    sealed.pop("integrity", None)
    sealed.pop("signature", None)
    sealed["integrity"] = {"algorithm": "sha256", "record_hash": action_hash(sealed)}
    if _receipt_signing_mode() == "kms" and _receipt_kms_key_id():
        message_type = _kms_message_type(_receipt_canonical_bytes(sealed))
        signature = _kms_sign(
            _receipt_canonical_bytes(sealed),
            _receipt_kms_key_id(),
            _receipt_kms_algorithm(),
            message_type,
        )
        sealed["signature"] = {
            "algorithm": "kms-rsassa-pss-sha256",
            "key_id": _receipt_kms_key_id(),
            "message_type": message_type,
            "value": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
        }
    else:
        secret = _receipt_signing_secret(signing_secret)
    if _receipt_signing_mode() != "kms" and secret:
        sealed["signature"] = {
            "algorithm": "hmac-sha256",
            "key_id": str(os.environ.get("RECEIPT_SIGNING_KEY_ID") or "prototype"),
            "value": _receipt_signature(sealed, secret),
        }
    return sealed


def verify_receipt(receipt: dict[str, Any] | None, signing_secret: str | None = None) -> dict[str, Any]:
    """Verify a receipt hash and, when configured, its service signature."""

    if not isinstance(receipt, dict):
        return {"valid": False, "reason": "receipt_missing"}
    integrity = receipt.get("integrity") if isinstance(receipt.get("integrity"), dict) else {}
    expected_hash = str(integrity.get("record_hash") or "")
    actual_hash = action_hash(_receipt_unsigned(receipt))
    hash_valid = hmac.compare_digest(expected_hash, actual_hash)
    signature = receipt.get("signature") if isinstance(receipt.get("signature"), dict) else None
    signature_valid: bool | None = None
    if signature:
        signature_algorithm = str(signature.get("algorithm") or "")
        try:
            if signature_algorithm == "kms-rsassa-pss-sha256":
                encoded = str(signature.get("value") or "")
                encoded += "=" * (-len(encoded) % 4)
                signature_valid = _kms_verify(
                    _receipt_canonical_bytes({key: value for key, value in receipt.items() if key != "signature"}),
                    base64.urlsafe_b64decode(encoded),
                    str(signature.get("key_id") or _receipt_kms_key_id()),
                    _receipt_kms_algorithm(),
                    str(signature.get("message_type") or "RAW").upper(),
                )
            else:
                secret = _receipt_signing_secret(signing_secret)
                if secret:
                    signature_valid = hmac.compare_digest(
                        str(signature.get("value") or ""),
                        _receipt_signature({key: value for key, value in receipt.items() if key != "signature"}, secret),
                    )
        except (RuntimeError, ValueError, TypeError):
            signature_valid = False
    return {
        "valid": hash_valid and signature_valid is not False,
        "hash_valid": hash_valid,
        "signature_present": bool(signature),
        "signature_valid": signature_valid,
        "signature_algorithm": (signature or {}).get("algorithm") if signature else None,
        "algorithm": str((integrity or {}).get("algorithm") or "unknown"),
        "record_hash": expected_hash,
        "receipt_id": receipt.get("receipt_id"),
    }


def _risk_reason(
    reasons: list[dict[str, Any]],
    code: str,
    message: str,
    decision: str,
) -> None:
    reasons.append(
        {
            "code": code,
            "rule_id": code,
            "message": message,
            "decision": decision,
        }
    )


def _apply_starter_rule_overrides(decision: dict[str, Any], starter_rules: list[dict[str, Any]]) -> dict[str, Any]:
    """Apply the tenant's editable settings to built-in detector matches."""

    try:
        from starter_rules import default_starter_rules, normalise_starter_rules
    except ModuleNotFoundError:
        from .starter_rules import default_starter_rules, normalise_starter_rules

    rules = normalise_starter_rules(starter_rules)
    try:
        from policy import rule_matches
    except ModuleNotFoundError:
        from .policy import rule_matches
    by_reason_code = {
        str(rule.get("reason_code") or "").upper(): rule
        for rule in rules
        if rule.get("kind") == "builtin"
    }
    default_decisions = {
        str(rule.get("reason_code") or "").upper(): str(rule.get("decision") or "")
        for rule in default_starter_rules()
    }
    kept_reasons: list[dict[str, Any]] = []
    for reason in decision.get("reasons") or []:
        code = str(reason.get("code") or "").upper()
        rule = by_reason_code.get(code)
        # An explicitly configured starter-rule list is authoritative: a
        # missing built-in rule means that tenant removed it.
        if rule is None or not rule.get("enabled"):
            continue
        if rule.get("conditions") and not rule_matches(rule, decision.get("action") or {}):
            continue
        reason = dict(reason)
        reason["rule_id"] = rule.get("rule_id") or code
        # Keep detector-specific defaults (for example, filesystem mutation
        # is a warning outside production) unless the administrator changed
        # the starter rule's decision explicitly.
        if str(rule.get("decision") or "") != default_decisions.get(code):
            reason["decision"] = rule.get("decision") or reason.get("decision")
        if rule.get("reason"):
            reason["message"] = rule["reason"]
        kept_reasons.append(reason)

    decision["reasons"] = kept_reasons
    decision["reason_codes"] = [str(reason.get("code")) for reason in kept_reasons]
    if "UNBOUNDED_UPDATE" not in decision["reason_codes"] and "AWS_PREVIEW_RECOMMENDED" not in decision["reason_codes"]:
        decision.pop("recommended_action", None)
    if not kept_reasons:
        baseline = "allow"
    else:
        baseline = max((str(reason.get("decision") or "allow") for reason in kept_reasons), key=lambda item: DECISION_RANK[item])
    decision["would_decision"] = baseline if decision.get("mode") == "observe" and baseline != "allow" else None
    decision["decision"] = "observe" if decision.get("mode") == "observe" and baseline != "allow" else baseline
    decision["risk"] = "low" if baseline == "allow" else "medium" if baseline == "warn" else "high" if baseline in {"rewrite", "require_approval"} else "critical"
    decision["risk_score"] = {"allow": 5, "warn": 40, "rewrite": 65, "require_approval": 80, "deny": 100}[baseline]
    decision["starter_rule_matches"] = [
        {
            "rule_id": reason.get("rule_id"),
            "reason_code": reason.get("code"),
            "decision": reason.get("decision"),
        }
        for reason in kept_reasons
    ]
    return decision


def evaluate(
    action: dict[str, Any],
    mode: str = "enforce",
    starter_rules: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Evaluate a normalised action using explainable built-in MVP rules."""

    mode = str(mode or "enforce").lower()
    if mode not in {"observe", "enforce"}:
        mode = "enforce"

    reasons: list[dict[str, Any]] = []
    recommendation: dict[str, str] | None = None
    tool = action["tool"]
    operation = action["operation"]
    environment = action["environment"].lower()
    params = action["parameters"]
    target_text = json.dumps(action.get("target"), ensure_ascii=False).lower()
    parameter_text = json.dumps(params, ensure_ascii=False).lower()

    def add(code: str, message: str, decision: str) -> None:
        _risk_reason(reasons, code, message, decision)

    def add_high_impact_fallback() -> None:
        if re.search(r"\b(send|broadcast|bulk|transfer|pay|charge|deploy|delete|destroy)\b", f"{operation} {target_text} {parameter_text}"):
            add("HIGH_IMPACT_UNSUPPORTED_ACTION", "Action appears high impact but has no specialised adapter.", "require_approval")

    if not tool:
        add("MISSING_TOOL", "The proposed action does not identify a tool.", "deny")
    elif tool in {"shell", "command", "terminal"}:
        command = str(params.get("command") or params.get("cmd") or params.get("executable") or action.get("target") or "")
        arguments = params.get("arguments")
        if arguments is None:
            arguments = params.get("args")
        if isinstance(arguments, list):
            command = " ".join([command, *[str(argument) for argument in arguments]]).strip()
        elif arguments not in (None, ""):
            command = " ".join([command, str(arguments)]).strip()
        lower = command.lower()
        if not command.strip():
            add("UNPARSEABLE_SHELL_ACTION", "Shell action does not provide a command that Guard can inspect.", "require_approval")
        tokens = re.findall(r"[a-z0-9_./-]+", lower)
        if re.search(r"(^|\s)rm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r)", lower) and re.search(r"(^|\s)/($|\s)|(^|\s)~/?($|\s)", lower):
            add("CATASTROPHIC_FILESYSTEM_OPERATION", "Recursive force deletion targets a filesystem root or home directory.", "deny")
        elif any(token in {"rm", "rmdir", "unlink", "mkfs", "dd"} for token in tokens):
            add("DESTRUCTIVE_FILESYSTEM_OPERATION", "Command can delete or overwrite filesystem data.", "require_approval")
        if _shell_database_command(command):
            upper_statement = command.upper()
            has_where = bool(re.search(r"\bWHERE\b", upper_statement))
            if re.search(r"\b(DROP|TRUNCATE)\b", upper_statement):
                add("DESTRUCTIVE_DATABASE_OPERATION", "Statement can remove a database object or all rows.", "require_approval")
            if re.search(r"\b(DELETE|UPDATE)\b", upper_statement) and not has_where:
                add("UNBOUNDED_UPDATE", "DELETE or UPDATE statement has no WHERE clause.", "require_approval")
                recommendation = {
                    "type": "rewrite",
                    "suggestion": "Add a constrained WHERE clause and run a dry-run query first.",
                }
            if environment == "production" and re.search(r"\b(INSERT|UPDATE|DELETE|ALTER|DROP|TRUNCATE)\b", upper_statement):
                add("PRODUCTION_DATABASE_TARGET", "Statement modifies a production database.", "require_approval")
        if any(token in {"sudo", "su", "doas"} for token in tokens):
            add("PRIVILEGE_ESCALATION", "Command attempts to run with elevated privileges.", "require_approval")
        if re.search(r"(\.aws/credentials|\.ssh/id_|\.env|password|secret|api[_-]?key|access[_-]?key)", lower):
            add("CREDENTIAL_EXPOSURE", "Command references a likely credential or secret location.", "deny")
        shell_context = action.get("shell_context") if isinstance(action.get("shell_context"), dict) else {}
        working_directory = str(shell_context.get("working_directory") or "").lower()
        if re.search(r"(^|/)(etc|root|var/lib|usr/local/bin)(/|$)|(^|/)\.ssh(/|$)|(^|/)\.aws(/|$)", working_directory):
            add("SHELL_PROTECTED_WORKING_DIRECTORY", "Shell execution starts in a protected or likely-sensitive working directory.", "require_approval")
        environment_variables = shell_context.get("environment_variables")
        environment_keys = " ".join(str(key).lower() for key in environment_variables) if isinstance(environment_variables, dict) else ""
        if re.search(r"(password|secret|token|api[_-]?key|private[_-]?key|access[_-]?key)", environment_keys):
            add("CREDENTIAL_EXPOSURE", "Shell execution receives an environment variable that may contain a credential or secret.", "deny")
        execution_context = shell_context.get("execution_context") if isinstance(shell_context.get("execution_context"), dict) else {}
        run_as = str(execution_context.get("run_as") or execution_context.get("user") or "").lower()
        if execution_context.get("privileged") is True or run_as in {"root", "administrator", "system"}:
            add("PRIVILEGE_ESCALATION", "Shell execution requests a privileged user or execution context.", "require_approval")
        if re.search(r"\b(curl|wget)\b[^\n|;&]*\|\s*(sh|bash|zsh)\b", lower):
            add("REMOTE_SCRIPT_EXECUTION", "Command pipes an unverified remote response into a shell.", "require_approval")
        if any(operator in lower for operator in [";", "&&", "||", "|", ">", "2>"]):
            add("COMPOUND_SHELL_SCOPE", "Compound shell operators make the action scope harder to constrain.", "warn")
    elif tool in {"sql", "database"}:
        statement = str(params.get("statement") or params.get("query") or action.get("target") or "")
        upper = statement.upper()
        if not statement.strip():
            add("UNPARSEABLE_SQL_ACTION", "SQL action does not provide a statement that Guard can inspect.", "require_approval")
        has_where = bool(re.search(r"\bWHERE\b", upper))
        if re.search(r"\b(DROP|TRUNCATE)\b", upper):
            add("DESTRUCTIVE_DATABASE_OPERATION", "Statement can remove a database object or all rows.", "require_approval")
        if re.search(r"\b(DELETE|UPDATE)\b", upper) and not has_where:
            add("UNBOUNDED_UPDATE", "DELETE or UPDATE statement has no WHERE clause.", "require_approval")
            recommendation = {
                "type": "rewrite",
                "suggestion": "Add a constrained WHERE clause and run a dry-run query first.",
            }
        if environment == "production" and re.search(r"\b(INSERT|UPDATE|DELETE|ALTER|DROP|TRUNCATE)\b", upper):
            add("PRODUCTION_DATABASE_TARGET", "Statement modifies a production database.", "require_approval")
        if re.search(r"\bSELECT\s+\*\b", upper) and not re.search(r"\bLIMIT\b", upper):
            add("UNBOUNDED_READ", "SELECT * without a LIMIT may retrieve an unexpectedly broad result.", "warn")
        if re.search(r"(USER|CUSTOMER|PATIENT|EMPLOYEE|PAYMENT|CREDENTIAL)", upper) and re.search(r"\bSELECT\b", upper):
            add("SENSITIVE_DATA_RETRIEVAL", "Query may retrieve sensitive business or personal data.", "require_approval")
    elif tool in {"file", "filesystem"}:
        path = str(params.get("path") or action.get("target") or "")
        lower_path = path.lower()
        if not path.strip():
            add("UNPARSEABLE_FILESYSTEM_ACTION", "Filesystem action does not provide a path that Guard can inspect.", "require_approval")
        if operation in {"delete", "remove", "unlink", "modify", "write", "overwrite"}:
            add("FILESYSTEM_MUTATION", "Action changes or deletes a filesystem object.", "require_approval" if environment == "production" else "warn")
        if params.get("recursive") or params.get("force"):
            add("BROAD_FILESYSTEM_SCOPE", "Recursive or forced file operation can affect more data than intended.", "require_approval")
        if re.search(r"(^|/)(etc|var|usr|root|home)(/|$)|\.ssh|\.aws|\.env", lower_path):
            add("PROTECTED_FILESYSTEM_TARGET", "Path is in a protected or likely-sensitive filesystem location.", "require_approval")
    elif action.get("adapter") == "aws":
        operation_name = aws_operation(action)
        adapter_context = action.get("adapter_context") if isinstance(action.get("adapter_context"), dict) else {}
        if not operation_name:
            add("UNPARSEABLE_AWS_ACTION", "The AWS action is missing a service or API operation.", "require_approval")
        else:
            if operation_name in {
                "cloudformation:deletestack",
                "dynamodb:deletetable",
                "ec2:terminateinstances",
                "eks:deletecluster",
                "lambda:deletefunction",
                "rds:deletedbcluster",
                "rds:deletedbinstance",
                "s3:deletebucket",
            }:
                add("AWS_DESTRUCTIVE_OPERATION", f"AWS operation {operation_name} can delete infrastructure or data.", "require_approval")
            if operation_name.startswith(("iam:", "kms:", "secretsmanager:")):
                add("AWS_PRIVILEGED_OPERATION", f"AWS operation {operation_name} changes privileged access or secrets.", "require_approval")
            if environment == "production" and is_mutating_operation(action):
                add("AWS_PRODUCTION_MUTATION", "A mutating AWS operation targets the production environment.", "require_approval")
            if is_mutating_operation(action) and not params.get("dry_run") and not params.get("preview"):
                add("AWS_PREVIEW_RECOMMENDED", "A dry-run or provider preview should be completed before this AWS mutation.", "require_approval" if environment == "production" else "warn")
                recommendation = {
                    "type": "dry_run",
                    "suggestion": "Run the provider's dry-run or preview operation first and attach its result.",
                }
            if adapter_context.get("requested_scope") is None and is_mutating_operation(action):
                add("AWS_SCOPE_NOT_DECLARED", "The AWS action does not declare its requested resource scope.", "require_approval")
    elif action.get("adapter") == "github":
        adapter_context = action.get("adapter_context") if isinstance(action.get("adapter_context"), dict) else {}
        operation_name = str(adapter_context.get("operation") or operation).lower()
        if operation_name in {"delete_repository", "delete_branch", "delete_release", "force_push", "remove_collaborator"}:
            add("GITHUB_DESTRUCTIVE_OPERATION", f"GitHub operation {operation_name} can remove or overwrite repository state.", "require_approval")
        if operation_name in {"change_branch_protection", "change_repository_visibility", "modify_permissions"}:
            add("GITHUB_PRIVILEGED_OPERATION", f"GitHub operation {operation_name} changes repository access or protection.", "require_approval")
        branch = str(adapter_context.get("branch") or "").lower()
        if operation_name in {"merge_pull_request", "push", "create_release"} and branch in {"main", "master", "production"}:
            add("GITHUB_PROTECTED_BRANCH_CHANGE", "GitHub action targets a protected or production branch.", "require_approval")
        if not adapter_context.get("repository"):
            add("GITHUB_SCOPE_NOT_DECLARED", "The GitHub action does not declare a repository scope.", "require_approval")
        add_high_impact_fallback()
    elif action.get("adapter") == "email":
        adapter_context = action.get("adapter_context") if isinstance(action.get("adapter_context"), dict) else {}
        operation_name = str(adapter_context.get("operation") or operation).lower()
        recipients_count = int(adapter_context.get("recipients_count") or 0)
        if not recipients_count:
            add("EMAIL_RECIPIENTS_MISSING", "The outbound email action does not declare recipients.", "deny")
        if operation_name in {"bulk_send", "broadcast", "send_bulk"} or recipients_count > 10:
            add("BULK_OUTBOUND_MESSAGE", "The email action targets a broad recipient set.", "require_approval")
        if adapter_context.get("external_recipients") or environment == "production":
            add("OUTBOUND_MESSAGE", "Outbound email can communicate externally and requires review in this context.", "require_approval")
        if not adapter_context.get("requested_scope") and recipients_count:
            add("EMAIL_SCOPE_NOT_DECLARED", "The email action does not declare its recipient scope.", "require_approval")
        add_high_impact_fallback()
    elif tool in {"aws", "azure", "cloud"}:
        operation_text = f"{operation} {target_text} {parameter_text}"
        if operation == "execute" and action.get("target") in (None, "") and not params:
            add("UNPARSEABLE_CLOUD_ACTION", "Cloud action does not provide enough operation or resource context for Guard to inspect.", "require_approval")
        if re.search(r"\b(delete|destroy|terminate|remove)\b", operation_text):
            add("INFRASTRUCTURE_DELETION", "Cloud action can delete or terminate infrastructure.", "require_approval")
        if re.search(r"\b(iam|role|policy|security[_-]?group|key[_-]?vault|secret)\b", operation_text):
            add("PRIVILEGED_CLOUD_CHANGE", "Cloud action affects identity, access, network policy, or secrets.", "require_approval")
        if environment == "production" and re.search(r"\b(create|put|update|deploy|start|stop|scale)\b", operation_text):
            add("PRODUCTION_CLOUD_CHANGE", "Cloud action changes a production resource.", "require_approval")
    else:
        add_high_impact_fallback()

    # Financial operations deserve a stable, dedicated reason code even when
    # the caller uses a generic API, workflow, or payment tool. This lets
    # policies, approval queues, and audit searches distinguish money movement
    # from other high-impact actions without storing or exposing secret values.
    # For SQL tools with the default execute operation, use the statement's
    # leading verb so SELECT queries are not treated as financial mutations.
    intent_operation = operation
    if tool in {"sql", "database"} and operation == "execute":
        raw_sql = str(params.get("statement") or params.get("query") or "")
        leading = re.sub(r"\A(\s*(--[^\n]*\n|/\*.*?\*/)\s*)*", "", raw_sql, flags=re.DOTALL).lstrip().lower().split()
        if leading:
            intent_operation = leading[0]
    financial_action_text = re.sub(r"[_:/.-]+", " ", f"{intent_operation} {target_text} {tool} {parameter_text}").lower()
    financial_intent_text = re.sub(r"[_:/.-]+", " ", f"{intent_operation} {target_text} {tool}").lower()
    financial_noun = re.search(
        r"\b(payment|payout|invoice|bank|wire|refund|withdrawal|deposit|charge|purchase|transaction|supplier)\b",
        financial_action_text,
    )
    financial_context = financial_noun or tool in {"payment", "payments", "finance", "banking", "billing", "invoice"}
    financial_parameter = any(
        key in params for key in ("amount", "currency", "payment_id", "transaction_id", "bank_account", "beneficiary_account")
    )
    read_only_financial = re.search(r"\b(read|list|get|retrieve|view|inspect|check|query|select)\b", financial_intent_text)
    financial_mutation = re.search(
        r"\b(create|execute|pay|transfer|charge|refund|withdraw|deposit|purchase|submit|approve|payout|wire|debit|credit|send)\b",
        financial_action_text,
    )
    if (financial_context or financial_parameter) and (not read_only_financial or financial_mutation) and (financial_mutation or financial_parameter):
        add("FINANCIAL_TRANSACTION", "Action appears to create, transfer, charge, refund, or otherwise move money and requires approval.", "require_approval")

    reversible = params.get("reversible")
    if reversible is False or str(reversible).strip().lower() in {"false", "no"}:
        add("IRREVERSIBLE_ACTION", "The action is explicitly marked irreversible and requires review before execution.", "require_approval")

    requested_scope = params.get("requested_scope") or params.get("resources")
    scope_count = len(requested_scope) if isinstance(requested_scope, list) else (1 if requested_scope else 0)
    if scope_count > 10:
        add("BROAD_RESOURCE_SCOPE", f"The action declares {scope_count} resources, exceeding the review threshold of 10.", "require_approval")

    affected_count = params.get("affected_resource_count")
    if affected_count is None:
        affected_count = params.get("resource_count")
    if affected_count is None:
        affected_count = params.get("estimated_rows")
    try:
        affected_count_value = int(affected_count) if affected_count is not None else 0
    except (TypeError, ValueError):
        affected_count_value = 0
    if affected_count_value > 1000:
        add("LARGE_AFFECTED_RESOURCE_COUNT", f"The action may affect {affected_count_value} resources, exceeding the review threshold of 1000.", "require_approval")

    intent = str(action.get("intent") or "").lower()
    mutating_action = f"{operation} {target_text} {parameter_text}"
    if re.search(r"\b(read|view|inspect|check|list)\b", intent) and re.search(
        r"\b(update|insert|delete|drop|truncate|write|overwrite|remove|destroy|terminate|deploy|send|transfer|pay|charge|rm|rmdir|unlink|mkfs|dd)\b",
        mutating_action,
    ):
        add("INTENT_SCOPE_MISMATCH", "The proposed mutation appears broader than the read-only intent supplied by the caller.", "require_approval")

    if not reasons:
        baseline = "allow"
    else:
        baseline = max((reason["decision"] for reason in reasons), key=lambda item: DECISION_RANK[item])

    risk = "low"
    if baseline == "warn":
        risk = "medium"
    elif baseline in {"rewrite", "require_approval"}:
        risk = "high"
    elif baseline == "deny":
        risk = "critical"

    score = {"allow": 5, "warn": 40, "rewrite": 65, "require_approval": 80, "deny": 100}[baseline]
    effective = "observe" if mode == "observe" and baseline != "allow" else baseline
    response: dict[str, Any] = {
        "decision": effective,
        "would_decision": baseline if mode == "observe" else None,
        "mode": mode,
        "risk": risk,
        "risk_score": score,
        "action_classification": action["classification"],
        "reasons": reasons,
        "reason_codes": [reason["code"] for reason in reasons],
        "action": action,
        "action_hash": action_hash(action),
        "evaluated_at": utc_now(),
    }
    if recommendation:
        response["recommended_action"] = recommendation
    if starter_rules is not None:
        response = _apply_starter_rule_overrides(response, starter_rules)
    return response
