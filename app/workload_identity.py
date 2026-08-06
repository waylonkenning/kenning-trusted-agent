"""AWS IAM workload-identity validation and tenant-scoped principal mapping.

The Lambda handler only trusts IAM context supplied by an API Gateway or
Lambda Function URL route configured with AWS_IAM authorization. A bearer
header is not treated as evidence of an AWS principal. Tenant configuration
then maps the verified role ARN to one registered Kenning agent and a bounded
set of runtime scopes.
"""

from __future__ import annotations

import fnmatch
import re
from typing import Any

try:
    from federation import FEDERATED_SCOPE_NAMES  # pragma: no cover
    from identity import normalise_authority_level  # pragma: no cover
except ModuleNotFoundError:  # Local package import during tests.
    from .federation import FEDERATED_SCOPE_NAMES
    from .identity import normalise_authority_level


AWS_IAM_PROVIDER = "aws_iam"
MAX_ACCOUNT_IDS = 50
MAX_MAPPINGS = 100
MAX_GROUPS = 50
MAX_SCOPE_COUNT = 30
ACCOUNT_PATTERN = re.compile(r"^\d{12}$")
ROLE_ARN_PATTERN = re.compile(r"^arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):role/[A-Za-z0-9+=,.@_*/?\-]+$")
ASSUMED_ROLE_ARN_PATTERN = re.compile(r"^arn:(aws|aws-us-gov|aws-cn):sts::(\d{12}):assumed-role/([^/]+)/[^/]+$")
WORKLOAD_AGENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")

# Workload identities may receive application scopes, but never the product
# admin or token-administration powers that are reserved for human/platform
# credentials. Tenant administrators choose the remaining scopes per mapping.
WORKLOAD_SCOPE_NAMES = set(FEDERATED_SCOPE_NAMES)


def _string_list(value: Any, field: str, maximum: int) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        raise ValueError(f"{field} must be an array.")
    if len(value) > maximum:
        raise ValueError(f"{field} may contain at most {maximum} values.")
    result = [str(item).strip() for item in value if str(item).strip()]
    if len(result) != len(set(result)):
        raise ValueError(f"{field} must not contain duplicates.")
    return result


def _normalise_principal_pattern(value: Any, field: str) -> tuple[str, str]:
    pattern = str(value or "").strip()
    if not pattern or len(pattern) > 2048 or any(char.isspace() for char in pattern):
        raise ValueError(f"{field} must be a non-empty AWS IAM role ARN pattern.")
    if not ROLE_ARN_PATTERN.fullmatch(pattern):
        raise ValueError(f"{field} must be an AWS IAM role ARN, optionally containing * or ? in the role path.")
    account_id = pattern.split(":", 5)[4]
    return pattern, account_id


def _canonical_role_arn(value: Any) -> tuple[str, str]:
    """Return an IAM role ARN for IAM or assumed-role request context."""

    principal_arn = str(value or "").strip()
    if ROLE_ARN_PATTERN.fullmatch(principal_arn):
        return principal_arn, principal_arn.split(":", 5)[4]
    assumed = ASSUMED_ROLE_ARN_PATTERN.fullmatch(principal_arn)
    if assumed:
        partition, account_id, role_name = assumed.groups()
        return f"arn:{partition}:iam::{account_id}:role/{role_name}", account_id
    raise ValueError("The trusted AWS IAM principal must be an IAM role ARN or assumed-role session ARN.")


def _normalise_mapping(value: Any, index: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"workload_identity.mappings item {index + 1} must be an object.")
    principal = value.get("principal_arn") or value.get("principal_arn_pattern") or value.get("role_arn")
    pattern, account_id = _normalise_principal_pattern(principal, f"workload_identity.mappings[{index}].principal_arn")
    agent_id = str(value.get("agent_id") or "").strip()
    if not WORKLOAD_AGENT_ID_PATTERN.fullmatch(agent_id):
        raise ValueError(f"workload_identity.mappings[{index}].agent_id must be a valid agent identifier.")
    scopes = _string_list(value.get("scopes"), f"workload_identity.mappings[{index}].scopes", MAX_SCOPE_COUNT)
    unsupported = sorted(set(scopes) - WORKLOAD_SCOPE_NAMES)
    if unsupported:
        raise ValueError(
            f"workload_identity.mappings[{index}].scopes contains unsupported or privileged scopes: {', '.join(unsupported)}."
        )
    if not scopes:
        raise ValueError(f"workload_identity.mappings[{index}].scopes must contain at least one runtime scope.")
    groups = _string_list(value.get("groups", []), f"workload_identity.mappings[{index}].groups", MAX_GROUPS)
    if any(len(group) > 128 for group in groups):
        raise ValueError(f"workload_identity.mappings[{index}].groups values must be no longer than 128 characters.")
    return {
        "principal_arn": pattern,
        "account_id": account_id,
        "agent_id": agent_id,
        "scopes": sorted(set(scopes)),
        "groups": sorted(set(groups), key=str.casefold),
        "maximum_authority": normalise_authority_level(
            value.get("maximum_authority") or value.get("authority_level"),
            f"workload_identity.mappings[{index}].maximum_authority",
        ),
    }


def normalise_workload_identity(value: Any = None, existing: dict[str, Any] | None = None) -> dict[str, Any]:
    """Validate an AWS IAM workload-identity tenant configuration."""

    if value is None:
        value = existing if isinstance(existing, dict) else {}
    if not isinstance(value, dict):
        raise ValueError("workload_identity must be an object.")
    enabled = value.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ValueError("workload_identity.enabled must be a boolean.")
    provider = str(value.get("provider") or AWS_IAM_PROVIDER).strip().lower()
    if provider != AWS_IAM_PROVIDER:
        raise ValueError("workload_identity.provider must be aws_iam.")
    if not enabled:
        return {
            "enabled": False,
            "provider": AWS_IAM_PROVIDER,
            "allowed_account_ids": [],
            "mappings": [],
        }
    account_ids = _string_list(value.get("allowed_account_ids", []), "workload_identity.allowed_account_ids", MAX_ACCOUNT_IDS)
    if any(not ACCOUNT_PATTERN.fullmatch(account_id) for account_id in account_ids):
        raise ValueError("workload_identity.allowed_account_ids must contain 12-digit AWS account IDs.")
    raw_mappings = value.get("mappings")
    if not isinstance(raw_mappings, list) or not raw_mappings:
        raise ValueError("workload_identity.mappings must contain at least one AWS IAM role mapping when enabled.")
    mappings = [_normalise_mapping(item, index) for index, item in enumerate(raw_mappings)]
    patterns = [item["principal_arn"] for item in mappings]
    if len(patterns) != len(set(patterns)):
        raise ValueError("workload_identity.mappings must not contain duplicate principal ARN patterns.")
    if account_ids and any(item["account_id"] not in account_ids for item in mappings):
        raise ValueError("Every workload identity mapping must belong to an allowed_account_ids value.")
    return {
        "enabled": True,
        "provider": AWS_IAM_PROVIDER,
        "allowed_account_ids": sorted(set(account_ids)),
        "mappings": mappings,
    }


def aws_iam_context(event: dict[str, Any]) -> dict[str, Any] | None:
    """Extract API Gateway/Lambda Function URL IAM authorizer context."""

    request_context = event.get("requestContext") if isinstance(event.get("requestContext"), dict) else {}
    authorizer = request_context.get("authorizer") if isinstance(request_context.get("authorizer"), dict) else {}
    iam = authorizer.get("iam") if isinstance(authorizer.get("iam"), dict) else None
    if iam is None and isinstance(authorizer.get("aws_iam"), dict):
        iam = authorizer["aws_iam"]
    if iam is None and isinstance(request_context.get("identity"), dict) and request_context["identity"].get("userArn"):
        iam = request_context["identity"]
    if iam is None:
        return None
    return {
        "principal_arn": str(iam.get("userArn") or iam.get("principalArn") or "").strip(),
        "account_id": str(iam.get("accountId") or "").strip(),
        "caller_id": str(iam.get("callerId") or "").strip(),
        "access_key": str(iam.get("accessKey") or "").strip(),
    }


def map_aws_iam_principal(
    principal_context: dict[str, Any],
    tenant_id: str,
    workload_identity: dict[str, Any] | None,
) -> dict[str, Any]:
    """Map verified API Gateway IAM context to a Kenning auth record."""

    config = normalise_workload_identity(workload_identity)
    if not config["enabled"]:
        raise ValueError("AWS IAM workload identity is not enabled for this tenant.")
    source_principal_arn = str((principal_context or {}).get("principal_arn") or "").strip()
    principal_arn, account_id = _canonical_role_arn(
        (principal_context or {}).get("role_arn") or source_principal_arn
    )
    if config["allowed_account_ids"] and account_id not in config["allowed_account_ids"]:
        raise ValueError("The AWS IAM role account is not allowed for this tenant.")
    matches = [item for item in config["mappings"] if fnmatch.fnmatchcase(principal_arn.lower(), item["principal_arn"].lower())]
    if len(matches) != 1:
        if not matches:
            raise ValueError("The AWS IAM role is not mapped to a Kenning agent.")
        raise ValueError("The AWS IAM role matches multiple workload identity mappings.")
    mapping = matches[0]
    return {
        "token_type": "workload",
        "auth_source": AWS_IAM_PROVIDER,
        "token_id": f"aws-iam:{principal_arn}",
        "tenant_id": str(tenant_id),
        "subject": principal_arn,
        "invoked_by": principal_arn,
        "agent_id": mapping["agent_id"],
        "principal_type": "workload",
        "issuer": "aws_iam",
        "scopes": list(mapping["scopes"]),
        "groups": list(mapping["groups"]),
        "status": "active",
        "maximum_authority": mapping["maximum_authority"],
        "workload_identity": {
            "provider": AWS_IAM_PROVIDER,
            "principal_arn": principal_arn,
            "source_principal_arn": source_principal_arn or principal_arn,
            "account_id": account_id,
            "caller_id": str((principal_context or {}).get("caller_id") or "") or None,
        },
    }
