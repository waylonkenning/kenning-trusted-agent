"""AWS action adapter for the common Agent Guard action model.

The adapter does not execute AWS calls. It enriches a proposed action with
provider-specific context so Guard can apply explainable AWS controls while
preserving the common action contract.
"""

from __future__ import annotations

from typing import Any


AWS_ADAPTER_VERSION = "0.1"

AWS_DESTRUCTIVE_OPERATIONS = {
    "cloudformation:deletestack",
    "dynamodb:deletetable",
    "ec2:terminateinstances",
    "eks:deletecluster",
    "iam:deletepolicy",
    "lambda:deletefunction",
    "rds:deletedbcluster",
    "rds:deletedbinstance",
    "s3:deletebucket",
}

AWS_PRIVILEGED_OPERATIONS = {
    "iam:attachgrouppolicy",
    "iam:attachrolepolicy",
    "iam:attachuserpolicy",
    "iam:createaccesskey",
    "iam:createpolicyversion",
    "iam:putgrouppolicy",
    "iam:putrolepolicy",
    "iam:putuserpolicy",
    "iam:updateassumerolepolicy",
    "kms:putkeypolicy",
    "secretsmanager:putsecretvalue",
}

AWS_MUTATING_PREFIXES = (
    "associate",
    "authorize",
    "create",
    "delete",
    "deregister",
    "disable",
    "disassociate",
    "enable",
    "modify",
    "put",
    "remove",
    "revoke",
    "run",
    "set",
    "start",
    "stop",
    "terminate",
    "update",
)


def normalise_aws_action(action: dict[str, Any]) -> dict[str, Any]:
    """Attach a stable AWS provider context to a normalised common action."""

    tool = str(action.get("tool") or "").lower()
    parameters = action.get("parameters") if isinstance(action.get("parameters"), dict) else {}
    provider = str(parameters.get("provider") or ("aws" if tool == "aws" else "")).lower()
    if provider != "aws":
        return action

    operation = str(action.get("operation") or "execute")
    service = str(parameters.get("service") or parameters.get("service_name") or "").strip().lower()
    api_operation = str(
        parameters.get("api_operation")
        or parameters.get("api_action")
        or operation
    ).strip()
    if not service and ":" in api_operation:
        service, api_operation = api_operation.split(":", 1)
        service = service.strip().lower()
    resource = parameters.get("resource") or action.get("target")
    requested_scope = parameters.get("requested_scope")
    if requested_scope is None:
        requested_scope = parameters.get("resources")
    context = {
        "provider": "aws",
        "adapter_version": AWS_ADAPTER_VERSION,
        "service": service,
        "api_operation": api_operation,
        "region": str(parameters.get("region") or ""),
        "resource": resource,
        "requested_scope": requested_scope,
    }
    enriched = dict(action)
    enriched["adapter"] = "aws"
    enriched["adapter_context"] = context
    return enriched


def aws_operation(action: dict[str, Any]) -> str:
    context = action.get("adapter_context") if isinstance(action.get("adapter_context"), dict) else {}
    service = str(context.get("service") or "").lower()
    operation = str(context.get("api_operation") or "").lower()
    return f"{service}:{operation}" if service and operation else ""


def is_mutating_operation(action: dict[str, Any]) -> bool:
    operation = str((action.get("adapter_context") or {}).get("api_operation") or "").lower()
    return operation.startswith(AWS_MUTATING_PREFIXES)
