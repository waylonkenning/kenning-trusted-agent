"""Common-model enrichment and risk metadata for GitHub and email actions."""

from __future__ import annotations

import re
from typing import Any


INTEGRATION_ADAPTER_VERSION = "0.1"

GITHUB_DESTRUCTIVE_OPERATIONS = {
    "delete_branch",
    "delete_repository",
    "delete_release",
    "force_push",
    "remove_collaborator",
}

GITHUB_PRIVILEGED_OPERATIONS = {
    "change_branch_protection",
    "change_repository_visibility",
    "modify_permissions",
}


def _normalise_github_branch(branch: Any) -> str:
    branch_name = str(branch or "").strip().lower()
    if branch_name.startswith("refs/heads/"):
        return branch_name.removeprefix("refs/heads/")
    return branch_name


def _normalise_email_recipients(recipients: Any) -> list[Any]:
    if recipients in (None, ""):
        return []
    if isinstance(recipients, str):
        return [recipient.strip() for recipient in re.split(r"[,;]", recipients) if recipient.strip()]
    if isinstance(recipients, list):
        return recipients
    return [recipients]


def normalise_integration_action(action: dict[str, Any]) -> dict[str, Any]:
    tool = str(action.get("tool") or "").lower()
    parameters = action.get("parameters") if isinstance(action.get("parameters"), dict) else {}
    provider = str(action.get("provider") or parameters.get("provider") or "").strip().lower()
    operation = str(
        parameters.get("operation")
        or parameters.get("action_type")
        or parameters.get("verb")
        or action.get("operation")
        or "execute"
    ).lower()
    enriched = dict(action)

    if tool == "github" or provider == "github":
        repository = parameters.get("repository") or parameters.get("repo") or action.get("target")
        branch = _normalise_github_branch(parameters.get("branch") or parameters.get("base_branch") or parameters.get("ref") or "")
        if tool != "github":
            # Provider metadata is authoritative when an integration arrives
            # through a generic tool shape. This prevents GitHub file paths
            # such as ``app/policy.py`` from reaching cloud keyword rules.
            enriched["tool"] = "github"
        enriched["operation"] = operation
        enriched["adapter"] = "github"
        enriched["adapter_context"] = {
            "provider": "github",
            "adapter_version": INTEGRATION_ADAPTER_VERSION,
            "operation": operation,
            "repository": repository,
            "branch": branch,
            "requested_scope": parameters.get("requested_scope") or parameters.get("files") or parameters.get("resources"),
        }
    elif tool in {"email", "mail", "messaging"}:
        recipients = _normalise_email_recipients(parameters.get("to") or parameters.get("recipients") or parameters.get("cc") or parameters.get("bcc") or [])
        enriched["adapter"] = "email"
        enriched["adapter_context"] = {
            "provider": "email",
            "adapter_version": INTEGRATION_ADAPTER_VERSION,
            "operation": operation,
            "recipients_count": len(recipients) if isinstance(recipients, list) else 0,
            "requested_scope": parameters.get("requested_scope") or recipients,
            "external_recipients": bool(parameters.get("external_recipients")),
        }
    return enriched
