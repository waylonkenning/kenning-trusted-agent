"""Tenant-owned starter rules for the built-in Agent Guard checks.

The starter set is deliberately data-shaped so a tenant administrator can
enable, disable, and tune the default checks without changing application
code.  Built-in detectors still provide the matching signal; custom starter
rules use the same condition vocabulary as versioned tenant policies.
"""

from __future__ import annotations

import copy
import re
from typing import Any

try:  # pragma: no cover - import style depends on Lambda packaging.
    from policy import normalise_compliance_tags
except ImportError:  # Local package import during tests.
    from .policy import normalise_compliance_tags


STARTER_RULE_DECISIONS = {"allow", "warn", "require_approval", "rewrite", "deny"}
STARTER_RULE_KINDS = {"builtin", "custom"}
MAX_STARTER_RULES = 100
RULE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
DEFAULT_STARTER_COMPLIANCE_TAGS = (
    "NZ Algorithm Charter:Accountability",
    "NZ Algorithm Charter:Transparency",
)


def _builtin(
    rule_id: str,
    name: str,
    description: str,
    decision: str,
    compliance_tags: tuple[str, ...] = (),
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "name": name,
        "description": description,
        "kind": "builtin",
        "reason_code": rule_id,
        "decision": decision,
        "enabled": True,
        "source": "kenning-default",
        "compliance_tags": [*DEFAULT_STARTER_COMPLIANCE_TAGS, *compliance_tags],
    }


# Keep this list aligned with the reason codes emitted by guard.evaluate.
# The detector remains in guard.py; this is the tenant-facing control surface
# for the detector's default enforcement decision.
STARTER_RULE_CATALOG: tuple[dict[str, Any], ...] = (
    _builtin("MISSING_TOOL", "Tool declaration required", "Reject actions that do not identify a tool.", "deny"),
    _builtin("UNPARSEABLE_SHELL_ACTION", "Inspectable shell command required", "Require review when Guard cannot inspect a shell command.", "require_approval"),
    _builtin("CATASTROPHIC_FILESYSTEM_OPERATION", "Catastrophic filesystem deletion", "Block recursive force deletion of a filesystem root or home directory.", "deny"),
    _builtin("DESTRUCTIVE_FILESYSTEM_OPERATION", "Destructive shell filesystem operation", "Require review for commands that can delete or overwrite filesystem data.", "require_approval"),
    _builtin("PRIVILEGE_ESCALATION", "Privilege escalation", "Require review when a command requests elevated privileges.", "require_approval"),
    _builtin(
        "CREDENTIAL_EXPOSURE",
        "Credential or secret exposure",
        "Block actions that reference likely credentials, secrets, or sensitive environment variables.",
        "deny",
        ("Privacy Act 2020:IPP 5", "Privacy Act 2020:IPP 10", "Privacy Act 2020:IPP 11"),
    ),
    _builtin("SHELL_PROTECTED_WORKING_DIRECTORY", "Protected shell working directory", "Require review for execution from protected or sensitive directories.", "require_approval"),
    _builtin("REMOTE_SCRIPT_EXECUTION", "Remote script execution", "Require review when a remote response is piped directly into a shell.", "require_approval"),
    _builtin("COMPOUND_SHELL_SCOPE", "Compound shell scope", "Warn when shell operators make the action scope harder to constrain.", "warn"),
    _builtin("UNPARSEABLE_SQL_ACTION", "Inspectable SQL statement required", "Require review when Guard cannot inspect a SQL statement.", "require_approval"),
    _builtin("DESTRUCTIVE_DATABASE_OPERATION", "Destructive database operation", "Require review for DROP or TRUNCATE statements.", "require_approval"),
    _builtin("UNBOUNDED_UPDATE", "Unbounded database update", "Require review for DELETE or UPDATE statements without a WHERE clause.", "require_approval"),
    _builtin("PRODUCTION_DATABASE_TARGET", "Production database mutation", "Require review for mutations against a production database.", "require_approval"),
    _builtin("UNBOUNDED_READ", "Unbounded database read", "Warn when SELECT * has no LIMIT clause.", "warn"),
    _builtin(
        "SENSITIVE_DATA_RETRIEVAL",
        "Sensitive data retrieval",
        "Require review for queries that may retrieve sensitive personal or business data.",
        "require_approval",
        ("Privacy Act 2020:IPP 5", "Privacy Act 2020:IPP 8", "Privacy Act 2020:IPP 10"),
    ),
    _builtin("UNPARSEABLE_FILESYSTEM_ACTION", "Inspectable filesystem path required", "Require review when Guard cannot inspect a filesystem path.", "require_approval"),
    _builtin("FILESYSTEM_MUTATION", "Filesystem mutation", "Review filesystem changes, with stricter handling in production.", "require_approval"),
    _builtin("BROAD_FILESYSTEM_SCOPE", "Broad filesystem scope", "Require review for recursive or forced filesystem operations.", "require_approval"),
    _builtin("PROTECTED_FILESYSTEM_TARGET", "Protected filesystem target", "Require review for protected or sensitive filesystem locations.", "require_approval"),
    _builtin("UNPARSEABLE_AWS_ACTION", "Inspectable AWS operation required", "Require review when an AWS service or API operation is missing.", "require_approval"),
    _builtin("AWS_DESTRUCTIVE_OPERATION", "Destructive AWS operation", "Require review for AWS operations that can delete infrastructure or data.", "require_approval"),
    _builtin("AWS_PRIVILEGED_OPERATION", "Privileged AWS operation", "Require review for AWS operations that change privileged access or secrets.", "require_approval"),
    _builtin("AWS_PRODUCTION_MUTATION", "Production AWS mutation", "Require review for mutating AWS operations in production.", "require_approval"),
    _builtin("AWS_PREVIEW_RECOMMENDED", "AWS preview recommended", "Require or warn on AWS mutations that lack a dry-run or provider preview.", "require_approval"),
    _builtin("AWS_SCOPE_NOT_DECLARED", "AWS resource scope required", "Require review when a mutating AWS action does not declare its resource scope.", "require_approval"),
    _builtin("GITHUB_DESTRUCTIVE_OPERATION", "Destructive GitHub operation", "Require review for GitHub operations that remove or overwrite repository state.", "require_approval"),
    _builtin("GITHUB_PRIVILEGED_OPERATION", "Privileged GitHub operation", "Require review for GitHub access or protection changes.", "require_approval"),
    _builtin("GITHUB_PROTECTED_BRANCH_CHANGE", "Protected GitHub branch change", "Require review for changes to protected or production branches.", "require_approval"),
    _builtin("GITHUB_SCOPE_NOT_DECLARED", "GitHub repository scope required", "Require review when a GitHub action does not declare a repository.", "require_approval"),
    _builtin("EMAIL_RECIPIENTS_MISSING", "Email recipients required", "Block outbound email that does not declare recipients.", "deny"),
    _builtin("BULK_OUTBOUND_MESSAGE", "Bulk outbound message", "Require review for broad recipient sets or bulk messaging operations.", "require_approval"),
    _builtin("OUTBOUND_MESSAGE", "Outbound message", "Require review for external or production outbound email.", "require_approval"),
    _builtin("EMAIL_SCOPE_NOT_DECLARED", "Email recipient scope required", "Require review when recipient scope is not declared.", "require_approval"),
    _builtin("UNPARSEABLE_CLOUD_ACTION", "Inspectable cloud action required", "Require review when a generic cloud action lacks enough context to inspect.", "require_approval"),
    _builtin("INFRASTRUCTURE_DELETION", "Infrastructure deletion", "Require review for cloud actions that can delete or terminate infrastructure.", "require_approval"),
    _builtin("PRIVILEGED_CLOUD_CHANGE", "Privileged cloud change", "Require review for cloud identity, access, network-policy, key, or secret changes.", "require_approval"),
    _builtin("PRODUCTION_CLOUD_CHANGE", "Production cloud change", "Require review for changes to production cloud resources.", "require_approval"),
    _builtin("HIGH_IMPACT_UNSUPPORTED_ACTION", "Unsupported high-impact action", "Require review when an unsupported tool appears to perform a high-impact operation.", "require_approval"),
    _builtin("FINANCIAL_TRANSACTION", "Financial transaction", "Require review for actions that may move, charge, refund, or transfer money.", "require_approval"),
    _builtin("IRREVERSIBLE_ACTION", "Irreversible action", "Require review for actions explicitly marked irreversible.", "require_approval"),
    _builtin("BROAD_RESOURCE_SCOPE", "Broad resource scope", "Require review when more than ten resources are declared.", "require_approval"),
    _builtin("LARGE_AFFECTED_RESOURCE_COUNT", "Large affected resource count", "Require review when an action may affect more than 1,000 resources or rows.", "require_approval"),
    _builtin("INTENT_SCOPE_MISMATCH", "Intent and scope mismatch", "Require review when read-only intent conflicts with a mutating action.", "require_approval"),
)


def default_starter_rules() -> list[dict[str, Any]]:
    """Return a detached copy of the default tenant starter set."""

    return copy.deepcopy(list(STARTER_RULE_CATALOG))


def _clean_text(value: Any, field: str, maximum: int, default: str = "") -> str:
    text = str(value if value is not None else default).strip()
    if len(text) > maximum:
        raise ValueError(f"{field} must be no longer than {maximum} characters.")
    return text


def _groups(value: Any) -> list[str]:
    if value is None:
        return []
    values = value if isinstance(value, list) else [value]
    groups = [_clean_text(item, "approver_groups", 128) for item in values]
    groups = [item for item in groups if item]
    if len(groups) > 50:
        raise ValueError("approver_groups may contain at most 50 groups.")
    return sorted(set(groups), key=str.casefold)


def normalise_starter_rules(value: Any) -> list[dict[str, Any]]:
    """Validate and normalise a tenant's editable starter-rule set."""

    raw_rules = default_starter_rules() if value is None else value
    if not isinstance(raw_rules, list):
        raise ValueError("starter_rules must be an array.")
    if len(raw_rules) > MAX_STARTER_RULES:
        raise ValueError(f"starter_rules may contain at most {MAX_STARTER_RULES} rules.")

    catalog_by_code = {str(rule["reason_code"]): rule for rule in STARTER_RULE_CATALOG}
    catalog_codes = set(catalog_by_code)
    rules: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_rules):
        if not isinstance(raw, dict):
            raise ValueError(f"Starter rule {index + 1} must be an object.")
        rule_id = _clean_text(raw.get("rule_id"), "rule_id", 64)
        if not rule_id or not RULE_ID_PATTERN.fullmatch(rule_id):
            raise ValueError("starter rule_id must start with a letter or number and contain only letters, numbers, ., _, :, or -.")
        if rule_id in seen:
            raise ValueError(f"starter rule_id is duplicated: {rule_id}.")
        seen.add(rule_id)

        reason_code = _clean_text(raw.get("reason_code") or rule_id, "reason_code", 128).upper()
        kind = _clean_text(raw.get("kind") or ("builtin" if reason_code in catalog_codes else "custom"), "kind", 16).lower()
        if kind not in STARTER_RULE_KINDS:
            raise ValueError(f"Starter rule {rule_id} kind must be builtin or custom.")
        if kind == "builtin" and reason_code not in catalog_codes:
            raise ValueError(f"Starter rule {rule_id} references an unknown built-in reason code: {reason_code}.")
        conditions = raw.get("conditions") if isinstance(raw.get("conditions"), dict) else {}
        if kind == "custom" and not conditions:
            raise ValueError(f"Custom starter rule {rule_id} must provide conditions.")
        decision = _clean_text(raw.get("decision") or "require_approval", "decision", 32).lower()
        if decision not in STARTER_RULE_DECISIONS:
            raise ValueError(f"Starter rule {rule_id} has unsupported decision: {decision}.")
        enabled = raw.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ValueError(f"Starter rule {rule_id} enabled must be a boolean.")

        catalog_rule = catalog_by_code.get(reason_code) or {}
        fallback_name = str(catalog_rule.get("name") or rule_id)
        fallback_description = str(catalog_rule.get("description") or "Tenant-defined starter rule.")
        default_tags = catalog_rule.get("compliance_tags") if kind == "builtin" else []
        compliance_tags = normalise_compliance_tags(
            raw.get("compliance_tags") if "compliance_tags" in raw else default_tags
        )
        rule = {
            "rule_id": rule_id,
            "name": _clean_text(raw.get("name"), "name", 160, fallback_name),
            "description": _clean_text(raw.get("description"), "description", 512, fallback_description),
            "kind": kind,
            "reason_code": reason_code,
            "decision": decision,
            "enabled": enabled,
            "conditions": copy.deepcopy(conditions),
            "reason": _clean_text(raw.get("reason"), "reason", 512, ""),
            "recommended_action": copy.deepcopy(raw.get("recommended_action")) if isinstance(raw.get("recommended_action"), dict) else None,
            "approver_groups": _groups(raw.get("approver_groups")),
            "compliance_tags": compliance_tags,
        }
        if kind == "builtin":
            rule["source"] = "kenning-default"
        else:
            rule["source"] = "tenant"
        rules.append(rule)
    return rules


def custom_starter_policy(rules: list[dict[str, Any]], tenant_id: str, version: int, mode: str = "enforce") -> dict[str, Any] | None:
    """Adapt enabled custom starter rules to the existing policy evaluator."""

    custom = []
    for rule in rules:
        if rule.get("kind") != "custom" or not rule.get("enabled"):
            continue
        item = {
            "rule_id": rule["rule_id"],
            "conditions": rule.get("conditions") or {},
            "decision": rule["decision"],
            "reason": rule.get("reason") or rule.get("description") or f"Starter rule {rule['rule_id']} matched.",
        }
        if rule.get("approver_groups"):
            item["approver_groups"] = list(rule["approver_groups"])
        if rule.get("recommended_action"):
            item["recommended_action"] = copy.deepcopy(rule["recommended_action"])
        custom.append(item)
    if not custom:
        return None
    return {
        "item_type": "policy",
        "policy_id": "tenant-starter-rules",
        "tenant_id": str(tenant_id),
        "name": "Tenant starter rules",
        "version": int(version or 1),
        "status": "published",
        "mode": "observe" if str(mode).lower() == "observe" else "enforce",
        "rules": custom,
    }


def starter_rule_summary(rules: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "count": len(rules),
        "enabled_count": sum(1 for rule in rules if rule.get("enabled")),
        "builtin_count": sum(1 for rule in rules if rule.get("kind") == "builtin"),
        "custom_count": sum(1 for rule in rules if rule.get("kind") == "custom"),
        "rule_ids": [str(rule.get("rule_id")) for rule in rules],
    }
