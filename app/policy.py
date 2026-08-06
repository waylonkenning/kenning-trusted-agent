"""Versioned policy records and deterministic policy overlays for Guard."""

from __future__ import annotations

import fnmatch
import json
import uuid
from typing import Any

try:
    from guard import CLASSIFICATION_LEVELS, CLASSIFICATION_RANK, DECISION_RANK, _redact, utc_now
    from model_registry import model_risk_at_least
except ModuleNotFoundError:  # Local package import during tests.
    from .guard import CLASSIFICATION_LEVELS, CLASSIFICATION_RANK, DECISION_RANK, _redact, utc_now
    from .model_registry import model_risk_at_least


POLICY_DECISIONS = {"allow", "warn", "require_approval", "rewrite", "deny"}
POLICY_TEST_DECISIONS = POLICY_DECISIONS | {"observe"}
MAX_POLICY_TEST_CASES = 100
MAX_APPROVER_GROUPS = 50
MAX_APPROVER_GROUP_LENGTH = 128
MAX_COMPLIANCE_TAGS = 50
MAX_COMPLIANCE_TAG_LENGTH = 160
MAX_CONSENT_FIELD_LENGTH = 256


def _list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def normalise_approver_groups(value: Any) -> list[str]:
    """Return bounded, deterministic reviewer-group names for approvals."""

    values = _list(value)
    if len(values) > MAX_APPROVER_GROUPS:
        raise ValueError(f"approver_groups may contain at most {MAX_APPROVER_GROUPS} groups.")
    groups: list[str] = []
    for value in values:
        group = str(value or "").strip()
        if not group:
            continue
        if len(group) > MAX_APPROVER_GROUP_LENGTH:
            raise ValueError(f"approver_groups values must be no longer than {MAX_APPROVER_GROUP_LENGTH} characters.")
        groups.append(group)
    return sorted(set(groups), key=str.casefold)


def normalise_compliance_tags(value: Any) -> list[str]:
    """Return bounded, deterministic compliance labels for a policy record."""

    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("compliance_tags must be an array.")
    if len(value) > MAX_COMPLIANCE_TAGS:
        raise ValueError(f"compliance_tags may contain at most {MAX_COMPLIANCE_TAGS} tags.")
    tags: list[str] = []
    seen: set[str] = set()
    for raw in value:
        tag = str(raw or "").strip()
        if not tag:
            continue
        if len(tag) > MAX_COMPLIANCE_TAG_LENGTH:
            raise ValueError(
                f"compliance_tags values must be no longer than {MAX_COMPLIANCE_TAG_LENGTH} characters."
            )
        key = tag.casefold()
        if key in seen:
            continue
        seen.add(key)
        tags.append(tag)
    return sorted(tags, key=str.casefold)


def normalise_requires_consent(value: Any) -> dict[str, str]:
    """Validate the purpose and data scope required by a consent rule."""

    if not isinstance(value, dict):
        raise ValueError("requires_consent must be an object with purpose and data_scope.")
    required: dict[str, str] = {}
    for field in ("purpose", "data_scope"):
        text = str(value.get(field) or "").strip()
        if not text:
            raise ValueError(f"requires_consent.{field} is required.")
        if len(text) > MAX_CONSENT_FIELD_LENGTH:
            raise ValueError(f"requires_consent.{field} must be no longer than {MAX_CONSENT_FIELD_LENGTH} characters.")
        required[field] = text
    return required


def normalise_approval_chain(value: Any) -> list[dict[str, Any]]:
    """Validate and normalise a multi-step approval chain (#245).

    Each step has a 1-based position, an optional label, a set of approver
    groups (alternatives within a step), and a separation-of-duties flag.
    Returns an empty list when no chain is defined so callers can treat the
    absence of a chain as the existing single-step behaviour.
    """

    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("approval_chain must be an array of steps.")
    if len(value) > MAX_APPROVER_GROUPS:
        raise ValueError(f"approval_chain may contain at most {MAX_APPROVER_GROUPS} steps.")
    steps: list[dict[str, Any]] = []
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            raise ValueError("Each approval_chain step must be an object.")
        groups = normalise_approver_groups(raw.get("approver_groups") or raw.get("groups"))
        label = str(raw.get("label") or f"Step {index + 1}").strip()
        if len(label) > MAX_APPROVER_GROUP_LENGTH:
            raise ValueError("approval_chain step labels are too long.")
        steps.append(
            {
                "step": index + 1,
                "label": label,
                "approver_groups": groups,
                "separation_of_duties": bool(raw.get("separation_of_duties", True)),
            }
        )
    return steps


def normalise_test_cases(value: Any) -> list[dict[str, Any]]:
    """Validate reusable policy test cases stored with a policy version."""

    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("test_cases must be an array.")
    if len(value) > MAX_POLICY_TEST_CASES:
        raise ValueError(f"test_cases may contain at most {MAX_POLICY_TEST_CASES} cases.")

    cases: list[dict[str, Any]] = []
    for index, raw_case in enumerate(value):
        if not isinstance(raw_case, dict):
            raise ValueError(f"Test case {index + 1} must be an object.")
        action = raw_case.get("action")
        if not isinstance(action, dict) or not action:
            raise ValueError(f"Test case {index + 1} must contain a non-empty action object.")
        expected_decision = str(raw_case.get("expected_decision") or raw_case.get("expected") or "").lower().strip()
        if expected_decision not in POLICY_TEST_DECISIONS:
            raise ValueError(
                f"Test case {index + 1} expected_decision must be one of: {', '.join(sorted(POLICY_TEST_DECISIONS))}."
            )
        expected_codes = raw_case.get("expected_reason_codes") or []
        if isinstance(expected_codes, str):
            expected_codes = [expected_codes]
        if not isinstance(expected_codes, list):
            raise ValueError(f"Test case {index + 1} expected_reason_codes must be an array.")
        context = raw_case.get("context") if isinstance(raw_case.get("context"), dict) else {}
        case_id = str(raw_case.get("case_id") or raw_case.get("id") or f"case-{index + 1}").strip()
        if not case_id:
            raise ValueError(f"Test case {index + 1} case_id must not be empty.")
        cases.append(
            {
                "case_id": case_id,
                "name": str(raw_case.get("name") or case_id),
                "context": _redact(context),
                "action": _redact(action),
                "intent": str(raw_case.get("intent") or ""),
                "expected_decision": expected_decision,
                "expected_reason_codes": [str(code) for code in expected_codes if str(code).strip()],
            }
        )
    return cases


def build_policy_record(payload: dict[str, Any], tenant_id: str, version: int) -> dict[str, Any]:
    policy_id = str(payload.get("policy_id") or f"policy-{uuid.uuid4().hex[:16]}")
    rules = payload.get("rules") if isinstance(payload.get("rules"), list) else []
    normalised_rules: list[dict[str, Any]] = []
    for index, raw_rule in enumerate(rules):
        if not isinstance(raw_rule, dict):
            raise ValueError(f"Rule {index + 1} must be an object.")
        decision = str(raw_rule.get("decision") or "").lower()
        if decision not in POLICY_DECISIONS:
            raise ValueError(f"Rule {index + 1} has unsupported decision: {decision or 'missing'}.")
        rule = _redact(raw_rule)
        rule["rule_id"] = str(raw_rule.get("rule_id") or f"rule-{index + 1}")
        rule["decision"] = decision
        conditions = raw_rule.get("conditions") if isinstance(raw_rule.get("conditions"), dict) else {}
        normalised_conditions = dict(conditions)
        if "classification_at_least" in conditions:
            threshold = str(conditions["classification_at_least"] or "").strip().lower()
            if threshold not in CLASSIFICATION_RANK:
                raise ValueError(
                    "classification_at_least must be one of: "
                    + ", ".join(CLASSIFICATION_LEVELS)
                    + "."
                )
            normalised_conditions["classification_at_least"] = threshold
        if "requires_consent" in conditions:
            normalised_conditions["requires_consent"] = normalise_requires_consent(conditions["requires_consent"])
        if normalised_conditions != conditions:
            rule["conditions"] = normalised_conditions
        configured_groups = raw_rule.get("approver_groups")
        if configured_groups is None:
            configured_groups = conditions.get("approver_groups")
        approver_groups = normalise_approver_groups(configured_groups)
        if approver_groups:
            rule["approver_groups"] = approver_groups
        rule.setdefault("reason", f"Matched policy rule {rule['rule_id']}.")
        normalised_rules.append(rule)
    test_cases = normalise_test_cases(payload.get("test_cases"))
    return {
        "item_type": "policy",
        "policy_id": policy_id,
        "tenant_id": str(tenant_id),
        "name": str(payload.get("name") or policy_id),
        "description": str(payload.get("description") or ""),
        "version": int(version),
        "status": "draft",
        "mode": str(payload.get("mode") or "enforce").lower() if str(payload.get("mode") or "enforce").lower() in {"observe", "enforce"} else "enforce",
        "compliance_tags": normalise_compliance_tags(payload.get("compliance_tags")),
        "rules": normalised_rules,
        "test_cases": test_cases,
        "created_by": str(payload.get("created_by") or "unknown-administrator"),
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "supersedes_version": payload.get("supersedes_version"),
        "last_reviewed_at": payload.get("last_reviewed_at"),
    }


def _match_text(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False).lower()
    return str(value or "").lower()


def _matches(expected: Any, actual: Any) -> bool:
    if expected is None:
        return True
    if isinstance(expected, list):
        return any(_matches(item, actual) for item in expected)
    expected_text = _match_text(expected)
    actual_text = _match_text(actual)
    if isinstance(actual, (dict, list)) and "*" not in expected_text and "?" not in expected_text:
        return expected_text in actual_text
    return fnmatch.fnmatchcase(actual_text, expected_text)


def rule_matches(rule: dict[str, Any], action: dict[str, Any]) -> bool:
    conditions = rule.get("conditions") if isinstance(rule.get("conditions"), dict) else rule
    fields = {
        "environment": action.get("environment"),
        "agent_id": action.get("agent_id"),
        "invoked_by": action.get("invoked_by"),
        "user": action.get("invoked_by"),
        "tool": action.get("tool"),
        "operation": action.get("operation"),
        "action_type": action.get("operation"),
        "target": action.get("target"),
        "resource": action.get("target"),
        "intent": action.get("intent"),
    }
    for field, actual in fields.items():
        if field in conditions and not _matches(conditions[field], actual):
            return False
    if "tools" in conditions and not _matches(conditions["tools"], action.get("tool")):
        return False
    if "model_risk_at_least" in conditions and not model_risk_at_least(
        action.get("model_risk_tier"), conditions["model_risk_at_least"]
    ):
        return False
    if "classification_at_least" in conditions:
        threshold = str(conditions["classification_at_least"] or "").strip().lower()
        actual = str(action.get("classification") or "unclassified").strip().lower()
        if threshold not in CLASSIFICATION_RANK or actual not in CLASSIFICATION_RANK:
            return False
        if CLASSIFICATION_RANK[actual] < CLASSIFICATION_RANK[threshold]:
            return False
    # Impact-assessment reminders are deliberately warn-only. The Lambda
    # adapter supplies this transient policy context from the tenant audit
    # stream; pure policy callers without a current assessment are treated as
    # overdue, which keeps the condition deterministic and fail-safe.
    if conditions.get("requires_impact_assessment") is True and action.get("_impact_assessment_current") is True:
        return False
    parameters = action.get("parameters") if isinstance(action.get("parameters"), dict) else {}
    if "requires_consent" in conditions:
        requirement = conditions["requires_consent"]
        action_purpose = action.get("purpose") or parameters.get("purpose")
        action_scope = action.get("data_scope") or parameters.get("data_scope")
        if action_purpose not in (None, "") and not _matches(requirement["purpose"], action_purpose):
            return False
        if action_scope not in (None, "") and not _matches(requirement["data_scope"], action_scope):
            return False
        active_consents = action.get("_active_consents") if isinstance(action.get("_active_consents"), list) else []
        if any(
            _matches(requirement["purpose"], consent.get("purpose"))
            and _matches(requirement["data_scope"], consent.get("data_scope"))
            for consent in active_consents
            if isinstance(consent, dict)
        ):
            return False
    adapter_context = action.get("adapter_context") if isinstance(action.get("adapter_context"), dict) else {}
    for field in ("provider", "region"):
        if field in conditions and not _matches(conditions[field], adapter_context.get(field)):
            return False

    requested_at = str(action.get("requested_at") or "")
    for field in ("start_time", "not_before"):
        if field in conditions and requested_at < str(conditions[field]):
            return False
    for field in ("end_time", "not_after"):
        if field in conditions and requested_at > str(conditions[field]):
            return False
    time_window = conditions.get("time_window")
    if isinstance(time_window, dict):
        if time_window.get("start") and requested_at < str(time_window["start"]):
            return False
        if time_window.get("end") and requested_at > str(time_window["end"]):
            return False

    if "reversible" in conditions and not _matches(conditions["reversible"], parameters.get("reversible")):
        return False
    if "query_scope" in conditions and not _matches(conditions["query_scope"], parameters.get("query_scope") or parameters.get("requested_scope")):
        return False
    if conditions.get("dry_run_required") and (parameters.get("dry_run") or parameters.get("preview")):
        return False
    if "maximum_amount" in conditions:
        try:
            if float(parameters.get("amount", 0)) > float(conditions["maximum_amount"]):
                return True
            return False
        except (TypeError, ValueError):
            return True
    if "minimum_amount" in conditions:
        try:
            return float(parameters.get("amount", 0)) >= float(conditions["minimum_amount"])
        except (TypeError, ValueError):
            return False
    if "maximum_scope" in conditions:
        scope = parameters.get("requested_scope") or parameters.get("resources") or []
        scope_size = len(scope) if isinstance(scope, list) else (1 if scope else 0)
        try:
            return scope_size > int(conditions["maximum_scope"])
        except (TypeError, ValueError):
            return True
    return True


def apply_policies(decision: dict[str, Any], action: dict[str, Any], policies: list[dict[str, Any]]) -> dict[str, Any]:
    """Apply all matching published or simulated policies deterministically."""

    matches: list[dict[str, Any]] = []
    current = decision.get("would_decision") or decision.get("decision") or "allow"
    current_rank = DECISION_RANK.get(current, 0)
    resolution: dict[str, Any] = {
        "strategy": "most_restrictive_wins",
        "decision_order": [name for name, _ in sorted(DECISION_RANK.items(), key=lambda item: item[1])],
        "baseline_decision": current,
        "baseline_rank": current_rank,
        "selected_decision": current,
        "selected_rank": current_rank,
        "effective_decision": decision.get("decision") or current,
        "selected_match": None,
        "evaluated_matches": [],
    }
    for policy in sorted(policies, key=lambda item: (str(item.get("policy_id")), int(item.get("version", 0)))):
        for rule in policy.get("rules") or []:
            if not isinstance(rule, dict) or not rule_matches(rule, action):
                continue
            rule_conditions = rule.get("conditions") if isinstance(rule.get("conditions"), dict) else rule
            impact_assessment_reminder = rule_conditions.get("requires_impact_assessment") is True
            desired = "warn" if impact_assessment_reminder else str(rule.get("decision") or "warn").lower()
            if desired not in POLICY_DECISIONS:
                continue
            desired_rank = DECISION_RANK.get(desired, 0)
            precedence = {
                "policy_id": policy.get("policy_id"),
                "policy_version": int(policy.get("version", 1)),
                "rule_id": rule.get("rule_id"),
                "decision": desired,
                "decision_rank": desired_rank,
                "decision_before": current,
                "applied": desired_rank >= current_rank,
                "precedence_reason": "equal_or_more_restrictive_than_current_decision"
                if desired_rank >= current_rank
                else "lower_precedence_than_current_decision",
            }
            matches.append(
                {
                    "policy_id": policy.get("policy_id"),
                    "policy_version": int(policy.get("version", 1)),
                    "rule_id": rule.get("rule_id"),
                    "decision": desired,
                    "precedence_rank": desired_rank,
                    "mode": policy.get("mode", "enforce"),
                    "approver_groups": normalise_approver_groups(
                        rule.get("approver_groups")
                        if rule.get("approver_groups") is not None
                        else (rule.get("conditions") or {}).get("approver_groups")
                    ),
                }
            )
            if desired_rank >= current_rank:
                precedence["decision_after"] = desired
                precedence["effective_decision_after"] = "observe" if policy.get("mode") == "observe" and desired != "allow" else desired
                current = desired
                current_rank = desired_rank
                resolution["selected_match"] = {
                    "policy_id": policy.get("policy_id"),
                    "policy_version": int(policy.get("version", 1)),
                    "rule_id": rule.get("rule_id"),
                    "decision": desired,
                    "decision_rank": desired_rank,
                    "mode": policy.get("mode", "enforce"),
                }
                if policy.get("mode") == "observe" and desired != "allow":
                    decision["decision"] = "observe"
                    decision["would_decision"] = desired
                else:
                    decision["decision"] = desired
                    decision["would_decision"] = None
                if desired == "deny":
                    decision["risk"] = "critical"
                    decision["risk_score"] = 100
                elif desired == "require_approval":
                    decision["risk"] = "high"
                    decision["risk_score"] = max(int(decision.get("risk_score") or 0), 80)
                    approver_groups = normalise_approver_groups(
                        rule.get("approver_groups")
                        if rule.get("approver_groups") is not None
                        else (rule.get("conditions") or {}).get("approver_groups")
                    )
                    if approver_groups and policy.get("mode") != "observe":
                        requirement = {
                            "groups": approver_groups,
                            "policy_id": policy.get("policy_id"),
                            "policy_version": int(policy.get("version", 1)),
                            "rule_id": rule.get("rule_id"),
                        }
                        requirements = decision.setdefault("approval_requirements", [])
                        if requirement not in requirements:
                            requirements.append(requirement)
                    # Multi-step approval chain (#245): a rule may define an ordered
                    # list of approval steps instead of (or alongside) flat groups.
                    chain = normalise_approval_chain(rule.get("approval_chain"))
                    if chain and policy.get("mode") != "observe":
                        decision["approval_chain"] = {
                            "steps": chain,
                            "policy_id": policy.get("policy_id"),
                            "policy_version": int(policy.get("version", 1)),
                            "rule_id": rule.get("rule_id"),
                        }
                elif desired in {"warn", "rewrite"}:
                    decision["risk"] = "medium" if desired == "warn" else "high"
                    decision["risk_score"] = max(int(decision.get("risk_score") or 0), 40 if desired == "warn" else 65)
                reason = str(
                    rule.get("reason")
                    or (
                        "The agent does not have a completed impact assessment from the last 365 days."
                        if impact_assessment_reminder
                        else f"Policy {policy.get('name', policy.get('policy_id'))} matched."
                    )
                )
                reason_code = "ASSESSMENT_OVERDUE" if impact_assessment_reminder else f"POLICY_{str(rule.get('rule_id')).upper()}"
                decision.setdefault("reasons", []).append({"code": reason_code, "message": reason, "decision": desired})
                decision.setdefault("reason_codes", []).append(reason_code)
                if rule.get("recommended_action"):
                    decision["recommended_action"] = _redact(rule["recommended_action"])
            else:
                precedence["decision_after"] = current
                precedence["effective_decision_after"] = decision.get("decision") or current
            resolution["evaluated_matches"].append(precedence)

    decision["policy_matches"] = matches
    resolution["selected_decision"] = current
    resolution["selected_rank"] = current_rank
    resolution["effective_decision"] = decision.get("decision") or current
    decision["policy_resolution"] = resolution
    if decision.get("approval_requirements"):
        decision["approval_requirements"] = sorted(
            decision["approval_requirements"],
            key=lambda item: (str(item.get("policy_id")), int(item.get("policy_version", 0)), str(item.get("rule_id"))),
        )
    return decision
