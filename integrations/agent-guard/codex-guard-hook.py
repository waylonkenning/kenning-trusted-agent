#!/usr/bin/env python3
"""Fail-closed Kenning Agent Guard hooks for Codex CLI.

The hook evaluates Codex tool calls before execution. It keeps only approval
IDs, action hashes, and bounded metadata on disk. Installed hooks read their
credentials from a local mode-0600 JSON file so Codex Desktop does not depend
on the user's interactive shell environment. The environment fallback keeps
standalone and legacy hook copies compatible.
"""

import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from urllib.error import HTTPError
import urllib.request
import uuid


TOOL_MAP = {
    "Bash": ("shell", "execute"),
    "shell_command": ("shell", "execute"),
    "exec_command": ("shell", "execute"),
    "apply_patch": ("filesystem", "modify"),
    "ApplyPatch": ("filesystem", "modify"),
    "Write": ("filesystem", "write"),
    "Create": ("filesystem", "write"),
    "Edit": ("filesystem", "modify"),
    "Read": ("filesystem", "read"),
    "View": ("filesystem", "read"),
    "Grep": ("filesystem", "read"),
    "Glob": ("filesystem", "read"),
}
BLOCKING_DECISIONS = {"deny", "require_approval", "rewrite"}
STATE_PATH = Path(__file__).with_name("kenning-guard-state.json")
LOCK_PATH = Path(__file__).with_name("kenning-guard-state.lock")
CREDENTIALS_PATH = Path(__file__).with_name("kenning-guard-credentials.json")
ENVIRONMENT_ALIASES = {
    "development": {"development", "prototype"},
    "staging": {"staging"},
    "production": {"production"},
}


class GuardHTTPError(RuntimeError):
    """An HTTP response from Guard that rejected the request."""

    def __init__(self, status, payload):
        super().__init__(f"Guard returned HTTP {status}")
        self.status = int(status)
        self.payload = payload if isinstance(payload, dict) else {}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def read_state():
    try:
        with STATE_PATH.open(encoding="utf-8") as handle:
            value = json.load(handle)
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def write_state(state):
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix="kenning-guard-state-", dir=STATE_PATH.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(state, handle, indent=2)
            handle.write("\n")
        os.replace(temporary, STATE_PATH)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


@contextlib.contextmanager
def locked_state():
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOCK_PATH.open("a+", encoding="utf-8") as lock:
        os.chmod(LOCK_PATH, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = read_state()
        state.setdefault("pending_approvals", {})
        state.setdefault("executions", {})
        now = time.time()
        state["pending_approvals"] = {
            key: value for key, value in state["pending_approvals"].items()
            if now - float(value.get("created_at", now)) < 1800
        }
        state["executions"] = {
            key: value for key, value in state["executions"].items()
            if now - float(value.get("created_at", now)) < 3600
        }
        try:
            yield state
        finally:
            write_state(state)
            fcntl.flock(lock, fcntl.LOCK_UN)


def credential_file_values():
    if not CREDENTIALS_PATH.exists():
        return None
    try:
        with CREDENTIALS_PATH.open(encoding="utf-8") as handle:
            values = json.load(handle)
    except (OSError, ValueError) as exc:
        raise RuntimeError("Kenning Agent Guard credentials file is invalid") from exc
    if not isinstance(values, dict):
        raise RuntimeError("Kenning Agent Guard credentials file is invalid")
    return values


def required_environment():
    stored = credential_file_values()
    if stored is None:
        values = {
            "api_url": os.environ.get("KENNING_API_URL", "").rstrip("/"),
            "pat": os.environ.get("KENNING_PAT", ""),
            "tenant_id": os.environ.get("KENNING_TENANT_ID", ""),
            "environment": os.environ.get("KENNING_ENVIRONMENT", "development"),
            "agent_id": os.environ.get("KENNING_AGENT_ID", "codex-cli-agent"),
            "invoked_by": os.environ.get("KENNING_INVOKED_BY", "codex-cli"),
        }
    else:
        values = {
            "api_url": str(stored.get("api_url") or "").rstrip("/"),
            "pat": str(stored.get("pat") or ""),
            "tenant_id": str(stored.get("tenant_id") or ""),
            "environment": str(stored.get("environment") or "development"),
            "agent_id": str(stored.get("agent_id") or "codex-cli-agent"),
            "invoked_by": str(stored.get("invoked_by") or "codex-cli"),
        }
    # A CLI environment can replace stale protected-file values. This keeps
    # Codex Desktop independent of the shell while giving operators a safe
    # recovery path when a token or endpoint changes.
    overrides = {
        "api_url": os.environ.get("KENNING_API_URL"),
        "pat": os.environ.get("KENNING_PAT"),
        "tenant_id": os.environ.get("KENNING_TENANT_ID"),
        "environment": os.environ.get("KENNING_ENVIRONMENT"),
        "agent_id": os.environ.get("KENNING_AGENT_ID"),
        "invoked_by": os.environ.get("KENNING_INVOKED_BY"),
    }
    for key, override in overrides.items():
        if override:
            values[key] = override.rstrip("/") if key == "api_url" else override
    if not values["api_url"] or not values["pat"] or not values["tenant_id"]:
        raise RuntimeError("Kenning Agent Guard API URL, PAT, and tenant ID must be configured")
    return values


def normalise_action(tool_name, tool_input, cwd):
    mapped = TOOL_MAP.get(tool_name)
    if mapped is None:
        return None
    tool, operation = mapped
    raw = dict(tool_input) if isinstance(tool_input, dict) else {}
    for field in ("content", "old_string", "new_string", "patch", "patchText", "patch_text"):
        value = raw.pop(field, None)
        if isinstance(value, str):
            raw[f"{field}_length"] = len(value)
            raw[f"{field}_sha256"] = "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()
    if tool == "shell":
        raw["command"] = str(raw.get("command") or raw.get("cmd") or raw.get("shell_command") or "")
        raw["cwd"] = str(raw.get("cwd") or raw.get("workdir") or cwd)
        return {"tool": tool, "operation": operation, "parameters": raw}
    path = str(raw.get("file_path") or raw.get("filePath") or raw.get("path") or raw.get("directory") or cwd)
    raw["path"] = path
    return {"tool": tool, "operation": operation, "target": path, "parameters": raw}


def fingerprint(tool_name, tool_input, context):
    return hashlib.sha256(canonical({
        "tool_name": tool_name,
        "tool_input": tool_input if isinstance(tool_input, dict) else {},
        "cwd": context["cwd"],
        "tenant_id": context["tenant_id"],
        "environment": context["environment"],
        "agent_id": context["agent_id"],
        "invoked_by": context["invoked_by"],
    }).encode("utf-8")).hexdigest()


def request(environment, path, payload):
    request_data = json.dumps(payload).encode("utf-8")
    request_object = urllib.request.Request(
        f"{environment['api_url']}{path}",
        data=request_data,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {environment['pat']}",
            "Content-Type": "application/json",
            "X-Kenning-Tenant-Id": environment["tenant_id"],
        },
    )
    try:
        with urllib.request.urlopen(request_object, timeout=25) as response:
            return json.loads(response.read() or b"{}")
    except HTTPError as exc:
        try:
            payload = json.loads(exc.read() or b"{}")
        except (OSError, ValueError):
            payload = {}
        raise GuardHTTPError(exc.code, payload) from exc



def health_diagnostic(environment):
    """Return a safe health summary for a failed action request."""

    health_request = urllib.request.Request(
        f"{environment['api_url']}/health",
        headers={"Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(health_request, timeout=5) as response:
            payload = json.loads(response.read() or b"{}")
    except HTTPError as exc:
        return f"health endpoint returned HTTP {exc.code}"
    except Exception:
        return "health endpoint could not be reached"
    if not isinstance(payload, dict):
        return "health endpoint returned an invalid response"
    if payload.get("status") != "ok":
        return "health endpoint did not report status ok"
    if payload.get("service") not in (None, "kenning-agent-guard"):
        return "configured endpoint is not Kenning Agent Guard"
    actual = str(payload.get("environment") or "").strip().lower()
    expected = str(environment.get("environment") or "development").strip().lower()
    allowed = ENVIRONMENT_ALIASES.get(expected, {expected})
    if actual and actual not in allowed:
        return f"endpoint environment is {actual}, expected {expected}"
    release_id = str(payload.get("release_id") or "").strip()
    release_text = f" release {release_id}" if release_id else ""
    return f"health check passed for {actual or expected}{release_text}"


def guard_failure_message(environment, error):
    """Return a safe and actionable message for a failed Guard request."""

    if isinstance(error, GuardHTTPError):
        if error.status == 401:
            message = "Guard authentication failed (HTTP 401); refresh KENNING_PAT for this environment"
        elif error.status == 403:
            message = "Guard authorization failed (HTTP 403); check KENNING_TENANT_ID and token scope"
        elif error.status >= 500:
            message = f"Guard service returned HTTP {error.status}"
        else:
            message = f"Guard rejected the request (HTTP {error.status})"
    else:
        message = "Guard endpoint could not be reached; check KENNING_API_URL and network access"
    return f"{message}; {health_diagnostic(environment)}"


def hook_input():
    try:
        value = json.load(sys.stdin)
    except Exception as exc:
        raise RuntimeError("could not parse Codex hook input") from exc
    if not isinstance(value, dict):
        raise RuntimeError("Codex hook input must be an object")
    return value


def call_key(hook, action_fingerprint):
    return str(hook.get("tool_use_id") or hook.get("tool_call_id") or f"fingerprint:{action_fingerprint}")


def block_result(reason):
    # Codex accepts a JSON decision only when the hook blocks. Successful
    # hooks must return no stdout. The Claude-style `approve` response is not
    # valid Codex hook output.
    print(json.dumps({"decision": "block", "reason": reason}))


def approval_failure_reason(error):
    """Return a safe operator message for an application-level rejection."""

    payload = error.payload
    error_code = str(payload.get("error") or "")
    approval_status = str(payload.get("status") or "")
    if approval_status in {"denied", "expired", "revoked"}:
        return f"approval {approval_status}"
    if error_code == "approval_not_approved":
        return "approval is not approved"
    if error_code == "approval_expired_or_already_decided":
        return "approval expired or already decided"
    if error_code == "approval_not_found":
        return "approval not found"
    if error_code == "approval_action_mismatch":
        return "approval does not match this tool call"
    return f"Guard rejected the approval retry (HTTP {error.status})"


def main():
    try:
        hook = hook_input()
        environment = required_environment()
        tool_name = str(hook.get("tool_name") or "")
        tool_input = hook.get("tool_input") if isinstance(hook.get("tool_input"), dict) else {}
        cwd = str(hook.get("cwd") or os.getcwd())
        action = normalise_action(tool_name, tool_input, cwd)
        if action is None:
            return 0
        event = str(hook.get("hook_event_name") or "PreToolUse")
        context_base = {
            "tenant_id": environment["tenant_id"],
            "environment": environment["environment"],
            "agent_id": environment["agent_id"],
            "invoked_by": environment["invoked_by"],
            "cwd": cwd,
        }
        action_fingerprint = fingerprint(tool_name, tool_input, context_base)
        key = call_key(hook, action_fingerprint)

        if event == "PostToolUse":
            with locked_state() as state:
                record = state["executions"].pop(key, None)
                if record is not None:
                    try:
                        request(environment, f"/v1/actions/{record['action_id']}/outcome", {
                            "context": record["context"],
                            "status": "success",
                            "action_hash": record.get("action_hash"),
                            "approval_id": record.get("approval_id"),
                            "proof_id": record.get("proof_id"),
                            "result": {"hook_event": event, "tool_name": tool_name},
                        })
                    except Exception as exc:
                        state["executions"][key] = record
                        print(f"Kenning Agent Guard outcome recording failed ({exc}); action already completed.", file=sys.stderr)
            return 0

        with locked_state() as state:
            pending = state["pending_approvals"].get(action_fingerprint)
            action_id = pending.get("action_id") if pending else f"codex-action-{uuid.uuid4().hex}"
            run_id = pending.get("run_id") if pending else f"codex-run-{uuid.uuid4().hex}"
            approval_id = str(pending.get("approval_id") or "") if pending else ""
            context = {**context_base, "action_id": action_id, "run_id": run_id}
            payload = {"context": context, "action": action}
            if pending:
                payload["approval_id"] = pending["approval_id"]
                payload["action_hash"] = pending["action_hash"]
            try:
                result = request(environment, "/v1/actions/evaluate", payload)
            except GuardHTTPError as exc:
                if 400 <= exc.status < 500:
                    state["pending_approvals"].pop(action_fingerprint, None)
                    if approval_id:
                        reason = approval_failure_reason(exc)
                        approval_text = f" Approval ID {approval_id}." if approval_id else ""
                    else:
                        reason = guard_failure_message(environment, exc)
                        approval_text = ""
                    block_result(f"Kenning Agent Guard: {reason}.{approval_text} The tool call was blocked.")
                    print(f"Kenning Agent Guard blocked the tool call: {reason}.{approval_text}", file=sys.stderr)
                    return 0
                reason = guard_failure_message(environment, exc)
                block_result(f"Kenning Agent Guard: {reason}. The tool call was blocked.")
                print(f"Kenning Agent Guard blocked the tool call: {reason}.", file=sys.stderr)
                return 0
            except Exception as exc:
                reason = guard_failure_message(environment, exc)
                block_result(f"Kenning Agent Guard: {reason}. The tool call was blocked.")
                print(f"Kenning Agent Guard blocked the tool call: {reason}.", file=sys.stderr)
                return 0

            decision = str(result.get("decision") or "deny")
            approval = result.get("approval") if isinstance(result.get("approval"), dict) else {}
            approval_id = str(result.get("approval_id") or approval.get("approval_id") or "")
            action_hash = str(result.get("action_hash") or approval.get("action_hash") or "")
            if decision in {"allow", "warn", "observe"}:
                state["pending_approvals"].pop(action_fingerprint, None)
                state["executions"][key] = {
                    "created_at": time.time(),
                    "action_id": action_id,
                    "context": context,
                    "action_hash": action_hash,
                    "approval_id": approval_id or None,
                    "proof_id": result.get("proof_id"),
                }
                if decision != "allow":
                    print(f"Kenning Agent Guard: {decision} — tool call allowed with warning.", file=sys.stderr)
                return 0

            if decision == "require_approval" and approval_id and action_hash:
                state["pending_approvals"][action_fingerprint] = {
                    "created_at": time.time(),
                    "action_id": action_id,
                    "run_id": run_id,
                    "approval_id": approval_id,
                    "action_hash": action_hash,
                }
            else:
                state["pending_approvals"].pop(action_fingerprint, None)
            reasons = result.get("reason_codes") if isinstance(result.get("reason_codes"), list) else []
            reason_text = ", ".join(str(reason) for reason in reasons) or decision
            approval_text = f" Approval ID {approval_id}; retry this exact tool call after approval." if approval_id else ""
            block_result(f"Kenning Agent Guard: {decision} — {reason_text}.{approval_text}")
            print(f"Kenning Agent Guard blocked the tool call ({decision}).{approval_text}", file=sys.stderr)
            return 0
    except Exception as exc:
        block_result("Kenning Agent Guard hook failed closed; the tool call was blocked.")
        print(f"Kenning Agent Guard hook failed closed ({exc}).", file=sys.stderr)
        return 0


if __name__ == "__main__":
    sys.exit(main())
