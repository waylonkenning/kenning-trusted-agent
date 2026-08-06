#!/usr/bin/env bash
set -euo pipefail

# Kenning Agent Guard installer.
#
# Configures OpenCode, Claude Code, or Codex CLI to evaluate tool actions
# through Kenning Agent Guard before they run.
#
# Usage:
#   curl -fsSL https://<kenning-host>/install/agent-guard/install.sh | bash -s -- --client claude-code
#
# Or inspect first:
#   curl -fsSL https://<kenning-host>/install/agent-guard/install.sh -o install.sh
#   less install.sh
#   bash install.sh --client opencode
#
# Required environment variables:
#   KENNING_API_URL    Control-plane API base URL
#   KENNING_PAT        Personal access token (stored in Codex's protected JSON file)
#   KENNING_TENANT_ID  Workspace/tenant identifier
#
# Optional:
#   KENNING_MCP_URL       MCP endpoint (defaults to $KENNING_API_URL/mcp)
#   KENNING_AGENT_ID      Agent identity (defaults per client)
#   KENNING_ENVIRONMENT   development | staging | production
#   KENNING_INVOKED_BY    Caller identifier

CLIENT=""
PROJECT_DIR="${KENNING_PROJECT_DIR:-$PWD}"
UNINSTALL=false

while [ $# -gt 0 ]; do
  case "$1" in
    --client) CLIENT="${2:?'--client requires a value'}"; shift 2 ;;
    --client=*) CLIENT="${1#*=}"; shift ;;
    --project-dir) PROJECT_DIR="${2:?'--project-dir requires a value'}"; shift 2 ;;
    --project-dir=*) PROJECT_DIR="${1#*=}"; shift ;;
    --uninstall) UNINSTALL=true; shift ;;
    --help|-h)
      echo "Usage: install.sh --client <opencode|claude-code|codex-cli> [--project-dir DIR] [--uninstall]"
      echo ""
      echo "Required environment: KENNING_API_URL, KENNING_PAT, KENNING_TENANT_ID"
      echo "Optional environment: KENNING_MCP_URL, KENNING_AGENT_ID, KENNING_ENVIRONMENT"
      exit 0
      ;;
    *) echo "kenning-agent-guard: unknown option: $1" >&2; exit 1 ;;
  esac
done

BACKUP_SUFFIX="$(date -u +%Y%m%dT%H%M%SZ)"

die() { echo "kenning-agent-guard: $*" >&2; exit 1; }

backup_file() {
  local path="$1"
  if [ -e "$path" ]; then
    cp -p "$path" "${path}.kenning-backup-${BACKUP_SUFFIX}"
    echo "  Backed up $(basename "$path")"
  fi
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1. Install it and try again."
}

# --- Validate client ---
if [ -z "$CLIENT" ]; then
  die "--client is required. Supported: opencode, claude-code, codex-cli"
fi
case "$CLIENT" in
  opencode|claude-code|codex-cli) ;;
  *) die "unsupported client: $CLIENT. Supported: opencode, claude-code, codex-cli" ;;
esac

# --- Validate prerequisites ---
require_command python3

if [ "$UNINSTALL" = false ]; then
  [ -n "${KENNING_API_URL:-}" ] || die "KENNING_API_URL must be exported before running the installer."
  [ -n "${KENNING_PAT:-}" ] || die "KENNING_PAT must be exported before running the installer so Codex can store it in the protected JSON file."
  [ -n "${KENNING_TENANT_ID:-}" ] || die "KENNING_TENANT_ID must be exported before running the installer."
fi

KENNING_API_URL="${KENNING_API_URL:-}"
KENNING_MCP_URL="${KENNING_MCP_URL:-${KENNING_API_URL%/}/mcp}"
KENNING_MCP_URL="${KENNING_MCP_URL%/mcp}/mcp"
DEFAULT_AGENT_ID="opencode-development-agent"
case "$CLIENT" in
  claude-code) DEFAULT_AGENT_ID="claude-code-development-agent" ;;
  codex-cli) DEFAULT_AGENT_ID="codex-cli-development-agent" ;;
esac
KENNING_AGENT_ID="${KENNING_AGENT_ID:-$DEFAULT_AGENT_ID}"
KENNING_ENVIRONMENT="${KENNING_ENVIRONMENT:-development}"
KENNING_INVOKED_BY="${KENNING_INVOKED_BY:-$CLIENT}"

if [ ! -d "$PROJECT_DIR" ]; then
  die "project directory does not exist: $PROJECT_DIR"
fi
PROJECT_DIR="$(cd "$PROJECT_DIR" && pwd)"

# --- Uninstall ---
if [ "$UNINSTALL" = true ]; then
  echo "Removing Kenning Agent Guard configuration for $CLIENT..."
  case "$CLIENT" in
    opencode)
      rm -f "$PROJECT_DIR/.opencode/plugins/kenning-agent-guard-plugin.js"
      rm -f "$PROJECT_DIR/AGENTS.kenning.md"
      echo "  Removed plugin and instruction file."
      echo "  Review $PROJECT_DIR/opencode.json to remove Kenning MCP entries if present."
      ;;
    claude-code)
      rm -f "$PROJECT_DIR/CLAUDE.kenning.md"
      rm -f "$PROJECT_DIR/.claude/kenning-guard-hook.py" \
        "$PROJECT_DIR/.claude/kenning-guard-state.json" \
        "$PROJECT_DIR/.claude/kenning-guard-state.lock"
      if [ -f "$PROJECT_DIR/.claude/settings.json" ]; then
        backup_file "$PROJECT_DIR/.claude/settings.json"
        python3 - "$PROJECT_DIR/.claude/settings.json" <<'PY'
import json
import sys

target = sys.argv[1]
with open(target, encoding="utf-8") as handle:
    config = json.load(handle)

managed_hook = "kenning-guard-hook.py"
for event in ("PreToolUse", "PostToolUse", "PostToolUseFailure"):
    groups = config.get("hooks", {}).get(event, [])
    kept_groups = []
    for group in groups:
        kept_hooks = [
            hook for hook in group.get("hooks", [])
            if managed_hook not in str(hook.get("command") or "")
        ]
        if kept_hooks:
            group["hooks"] = kept_hooks
            kept_groups.append(group)
    if groups:
        config.setdefault("hooks", {})[event] = kept_groups

hooks = config.get("hooks", {})
if hooks:
    config["hooks"] = {key: value for key, value in hooks.items() if value}
if not config.get("hooks"):
    config.pop("hooks", None)

mcp_servers = config.get("mcpServers", {})
if isinstance(mcp_servers, dict):
    mcp_servers.pop("kenning-agent-guard", None)
    if mcp_servers:
        config["mcpServers"] = mcp_servers
    else:
        config.pop("mcpServers", None)

with open(target, "w", encoding="utf-8") as handle:
    json.dump(config, handle, indent=2)
    handle.write("\n")
PY
      fi
      echo "  Removed instruction, hook, state, and Kenning settings entries."
      ;;
    codex-cli)
      rm -f "$PROJECT_DIR/AGENTS.kenning.md"
      rm -f "$PROJECT_DIR/.codex/kenning-guard-hook.py" \
        "$PROJECT_DIR/.codex/kenning-agent-guard-mcp.py" \
        "$PROJECT_DIR/.codex/kenning-guard-credentials.json" \
        "$PROJECT_DIR/.codex/kenning-guard-state.json" \
        "$PROJECT_DIR/.codex/kenning-guard-state.lock"
      if [ -f "$PROJECT_DIR/.gitignore" ]; then
        backup_file "$PROJECT_DIR/.gitignore"
        python3 - "$PROJECT_DIR/.gitignore" <<'PY'
import os
import re
import sys

target = sys.argv[1]
with open(target, encoding="utf-8") as handle:
    text = handle.read()
text = re.sub(
    r"\n?# >>> kenning-agent-guard managed credentials >>>.*?# <<< kenning-agent-guard managed credentials <<<\n?",
    "\n",
    text,
    flags=re.DOTALL,
)
if text.strip():
    with open(target, "w", encoding="utf-8") as handle:
        handle.write(text.rstrip() + "\n")
else:
    os.unlink(target)
PY
      fi
      if [ -f "$PROJECT_DIR/.codex/hooks.json" ]; then
        backup_file "$PROJECT_DIR/.codex/hooks.json"
        python3 - "$PROJECT_DIR/.codex/hooks.json" <<'PY'
import json
import sys

target = sys.argv[1]
with open(target, encoding="utf-8") as handle:
    config = json.load(handle)

hooks = config.get("hooks", {})
managed = "kenning-guard-hook.py"
for event in ("PreToolUse", "PostToolUse"):
    groups = hooks.get(event, [])
    kept_groups = []
    for group in groups:
        kept_hooks = [
            hook for hook in group.get("hooks", [])
            if managed not in str(hook.get("command") or "")
        ]
        if kept_hooks:
            group["hooks"] = kept_hooks
            kept_groups.append(group)
    if kept_groups:
        hooks[event] = kept_groups
    else:
        hooks.pop(event, None)
if hooks:
    config["hooks"] = hooks
else:
    config.pop("hooks", None)

with open(target, "w", encoding="utf-8") as handle:
    json.dump(config, handle, indent=2)
    handle.write("\n")
PY
      fi
      if [ -f "$PROJECT_DIR/.codex/config.toml" ]; then
        backup_file "$PROJECT_DIR/.codex/config.toml"
        python3 - "$PROJECT_DIR/.codex/config.toml" <<'PY'
import json
import re
import sys

target = sys.argv[1]
with open(target, encoding="utf-8") as handle:
    text = handle.read()

managed_begin = "# >>> kenning-agent-guard managed block >>>"
managed_end = "# <<< kenning-agent-guard managed block <<<"
text = re.sub(
    rf"\n?{re.escape(managed_begin)}.*?{re.escape(managed_end)}\n?",
    "\n",
    text,
    flags=re.DOTALL,
)
text = re.sub(
    r"(?ms)^\[mcp_servers\.kenning-agent-guard\]\n.*?(?=^\[|\Z)",
    "",
    text,
)

fallback_match = re.search(r"(?m)^project_doc_fallback_filenames\s*=\s*\[(.*?)\]\s*$", text)
if fallback_match:
    names = re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', fallback_match.group(1))
    names = [name for name in names if name != "AGENTS.kenning.md"]
    replacement = "" if not names else "project_doc_fallback_filenames = [" + ", ".join(json.dumps(name) for name in names) + "]\n"
    text = text[:fallback_match.start()] + replacement + text[fallback_match.end():]

with open(target, "w", encoding="utf-8") as handle:
    handle.write(text.lstrip())
PY
      fi
      if [ -f "$PROJECT_DIR/.codex/config.json" ]; then
        backup_file "$PROJECT_DIR/.codex/config.json"
        python3 - "$PROJECT_DIR/.codex/config.json" <<'PY'
import json
import sys

target = sys.argv[1]
with open(target, encoding="utf-8") as handle:
    config = json.load(handle)

mcp_servers = config.get("mcpServers", {})
if isinstance(mcp_servers, dict):
    mcp_servers.pop("kenning-agent-guard", None)
    if mcp_servers:
        config["mcpServers"] = mcp_servers
    else:
        config.pop("mcpServers", None)
instructions = config.get("instructions", [])
if isinstance(instructions, list):
    instructions = [item for item in instructions if item != "./AGENTS.kenning.md"]
    if instructions:
        config["instructions"] = instructions
    else:
        config.pop("instructions", None)

with open(target, "w", encoding="utf-8") as handle:
    json.dump(config, handle, indent=2)
    handle.write("\n")
PY
      fi
      echo "  Removed instruction, hook, state, and Kenning MCP entries."
      ;;
  esac
  echo "Kenning Agent Guard removed for $CLIENT. Backups from installation are preserved."
  exit 0
fi

# --- Verify API connectivity ---
echo "Verifying Kenning Agent Guard connectivity..."
HEALTH_RESPONSE="$(curl --silent --show-error --max-time 10 \
  -H "Authorization: Bearer ${KENNING_PAT}" \
  -H "X-Kenning-Tenant-Id: ${KENNING_TENANT_ID}" \
  "${KENNING_API_URL%/}/health" 2>/dev/null || true)"
if [ -z "$HEALTH_RESPONSE" ]; then
  die "cannot reach $KENNING_API_URL — check the URL and your network connection."
fi
if ! HEALTH_VALIDATION="$(printf '%s' "$HEALTH_RESPONSE" | KENNING_EXPECTED_ENVIRONMENT="${KENNING_ENVIRONMENT}" python3 -c '
import json
import os
import sys

try:
    payload = json.load(sys.stdin)
except (TypeError, ValueError):
    print("health endpoint returned invalid JSON")
    raise SystemExit(1)

if payload.get("status") != "ok":
    print("health endpoint did not report status ok")
    raise SystemExit(1)
if payload.get("service") not in (None, "kenning-agent-guard"):
    print("configured endpoint is not Kenning Agent Guard")
    raise SystemExit(1)

expected = str(os.environ.get("KENNING_EXPECTED_ENVIRONMENT") or "development").strip().lower()
actual = str(payload.get("environment") or "").strip().lower()
allowed = {
    "development": {"development", "prototype"},
    "staging": {"staging"},
    "production": {"production"},
}.get(expected, {expected})
if actual and actual not in allowed:
    print(f"endpoint environment is {actual}; expected {expected}")
    raise SystemExit(1)

print("ok")
')"; then
  die "${HEALTH_VALIDATION:-health endpoint validation failed.}"
fi
echo "  Guard health check passed for ${KENNING_ENVIRONMENT}."

# --- Client-specific installation ---
case "$CLIENT" in
opencode)
  echo "Installing Kenning Agent Guard for OpenCode..."
  mkdir -p "$PROJECT_DIR/.opencode/plugins"

  # Write the fail-closed OpenCode enforcement plugin.
  # This must remain equivalent to integrations/opencode/kenning-agent-guard-plugin.js.
  cat > "$PROJECT_DIR/.opencode/plugins/kenning-agent-guard-plugin.js" <<'PLUGIN'
/*
 * OpenCode plugin for synchronous Kenning Agent Guard enforcement.
 *
 * The plugin evaluates the built-in development tools before OpenCode runs
 * them and records the execution outcome afterward. It intentionally keeps
 * the PAT in the process environment; the launcher used by the EC2 test
 * environment retrieves that value from AWS Secrets Manager at startup.
 */

import { createHash } from "node:crypto"

const BLOCKING_DECISIONS = new Set(["deny", "require_approval", "rewrite"])
const GUARDED_TOOLS = new Set(["bash", "edit", "write", "apply_patch", "read", "grep", "glob"])

function requiredEnv(name) {
  const value = String(globalThis.process?.env?.[name] || "").trim()
  if (!value) throw new Error(`Kenning Agent Guard integration requires ${name}.`)
  return value
}

function optionalEnv(name, fallback) {
  const value = String(globalThis.process?.env?.[name] || "").trim()
  return value || fallback
}

function actionId(input) {
  return String(input?.callID || `opencode-${Date.now()}-${Math.random().toString(16).slice(2)}`)
}

function stringLength(value) {
  return typeof value === "string" ? value.length : 0
}

function stringHash(value) {
  if (typeof value !== "string") return null
  return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`
}

function patchTargets(patchText) {
  if (typeof patchText !== "string") return []
  const targets = []
  for (const line of patchText.split("\n")) {
    const match = line.match(/^\*\*\* (?:Add|Update|Delete) File: (.+)$/)
    if (match) targets.push(match[1].trim())
  }
  return [...new Set(targets)].slice(0, 50)
}

function actionForTool(tool, args, directory) {
  const parameters = args && typeof args === "object" ? args : {}
  if (tool === "bash") {
    return {
      tool: "shell",
      operation: "execute",
      parameters: {
        command: String(parameters.command || parameters.cmd || ""),
        cwd: String(parameters.cwd || parameters.workdir || directory || ""),
      },
    }
  }

  if (tool === "edit") {
    const path = String(parameters.filePath || parameters.path || "")
    return {
      tool: "filesystem",
      operation: "modify",
      target: path,
      parameters: {
        path,
        old_string_length: stringLength(parameters.oldString),
        old_string_sha256: stringHash(parameters.oldString),
        new_string_length: stringLength(parameters.newString),
        new_string_sha256: stringHash(parameters.newString),
        replace_all: Boolean(parameters.replaceAll),
      },
    }
  }

  if (tool === "write") {
    const path = String(parameters.filePath || parameters.path || "")
    return {
      tool: "filesystem",
      operation: "write",
      target: path,
      parameters: {
        path,
        content_length: stringLength(parameters.content),
        content_sha256: stringHash(parameters.content),
      },
    }
  }

  if (tool === "apply_patch") {
    const targets = patchTargets(parameters.patchText)
    return {
      tool: "filesystem",
      operation: "modify",
      target: targets[0] || "patch",
      parameters: {
        paths: targets,
        patch_length: stringLength(parameters.patchText),
        patch_sha256: stringHash(parameters.patchText),
      },
    }
  }

  if (tool === "read") {
    const path = String(parameters.filePath || parameters.path || "")
    return { tool: "filesystem", operation: "read", target: path, parameters: { path } }
  }

  if (tool === "grep" || tool === "glob") {
    const path = String(parameters.path || parameters.directory || directory || "")
    const pattern = String(parameters.pattern || parameters.query || "")
    return { tool: "filesystem", operation: "read", target: path, parameters: { path, pattern } }
  }

  return null
}

function safeOutput(output) {
  if (!output || typeof output !== "object") return { type: typeof output }
  return {
    keys: Object.keys(output).slice(0, 20),
    has_error: Boolean(output.error || output.isError),
  }
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue)
  if (!value || typeof value !== "object") return value
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableValue(value[key])]))
}

function actionKey(action) {
  return JSON.stringify(stableValue(action))
}

export const KenningAgentGuard = async ({ client, directory }) => {
  const apiUrl = requiredEnv("KENNING_API_URL").replace(/\/$/, "")
  const pat = requiredEnv("KENNING_PAT")
  const tenantId = requiredEnv("KENNING_TENANT_ID")
  const environment = optionalEnv("KENNING_ENVIRONMENT", "development")
  const agentId = optionalEnv("KENNING_AGENT_ID", "opencode-development-agent")
  const invokedBy = optionalEnv("KENNING_INVOKED_BY", "opencode")
  const mode = optionalEnv("KENNING_GUARD_MODE", "enforce")
  const pending = new Map()
  const blockedApprovals = new Map()

  async function log(level, message, extra = {}) {
    try {
      if (client?.app?.log) {
        await client.app.log({ body: { service: "kenning-agent-guard", level, message, extra } })
      } else {
        console.error(`[kenning-agent-guard] ${message}`)
      }
    } catch {
      // Logging must never reveal credentials or change enforcement behavior.
    }
  }

  async function request(path, payload) {
    const response = await fetch(`${apiUrl}${path}`, {
      method: "POST",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${pat}`,
        "Content-Type": "application/json",
        "X-Kenning-Tenant-Id": tenantId,
      },
      body: JSON.stringify(payload),
    })
    const raw = await response.text()
    let body
    try {
      body = raw ? JSON.parse(raw) : {}
    } catch {
      body = { error: raw.slice(0, 400) }
    }
    if (!response.ok) {
      throw new Error(`Kenning Agent Guard returned HTTP ${response.status}: ${body.error || "request failed"}`)
    }
    return body
  }

  return {
    "tool.execute.before": async (input, output) => {
      const tool = String(input?.tool || "")
      if (!GUARDED_TOOLS.has(tool)) return

      const callId = actionId(input)
      const action = actionForTool(tool, output?.args, directory)
      if (!action) return
      const key = actionKey(action)
      const priorApproval = blockedApprovals.get(key)
      const evaluationId = priorApproval?.approval?.action_id || callId
      const context = {
        tenant_id: tenantId,
        environment,
        agent_id: agentId,
        invoked_by: invokedBy,
        run_id: String(input?.sessionID || `opencode-run-${Date.now()}`),
        action_id: evaluationId,
        mode,
      }
      const payload = {
        context: priorApproval ? { ...priorApproval.context, action_id: evaluationId } : context,
        mode,
        action,
        intent: priorApproval?.approval?.intent || "Develop and test software safely.",
      }
      if (priorApproval) {
        payload.approval_id = priorApproval.approval.approval_id
        payload.action_hash = priorApproval.approval.action_hash
      }

      let decision
      try {
        decision = await request("/v1/actions/evaluate", payload)
      } catch (error) {
        await log("error", "Guard evaluation failed; blocking the tool call.", { tool, action_id: evaluationId })
        throw new Error(`Kenning Agent Guard unavailable; tool call blocked. ${error.message}`)
      }

      const approval = decision?.approval
      const approvalId = String(decision?.approval_id || approval?.approval_id || priorApproval?.approval?.approval_id || "")
      const executionContext = priorApproval ? { ...priorApproval.context, action_id: evaluationId } : context
      pending.set(callId, { context: executionContext, action, decision, approval_id: approvalId })
      const result = String(decision?.decision || "")
      const observeOnly = optionalEnv("KENNING_GUARD_OBSERVE_ONLY", "false").toLowerCase() === "true"
      if (priorApproval && result === "allow") {
        blockedApprovals.delete(key)
      }
      if (BLOCKING_DECISIONS.has(result) && !observeOnly) {
        if (result === "require_approval" && approvalId) {
          blockedApprovals.set(key, {
            context: executionContext,
            approval: approval || {
              approval_id: approvalId,
              action_id: evaluationId,
              action_hash: decision?.action_hash,
              intent: payload.intent,
            },
          })
        }
        const reasons = Array.isArray(decision.reason_codes) ? decision.reason_codes.join(", ") : "policy decision"
        const suggestion = decision.recommended_action?.suggestion || decision.rewrite?.suggestion || ""
        const approvalMessage = result === "require_approval" && approvalId
          ? `. Approval ID ${approvalId}; retry this exact tool call after an operator approves it.`
          : ""
        throw new Error(`Kenning Agent Guard blocked ${tool} (${result}): ${reasons}${suggestion ? `. ${suggestion}` : ""}${approvalMessage}`)
      }
      if (!new Set(["allow", "warn", "observe", "deny", "require_approval", "rewrite"]).has(result)) {
        throw new Error("Kenning Agent Guard returned an unknown decision; tool call blocked.")
      }
      if (result === "warn" || result === "observe") {
        await log("warn", "Guard allowed a tool call with a warning/observe decision.", { tool, action_id: callId, decision: result })
      }
    },

    "tool.execute.after": async (input, output) => {
      const id = actionId(input)
      const record = pending.get(id)
      if (!record) return
      pending.delete(id)
      const status = output?.error || output?.isError ? "failure" : "success"
      try {
        const evaluationId = String(record.context?.action_id || id)
        await request(`/v1/actions/${encodeURIComponent(evaluationId)}/outcome`, {
          context: record.context,
          status,
          action_hash: record.decision?.action_hash,
          proof_id: record.decision?.proof_id,
          approval_id: record.approval_id || record.decision?.approval_id,
          result: safeOutput(output),
        })
      } catch {
        await log("warn", "Guard outcome recording failed after the tool completed.", { tool: input?.tool, action_id: id })
      }
    },
  }
}
PLUGIN
  chmod 600 "$PROJECT_DIR/.opencode/plugins/kenning-agent-guard-plugin.js"

  # Write instructions that describe the local enforcement boundary.
  cat > "$PROJECT_DIR/AGENTS.kenning.md" <<'AGENTS'
# Kenning Agent Guard development agent

This workspace is connected to Kenning Agent Guard through the local OpenCode
plugin in `.opencode/plugins/kenning-agent-guard-plugin.js` and the remote
Kenning MCP server.

- Every `bash`, `read`, `grep`, `glob`, `edit`, `write`, and `apply_patch` call
  is evaluated by Kenning Agent Guard before execution.
- A `deny`, `require_approval`, or `rewrite` result is a hard stop. Do not
  retry by changing the command or hiding its scope; report the decision and
  wait for the operator to approve or change policy.
- When an operator approves a request, retry the exact original built-in tool
  call. The local plugin carries the original action ID and hash into Guard so
  the approval can be verified and consumed. Do not create a new command or
  add approval text to the command itself.
- A Guard outage is fail-closed. Do not execute the action manually when the
  Guard API cannot be reached.
- Do not call the MCP `evaluate_action` tool as a second pre-check for the
  built-in tools above. The local plugin is the authoritative pre-execution
  boundary and supplies the registered agent identity while recording the
  outcome. The OpenCode configuration denies this MCP tool deliberately. If a
  model attempts to call it for a built-in tool, do not treat that result as
  approval for the later `bash`, `edit`, or filesystem call; ask the model to
  retry the original built-in operation so the local plugin can create the
  correct approval request.
- Use the product-specific Kenning MCP tools for explicit work:
  `kenning-agent-guard` for action evaluations,
  `kenning-citation-trust_verify_citations` for citation verification, and
  the Proof server for provenance and receipt verification. For Citation
  Trust, call only `kenning-citation-trust_verify_citations` and do not include
  `tenant_id`, `environment`, or Guard action fields; the tenant is bound from
  the PAT. If making an explicit Guard evaluation, include the full tenant,
  environment, agent, and invoking-user context; never rely on the server's
  unregistered-agent default. To resume an approved MCP evaluation, pass the
  original `approval_id` and `action_hash` with the unchanged action.
- Do not print or commit `KENNING_PAT`, provider credentials, or secret values.
- This test agent runs without subagents so the pre-execution boundary is
  unambiguous while the integration is being validated.
AGENTS

  # Merge MCP config into opencode.json
  backup_file "$PROJECT_DIR/opencode.json"
  python3 - "$PROJECT_DIR/opencode.json" "$KENNING_MCP_URL" "$KENNING_TENANT_ID" <<'PY'
import json, os, sys
target, mcp_url, tenant_id = sys.argv[1:]
config = {}
if os.path.exists(target):
    with open(target, encoding="utf-8") as f:
        config = json.load(f)
mcp = config.setdefault("mcp", {})
mcp["kenning-agent-guard"] = {
    "type": "remote",
    "url": "{env:KENNING_MCP_URL}",
    "enabled": True,
    "headers": {
        "Authorization": "Bearer {env:KENNING_PAT}",
        "X-Kenning-Tenant-Id": "{env:KENNING_TENANT_ID}"
    }
}
permission = config.setdefault("permission", {})
permission.update({
    "bash": "allow",
    "edit": "allow",
    "write": "allow",
    "apply_patch": "allow",
    "read": "allow",
    "grep": "allow",
    "glob": "allow",
    "kenning-agent-guard_evaluate_action": "deny",
})
instructions = config.setdefault("instructions", [])
if "./AGENTS.kenning.md" not in instructions:
    instructions.append("./AGENTS.kenning.md")
with open(target, "w", encoding="utf-8") as f:
    json.dump(config, f, indent=2)
    f.write("\n")
PY
  ;;

claude-code)
  echo "Installing Kenning Agent Guard for Claude Code..."
  mkdir -p "$PROJECT_DIR/.claude"

  # Write the fail-closed enforcement hook.
  cat > "$PROJECT_DIR/.claude/kenning-guard-hook.py" <<'HOOK'
#!/usr/bin/env python3
"""Kenning Agent Guard hooks for Claude Code.

PreToolUse evaluates the exact Claude tool input and blocks deny,
require_approval, and rewrite decisions. Approval state is kept locally so a
new hook process can resume the same approved action. PostToolUse and
PostToolUseFailure record the result after Claude executes the action.

The state file contains action IDs, approval IDs, and hashes only; PATs and
provider credentials are read from the environment and never persisted.
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
import urllib.error
import urllib.request
import uuid

TOOL_MAP = {
    "Bash": ("shell", "execute"),
    "Write": ("filesystem", "write"),
    "Edit": ("filesystem", "modify"),
    "MultiEdit": ("filesystem", "modify"),
    "NotebookEdit": ("filesystem", "modify"),
    "Read": ("filesystem", "read"),
    "Grep": ("filesystem", "read"),
    "Glob": ("filesystem", "read"),
}
BLOCKING_DECISIONS = {"deny", "require_approval", "rewrite"}
STATE_PATH = Path(__file__).with_name("kenning-guard-state.json")
LOCK_PATH = Path(__file__).with_name("kenning-guard-state.lock")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def read_state():
    try:
        with STATE_PATH.open(encoding="utf-8") as handle:
            state = json.load(handle)
        if isinstance(state, dict):
            return state
    except (OSError, ValueError):
        pass
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
            key: value
            for key, value in state["pending_approvals"].items()
            if now - float(value.get("created_at", now)) < 1800
        }
        state["executions"] = {
            key: value
            for key, value in state["executions"].items()
            if now - float(value.get("created_at", now)) < 3600
        }
        try:
            yield state
        finally:
            write_state(state)
            fcntl.flock(lock, fcntl.LOCK_UN)


def required_environment():
    values = {
        "api_url": os.environ.get("KENNING_API_URL", "").rstrip("/"),
        "pat": os.environ.get("KENNING_PAT", ""),
        "tenant_id": os.environ.get("KENNING_TENANT_ID", ""),
        "environment": os.environ.get("KENNING_ENVIRONMENT", "development"),
        "agent_id": os.environ.get("KENNING_AGENT_ID", "claude-code-agent"),
        "invoked_by": os.environ.get("KENNING_INVOKED_BY", "claude-code"),
    }
    if not values["api_url"] or not values["pat"] or not values["tenant_id"]:
        raise RuntimeError("KENNING_API_URL, KENNING_PAT, and KENNING_TENANT_ID must be set.")
    return values


def normalise_action(tool_name, tool_input, cwd):
    mapped = TOOL_MAP.get(tool_name)
    if mapped is None:
        raise RuntimeError(f"unsupported Claude tool: {tool_name or 'unknown'}")
    tool, operation = mapped
    raw = dict(tool_input) if isinstance(tool_input, dict) else {}
    # Claude includes full file bodies and edit strings in Write/Edit/
    # NotebookEdit inputs. Never send those values to the evaluator: the
    # server may retain the original action for audit/capture. Preserve only
    # bounded metadata so the request remains useful without leaking content.
    text_fields = ("content", "old_string", "new_string", "new_source", "patchText", "patch_text")
    for field in text_fields:
        if field not in raw:
            continue
        value = raw.pop(field)
        if isinstance(value, str):
            raw[f"{field}_length"] = len(value)
            raw[f"{field}_sha256"] = "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()
    if tool == "shell":
        raw.setdefault("command", "")
        raw.setdefault("cwd", cwd)
        return {"tool": tool, "operation": operation, "parameters": raw}

    path = str(raw.get("file_path") or raw.get("filePath") or raw.get("notebook_path") or raw.get("path") or raw.get("directory") or cwd)
    raw["path"] = path
    return {"tool": tool, "operation": operation, "target": path, "parameters": raw}


def action_fingerprint(tool_name, tool_input, context):
    semantic = {
        "tool_name": tool_name,
        "tool_input": tool_input if isinstance(tool_input, dict) else {},
        "tenant_id": context["tenant_id"],
        "environment": context["environment"],
        "agent_id": context["agent_id"],
        "invoked_by": context["invoked_by"],
    }
    return hashlib.sha256(canonical(semantic).encode("utf-8")).hexdigest()


def request(environment, path, payload):
    request_data = json.dumps(payload).encode("utf-8")
    request_object = urllib.request.Request(
        f"{environment['api_url']}{path}",
        data=request_data,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {environment['pat']}",
            "X-Kenning-Tenant-Id": environment["tenant_id"],
        },
    )
    with urllib.request.urlopen(request_object, timeout=25) as response:
        return json.loads(response.read())


def hook_input():
    try:
        value = json.load(sys.stdin)
    except Exception as exc:
        raise RuntimeError("could not parse Claude hook input") from exc
    if not isinstance(value, dict):
        raise RuntimeError("Claude hook input must be an object")
    return value


def call_key(hook, fingerprint):
    return str(hook.get("tool_use_id") or hook.get("tool_call_id") or f"fingerprint:{fingerprint}")


def main():
    try:
        hook = hook_input()
        environment = required_environment()
        tool_name = str(hook.get("tool_name") or "")
        tool_input = hook.get("tool_input") if isinstance(hook.get("tool_input"), dict) else {}
        action = normalise_action(tool_name, tool_input, str(hook.get("cwd") or os.getcwd()))
        event = str(hook.get("hook_event_name") or "PreToolUse")
        context_base = {
            "tenant_id": environment["tenant_id"],
            "environment": environment["environment"],
            "agent_id": environment["agent_id"],
            "invoked_by": environment["invoked_by"],
        }
        fingerprint = action_fingerprint(tool_name, tool_input, context_base)
        key = call_key(hook, fingerprint)

        if event in {"PostToolUse", "PostToolUseFailure"}:
            with locked_state() as state:
                record = state["executions"].pop(key, None)
                if record is None:
                    return 0
                outcome = {
                    "context": record["context"],
                    "status": "failure" if event == "PostToolUseFailure" else "success",
                    "action_hash": record.get("action_hash"),
                    "approval_id": record.get("approval_id"),
                    "proof_id": record.get("proof_id"),
                    "result": {"hook_event": event, "tool_name": tool_name},
                }
                try:
                    request(environment, f"/v1/actions/{record['context']['action_id']}/outcome", outcome)
                except Exception as exc:
                    state["executions"][key] = record
                    print(f"Kenning Agent Guard outcome recording failed ({exc}).", file=sys.stderr)
            return 0

        with locked_state() as state:
            pending = state["pending_approvals"].get(fingerprint)
            action_id = pending.get("action_id") if pending else f"claude-action-{uuid.uuid4().hex}"
            run_id = pending.get("run_id") if pending else f"claude-run-{uuid.uuid4().hex}"
            context = {**context_base, "action_id": action_id, "run_id": run_id}
            payload = {"action": action, "context": context}
            if pending:
                payload["approval_id"] = pending["approval_id"]
                payload["action_hash"] = pending["action_hash"]
            try:
                result = request(environment, "/v1/actions/evaluate", payload)
            except Exception as exc:
                print(f"Kenning Agent Guard unavailable ({exc}); tool call blocked.", file=sys.stderr)
                return 2

            decision = str(result.get("decision") or "deny")
            approval = result.get("approval") if isinstance(result.get("approval"), dict) else {}
            approval_id = str(result.get("approval_id") or approval.get("approval_id") or "")
            action_hash = str(result.get("action_hash") or approval.get("action_hash") or "")
            if decision in {"allow", "warn", "observe"}:
                state["pending_approvals"].pop(fingerprint, None)
                state["executions"][key] = {
                    "created_at": time.time(),
                    "context": context,
                    "action_hash": action_hash,
                    "approval_id": approval_id or None,
                    "proof_id": result.get("proof_id"),
                }
                if decision != "allow":
                    print(f"Kenning Agent Guard: {decision} — tool call allowed with warning.", file=sys.stderr)
                return 0

            if decision == "require_approval" and approval_id and action_hash:
                state["pending_approvals"][fingerprint] = {
                    "created_at": time.time(),
                    "action_id": action_id,
                    "run_id": run_id,
                    "approval_id": approval_id,
                    "action_hash": action_hash,
                }
            else:
                state["pending_approvals"].pop(fingerprint, None)
            reasons = result.get("reason_codes") if isinstance(result.get("reason_codes"), list) else []
            reason_text = ", ".join(str(reason) for reason in reasons) or decision
            approval_text = f" Approval ID {approval_id}; retry this exact tool call after approval." if approval_id else ""
            print(f"Kenning Agent Guard: {decision} — {reason_text}.{approval_text}", file=sys.stderr)
            return 2
    except Exception as exc:
        print(f"Kenning Agent Guard hook failed closed ({exc}).", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
HOOK
  chmod 700 "$PROJECT_DIR/.claude/kenning-guard-hook.py"

  # Write instruction file
  cat > "$PROJECT_DIR/CLAUDE.kenning.md" <<'AGENTS'
# Kenning Agent Guard

All guarded tool calls (Bash, Write, Edit, MultiEdit, NotebookEdit, Read, Grep, Glob)
are evaluated by Kenning Agent Guard before execution via a PreToolUse hook.
PostToolUse and PostToolUseFailure hooks record the execution outcome.

- If the decision is `deny`, the tool call is blocked automatically.
- If the decision is `require_approval`, the tool call is blocked until
  an operator approves it in the Kenning console.
- If Guard is unavailable, the tool call is blocked (fail-closed).

Do not remove or modify `.claude/kenning-guard-hook.py` or the hooks
entry in `.claude/settings.json`. Do not print or commit `KENNING_PAT`,
provider credentials, or secret values.
AGENTS

  # Merge MCP config and PreToolUse hooks into .claude/settings.json
  backup_file "$PROJECT_DIR/.claude/settings.json"
  python3 - "$PROJECT_DIR/.claude/settings.json" "$KENNING_MCP_URL" "$PROJECT_DIR" <<'PY'
import json, os, shlex, sys
target, mcp_url, project_dir = sys.argv[1], sys.argv[2], sys.argv[3]
config = {}
if os.path.exists(target):
    with open(target, encoding="utf-8") as f:
        config = json.load(f)
mcp = config.setdefault("mcpServers", {})
mcp["kenning-agent-guard"] = {
    "type": "url",
    "url": mcp_url,
    "headers": {
        "Authorization": "Bearer ${KENNING_PAT}",
        "X-Kenning-Tenant-Id": "${KENNING_TENANT_ID}"
    }
}
hook_cmd = f"python3 {shlex.quote(os.path.join(project_dir, '.claude', 'kenning-guard-hook.py'))}"
hooks = config.setdefault("hooks", {})
guarded = "Bash|Write|Edit|MultiEdit|NotebookEdit|Read|Grep|Glob"
legacy_guarded = "Bash|Write|Edit|NotebookEdit|Read|Grep|Glob"
for event in ("PreToolUse", "PostToolUse", "PostToolUseFailure"):
    groups = hooks.setdefault(event, [])
    managed = next((group for group in groups if group.get("matcher") in {guarded, legacy_guarded}), None)
    managed_hook = {"type": "command", "command": hook_cmd, "timeout": 15}
    if managed is None:
        groups.append({"matcher": guarded, "hooks": [managed_hook]})
    else:
        managed["matcher"] = guarded
        existing_hooks = [
            hook for hook in managed.get("hooks", [])
            if "kenning-guard-hook.py" not in str(hook.get("command") or "")
        ]
        managed["hooks"] = existing_hooks + [managed_hook]
with open(target, "w", encoding="utf-8") as f:
    json.dump(config, f, indent=2)
    f.write("\n")
PY
  chmod 600 "$PROJECT_DIR/.claude/settings.json"

  # Append instruction reference to CLAUDE.md if it exists
  if [ -f "$PROJECT_DIR/CLAUDE.md" ]; then
    if ! grep -q "CLAUDE.kenning.md" "$PROJECT_DIR/CLAUDE.md" 2>/dev/null; then
      backup_file "$PROJECT_DIR/CLAUDE.md"
      echo "" >> "$PROJECT_DIR/CLAUDE.md"
      echo "See also: [Kenning Agent Guard](./CLAUDE.kenning.md)" >> "$PROJECT_DIR/CLAUDE.md"
    fi
  fi
  ;;

codex-cli)
  echo "Installing Kenning Agent Guard for Codex CLI..."
  mkdir -p "$PROJECT_DIR/.codex"

  # Write the fail-closed Codex PreToolUse/PostToolUse hook.
  cat > "$PROJECT_DIR/.codex/kenning-guard-hook.py" <<'HOOK'
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
HOOK
  chmod 700 "$PROJECT_DIR/.codex/kenning-guard-hook.py"

  # Install the local STDIO bridge. Codex Desktop does not pass interactive
  # shell variables to Streamable HTTP MCP servers, so the bridge reads the
  # mode-0600 credential file and adds the remote authentication headers.
  backup_file "$PROJECT_DIR/.codex/kenning-agent-guard-mcp.py"
  cat > "$PROJECT_DIR/.codex/kenning-agent-guard-mcp.py" <<'MCP_BRIDGE'
#!/usr/bin/env python3
"""Forward Codex MCP JSON-RPC messages with file-based Agent Guard credentials."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import urllib.error
import urllib.request


CREDENTIALS_PATH = Path(__file__).with_name("kenning-guard-credentials.json")


def credentials() -> tuple[str, str, str]:
    try:
        with CREDENTIALS_PATH.open(encoding="utf-8") as handle:
            values = json.load(handle)
    except (OSError, ValueError) as exc:
        raise RuntimeError("Kenning Agent Guard credentials file is invalid or missing") from exc
    if not isinstance(values, dict):
        raise RuntimeError("Kenning Agent Guard credentials file is invalid")
    mcp_url = str(values.get("mcp_url") or "").rstrip("/")
    pat = str(values.get("pat") or "")
    tenant_id = str(values.get("tenant_id") or "")
    if not mcp_url or not pat or not tenant_id:
        raise RuntimeError("Kenning Agent Guard credentials file is incomplete")
    return mcp_url, pat, tenant_id


def forward(message: dict) -> dict | None:
    mcp_url, pat, tenant_id = credentials()
    method = str(message.get("method") or "")
    headers = {
        "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {pat}",
        "Content-Type": "application/json",
        "X-Kenning-Tenant-Id": tenant_id,
    }
    if method != "initialize":
        headers["MCP-Protocol-Version"] = "2025-06-18"
    request = urllib.request.Request(
        mcp_url,
        data=json.dumps(message, separators=(",", ":")).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as result:
            raw = result.read()
            if not raw:
                return None
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Remote MCP server returned HTTP {exc.code}: {detail}") from exc


def main() -> int:
    for line in sys.stdin:
        if not line.strip():
            continue
        message = None
        try:
            message = json.loads(line)
            result = forward(message)
            if result is not None:
                sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
                sys.stdout.flush()
        except Exception as exc:
            request_id = message.get("id") if isinstance(message, dict) else None
            error = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32000, "message": str(exc)},
            }
            sys.stdout.write(json.dumps(error, separators=(",", ":")) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
MCP_BRIDGE
  chmod 700 "$PROJECT_DIR/.codex/kenning-agent-guard-mcp.py"

  # Store Codex Desktop credentials outside TOML and protect the file.
  python3 - "$PROJECT_DIR/.codex/kenning-guard-credentials.json" "$KENNING_MCP_URL" <<'PY'
import json
import os
import sys
import tempfile

target, mcp_url = sys.argv[1], sys.argv[2]
credentials = {
    "api_url": os.environ["KENNING_API_URL"].rstrip("/"),
    "mcp_url": mcp_url,
    "pat": os.environ["KENNING_PAT"],
    "tenant_id": os.environ["KENNING_TENANT_ID"],
    "environment": os.environ.get("KENNING_ENVIRONMENT", "development"),
    "agent_id": os.environ.get("KENNING_AGENT_ID", "codex-cli-development-agent"),
    "invoked_by": os.environ.get("KENNING_INVOKED_BY", "codex-cli"),
}
directory = os.path.dirname(target)
descriptor, temporary = tempfile.mkstemp(prefix=".kenning-guard-credentials-", dir=directory)
try:
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(credentials, handle, indent=2)
        handle.write("\n")
    os.replace(temporary, target)
    os.chmod(target, 0o600)
except Exception:
    try:
        os.unlink(temporary)
    except OSError:
        pass
    raise
PY

  # Keep the credential file out of version control without replacing the
  # project's existing ignore rules.
  backup_file "$PROJECT_DIR/.gitignore"
  python3 - "$PROJECT_DIR/.gitignore" <<'PY'
import os
import re
import sys

target = sys.argv[1]
text = ""
if os.path.exists(target):
    with open(target, encoding="utf-8") as handle:
        text = handle.read()
text = re.sub(
    r"\n?# >>> kenning-agent-guard managed credentials >>>.*?# <<< kenning-agent-guard managed credentials <<<\n?",
    "\n",
    text,
    flags=re.DOTALL,
)
managed = "\n".join([
    "# >>> kenning-agent-guard managed credentials >>>",
    ".codex/kenning-guard-credentials.json",
    "# <<< kenning-agent-guard managed credentials <<<",
])
text = text.rstrip()
text = (text + "\n\n" if text else "") + managed + "\n"
with open(target, "w", encoding="utf-8") as handle:
    handle.write(text)
PY

  # Write instructions and make the non-standard filename discoverable by Codex.
  cat > "$PROJECT_DIR/AGENTS.kenning.md" <<'AGENTS'
# Kenning Agent Guard

This project uses a local Codex PreToolUse hook as the execution boundary.
The hook evaluates supported shell and filesystem actions before Codex runs
them. A deny, rewrite, or approval requirement blocks the action. After an
operator approves a request, retry the exact same tool call so the hook can
resume it with the original approval ID and action hash.

Guard is fail-closed. Do not run an action manually when the Guard API is
unavailable. Installed Codex hooks and the MCP bridge read credentials from
the local mode-0600 JSON file. Legacy standalone hooks can use environment
variables at runtime.
AGENTS

  # Merge the Codex project config. Codex reads TOML and does not enforce tool
  # calls from instructions or an MCP server alone, so the local hook is the
  # authoritative pre-execution boundary.
  backup_file "$PROJECT_DIR/.codex/config.toml"
  python3 - "$PROJECT_DIR/.codex/config.toml" "$PROJECT_DIR" <<'PY'
import json
import os
import re
import sys

target, project_dir = sys.argv[1], sys.argv[2]
text = ""
if os.path.exists(target):
    with open(target, encoding="utf-8") as handle:
        text = handle.read()

managed_begin = "# >>> kenning-agent-guard managed block >>>"
managed_end = "# <<< kenning-agent-guard managed block <<<"
text = re.sub(
    rf"\n?{re.escape(managed_begin)}.*?{re.escape(managed_end)}\n?",
    "\n",
    text,
    flags=re.DOTALL,
)
text = re.sub(
    r"(?ms)^\[mcp_servers\.kenning-agent-guard\]\n.*?(?=^\[|\Z)",
    "",
    text,
)
text = re.sub(r"(?ms)^project_doc_fallback_filenames\s*=\s*\[.*?\]\s*", "", text)

managed = "\n".join([
    managed_begin,
    "[mcp_servers.kenning-agent-guard]",
    'command = "python3"',
    f"args = [{json.dumps(os.path.join(project_dir, '.codex', 'kenning-agent-guard-mcp.py'))}]",
    f"cwd = {json.dumps(project_dir)}",
    managed_end,
])
text = 'project_doc_fallback_filenames = ["AGENTS.kenning.md"]\n\n' + text.lstrip()
text = text.rstrip() + "\n\n" + managed + "\n"
with open(target, "w", encoding="utf-8") as handle:
    handle.write(text)
PY
  chmod 600 "$PROJECT_DIR/.codex/config.toml"

  # Install Codex's command-hook configuration and preserve unrelated hooks.
  backup_file "$PROJECT_DIR/.codex/hooks.json"
  python3 - "$PROJECT_DIR/.codex/hooks.json" "$PROJECT_DIR" <<'PY'
import json
import os
import shlex
import sys

target, project_dir = sys.argv[1], sys.argv[2]
config = {}
if os.path.exists(target):
    with open(target, encoding="utf-8") as handle:
        config = json.load(handle)
hooks = config.setdefault("hooks", {})
matcher = r"^(Bash|shell_command|exec_command|apply_patch|ApplyPatch|Write|Create|Edit|Read|View|Grep|Glob)$"
command = f"python3 {shlex.quote(os.path.join(project_dir, '.codex', 'kenning-guard-hook.py'))}"
for event in ("PreToolUse", "PostToolUse"):
    groups = hooks.setdefault(event, [])
    managed = next((group for group in groups if group.get("matcher") == matcher), None)
    managed_hook = {
        "type": "command",
        "command": command,
        "timeout": 30,
        "statusMessage": "Checking Kenning Agent Guard",
    }
    if managed is None:
        groups.append({"matcher": matcher, "hooks": [managed_hook]})
    else:
        existing = [
            hook for hook in managed.get("hooks", [])
            if "kenning-guard-hook.py" not in str(hook.get("command") or "")
        ]
        managed["hooks"] = existing + [managed_hook]
with open(target, "w", encoding="utf-8") as handle:
    json.dump(config, handle, indent=2)
    handle.write("\n")
PY
  chmod 600 "$PROJECT_DIR/.codex/hooks.json"

  # Remove the old non-Codex JSON integration while preserving unrelated keys.
  if [ -f "$PROJECT_DIR/.codex/config.json" ]; then
    backup_file "$PROJECT_DIR/.codex/config.json"
    python3 - "$PROJECT_DIR/.codex/config.json" <<'PY'
import json
import sys

target = sys.argv[1]
with open(target, encoding="utf-8") as handle:
    config = json.load(handle)
mcp_servers = config.get("mcpServers", {})
if isinstance(mcp_servers, dict):
    mcp_servers.pop("kenning-agent-guard", None)
    if mcp_servers:
        config["mcpServers"] = mcp_servers
    else:
        config.pop("mcpServers", None)
instructions = config.get("instructions", [])
if isinstance(instructions, list):
    instructions = [item for item in instructions if item != "./AGENTS.kenning.md"]
    if instructions:
        config["instructions"] = instructions
    else:
        config.pop("instructions", None)
with open(target, "w", encoding="utf-8") as handle:
    json.dump(config, handle, indent=2)
    handle.write("\n")
PY
  fi
  ;;

esac

# --- Post-install verification ---
echo ""
echo "Checking Kenning Agent Guard API evaluation endpoint..."
if ! VERIFY_RESULT="$(curl --silent --show-error --max-time 10 --fail \
  -X POST "${KENNING_API_URL%/}/v1/actions/evaluate" \
  -H "Authorization: Bearer ${KENNING_PAT}" \
  -H "X-Kenning-Tenant-Id: ${KENNING_TENANT_ID}" \
  -H "Content-Type: application/json" \
  -d "{\"action\":{\"tool\":\"shell\",\"parameters\":{\"command\":\"echo kenning-install-check\"}},\"context\":{\"tenant_id\":\"${KENNING_TENANT_ID}\",\"environment\":\"${KENNING_ENVIRONMENT}\",\"agent_id\":\"${KENNING_AGENT_ID}\",\"invoked_by\":\"${KENNING_INVOKED_BY}\"}}")"; then
  die "Guard evaluation check failed; verify KENNING_API_URL, KENNING_PAT, KENNING_TENANT_ID, and KENNING_ENVIRONMENT."
fi
if ! VERIFY_DECISION="$(printf '%s' "$VERIFY_RESULT" | python3 -c "import json,sys; print(str(json.load(sys.stdin).get('decision','')).strip().lower())")"; then
  die "Guard evaluation check returned invalid JSON."
fi
case "$VERIFY_DECISION" in
  allow|warn|observe) ;;
  require_approval|deny|rewrite)
    die "Guard evaluation check returned decision=$VERIFY_DECISION; installation was not verified."
    ;;
  *)
    die "Guard evaluation check returned no valid decision; installation was not verified."
    ;;
esac

echo ""
echo "============================================"
echo "  Kenning Agent Guard installed for $CLIENT"
echo "============================================"
echo "  Project:     $PROJECT_DIR"
echo "  Agent:       $KENNING_AGENT_ID"
echo "  Tenant:      $KENNING_TENANT_ID"
echo "  Environment: $KENNING_ENVIRONMENT"
echo "  MCP URL:     $KENNING_MCP_URL"
echo "  API evaluation check: decision=$VERIFY_DECISION"
echo ""
case "$CLIENT" in
  opencode)
    echo "  KENNING_PAT was validated in memory and was not written to disk."
    echo "  OpenCode built-in tools are intercepted by the local fail-closed enforcement plugin."
    ;;
  claude-code)
    echo "  KENNING_PAT was validated in memory and was not written to disk."
    echo "  Claude Code tools are intercepted by fail-closed PreToolUse/PostToolUse hooks."
    ;;
  codex-cli)
    echo "  Codex credentials are stored in $PROJECT_DIR/.codex/kenning-guard-credentials.json with mode 600."
    echo "  Codex Desktop MCP uses a local STDIO bridge; the hook enforces actions before execution."
    ;;
esac
echo ""
echo "  To uninstall: bash install.sh --client $CLIENT --uninstall"
echo "============================================"
