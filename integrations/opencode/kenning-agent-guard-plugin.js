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
