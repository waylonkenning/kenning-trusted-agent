import assert from "node:assert/strict"
import { readFile } from "node:fs/promises"
import { KenningAgentGuard } from "../integrations/opencode/kenning-agent-guard-plugin.js"

process.env.KENNING_API_URL = "https://guard.example.test"
process.env.KENNING_PAT = "kta_pat_test"
process.env.KENNING_TENANT_ID = "opencode-test"
process.env.KENNING_AGENT_ID = "opencode-development-agent"
process.env.KENNING_ENVIRONMENT = "development"

const requests = []
globalThis.fetch = async (url, options) => {
  requests.push({ url, options })
  if (url.endsWith("/outcome")) return new Response(JSON.stringify({ status: "recorded" }), { status: 200 })
  const payload = JSON.parse(options.body)
  if (payload.action.parameters.command === "rm -rf /") {
    return new Response(JSON.stringify({ decision: "deny", reason_codes: ["CATASTROPHIC_FILESYSTEM_OPERATION"] }), { status: 200 })
  }
  if (payload.action.parameters.command === "rm -rf /tmp/cool" && !payload.approval_id) {
    return new Response(JSON.stringify({
      decision: "require_approval",
      action_hash: "sha256:approval",
      approval: {
        approval_id: "approval-plugin-test",
        action_id: payload.context.action_id,
        action_hash: "sha256:approval",
        intent: payload.intent,
      },
      reason_codes: ["DESTRUCTIVE_FILESYSTEM_OPERATION"],
    }), { status: 200 })
  }
  if (payload.action.parameters.path === "/workspace/victim.txt" && payload.action.parameters.content_sha256?.endsWith("40b2c1862f58d622c4104f056adce2f5cc31947bd7cf628bf1c7ebfe01dbe22d")) {
    return new Response(JSON.stringify({
      decision: "require_approval",
      action_hash: "sha256:write-approval",
      approval: {
        approval_id: "approval-write-test",
        action_id: payload.context.action_id,
        action_hash: "sha256:write-approval",
        intent: payload.intent,
      },
      reason_codes: ["SENSITIVE_FILE_WRITE"],
    }), { status: 200 })
  }
  if (payload.action.parameters.command === "rm -rf /tmp/cool" && payload.approval_id === "approval-plugin-test") {
    return new Response(JSON.stringify({
      decision: "allow",
      action_hash: "sha256:approval",
      approval_id: "approval-plugin-test",
      approval_status: "approved",
      approval_resume: true,
      proof_id: "proof://approved",
    }), { status: 200 })
  }
  return new Response(JSON.stringify({ decision: "allow", action_hash: "sha256:test", proof_id: "proof://test" }), { status: 200 })
}

const hooks = await KenningAgentGuard({ directory: "/workspace" })
await hooks["tool.execute.before"](
  { tool: "bash", sessionID: "session-1", callID: "call-safe" },
  { args: { command: "npm test" } },
)
await hooks["tool.execute.after"](
  { tool: "bash", sessionID: "session-1", callID: "call-safe" },
  { output: "ok" },
)
await assert.rejects(
  hooks["tool.execute.before"](
    { tool: "bash", sessionID: "session-1", callID: "call-dangerous" },
    { args: { command: "rm -rf /" } },
  ),
  /blocked.*deny/i,
)
await assert.rejects(
  hooks["tool.execute.before"](
    { tool: "bash", sessionID: "session-1", callID: "call-approval" },
    { args: { command: "rm -rf /tmp/cool" } },
  ),
  /Approval ID approval-plugin-test/i,
)
await hooks["tool.execute.before"](
  { tool: "bash", sessionID: "session-1", callID: "call-approval-retry" },
  { args: { command: "rm -rf /tmp/cool" } },
)
await hooks["tool.execute.after"](
  { tool: "bash", sessionID: "session-1", callID: "call-approval-retry" },
  { output: "approved" },
)
assert.equal(requests.length, 6)
assert.equal(JSON.parse(requests[0].options.body).context.tenant_id, "opencode-test")
assert.match(requests[1].url, /\/outcome$/)
const firstApprovalPayload = JSON.parse(requests[3].options.body)
const retryPayload = JSON.parse(requests[4].options.body)
assert.equal(firstApprovalPayload.context.action_id, "call-approval")
assert.equal(retryPayload.approval_id, "approval-plugin-test")
assert.equal(retryPayload.action_hash, "sha256:approval")
assert.equal(retryPayload.context.action_id, "call-approval")
assert.match(requests[5].url, /\/v1\/actions\/call-approval\/outcome$/)

await assert.rejects(
  hooks["tool.execute.before"](
    { tool: "write", sessionID: "session-1", callID: "call-write-approval" },
    { args: { path: "/workspace/victim.txt", content: "SAFE_DATA" } },
  ),
  /Approval ID approval-write-test/i,
)
await hooks["tool.execute.before"](
  { tool: "write", sessionID: "session-1", callID: "call-write-different-content" },
  { args: { path: "/workspace/victim.txt", content: "EVIL_CMDS" } },
)
const approvedWritePayload = JSON.parse(requests[6].options.body)
const changedWritePayload = JSON.parse(requests[7].options.body)
assert.equal(approvedWritePayload.action.parameters.content_length, changedWritePayload.action.parameters.content_length)
assert.notEqual(approvedWritePayload.action.parameters.content_sha256, changedWritePayload.action.parameters.content_sha256)
assert.equal(changedWritePayload.approval_id, undefined)
assert.equal(changedWritePayload.action.parameters.content, undefined)
console.log("OpenCode plugin tests passed")

const installer = await readFile(
  new URL("../integrations/agent-guard/install.sh", import.meta.url),
  "utf8",
)
const installedPlugin = installer.match(
  /cat > "\$PROJECT_DIR\/\.opencode\/plugins\/kenning-agent-guard-plugin\.js" <<'PLUGIN'\n([\s\S]*?)\nPLUGIN/,
)?.[1]
const canonicalPlugin = await readFile(
  new URL("../integrations/opencode/kenning-agent-guard-plugin.js", import.meta.url),
  "utf8",
)
assert.equal(installedPlugin, canonicalPlugin.trimEnd())
console.log("Shared installer OpenCode plugin parity test passed")
