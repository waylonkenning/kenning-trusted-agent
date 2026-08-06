import assert from "node:assert/strict"
import { chmod, mkdtemp, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { spawnSync } from "node:child_process"

const repositoryRoot = new URL("..", import.meta.url).pathname
const installer = join(repositoryRoot, "integrations/agent-guard/install.sh")
const testPat = "kta_pat_must_not_be_persisted"

async function fileMode(path) {
  return (await stat(path)).mode & 0o777
}

async function runInstaller(client, verify) {
  const projectDir = await mkdtemp(join(tmpdir(), "kenning-agent-guard-"))
  const binDir = join(projectDir, "bin")
  await mkdir(binDir)
  const curl = join(binDir, "curl")
  await writeFile(curl, '#!/usr/bin/env bash\necho \'{"status":"ok","service":"kenning-agent-guard","environment":"prototype","decision":"allow"}\'\n')
  await chmod(curl, 0o755)

  try {
    const result = spawnSync("bash", [installer, "--client", client, "--project-dir", projectDir], {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${binDir}:${process.env.PATH}`,
        KENNING_API_URL: "https://guard.example.test",
        KENNING_PAT: testPat,
        KENNING_TENANT_ID: "tenant-test",
      },
    })
    assert.equal(result.status, 0, result.stderr)
    await verify(projectDir)
  } finally {
    await rm(projectDir, { force: true, recursive: true })
  }
}

await runInstaller("claude-code", async (projectDir) => {
  const configPath = join(projectDir, ".claude/settings.json")
  const configText = await readFile(configPath, "utf8")
  const config = JSON.parse(configText)
  const mcp = config.mcpServers["kenning-agent-guard"]
  assert.doesNotMatch(configText, new RegExp(testPat))
  assert.equal(mcp.headers.Authorization, "Bearer ${KENNING_PAT}")
  assert.equal(mcp.headers["X-Kenning-Tenant-Id"], "${KENNING_TENANT_ID}")
  assert.equal(await fileMode(configPath), 0o600)
})

await runInstaller("opencode", async (projectDir) => {
  const configPath = join(projectDir, "opencode.json")
  const pluginPath = join(projectDir, ".opencode/plugins/kenning-agent-guard-plugin.js")
  const configText = await readFile(configPath, "utf8")
  const pluginText = await readFile(pluginPath, "utf8")
  const config = JSON.parse(configText)
  const mcp = config.mcp["kenning-agent-guard"]
  assert.doesNotMatch(configText, new RegExp(testPat))
  assert.doesNotMatch(pluginText, new RegExp(testPat))
  assert.equal(mcp.headers.Authorization, "Bearer {env:KENNING_PAT}")
  assert.equal(mcp.headers["X-Kenning-Tenant-Id"], "{env:KENNING_TENANT_ID}")
  assert.equal(await fileMode(pluginPath), 0o600)
})

await runInstaller("codex-cli", async (projectDir) => {
  const tomlPath = join(projectDir, ".codex/config.toml")
  const hooksPath = join(projectDir, ".codex/hooks.json")
  const credentialsPath = join(projectDir, ".codex/kenning-guard-credentials.json")
  const toml = await readFile(tomlPath, "utf8")
  const hooks = await readFile(hooksPath, "utf8")
  const credentials = JSON.parse(await readFile(credentialsPath, "utf8"))
  assert.doesNotMatch(toml, new RegExp(testPat))
  assert.doesNotMatch(hooks, new RegExp(testPat))
  assert.match(toml, /\[mcp_servers\.kenning-agent-guard\]/)
  assert.match(toml, /kenning-agent-guard-mcp\.py/)
  assert.match(hooks, /kenning-guard-hook\.py/)
  assert.equal(credentials.pat, testPat)
  assert.equal(await fileMode(tomlPath), 0o600)
  assert.equal(await fileMode(hooksPath), 0o600)
  assert.equal(await fileMode(credentialsPath), 0o600)
})

console.log("Agent Guard installer credential persistence tests passed for claude-code, opencode, and codex-cli")
