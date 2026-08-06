# Kenning Agent Guard installer

One-line installation of Kenning Agent Guard for OpenCode, Claude Code, and Codex CLI.

## Quick start

```sh
export KENNING_API_URL="https://your-api-id.execute-api.us-east-1.amazonaws.com"
export KENNING_PAT="kta_pat_..."
export KENNING_TENANT_ID="your-workspace"

# OpenCode
curl -fsSL https://<kenning-host>/install/agent-guard/install.sh | bash -s -- --client opencode

# Claude Code
curl -fsSL https://<kenning-host>/install/agent-guard/install.sh | bash -s -- --client claude-code

# Codex CLI
curl -fsSL https://<kenning-host>/install/agent-guard/install.sh | bash -s -- --client codex-cli
```

## Inspectable install

Download the installer first, review it, then run:

```sh
curl -fsSL https://<kenning-host>/install/agent-guard/install.sh -o install.sh
less install.sh
bash install.sh --client claude-code
```

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `KENNING_API_URL` | Yes | — | Control-plane API base URL |
| `KENNING_PAT` | Yes | — | Personal access token. For Codex, the installer writes it to the protected project credential file. |
| `KENNING_TENANT_ID` | Yes | — | Workspace/tenant identifier |
| `KENNING_MCP_URL` | No | `$KENNING_API_URL/mcp` | MCP endpoint |
| `KENNING_AGENT_ID` | No | Per-client default | Agent identity |
| `KENNING_ENVIRONMENT` | No | `development` | development, staging, or production |
| `KENNING_PROJECT_DIR` | No | Current directory | Target project directory |

## What the installer does

1. Validates prerequisites and API connectivity.
2. For OpenCode, installs a local fail-closed plugin that intercepts guarded built-in tool calls before execution and records their outcomes afterward.
3. For Claude Code, installs fail-closed `PreToolUse`, `PostToolUse`, and `PostToolUseFailure` hooks. Approval references are retained locally so an approved exact action can be retried across hook processes, and outcomes are recorded after execution.
4. For Codex CLI and Codex Desktop, installs a local fail-closed `PreToolUse` and `PostToolUse` hook. The hook evaluates supported shell and filesystem actions before execution. It uses Codex's `config.toml` and `hooks.json` files, plus a local STDIO bridge for the remote MCP server. It does not rely on instructions or MCP alone for enforcement.
5. Configures the client's MCP settings and instructions.
6. Backs up existing configuration before modifying it.
7. Checks connectivity to the evaluate API endpoint.

## Security model

- OpenCode and Claude Code validate the PAT in memory and use environment variables at runtime.
- Codex stores the API URL, PAT, tenant ID, and agent settings in `.codex/kenning-guard-credentials.json` with mode `600`. The PAT is not written to TOML or printed by the installer.
- Codex `config.toml` starts a local STDIO bridge. The bridge reads the protected JSON file and adds the remote MCP authentication headers. This supports Codex CLI and Codex Desktop.
- The installer is idempotent — running it again updates the Kenning entries without overwriting unrelated configuration.
- **OpenCode, Claude Code, and Codex CLI enforcement is mandatory.** Their local plugin/hooks evaluate guarded built-in tools before execution, fail closed if Guard is unavailable, and block `deny`, `require_approval`, and `rewrite` decisions. The MCP and instruction files are not the enforcement boundary.

## Uninstall

```sh
bash install.sh --client claude-code --uninstall
```

This removes Kenning instruction files, the generated client hook, bridge, credential file, state, and only Kenning-managed MCP/hook entries. Unrelated client configuration is preserved. Backups from installation are preserved.

## Troubleshooting

The client must use the control-plane API URL, not the portal URL. Set
`KENNING_API_URL` to the API URL from your own deployment. The installer checks
the public `/health` response and rejects a URL that reports a different
environment from `KENNING_ENVIRONMENT`.

If a tool is blocked with an authentication message, refresh `KENNING_PAT` for the configured environment and rerun the installer. The hook fails closed when it cannot authenticate with Guard. It reports the endpoint, environment, and health result without printing the PAT.


- **Cannot reach API**: Check `KENNING_API_URL` and your network connection.
- **401/403**: Verify `KENNING_PAT` is valid and has the `guard:evaluate` scope.
- **MCP not listed**: Run the client's MCP list command (e.g. `opencode mcp list`) to verify the server is registered.
- **OpenCode actions not evaluated**: Confirm `.opencode/plugins/kenning-agent-guard-plugin.js` exists and that OpenCode loads project plugins; this plugin, not the instruction file, is the enforcement boundary.
- **Codex MCP does not start**: Confirm `.codex/kenning-guard-credentials.json` exists with mode `600`, and `.codex/kenning-agent-guard-mcp.py`, `.codex/hooks.json`, and `.codex/config.toml` exist. Start a new Codex CLI or Codex Desktop session after installation.
- **Codex actions not evaluated**: Confirm `.codex/kenning-guard-hook.py` exists and the project is trusted so Codex loads its project configuration and hooks. The local hook, not the MCP server, is the enforcement boundary.
- **Codex approval retry**: After an operator approves a request, retry the exact original tool call. Do not change the command, path, or arguments. A changed action creates a new evaluation and cannot use the previous approval.
- **Codex hook protocol errors**: Successful PreToolUse and PostToolUse events return no JSON output. Only blocked PreToolUse events return `decision:block` with a reason. If Codex reports an unsupported `decision:approve` or invalid PostToolUse JSON response, reinstall the current hook and start a new Codex session.

## OpenCode migration

The existing OpenCode installer at `integrations/opencode/install.sh` remains functional. The shared installer produces equivalent configuration. To migrate, run the shared installer with `--client opencode` in the same project directory.
