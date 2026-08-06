# OpenCode + Kenning Agent Guard

This integration makes Kenning Agent Guard the pre-execution control point for
an OpenCode software-development agent.

It has two complementary paths:

1. The local OpenCode plugin evaluates built-in development tools before they
   execute and records their outcomes afterward.
2. The remote MCP servers expose product-specific Kenning tools for action
   evaluation, Proof, Citation Trust, and receipt verification.

The local plugin is the authoritative boundary for OpenCode's built-in
`bash`, `read`, `grep`, `glob`, `edit`, `write`, and `apply_patch` tools. MCP is
available for explicit provenance and verification operations; it should not
be used as a second pre-check for those built-in tools.

The shipped OpenCode permission profile denies the MCP
`kenning-agent-guard_evaluate_action` tool. This is intentional: an MCP
approval describes the structured MCP request, while the plugin approval is
bound to the exact built-in tool payload that will execute. Allowing both
paths would create two independent approvals for one operation. Use the MCP
server for explicit evaluations from other clients and for Proof, Citation
Trust, and receipt operations; use the local plugin for OpenCode execution.

## Integration files

| File | Purpose |
| --- | --- |
| `kenning-agent-guard-plugin.js` | OpenCode `tool.execute.before` and `tool.execute.after` hooks. |
| `opencode.json.example` | Bedrock provider, remote MCP, permissions, and test boundaries. |
| `AGENTS.md` | Runtime instructions for the guarded development agent. |
| `ec2-user-data.sh` | Installs OpenCode and base packages on Amazon Linux. |
| `ec2-configure.sh` | Installs the project hooks and Secrets Manager-backed launcher. |
| `../../scripts/provision_opencode_ec2.sh` | Provisions the isolated EC2 test environment. |

## How enforcement works

For every built-in tool call:

```text
OpenCode proposes a tool call
        ↓
Kenning plugin normalises the action
        ↓
POST /v1/actions/evaluate
        ↓
allow / warn / require_approval / rewrite / deny
        ↓
execute or block
        ↓
POST /v1/actions/{action_id}/outcome
```

The plugin sends tenant, environment, agent, invoking-user, run, and action
context with each evaluation. `allow` and `warn` proceed; `require_approval`,
`rewrite`, and `deny` are hard stops. An unavailable Guard API also blocks the
tool call, so the integration fails closed.

The plugin does not send file contents to Guard for normal `read`, `grep`, or
`glob` checks. It sends the target path, operation, command metadata, and
bounded metadata such as content or patch lengths.

## One-command installer

The hosted installer configures the current project directory. Export the
tenant-scoped settings first so the PAT is available to the installer process
but is never written to the project:

```bash
export KENNING_API_URL="https://your-api.example.invalid"
export KENNING_PAT="kta_pat_..."
export KENNING_TENANT_ID="opencode-test"
export KENNING_AGENT_ID="opencode-development-agent"
export KENNING_ENVIRONMENT="development"
export KENNING_GUARD_MODE="enforce"

curl -fsSL https://your-portal.example.invalid/install/opencode/install.sh | bash
```

The installer downloads the integration archive, verifies its SHA-256
checksum, installs the plugin under `.opencode/plugins`, merges the Guard MCP
and permission settings into `opencode.json`, and writes the Guard instructions
to `AGENTS.kenning.md`. Existing files are backed up with a timestamped
`.kenning-backup-*` suffix. It never writes `KENNING_PAT`.

For a reviewable install, download the script first and inspect it before
running it:

```bash
curl -fsSL https://your-portal.example.invalid/install/opencode/install.sh \
  -o /tmp/kenning-opencode-install.sh
bash /tmp/kenning-opencode-install.sh
```

To install into another project, set:

```bash
KENNING_OPENCODE_PROJECT_DIR="/path/to/project" \
bash /tmp/kenning-opencode-install.sh
```

The installer requires `python3` and `tar`. A local checkout can be tested
without downloading the archive:

```bash
KENNING_OPENCODE_SOURCE_DIR="/path/to/kenning-trusted-agent/integrations/opencode" \
bash /path/to/kenning-trusted-agent/integrations/opencode/install.sh
```

## Configure a local OpenCode project

Run these commands from the root of the project OpenCode will modify:

```bash
mkdir -p .opencode/plugins

cp /path/to/kenning-trusted-agent/integrations/opencode/kenning-agent-guard-plugin.js \
  .opencode/plugins/
cp /path/to/kenning-trusted-agent/integrations/opencode/package.json \
  .opencode/package.json
cp /path/to/kenning-trusted-agent/integrations/opencode/opencode.json.example \
  opencode.json
cp /path/to/kenning-trusted-agent/integrations/opencode/AGENTS.md \
  AGENTS.md
```

Set the runtime variables before starting OpenCode:

```bash
export KENNING_API_URL="https://your-api.example.invalid"
export KENNING_MCP_URL="$KENNING_API_URL/mcp/agent-guard"
export KENNING_CITATION_MCP_URL="$KENNING_API_URL/mcp/citation-trust"
export KENNING_PAT="kta_pat_..."
export KENNING_TENANT_ID="opencode-test"
export KENNING_AGENT_ID="opencode-development-agent"
export KENNING_INVOKED_BY="opencode"
export KENNING_ENVIRONMENT="development"
export KENNING_GUARD_MODE="enforce"
export AWS_REGION="us-east-1"
export OPENCODE_MODEL="amazon-bedrock/us.anthropic.claude-sonnet-4-6"

opencode
```

The PAT must be tenant-scoped and include at least `guard:evaluate` and
`actions:write`. Add `mcp:read` when using the remote MCP server. Never commit
the PAT or put it in `opencode.json`.

## Product-specific MCP configuration

The configuration exposes separate MCP servers so the model cannot select a
Guard, Proof, or Identity tool when the task is citation verification:

- `kenning-agent-guard` points to `/mcp/agent-guard`.
- `kenning-citation-trust` points to `/mcp/citation-trust` and exposes only
  `verify_citations`.

Citation Trust derives the tenant from the PAT. Its tool call must contain only
the response and citations; do not add tenant, environment, or action context.

## OpenCode configuration

`opencode.json.example` configures:

- `amazon-bedrock` as the provider, using the configured AWS region.
- `kenning-agent-guard` as a remote MCP server with Bearer PAT and tenant
  headers.
- `kenning-citation-trust` as a separate remote MCP server with only the
  Citation Trust tool and a PAT-derived tenant boundary.
- permissions for the built-in development tools and Kenning MCP tools.
- an explicit deny for `kenning-agent-guard_evaluate_action`, so a model cannot
  create an MCP approval and then attempt the same operation through a second,
  differently shaped OpenCode tool call.
- `task: deny`, `external_directory: deny`, and `subagent_depth: 0` for the
  PoC boundary. These settings keep subagent execution out of the initial
  safety test.
- `share: disabled` and `autoupdate: false` for the isolated test agent.

For a production deployment, review permissions, subagent policy, retention,
PAT lifetime, and model access with the tenant security owner.

## Verify a local configuration

Confirm the plugin and MCP connection before asking the agent to modify code:

```bash
opencode --version
opencode mcp list
```

Run a harmless tool test:

```bash
opencode run \
  --model "$OPENCODE_MODEL" \
  "Use bash exactly once to run: printf 'kenning-safe\\n' > /tmp/kenning-safe.txt. Then report the Guard decision."
```

The response should include a Guard decision, normally `warn` for shell
redirection, followed by successful execution.

For a non-destructive blocking test, ask the agent to run:

```text
rm -rf /tmp/kenning-agent-guard-test-target
```

Use a disposable `/tmp` target only. In `enforce` mode, Guard should return
`require_approval` and the target should remain intact.

When the operator approves an OpenCode action, retry the exact original
built-in tool call. Do not call the MCP `evaluate_action` tool first and do not
change the path, command, or working directory. The plugin carries the
approval ID and action hash automatically.

## Configure the isolated EC2 agent

From the repository root, the provisioning script:

1. creates a short-lived PAT and configures the test tenant and agent;
2. publishes the integration and committed workspace archives to a private,
   AES-256-encrypted S3 bucket;
3. creates an instance role with SSM, Secrets Manager, S3 artifact, and
   Bedrock inference-profile permissions;
4. starts an ARM64 Amazon Linux EC2 instance with no inbound security-group
   rules;
5. installs OpenCode through user data; and
6. configures the workspace through SSM.

The workspace is created from the repository's committed `HEAD`, so commit the
code you want the remote agent to test before provisioning:

```bash
AWS_REGION=us-east-1 \
KENNING_API_URL="https://your-api.example.invalid" \
bash scripts/provision_opencode_ec2.sh
```

The managed workspace is `/workspace/kenning-trusted-agent`. The EC2 launcher
is `/usr/local/bin/kenning-opencode`; it retrieves the PAT from Secrets
Manager, obtains short-lived instance-role credentials for Bedrock, exports
the integration variables, and starts OpenCode in the managed workspace.

The hosted installer is published with:

```bash
KENNING_INSTALL_BUCKET="your-private-artifact-bucket" \
bash scripts/publish_opencode_installer.sh
```

Set `KENNING_INSTALL_BUCKET` to the public static-site bucket for the target
environment when publishing outside this prototype environment.

## Connect to EC2 from macOS

The AWS CLI needs the local Session Manager plugin before `start-session` can
open a shell. On Apple Silicon:

```bash
curl "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/mac_arm64/session-manager-plugin.pkg" \
  -o /tmp/session-manager-plugin.pkg
sudo installer -pkg /tmp/session-manager-plugin.pkg -target /
sudo mkdir -p /usr/local/bin
sudo ln -sf /usr/local/sessionmanagerplugin/bin/session-manager-plugin \
  /usr/local/bin/session-manager-plugin
```

Use the `mac` download path instead of `mac_arm64` on an Intel Mac. Then start
the session:

```bash
aws ssm start-session \
  --region us-east-1 \
  --target i-07fba533e4c5c2319
```

Only after the EC2 shell opens should you run:

```bash
sudo -iu ec2-user kenning-opencode
```

If `SessionManagerPlugin is not found` appears, the command has not connected
to EC2 and any following `sudo` command is still running on the local Mac.

## Operational security

- Use SSM rather than opening SSH or other inbound ports.
- Keep the PAT in Secrets Manager for EC2; do not place it in the project or
  command history.
- Use short PAT expirations for the PoC and revoke them after testing.
- Keep the S3 artifact bucket private and encrypted.
- Keep the workspace outside protected system paths. The configured
  `/workspace/kenning-trusted-agent` path is intentional; paths such as
  `/home`, `/etc`, `/root`, and `.aws` may require approval or be blocked.
- Review Guard audit events, Proof records, approvals, and receipts after each
  test run.

## References

- [OpenCode plugins](https://dev.opencode.ai/docs/plugins/)
- [OpenCode MCP configuration](https://opencode.ai/docs/mcp/)
- [AWS Session Manager plugin for macOS](https://docs.aws.amazon.com/systems-manager/latest/userguide/install-plugin-macos-overview.html)
