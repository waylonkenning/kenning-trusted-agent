#!/usr/bin/env bash
set -euo pipefail

: "${KENNING_API_URL:?KENNING_API_URL is required}"
: "${KENNING_MCP_URL:?KENNING_MCP_URL is required}"
: "${KENNING_CITATION_MCP_URL:=${KENNING_API_URL%/}/mcp/citation-trust}"
: "${KENNING_PAT_SECRET_ID:?KENNING_PAT_SECRET_ID is required}"
: "${KENNING_TENANT_ID:?KENNING_TENANT_ID is required}"
: "${KENNING_AGENT_ID:?KENNING_AGENT_ID is required}"
: "${AWS_REGION:?AWS_REGION is required}"
: "${OPENCODE_MODEL:?OPENCODE_MODEL is required}"

WORKSPACE="/workspace/kenning-trusted-agent"
if [ ! -d "$WORKSPACE/.git" ]; then
  echo "Expected the repository to be cloned at $WORKSPACE." >&2
  exit 1
fi
install -d -o ec2-user -g ec2-user -m 0700 "$WORKSPACE/.opencode/plugins"
cp "$WORKSPACE/integrations/opencode/kenning-agent-guard-plugin.js" "$WORKSPACE/.opencode/plugins/"
cp "$WORKSPACE/integrations/opencode/package.json" "$WORKSPACE/.opencode/package.json"
cp "$WORKSPACE/integrations/opencode/opencode.json.example" "$WORKSPACE/opencode.json"
cp "$WORKSPACE/integrations/opencode/AGENTS.md" "$WORKSPACE/AGENTS.md"
chmod 600 "$WORKSPACE/.opencode/package.json" "$WORKSPACE/.opencode/plugins/kenning-agent-guard-plugin.js" "$WORKSPACE/opencode.json" "$WORKSPACE/AGENTS.md"
chown -R ec2-user:ec2-user "$WORKSPACE/.opencode" "$WORKSPACE/opencode.json" "$WORKSPACE/AGENTS.md"

install -d -o ec2-user -g ec2-user -m 0700 /home/ec2-user/.config
install -d -o ec2-user -g ec2-user -m 0700 /home/ec2-user/.config/kenning
cat > /home/ec2-user/.config/kenning/opencode.env <<EOF
KENNING_API_URL=$KENNING_API_URL
KENNING_MCP_URL=$KENNING_MCP_URL
KENNING_CITATION_MCP_URL=$KENNING_CITATION_MCP_URL
KENNING_PAT_SECRET_ID=$KENNING_PAT_SECRET_ID
KENNING_TENANT_ID=$KENNING_TENANT_ID
KENNING_AGENT_ID=$KENNING_AGENT_ID
KENNING_ENVIRONMENT=development
KENNING_GUARD_MODE=enforce
AWS_REGION=$AWS_REGION
OPENCODE_MODEL=$OPENCODE_MODEL
KENNING_WORKSPACE=$WORKSPACE
EOF
chown ec2-user:ec2-user /home/ec2-user/.config/kenning/opencode.env
chmod 600 /home/ec2-user/.config/kenning/opencode.env

cat > /usr/local/bin/kenning-opencode <<'LAUNCHER'
#!/usr/bin/env bash
set -euo pipefail
set -a
source /home/ec2-user/.config/kenning/opencode.env
set +a
eval "$(aws configure export-credentials --format env)"
export KENNING_PAT="$(aws secretsmanager get-secret-value --region "$AWS_REGION" --secret-id "$KENNING_PAT_SECRET_ID" --query SecretString --output text)"
export PATH="/home/ec2-user/.opencode/bin:/home/ec2-user/.local/bin:/usr/local/bin:$PATH"
cd "$KENNING_WORKSPACE"
exec opencode "$@"
LAUNCHER
chmod 755 /usr/local/bin/kenning-opencode
chown root:root /usr/local/bin/kenning-opencode
