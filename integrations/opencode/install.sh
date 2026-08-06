#!/usr/bin/env bash
set -euo pipefail

# Kenning OpenCode project installer.
#
# The installer intentionally keeps the PAT out of files. It only validates
# KENNING_PAT so the generated OpenCode config can refer to {env:KENNING_PAT}.

PROJECT_DIR="${KENNING_OPENCODE_PROJECT_DIR:-$PWD}"
PACKAGE_BASE_URL="${KENNING_OPENCODE_PACKAGE_BASE_URL:-https://your-portal.example.invalid/install/opencode}"
PACKAGE_URL="${KENNING_OPENCODE_PACKAGE_URL:-${PACKAGE_BASE_URL%/}/opencode-integration.tgz}"
CHECKSUM_URL="${KENNING_OPENCODE_CHECKSUM_URL:-${PACKAGE_URL}.sha256}"
SOURCE_DIR="${KENNING_OPENCODE_SOURCE_DIR:-}"
BACKUP_SUFFIX="$(date -u +%Y%m%dT%H%M%SZ)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/kenning-opencode-install.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

die() {
  echo "kenning-opencode: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

backup_file() {
  local path="$1"
  if [ -e "$path" ]; then
    cp -p "$path" "${path}.kenning-backup-${BACKUP_SUFFIX}"
    echo "Backed up $path to ${path}.kenning-backup-${BACKUP_SUFFIX}"
  fi
}

require_command tar
require_command python3

if [ -z "${KENNING_API_URL:-}" ]; then
  die "KENNING_API_URL must be exported before running the installer."
fi
if [ -z "${KENNING_PAT:-}" ]; then
  die "KENNING_PAT must be exported before running the installer; it is never written to disk."
fi
if [ -z "${KENNING_TENANT_ID:-}" ]; then
  die "KENNING_TENANT_ID must be exported before running the installer."
fi

KENNING_MCP_URL="${KENNING_MCP_URL:-${KENNING_API_URL%/}/mcp}"
KENNING_AGENT_ID="${KENNING_AGENT_ID:-opencode-development-agent}"
KENNING_ENVIRONMENT="${KENNING_ENVIRONMENT:-development}"
KENNING_INVOKED_BY="${KENNING_INVOKED_BY:-opencode}"
KENNING_GUARD_MODE="${KENNING_GUARD_MODE:-enforce}"
OPENCODE_MODEL="${OPENCODE_MODEL:-amazon-bedrock/us.anthropic.claude-sonnet-4-6}"

if [ ! -d "$PROJECT_DIR" ]; then
  die "project directory does not exist: $PROJECT_DIR"
fi
PROJECT_DIR="$(cd "$PROJECT_DIR" && pwd)"

if [ -n "$SOURCE_DIR" ]; then
  SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd)"
  PACKAGE_ROOT="$SOURCE_DIR"
  [ -f "$PACKAGE_ROOT/kenning-agent-guard-plugin.js" ] || die "source directory is missing kenning-agent-guard-plugin.js"
else
  require_command curl
  PACKAGE_FILE="$TMP_DIR/opencode-integration.tgz"
  CHECKSUM_FILE="$TMP_DIR/opencode-integration.tgz.sha256"
  echo "Downloading Kenning OpenCode integration..."
  curl --fail --silent --show-error --location "$PACKAGE_URL" --output "$PACKAGE_FILE"
  curl --fail --silent --show-error --location "$CHECKSUM_URL" --output "$CHECKSUM_FILE"

  EXPECTED_SHA256="$(awk 'NF { print $1; exit }' "$CHECKSUM_FILE")"
  [ "${#EXPECTED_SHA256}" -eq 64 ] || die "invalid SHA-256 checksum file: $CHECKSUM_URL"
  if command -v shasum >/dev/null 2>&1; then
    ACTUAL_SHA256="$(shasum -a 256 "$PACKAGE_FILE" | awk '{print $1}')"
  else
    require_command sha256sum
    ACTUAL_SHA256="$(sha256sum "$PACKAGE_FILE" | awk '{print $1}')"
  fi
  [ "$EXPECTED_SHA256" = "$ACTUAL_SHA256" ] || die "integration archive checksum verification failed"

  mkdir -p "$TMP_DIR/package"
  tar -xzf "$PACKAGE_FILE" -C "$TMP_DIR/package"
  PACKAGE_ROOT="$TMP_DIR/package/opencode"
fi

for required_file in kenning-agent-guard-plugin.js package.json opencode.json.example AGENTS.md; do
  [ -f "$PACKAGE_ROOT/$required_file" ] || die "integration archive is missing $required_file"
done

mkdir -p "$PROJECT_DIR/.opencode/plugins"
backup_file "$PROJECT_DIR/.opencode/plugins/kenning-agent-guard-plugin.js"
backup_file "$PROJECT_DIR/.opencode/package.json"
backup_file "$PROJECT_DIR/AGENTS.kenning.md"
cp "$PACKAGE_ROOT/kenning-agent-guard-plugin.js" \
  "$PROJECT_DIR/.opencode/plugins/kenning-agent-guard-plugin.js"

python3 - "$PROJECT_DIR/.opencode/package.json" "$PACKAGE_ROOT/package.json" <<'PY'
import json
import os
import sys

target, patch_path = sys.argv[1:]
base = {}
if os.path.exists(target):
    with open(target, encoding="utf-8") as handle:
        base = json.load(handle)
with open(patch_path, encoding="utf-8") as handle:
    patch = json.load(handle)
base.update({key: value for key, value in patch.items() if key not in base})
with open(target, "w", encoding="utf-8") as handle:
    json.dump(base, handle, indent=2)
    handle.write("\n")
PY

cp "$PACKAGE_ROOT/AGENTS.md" "$PROJECT_DIR/AGENTS.kenning.md"

if [ -e "$PROJECT_DIR/opencode.json" ]; then
  backup_file "$PROJECT_DIR/opencode.json"
fi

python3 - "$PROJECT_DIR/opencode.json" "$PACKAGE_ROOT/opencode.json.example" <<'PY'
import json
import os
import sys

target, patch_path = sys.argv[1:]
base = {}
if os.path.exists(target):
    with open(target, encoding="utf-8") as handle:
        base = json.load(handle)
with open(patch_path, encoding="utf-8") as handle:
    patch = json.load(handle)

for key in ("model", "subagent_depth", "share", "autoupdate"):
    if key not in base and key in patch:
        base[key] = patch[key]

for key in ("provider", "mcp", "permission"):
    current = base.setdefault(key, {})
    if not isinstance(current, dict):
        current = {}
        base[key] = current
    current.update(patch.get(key, {}))

providers = base.setdefault("enabled_providers", [])
if not isinstance(providers, list):
    providers = []
    base["enabled_providers"] = providers
for provider in patch.get("enabled_providers", []):
    if provider not in providers:
        providers.append(provider)

instructions = base.setdefault("instructions", [])
if not isinstance(instructions, list):
    instructions = []
    base["instructions"] = instructions
if "./AGENTS.kenning.md" not in instructions:
    instructions.append("./AGENTS.kenning.md")

with open(target, "w", encoding="utf-8") as handle:
    json.dump(base, handle, indent=2)
    handle.write("\n")
PY

chmod 600 "$PROJECT_DIR/.opencode/plugins/kenning-agent-guard-plugin.js" "$PROJECT_DIR/.opencode/package.json"

echo
echo "Kenning Agent Guard is configured for OpenCode."
echo "Project: $PROJECT_DIR"
echo "Agent: $KENNING_AGENT_ID"
echo "Tenant: $KENNING_TENANT_ID"
echo "Environment: $KENNING_ENVIRONMENT"
echo
echo "Run:"
echo "  cd \"$PROJECT_DIR\""
echo "  opencode mcp list"
echo "  opencode"
echo
echo "KENNING_PAT was validated in memory and was not written to disk."
