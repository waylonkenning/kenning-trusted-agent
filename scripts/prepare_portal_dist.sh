#!/usr/bin/env bash
set -euo pipefail

DIST_DIR="${1:-}"
if [ -z "$DIST_DIR" ]; then
  echo "usage: $0 DIST_DIR" >&2
  exit 2
fi
if [ ! -f "$DIST_DIR/index.html" ]; then
  echo "Portal build is missing $DIST_DIR/index.html" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cp "$ROOT_DIR/CHANGELOG.md" "$DIST_DIR/CHANGELOG.md"
cp "$ROOT_DIR/docs/openapi.json" "$DIST_DIR/openapi.json"

for route in app confirm; do
  mkdir -p "$DIST_DIR/$route"
  cp "$DIST_DIR/index.html" "$DIST_DIR/$route/index.html"
done

INSTALLER_SOURCE="$ROOT_DIR/integrations/agent-guard/install.sh"
INSTALLER_DEST="$DIST_DIR/install/agent-guard/install.sh"
if [ ! -f "$INSTALLER_SOURCE" ]; then
  echo "Agent Guard installer is missing: $INSTALLER_SOURCE" >&2
  exit 1
fi
mkdir -p "$(dirname "$INSTALLER_DEST")"
cp "$INSTALLER_SOURCE" "$INSTALLER_DEST"
chmod 755 "$INSTALLER_DEST"
