#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python3}"
export PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}"

"$PYTHON_BIN" scripts/check_documentation_inventory.py
"$PYTHON_BIN" scripts/check_public_boundary.py
"$PYTHON_BIN" scripts/check_public_links.py
"$PYTHON_BIN" scripts/validate_single_tenant_package.py --skip-cloudformation
"$PYTHON_BIN" scripts/run_required_tests.py
node --test tests/*.mjs
npx --yes @apidevtools/swagger-cli validate docs/openapi.json
npm --prefix portal ci --ignore-scripts
npm --prefix portal run build
npm --prefix portal run lint
command -v gitleaks >/dev/null || {
  echo "gitleaks is required for the publication scan." >&2
  exit 1
}
gitleaks git --no-banner --redact --log-opts='--all --reflog' "$ROOT_DIR"
