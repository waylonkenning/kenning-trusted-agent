#!/usr/bin/env bash
# Run Playwright E2E tests against a local Vite dev server + the deployed
# development API. This catches selector breakages from local UI changes
# before pushing to CI.
#
# Prerequisites:
#   - AWS credentials configured (for PAT creation in global setup)
#   - npx playwright install (browser binaries)
#
# Usage:
#   cd portal && npm run test:e2e:local
#   cd portal && npm run test:e2e:local -- --grep "policy"
set -euo pipefail
cd "$(dirname "$0")"

LOCAL_PORT="${LOCAL_PORT:-5199}"
DEV_API_URL="${E2E_API_URL:-http://127.0.0.1:3000}"
export E2E_API_URL="${DEV_API_URL}"
export E2E_PORTAL_URL="http://localhost:${LOCAL_PORT}/app"
export E2E_PLATFORM_URL="http://localhost:${LOCAL_PORT}/app"
export E2E_PORTAL_API_MODE="${E2E_PORTAL_API_MODE:-same-origin}"
export E2E_EXPECTED_ENVIRONMENT="development"
# E2E_DOCS_BASE_URL keeps its default (deployed dev).

echo "Starting local Vite dev server on port ${LOCAL_PORT} (API proxy: ${DEV_API_URL})..."
KENNING_API_PROXY_TARGET="${DEV_API_URL}" VITE_KENNING_DEPLOYMENT_ENVIRONMENT="development" npx vite --port "${LOCAL_PORT}" --strictPort &
VITE_PID=$!
trap 'kill ${VITE_PID} 2>/dev/null || true' EXIT

# Wait for the dev server to accept connections.
for i in $(seq 1 30); do
  if curl -sf "http://localhost:${LOCAL_PORT}/" >/dev/null 2>&1; then break; fi
  sleep 0.5
done

echo "Running Playwright against ${E2E_PORTAL_URL}..."
npx playwright test "$@"
