#!/usr/bin/env bash
set -Eeuo pipefail

API_URL="${KENNING_API_URL:-}"
PAT="${KENNING_PAT:-}"
TENANT_ID="${KENNING_TEST_TENANT_ID:-}"
if [ -z "$API_URL" ] || [ -z "$PAT" ] || [ -z "$TENANT_ID" ]; then
  echo "Set KENNING_API_URL, KENNING_PAT, and KENNING_TEST_TENANT_ID." >&2
  exit 2
fi
case "$API_URL" in
  https://?*) ;;
  *) echo "KENNING_API_URL must use HTTPS." >&2; exit 2 ;;
esac

HEALTH="$(curl --fail-with-body -sS "${API_URL%/}/health")"
if [ "$(printf '%s' "$HEALTH" | jq -r '.status')" != "ok" ]; then
  echo "Health check did not return status=ok." >&2
  exit 1
fi
AUTH_CONFIG="$(curl --fail-with-body -sS "${API_URL%/}/auth/config")"
if [ "$(printf '%s' "$AUTH_CONFIG" | jq -r '.oidc_enabled')" != "true" ]; then
  echo "OIDC is not enabled." >&2
  exit 1
fi

ACTION_ID="single-tenant-smoke-$(date +%s)"
ALLOW_PAYLOAD="$(jq -cn \
  --arg tenant "$TENANT_ID" \
  --arg action_id "$ACTION_ID" \
  '{context:{tenant_id:$tenant,environment:"production",agent_id:"single-tenant-smoke-agent",invoked_by:"single-tenant-smoke",action_id:$action_id},action:{tool:"shell",parameters:{command:"printf single-tenant-smoke"}}}')"
ALLOW_RESPONSE="$(curl --fail-with-body -sS -X POST "${API_URL%/}/v1/actions/evaluate" \
  -H "Authorization: Bearer $PAT" \
  -H 'Content-Type: application/json' \
  --data "$ALLOW_PAYLOAD")"
if [ "$(printf '%s' "$ALLOW_RESPONSE" | jq -r '.decision')" != "allow" ]; then
  echo "The configured workspace did not return an allow decision." >&2
  exit 1
fi

MISMATCH_PAYLOAD="$(printf '%s' "$ALLOW_PAYLOAD" | jq '.context.tenant_id = "different-workspace"')"
MISMATCH_FILE="$(mktemp)"
trap 'rm -f "$MISMATCH_FILE"' EXIT
MISMATCH_STATUS="$(curl -sS -o "$MISMATCH_FILE" -w '%{http_code}' -X POST "${API_URL%/}/v1/actions/evaluate" \
  -H "Authorization: Bearer $PAT" \
  -H 'Content-Type: application/json' \
  --data "$MISMATCH_PAYLOAD")"
if [ "$MISMATCH_STATUS" != "403" ] || [ "$(jq -r '.error' "$MISMATCH_FILE")" != "single_tenant_mismatch" ]; then
  echo "The cross-workspace request was not rejected by the single-tenant boundary." >&2
  exit 1
fi

echo "Single-tenant smoke test passed: health, OIDC configuration, allow decision, and cross-workspace rejection."
