#!/usr/bin/env bash
set -euo pipefail

# Hosted smoke test for the tenant-facing control plane. It creates temporary
# AWS-backed PATs, exercises the browser session and platform support paths,
# then revokes the PATs even if a check fails.

API_URL="${API_URL:-}"
AWS_REGION="${AWS_REGION:-$(aws configure get region 2>/dev/null || true)}"
AWS_REGION="${AWS_REGION:-us-east-1}"
TOKEN_TABLE_NAME="${TOKEN_TABLE_NAME:-kenning-agent-guard-tokens-prototype}"
if [ -z "$API_URL" ]; then
  echo "Set API_URL to the deployed HTTPS API URL." >&2
  exit 1
fi

TENANT="hosted-saas-$(date +%s)"
TENANT_TOKEN_ID=""
PLATFORM_TOKEN_ID=""
COOKIE_JAR="$(mktemp)"
COOKIE_HEADERS="${COOKIE_JAR}.headers"

cleanup() {
  rm -f "$COOKIE_JAR"
  rm -f "$COOKIE_HEADERS"
  if [ -n "$TENANT_TOKEN_ID" ]; then
    AWS_REGION="$AWS_REGION" TOKEN_TABLE_NAME="$TOKEN_TABLE_NAME" python3 scripts/manage_pat.py revoke --token-id "$TENANT_TOKEN_ID" >/dev/null 2>&1 || true
  fi
  if [ -n "$PLATFORM_TOKEN_ID" ]; then
    AWS_REGION="$AWS_REGION" TOKEN_TABLE_NAME="$TOKEN_TABLE_NAME" python3 scripts/manage_pat.py revoke --token-id "$PLATFORM_TOKEN_ID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

STATUS=""
BODY=""
request() {
  local result
  result="$(curl -sS -w "\n%{http_code}" "$@")"
  STATUS="${result##*$'\n'}"
  BODY="${result%$'\n'*}"
}

assert_status() {
  local expected="$1"
  local label="$2"
  if [ "$STATUS" != "$expected" ]; then
    echo "$label failed with HTTP $STATUS: $BODY" >&2
    exit 1
  fi
}

PAT_OUTPUT="$(AWS_REGION="$AWS_REGION" TOKEN_TABLE_NAME="$TOKEN_TABLE_NAME" python3 scripts/manage_pat.py create \
  --name hosted-saas-validation \
  --tenant-id "$TENANT" \
  --scopes admin \
  --expires-in-days 1)"
TENANT_PAT="$(printf '%s\n' "$PAT_OUTPUT" | sed -n 's/^token: //p')"
TENANT_TOKEN_ID="$(printf '%s\n' "$PAT_OUTPUT" | sed -n 's/^token_id: //p')"
if [ -z "$TENANT_PAT" ] || [ -z "$TENANT_TOKEN_ID" ]; then
  echo "Tenant PAT creation did not return the expected one-time value." >&2
  exit 1
fi

AUTH_HEADERS=(-H "Authorization: Bearer $TENANT_PAT" -H "Accept: application/json")
JSON_HEADERS=(-H "Content-Type: application/json" -H "Accept: application/json")
TENANT_PAYLOAD="$(jq -cn --arg tenant "$TENANT" \
  '{tenant_id:$tenant,name:"Hosted SaaS validation tenant",status:"active",default_environment:"production",retention_enabled:false,legal_hold_enabled:false,data_residency_region:"us-east-1",capture_policy:{store_original_action:false,redact_fields:["target"],hash_fields:["parameters.statement"],max_field_length:2048},audit_sink:{enabled:false},environments:[{environment_id:"production",status:"active",mode:"enforce",allowed_tools:["shell","sql"]}]}')"

request "${AUTH_HEADERS[@]}" "${JSON_HEADERS[@]}" -X PUT "$API_URL/v1/tenants/$TENANT" --data "$TENANT_PAYLOAD"
if [ "$STATUS" != "200" ] && [ "$STATUS" != "201" ]; then
  echo "Tenant configuration failed with HTTP $STATUS: $BODY" >&2
  exit 1
fi

MEMBER_PAYLOAD="$(jq -cn --arg subject "$TENANT_TOKEN_ID" \
  '{subject:$subject,email:"hosted-validation@example.org",display_name:"Hosted Validation Owner",role:"owner",status:"active"}')"
request "${AUTH_HEADERS[@]}" "${JSON_HEADERS[@]}" -X POST "$API_URL/v1/tenants/$TENANT/members" --data "$MEMBER_PAYLOAD"
if [ "$STATUS" != "200" ] && [ "$STATUS" != "201" ]; then
  echo "Tenant membership failed with HTTP $STATUS: $BODY" >&2
  exit 1
fi

request -D "$COOKIE_HEADERS" -c "$COOKIE_JAR" "${AUTH_HEADERS[@]}" "${JSON_HEADERS[@]}" -X POST "$API_URL/auth/session" --data '{}'
assert_status 201 "Browser session creation"
if ! grep -q $'\tkta_session\t' "$COOKIE_JAR"; then
  echo "Browser session response did not produce a reusable cookie." >&2
  sed -E 's/(kta_session=)[^;]+/\1REDACTED/' "$COOKIE_HEADERS" >&2
  exit 1
fi
echo "$BODY" | jq -e --arg tenant "$TENANT" \
  '.memberships | any(.[]; .tenant_id == $tenant and .role == "owner")' >/dev/null

request -b "$COOKIE_JAR" "$API_URL/auth/csrf"
if [ "$STATUS" != "200" ]; then
  echo "CSRF token issuance failed with HTTP $STATUS: $BODY" >&2
  sed -E 's/(kta_session[[:space:]]+)[^[:space:]]+/\1REDACTED/' "$COOKIE_JAR" >&2
  sed -E 's/(kta_session=)[^;]+/\1REDACTED/' "$COOKIE_HEADERS" >&2
  exit 1
fi
CSRF_TOKEN="$(echo "$BODY" | jq -r .csrf_token)"
[ -n "$CSRF_TOKEN" ] && [ "$CSRF_TOKEN" != "null" ]

request -b "$COOKIE_JAR" -H "X-Kenning-Tenant-Id: $TENANT" "$API_URL/v1/me"
assert_status 200 "Session identity"
echo "$BODY" | jq -e --arg tenant "$TENANT" \
  '.active_tenant_id == $tenant and (.memberships | any(.[]; .tenant_id == $tenant))' >/dev/null

request -b "$COOKIE_JAR" -H "X-Kenning-Tenant-Id: $TENANT" "$API_URL/v1/tenants/$TENANT"
assert_status 200 "Tenant-scoped read"

request -b "$COOKIE_JAR" -H "X-Kenning-Tenant-Id: $TENANT" -H "X-Kenning-CSRF: $CSRF_TOKEN" \
  "${JSON_HEADERS[@]}" -X PUT "$API_URL/v1/tenants/$TENANT" --data "$TENANT_PAYLOAD"
assert_status 200 "Tenant-scoped settings write"

request -b "$COOKIE_JAR" -H "X-Kenning-Tenant-Id: $TENANT" "$API_URL/v1/security/events?limit=20"
assert_status 200 "Tenant security event read"
echo "$BODY" | jq -e --arg tenant "$TENANT" \
  '.events | any(.[]; .tenant_id == $tenant)' >/dev/null

request -b "$COOKIE_JAR" -H "X-Kenning-CSRF: $CSRF_TOKEN" -X POST "$API_URL/auth/logout"
assert_status 204 "Browser session logout"

request -b "$COOKIE_JAR" "$API_URL/v1/me"
assert_status 401 "Revoked browser session rejection"

PLATFORM_OUTPUT="$(AWS_REGION="$AWS_REGION" TOKEN_TABLE_NAME="$TOKEN_TABLE_NAME" python3 scripts/manage_pat.py create \
  --name hosted-platform-validation \
  --tenant-id platform \
  --scopes admin \
  --expires-in-days 1)"
PLATFORM_PAT="$(printf '%s\n' "$PLATFORM_OUTPUT" | sed -n 's/^token: //p')"
PLATFORM_TOKEN_ID="$(printf '%s\n' "$PLATFORM_OUTPUT" | sed -n 's/^token_id: //p')"
PLATFORM_HEADERS=(-H "Authorization: Bearer $PLATFORM_PAT" -H "Accept: application/json")
GRANT_PAYLOAD="$(jq -cn --arg tenant "$TENANT" \
  '{tenant_id:$tenant,reason:"Validate hosted tenant support workflow",operation:"support",expires_in_seconds:300}')"

request "${PLATFORM_HEADERS[@]}" "${JSON_HEADERS[@]}" -X POST "$API_URL/v1/platform/access-grants" --data "$GRANT_PAYLOAD"
assert_status 201 "Platform support grant creation"
GRANT_ID="$(echo "$BODY" | jq -r .grant_id)"
SUPPORT_PAYLOAD="$(jq -cn --arg tenant "$TENANT" --arg grant "$GRANT_ID" \
  '{tenant_id:$tenant,grant_id:$grant,resource:"members",limit:20}')"

request "${PLATFORM_HEADERS[@]}" "${JSON_HEADERS[@]}" -X POST "$API_URL/v1/platform/support/read" --data "$SUPPORT_PAYLOAD"
assert_status 200 "Platform read-only support operation"
echo "$BODY" | jq -e --arg tenant "$TENANT" \
  '.tenant_id == $tenant and (.memberships | any(.[]; .role == "owner"))' >/dev/null

request "${PLATFORM_HEADERS[@]}" "${JSON_HEADERS[@]}" -X POST \
  "$API_URL/v1/platform/access-grants/$GRANT_ID/revoke" --data '{"reason":"Hosted support validation complete"}'
assert_status 200 "Platform support grant revocation"

echo "Hosted tenant portal smoke test passed for $TENANT"
