#!/usr/bin/env bash
set -euo pipefail

PORTAL_URL="${PORTAL_URL:-}"
API_URL="${API_URL:-}"
if [ -z "$PORTAL_URL" ]; then
  echo "Set PORTAL_URL to the CloudFront or custom-domain HTTPS URL." >&2
  exit 1
fi

for route in / /app; do
  body="$(curl --fail --silent --show-error --location --max-time 15 "$PORTAL_URL$route")"
  if ! grep -q "Kenning" <<<"$body"; then
    echo "Portal route did not return the Kenning application: $route" >&2
    exit 1
  fi
done

if [ -n "$API_URL" ]; then
  health="$(curl --fail --silent --show-error --max-time 15 "$API_URL/health")"
  if ! grep -q '"status"[[:space:]]*:[[:space:]]*"ok"' <<<"$health"; then
    echo "API health response was not healthy." >&2
    exit 1
  fi
  auth_config="$(curl --fail --silent --show-error --max-time 15 "$API_URL/auth/config")"
  if ! grep -q '"session_cookie"' <<<"$auth_config"; then
    echo "API authentication configuration is missing session_cookie." >&2
    exit 1
  fi
  protected_status="$(curl --silent --show-error --max-time 15 -o /dev/null -w '%{http_code}' "$API_URL/v1/tenants/release-smoke-boundary")"
  if [ "$protected_status" != "401" ]; then
    echo "Unauthenticated protected API boundary returned HTTP $protected_status, expected 401." >&2
    exit 1
  fi
fi

echo "Portal smoke test passed for $PORTAL_URL"
