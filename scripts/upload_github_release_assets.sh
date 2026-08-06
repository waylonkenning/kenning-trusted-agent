#!/usr/bin/env bash
set -Eeuo pipefail

: "${GITHUB_RELEASE_UPLOAD_URL:?GITHUB_RELEASE_UPLOAD_URL must be set}"
: "${GITHUB_RELEASE_TOKEN:?GITHUB_RELEASE_TOKEN must be set}"

failures=0

for asset in "$@"; do
  asset_name="$(basename "$asset")"
  content_type="application/octet-stream"
  case "$asset_name" in
    *.json) content_type="application/json" ;;
    *.txt) content_type="text/plain" ;;
  esac

  response_file="$(mktemp)"
  http_status="000"
  if http_status="$(curl --silent --show-error --request POST \
    --header "Authorization: Bearer $GITHUB_RELEASE_TOKEN" \
    --header "Content-Type: $content_type" \
    --data-binary "@$asset" \
    --output "$response_file" \
    --write-out '%{http_code}' \
    "${GITHUB_RELEASE_UPLOAD_URL}?name=${asset_name}")"; then
    :
  else
    http_status="000"
  fi

  uploaded_name=""
  if [[ "$http_status" =~ ^2[0-9][0-9]$ ]]; then
    uploaded_name="$(jq -er '.name // empty' "$response_file" 2>/dev/null || true)"
  fi
  if [[ "$http_status" =~ ^2[0-9][0-9]$ ]] && [ -n "$uploaded_name" ]; then
    echo "  uploaded asset: $uploaded_name"
  else
    echo "  WARNING: failed to upload asset $asset_name (HTTP $http_status; non-fatal)" >&2
    failures=$((failures + 1))
  fi
  rm -f "$response_file"
done

if [ "$failures" -gt 0 ]; then
  echo "GitHub release asset upload warnings: $failures" >&2
fi

# S3 release evidence remains the deployment gate and source of truth. Asset
# upload failures are visible in the release log but do not fail promotion.
exit 0
