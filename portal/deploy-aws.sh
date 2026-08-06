#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
AWS_REGION="$(aws configure get region 2>/dev/null || true)"
AWS_REGION="${AWS_REGION:-us-east-1}"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
ENVIRONMENT_NAME="${KENNING_ENVIRONMENT:-${KENNING_ENV:-prototype}}"
if [[ ! "$ENVIRONMENT_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9-]{0,31}$ ]]; then
  echo "KENNING_ENVIRONMENT must be a bounded environment identifier." >&2
  exit 1
fi
BUCKET_NAME="${KENNING_PORTAL_BUCKET:-kenning-trusted-agent-portal-${ENVIRONMENT_NAME}-${ACCOUNT_ID}}"
CF_STATE_FILE="$ROOT_DIR/.cloudfront-distribution-id-${ENVIRONMENT_NAME}"
PORTAL_DISTRIBUTION_ID="${PORTAL_DISTRIBUTION_ID:-}"
if [ "$ENVIRONMENT_NAME" = "prototype" ] && [ ! -f "$CF_STATE_FILE" ] && [ -f "$ROOT_DIR/.cloudfront-distribution-id" ]; then
  CF_STATE_FILE="$ROOT_DIR/.cloudfront-distribution-id"
fi
ORIGIN_ID="kenning-portal-s3-origin"
ORIGIN_DOMAIN="${BUCKET_NAME}.s3.${AWS_REGION}.amazonaws.com"
PORTAL_DOMAIN="${PORTAL_DOMAIN:-}"
PORTAL_ALIASES="${PORTAL_ALIASES:-$PORTAL_DOMAIN}"
ACM_CERTIFICATE_ARN="${ACM_CERTIFICATE_ARN:-}"
HOSTED_ZONE_ID="${HOSTED_ZONE_ID:-}"
PORTAL_ORIGIN="${PORTAL_ORIGIN:-}"
if [ -n "$PORTAL_ALIASES" ]; then
  PORTAL_ALIAS_JSON="$(printf '%s' "$PORTAL_ALIASES" | jq -R 'split(",") | map(gsub("^\\s+|\\s+$"; "")) | map(select(length > 0))')"
else
  PORTAL_ALIAS_JSON='[]'
fi
PORTAL_ALIAS_COUNT="$(jq 'length' <<<"$PORTAL_ALIAS_JSON")"
VITE_KENNING_API_URL="${VITE_KENNING_API_URL:-${KENNING_API_URL:-}}"
VITE_KENNING_RELEASE_ID="${VITE_KENNING_RELEASE_ID:-${RELEASE_ID:-local}}"
VITE_KENNING_RELEASE_NAME="${VITE_KENNING_RELEASE_NAME:-${RELEASE_NAME:-Ahipara}}"
VITE_KENNING_RELEASE_VERSION="${VITE_KENNING_RELEASE_VERSION:-${RELEASE_VERSION:-0.1.0-local}}"
PORTAL_API_MODE="${PORTAL_API_MODE:-cross-origin}"
API_ORIGIN_ID="kenning-control-plane-api-origin"
API_ORIGIN_DOMAIN="${KENNING_CLOUDFRONT_API_ORIGIN_DOMAIN:-}"
RELEASE_WEB_DIR="${RELEASE_WEB_DIR:-}"

if [ "$PORTAL_API_MODE" = "same-origin" ]; then
  if [ -z "$VITE_KENNING_API_URL" ]; then
    echo "VITE_KENNING_API_URL or KENNING_API_URL is required for same-origin portal API proxying." >&2
    exit 1
  fi
  if [ -z "$API_ORIGIN_DOMAIN" ]; then
    API_ORIGIN_DOMAIN="${VITE_KENNING_API_URL#https://}"
    API_ORIGIN_DOMAIN="${API_ORIGIN_DOMAIN#http://}"
    API_ORIGIN_DOMAIN="${API_ORIGIN_DOMAIN%%/*}"
  fi
  VITE_BUILD_API_URL="same-origin"
else
  VITE_BUILD_API_URL="$VITE_KENNING_API_URL"
fi

if [ "$PORTAL_ALIAS_COUNT" -gt 0 ] && [ -z "$ACM_CERTIFICATE_ARN" ]; then
  echo "ACM_CERTIFICATE_ARN is required when PORTAL_ALIASES is set. The certificate must be in us-east-1." >&2
  exit 1
fi
if [ -n "$PORTAL_ORIGIN" ] && [[ ! "$PORTAL_ORIGIN" =~ ^https://[^/]+/?$ ]]; then
  echo "PORTAL_ORIGIN must be an HTTPS origin without a path." >&2
  exit 1
fi
if [ -n "$ACM_CERTIFICATE_ARN" ]; then
  CERTIFICATE_STATUS="$(aws acm describe-certificate --region us-east-1 --certificate-arn "$ACM_CERTIFICATE_ARN" --query 'Certificate.Status' --output text)"
  if [ "$CERTIFICATE_STATUS" != "ISSUED" ]; then
    echo "ACM certificate is not ISSUED: $CERTIFICATE_STATUS" >&2
    exit 1
  fi
fi

if [ -n "$RELEASE_WEB_DIR" ]; then
  if [ ! -f "$RELEASE_WEB_DIR/index.html" ]; then
    echo "RELEASE_WEB_DIR is not a prepared web artifact: $RELEASE_WEB_DIR" >&2
    exit 1
  fi
  DIST_DIR="$RELEASE_WEB_DIR"
  echo "Using retained web artifact: $DIST_DIR"
else
  echo "Building Kenning Trusted Agent portal..."
  if [ -n "$VITE_KENNING_API_URL" ]; then
    if [ "$PORTAL_API_MODE" = "same-origin" ]; then
      echo "Using same-origin control-plane proxy: $API_ORIGIN_DOMAIN"
    else
      echo "Using control-plane API: $VITE_KENNING_API_URL"
    fi
  else
    echo "Warning: VITE_KENNING_API_URL is unset; the tenant portal will not reach the control-plane API." >&2
  fi
  DEPLOYMENT_ENVIRONMENT="$ENVIRONMENT_NAME"
  if [ "$DEPLOYMENT_ENVIRONMENT" = "prototype" ]; then DEPLOYMENT_ENVIRONMENT="development"; fi
  VITE_KENNING_API_URL="$VITE_BUILD_API_URL" VITE_KENNING_DEPLOYMENT_ENVIRONMENT="$DEPLOYMENT_ENVIRONMENT" VITE_KENNING_RELEASE_ID="$VITE_KENNING_RELEASE_ID" VITE_KENNING_RELEASE_NAME="$VITE_KENNING_RELEASE_NAME" VITE_KENNING_RELEASE_VERSION="$VITE_KENNING_RELEASE_VERSION" npm --prefix "$ROOT_DIR" run build
  "$ROOT_DIR/../scripts/prepare_portal_dist.sh" "$ROOT_DIR/dist"
  DIST_DIR="$ROOT_DIR/dist"
fi

# Inject the runtime deployment environment so the portal banner is correct
# regardless of whether the artifact was pre-built or freshly compiled.
# Uses a meta tag because the page CSP blocks inline scripts (script-src 'self').
RUNTIME_ENVIRONMENT="$ENVIRONMENT_NAME"
if [ "$RUNTIME_ENVIRONMENT" = "prototype" ]; then RUNTIME_ENVIRONMENT="development"; fi
if [ -f "$DIST_DIR/index.html" ]; then
  sed -i.bak "s|</head>|<meta name=\"kenning-deployment-environment\" content=\"${RUNTIME_ENVIRONMENT}\"></head>|" "$DIST_DIR/index.html"
  rm -f "$DIST_DIR/index.html.bak"
  echo "Injected runtime deployment environment: $RUNTIME_ENVIRONMENT"
fi

# Retained web artifacts from before the stable installer was introduced do
# not contain this file. Resolve and backfill the installer before the
# destructive sync so rollback and promotion cannot delete the stable object.
INSTALLER_DEST="$DIST_DIR/install/agent-guard/install.sh"
INSTALLER_SOURCE="$INSTALLER_DEST"
if [ ! -f "$INSTALLER_SOURCE" ]; then
  INSTALLER_SOURCE="$ROOT_DIR/../integrations/agent-guard/install.sh"
  echo "Retained web artifact predates the stable installer; using checkout source: $INSTALLER_SOURCE"
  if [ ! -f "$INSTALLER_SOURCE" ]; then
    echo "Agent Guard installer is missing from the web artifact and checkout: $INSTALLER_SOURCE" >&2
    exit 1
  fi
  mkdir -p "$(dirname "$INSTALLER_DEST")"
  cp "$INSTALLER_SOURCE" "$INSTALLER_DEST"
fi

# The immutable artifact is built once and promoted to multiple environments.
# Stamp the environment's public origin at deployment time so share previews
# and crawlers never inherit a development hostname from the build artifact.
if grep -R -q -- "__KENNING_CANONICAL_URL__" "$DIST_DIR"; then
  if [ -z "$PORTAL_ORIGIN" ]; then
    echo "PORTAL_ORIGIN is required to resolve the canonical web URL." >&2
    exit 1
  fi
  CANONICAL_URL="${PORTAL_ORIGIN%/}/"
  while IFS= read -r -d '' index_page; do
    sed -i.bak "s|__KENNING_CANONICAL_URL__|${CANONICAL_URL}|g" "$index_page"
    rm -f "$index_page.bak"
  done < <(find "$DIST_DIR" -type f -name 'index.html' -print0)
  echo "Injected canonical web URL: $CANONICAL_URL"
fi

if ! aws s3api head-bucket --bucket "$BUCKET_NAME" >/dev/null 2>&1; then
  aws s3api create-bucket --bucket "$BUCKET_NAME" --region "$AWS_REGION" >/dev/null
fi

aws s3api put-public-access-block \
  --bucket "$BUCKET_NAME" \
  --public-access-block-configuration BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false

aws s3api put-bucket-website \
  --bucket "$BUCKET_NAME" \
  --website-configuration '{"IndexDocument":{"Suffix":"index.html"},"ErrorDocument":{"Key":"index.html"}}'

POLICY="$(printf '{"Version":"2012-10-17","Statement":[{"Sid":"PublicReadForWebsite","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::%s/*"}]}' "$BUCKET_NAME")"
aws s3api put-bucket-policy --bucket "$BUCKET_NAME" --policy "$POLICY"

aws s3 sync "$DIST_DIR" "s3://$BUCKET_NAME" --delete --cache-control "public,max-age=300"
# Keep the release history readable in a browser and do not cache it across
# releases. The file is part of the retained artifact and is never rebuilt
# during production promotion.
aws s3 cp "$DIST_DIR/CHANGELOG.md" \
  "s3://$BUCKET_NAME/CHANGELOG.md" \
  --cache-control "no-cache" \
  --content-type "text/markdown"
# The wizard presents this path as a shell installer. Set its content type
# explicitly because S3 sync otherwise infers a generic binary type.
aws s3 cp "$INSTALLER_SOURCE" \
  "s3://$BUCKET_NAME/install/agent-guard/install.sh" \
  --cache-control "no-cache" \
  --content-type "application/x-sh"
# HTML entry points must not be held by a browser or an intermediate cache;
# otherwise a route can continue loading an older hashed JavaScript bundle
# after a deployment. Static assets remain cacheable because their filenames
# are content-hashed by Vite.
aws s3 cp "$DIST_DIR" "s3://$BUCKET_NAME" --recursive \
  --exclude "*" --include "index.html" --include "*/index.html" \
  --cache-control "no-cache" --content-type "text/html"
# Publish the OpenAPI contract as a stable, self-hosted asset.
aws s3 cp "$DIST_DIR/openapi.json" "s3://$BUCKET_NAME/openapi.json" --cache-control "public,max-age=300" --content-type "application/json"

if [ -n "$PORTAL_DISTRIBUTION_ID" ]; then
  DISTRIBUTION_ID="$PORTAL_DISTRIBUTION_ID"
elif [ -f "$CF_STATE_FILE" ]; then
  DISTRIBUTION_ID="$(sed -n '1p' "$CF_STATE_FILE")"
  if ! aws cloudfront get-distribution --id "$DISTRIBUTION_ID" >/dev/null 2>&1; then
    DISTRIBUTION_ID=""
  fi
else
  DISTRIBUTION_ID=""
fi

if [ -z "$DISTRIBUTION_ID" ]; then
  CONFIG_FILE="$(mktemp)"
  CONFIG="$(printf '{"CallerReference":"kenning-portal-%s-%s","Comment":"Kenning Trusted Agent portal (%s)","Enabled":true,"DefaultRootObject":"index.html","PriceClass":"PriceClass_100","HttpVersion":"http2","IsIPV6Enabled":true,"Origins":{"Quantity":1,"Items":[{"Id":"%s","DomainName":"%s","S3OriginConfig":{"OriginAccessIdentity":""}}]},"DefaultCacheBehavior":{"TargetOriginId":"%s","ViewerProtocolPolicy":"redirect-to-https","AllowedMethods":{"Quantity":2,"Items":["GET","HEAD"],"CachedMethods":{"Quantity":2,"Items":["GET","HEAD"]}},"ForwardedValues":{"QueryString":false,"Cookies":{"Forward":"none"}},"MinTTL":0},"ViewerCertificate":{"CloudFrontDefaultCertificate":true,"MinimumProtocolVersion":"TLSv1.2_2021"}}' "$(date +%s)" "$ENVIRONMENT_NAME" "$ENVIRONMENT_NAME" "$ORIGIN_ID" "$ORIGIN_DOMAIN" "$ORIGIN_ID")"
  printf '%s' "$CONFIG" > "$CONFIG_FILE"
  if [ "$PORTAL_ALIAS_COUNT" -gt 0 ]; then
    jq --argjson aliases "$PORTAL_ALIAS_JSON" --arg certificate "$ACM_CERTIFICATE_ARN" '.Aliases={"Quantity":($aliases|length),"Items":$aliases} | .ViewerCertificate={"ACMCertificateArn":$certificate,"SSLSupportMethod":"sni-only","MinimumProtocolVersion":"TLSv1.2_2021"}' "$CONFIG_FILE" > "${CONFIG_FILE}.custom"
    mv "${CONFIG_FILE}.custom" "$CONFIG_FILE"
  fi
  DISTRIBUTION_ID="$(aws cloudfront create-distribution --distribution-config "file://$CONFIG_FILE" --query 'Distribution.Id' --output text)"
  printf '%s\n' "$DISTRIBUTION_ID" > "$CF_STATE_FILE"
  rm -f "$CONFIG_FILE"
fi

echo "Using CloudFront distribution: $DISTRIBUTION_ID"

# CloudFront only permits an alternate domain name to move between
# distributions after DNS points at the new distribution. Update the branded
# records before the alias-bearing distribution update below.
CF_DOMAIN="$(aws cloudfront get-distribution --id "$DISTRIBUTION_ID" --query 'Distribution.DomainName' --output text)"
if [ -n "$PORTAL_DOMAIN" ] && [ -n "$HOSTED_ZONE_ID" ]; then
  PORTAL_DOMAIN_ROOT="${PORTAL_DOMAIN%.}"
  WWW_DOMAIN="www.${PORTAL_DOMAIN_ROOT}"
  if ! jq -e --arg apex "$PORTAL_DOMAIN_ROOT" 'index($apex) != null' <<<"$PORTAL_ALIAS_JSON" >/dev/null; then
    echo "PORTAL_DOMAIN must be included in PORTAL_ALIASES." >&2
    exit 1
  fi
  if ! jq -e --arg www "$WWW_DOMAIN" 'index($www) != null' <<<"$PORTAL_ALIAS_JSON" >/dev/null; then
    echo "PORTAL_ALIASES must include $WWW_DOMAIN when updating Route 53." >&2
    exit 1
  fi
  if ! command -v dig >/dev/null 2>&1; then
    echo "dig is required to validate branded DNS propagation before a CloudFront alias transfer." >&2
    exit 1
  fi
  CHANGE_FILE="$(mktemp)"
  jq -n --arg apex "$PORTAL_DOMAIN_ROOT" --arg www "$WWW_DOMAIN" --arg value "$CF_DOMAIN" '{Changes:[
    {Action:"UPSERT",ResourceRecordSet:{Name:($apex+"."),Type:"A",AliasTarget:{HostedZoneId:"Z2FDTNDATAQYW2",DNSName:$value,EvaluateTargetHealth:false}}},
    {Action:"UPSERT",ResourceRecordSet:{Name:($apex+"."),Type:"AAAA",AliasTarget:{HostedZoneId:"Z2FDTNDATAQYW2",DNSName:$value,EvaluateTargetHealth:false}}},
    {Action:"UPSERT",ResourceRecordSet:{Name:($www+"."),Type:"CNAME",TTL:300,ResourceRecords:[{Value:($value+".")}] }},
    {Action:"UPSERT",ResourceRecordSet:{Name:("_."+$apex+"."),Type:"TXT",TTL:300,ResourceRecords:[{Value:("\""+$value+"\"")}] }},
    {Action:"UPSERT",ResourceRecordSet:{Name:("_"+$www+"."),Type:"TXT",TTL:300,ResourceRecords:[{Value:("\""+$value+"\"")}] }}
  ]}' > "$CHANGE_FILE"
  DNS_CHANGE_ID="$(aws route53 change-resource-record-sets \
    --hosted-zone-id "$HOSTED_ZONE_ID" \
    --change-batch "file://$CHANGE_FILE" \
    --query 'ChangeInfo.Id' \
    --output text)"
  rm -f "$CHANGE_FILE"
  aws route53 wait resource-record-sets-changed --id "$DNS_CHANGE_ID"

  DNS_AUTHORITY="$(dig +short NS "$PORTAL_DOMAIN_ROOT" | sed '/^[[:space:]]*$/d; s/\.$//' | head -n1)"
  if [ -z "$DNS_AUTHORITY" ]; then
    echo "Could not find an authoritative nameserver for $PORTAL_DOMAIN_ROOT." >&2
    exit 1
  fi

  dns_answers() {
    dig +short "$1" "$2" "@$DNS_AUTHORITY" | tr -d '"' | sed '/^[[:space:]]*$/d; s/\.$//' | sort -u | paste -sd, -
  }

  route53_alias_target() {
    local record_type="$1"
    aws route53 list-resource-record-sets \
      --hosted-zone-id "$HOSTED_ZONE_ID" \
      --output json |
      jq -r --arg name "${PORTAL_DOMAIN_ROOT}." --arg type "$record_type" \
        '.ResourceRecordSets[] | select(.Name == $name and .Type == $type) | .AliasTarget.DNSName // empty' |
      sed 's/\.$//' |
      head -n1
  }

  wait_for_cloudfront_ownership_txt() {
    local txt_name="$1"
    local attempt
    local actual
    for attempt in $(seq 1 30); do
      actual="$(dns_answers TXT "$txt_name")"
      if [ "$actual" = "$CF_DOMAIN" ]; then
        return 0
      fi
      sleep 2
    done
    echo "CloudFront ownership TXT record did not propagate: $txt_name (expected $CF_DOMAIN, got ${actual:-<empty>})." >&2
    return 1
  }

  wait_for_cloudfront_alias_dns() {
    local alias="$1"
    local attempt
    local actual_v4
    local actual_v6
    local actual_cname
    local route53_v4
    local route53_v6
    for attempt in $(seq 1 30); do
      if [ "$alias" = "$WWW_DOMAIN" ]; then
        actual_cname="$(dns_answers CNAME "$alias")"
        if [ "$actual_cname" = "$CF_DOMAIN" ]; then
          return 0
        fi
      else
        route53_v4="$(route53_alias_target A)"
        route53_v6="$(route53_alias_target AAAA)"
        actual_v4="$(dns_answers A "$alias")"
        actual_v6="$(dns_answers AAAA "$alias")"
        if [ "$route53_v4" = "$CF_DOMAIN" ] \
          && [ "$route53_v6" = "$CF_DOMAIN" ] \
          && [ -n "$actual_v4$actual_v6" ]; then
          return 0
        fi
      fi
      sleep 2
    done
    echo "Branded DNS did not resolve to the target CloudFront distribution: $alias (expected $CF_DOMAIN; authoritative nameserver $DNS_AUTHORITY; Route 53 A=${route53_v4:-<empty>}; Route 53 AAAA=${route53_v6:-<empty>}; A=${actual_v4:-<empty>}; AAAA=${actual_v6:-<empty>}; CNAME=${actual_cname:-<empty>})." >&2
    return 1
  }

  wait_for_cloudfront_ownership_txt "_.${PORTAL_DOMAIN_ROOT}"
  wait_for_cloudfront_ownership_txt "_${WWW_DOMAIN}"
  wait_for_cloudfront_alias_dns "$PORTAL_DOMAIN_ROOT"
  wait_for_cloudfront_alias_dns "$WWW_DOMAIN"
fi

# The S3 REST origin returns an access error for client-side route paths. Use
# the app entry point for missing objects so direct links such as
# /products/agent-guard/ still render through the React route resolver.
DIST_CONFIG_FILE="$(mktemp)"
DIST_UPDATED_CONFIG_FILE="$(mktemp)"
DIST_ETAG="$(aws cloudfront get-distribution-config --id "$DISTRIBUTION_ID" --query 'ETag' --output text)"
aws cloudfront get-distribution-config --id "$DISTRIBUTION_ID" > "$DIST_CONFIG_FILE"
CURRENT_ALIAS_JSON="$(jq -c '.DistributionConfig.Aliases.Items // []' "$DIST_CONFIG_FILE")"
if [ "$PORTAL_API_MODE" = "same-origin" ]; then
  jq --argjson aliases "$PORTAL_ALIAS_JSON" \
    --arg certificate "$ACM_CERTIFICATE_ARN" \
    --arg origin "$ORIGIN_DOMAIN" \
    --arg origin_id "$ORIGIN_ID" \
    --arg api_origin_id "$API_ORIGIN_ID" \
    --arg api_domain "$API_ORIGIN_DOMAIN" \
    --argjson api_paths '["/auth/*","/v1/*","/mcp*","/health"]' \
    '
      def api_origin:
        {
          Id: $api_origin_id,
          DomainName: $api_domain,
          OriginPath: "",
          CustomHeaders: {Quantity: 0},
          CustomOriginConfig: {
            HTTPPort: 80,
            HTTPSPort: 443,
            OriginProtocolPolicy: "https-only",
            OriginSslProtocols: {Quantity: 1, Items: ["TLSv1.2"]},
            OriginReadTimeout: 60,
            OriginKeepaliveTimeout: 5
          },
          ConnectionAttempts: 3,
          ConnectionTimeout: 10,
          OriginShield: {Enabled: false},
          OriginAccessControlId: ""
        };
      def api_behavior($pattern):
        {
          PathPattern: $pattern,
          TargetOriginId: $api_origin_id,
          TrustedSigners: {Enabled: false, Quantity: 0},
          TrustedKeyGroups: {Enabled: false, Quantity: 0},
          ViewerProtocolPolicy: "redirect-to-https",
          AllowedMethods: {
            Quantity: 7,
            Items: ["GET","HEAD","OPTIONS","PUT","PATCH","POST","DELETE"],
            CachedMethods: {Quantity: 2, Items: ["GET","HEAD"]}
          },
          SmoothStreaming: false,
          Compress: true,
          LambdaFunctionAssociations: {Quantity: 0},
          FunctionAssociations: {Quantity: 0},
          FieldLevelEncryptionId: "",
          GrpcConfig: {Enabled: false},
          ForwardedValues: {
            QueryString: true,
            Cookies: {Forward: "all"},
            Headers: {
              Quantity: 6,
              Items: ["Accept","Authorization","Content-Type","Origin","X-Kenning-CSRF","X-Kenning-Tenant-Id"]
            },
            QueryStringCacheKeys: {Quantity: 0}
          },
          MinTTL: 0,
          DefaultTTL: 0,
          MaxTTL: 0
        };
      .DistributionConfig
      | .Origins.Items = ([.Origins.Items[] | select(.Id != $api_origin_id)] + [api_origin])
      | .Origins.Quantity = (.Origins.Items | length)
      | .CacheBehaviors.Items = ([((.CacheBehaviors.Items // [])[] | select((.PathPattern // "") as $pattern | ($api_paths | index($pattern) | not)))] + ($api_paths | map(api_behavior(.))))
      | .CacheBehaviors.Quantity = (.CacheBehaviors.Items | length)
      | .Origins.Items[0].DomainName = $origin
      | .Origins.Items[0].Id = $origin_id
      | .DefaultCacheBehavior.TargetOriginId = $origin_id
      | .CustomErrorResponses = {"Quantity":2,"Items":[{"ErrorCode":403,"ResponsePagePath":"/index.html","ResponseCode":"200","ErrorCachingMinTTL":0},{"ErrorCode":404,"ResponsePagePath":"/index.html","ResponseCode":"200","ErrorCachingMinTTL":0}]}
      | if ($aliases | length) > 0 then .ViewerCertificate={"ACMCertificateArn":$certificate,"SSLSupportMethod":"sni-only","MinimumProtocolVersion":"TLSv1.2_2021"} else . end
    ' "$DIST_CONFIG_FILE" > "$DIST_UPDATED_CONFIG_FILE"
else
  jq --argjson aliases "$PORTAL_ALIAS_JSON" --arg certificate "$ACM_CERTIFICATE_ARN" --arg origin "$ORIGIN_DOMAIN" --arg origin_id "$ORIGIN_ID" '.DistributionConfig | .Origins.Items[0].DomainName=$origin | .Origins.Items[0].Id=$origin_id | .DefaultCacheBehavior.TargetOriginId=$origin_id | .CustomErrorResponses = {"Quantity":2,"Items":[{"ErrorCode":403,"ResponsePagePath":"/index.html","ResponseCode":"200","ErrorCachingMinTTL":0},{"ErrorCode":404,"ResponsePagePath":"/index.html","ResponseCode":"200","ErrorCachingMinTTL":0}]} | if ($aliases | length) > 0 then .ViewerCertificate={"ACMCertificateArn":$certificate,"SSLSupportMethod":"sni-only","MinimumProtocolVersion":"TLSv1.2_2021"} else . end' "$DIST_CONFIG_FILE" > "$DIST_UPDATED_CONFIG_FILE"
fi
aws cloudfront update-distribution --id "$DISTRIBUTION_ID" --if-match "$DIST_ETAG" --distribution-config "file://$DIST_UPDATED_CONFIG_FILE" >/dev/null
rm -f "$DIST_CONFIG_FILE" "$DIST_UPDATED_CONFIG_FILE"

echo "Waiting for the HTTPS distribution certificate and origin changes to finish deploying..."
aws cloudfront wait distribution-deployed --id "$DISTRIBUTION_ID"

# When an alternate domain already belongs to another standard distribution in
# this account, move it with CloudFront's atomic alias-transfer API. Updating
# the target distribution's Aliases field directly is DNS-cache-sensitive and
# can fail even after Route 53 reports the new target as INSYNC.
if [ "$PORTAL_ALIAS_COUNT" -gt 0 ]; then
  ALIAS_CONFIG_UPDATE_REQUIRED=0
  while IFS= read -r alias; do
    if jq -e --arg alias "$alias" 'index($alias) != null' <<<"$CURRENT_ALIAS_JSON" >/dev/null; then
      continue
    fi
    CONFLICT_COUNT="$(aws cloudfront list-conflicting-aliases \
      --distribution-id "$DISTRIBUTION_ID" \
      --alias "$alias" \
      --query 'ConflictingAliasesList.Quantity' \
      --output text)"
    if [ "$CONFLICT_COUNT" -gt 0 ]; then
      ALIAS_TRANSFER_SUCCEEDED=0
      for attempt in $(seq 1 6); do
        if aws cloudfront associate-alias \
          --target-distribution-id "$DISTRIBUTION_ID" \
          --alias "$alias"; then
          ALIAS_TRANSFER_SUCCEEDED=1
          break
        fi
        # A Route 53 change can be INSYNC before CloudFront's DNS validation
        # observes it. Retry the transfer for that bounded propagation window.
        if [ "$attempt" -lt 6 ]; then
          echo "CloudFront alias transfer is not ready; retrying ($attempt/5): $alias" >&2
          sleep 5
        fi
      done
      if [ "$ALIAS_TRANSFER_SUCCEEDED" -ne 1 ]; then
        echo "CloudFront alias transfer failed after bounded retries: $alias" >&2
        exit 1
      fi
      echo "Moved CloudFront alias to target distribution: $alias"
    else
      ALIAS_CONFIG_UPDATE_REQUIRED=1
    fi
  done < <(jq -r '.[]' <<<"$PORTAL_ALIAS_JSON")

  # A new or previously unassociated distribution has no source alias to
  # transfer. Add those aliases through the normal distribution update path.
  if [ "$ALIAS_CONFIG_UPDATE_REQUIRED" -eq 1 ]; then
    FALLBACK_CONFIG_FILE="$(mktemp)"
    FALLBACK_UPDATED_CONFIG_FILE="$(mktemp)"
    FALLBACK_ETAG="$(aws cloudfront get-distribution-config --id "$DISTRIBUTION_ID" --query 'ETag' --output text)"
    aws cloudfront get-distribution-config --id "$DISTRIBUTION_ID" > "$FALLBACK_CONFIG_FILE"
    jq --argjson aliases "$PORTAL_ALIAS_JSON" --arg certificate "$ACM_CERTIFICATE_ARN" \
      '.DistributionConfig | .Aliases={"Quantity":($aliases|length),"Items":$aliases} | .ViewerCertificate={"ACMCertificateArn":$certificate,"SSLSupportMethod":"sni-only","MinimumProtocolVersion":"TLSv1.2_2021"}' \
      "$FALLBACK_CONFIG_FILE" > "$FALLBACK_UPDATED_CONFIG_FILE"
    aws cloudfront update-distribution \
      --id "$DISTRIBUTION_ID" \
      --if-match "$FALLBACK_ETAG" \
      --distribution-config "file://$FALLBACK_UPDATED_CONFIG_FILE" >/dev/null
    rm -f "$FALLBACK_CONFIG_FILE" "$FALLBACK_UPDATED_CONFIG_FILE"
  fi
fi

echo "Waiting for the HTTPS distribution alias changes to finish deploying..."
aws cloudfront wait distribution-deployed --id "$DISTRIBUTION_ID"
INVALIDATION_ID="$(aws cloudfront create-invalidation --distribution-id "$DISTRIBUTION_ID" --paths '/*' --query 'Invalidation.Id' --output text)"
aws cloudfront wait invalidation-completed --distribution-id "$DISTRIBUTION_ID" --id "$INVALIDATION_ID"
CF_DOMAIN="$(aws cloudfront get-distribution --id "$DISTRIBUTION_ID" --query 'Distribution.DomainName' --output text)"

echo
echo "Kenning Trusted Agent portal deployed."
echo "Bucket: $BUCKET_NAME"
echo "Environment: $ENVIRONMENT_NAME"
echo "HTTPS URL: https://$CF_DOMAIN"
if [ -n "$PORTAL_DOMAIN" ]; then echo "Custom domain: https://$PORTAL_DOMAIN"; fi
echo "S3 origin URL: http://$BUCKET_NAME.s3-website-$AWS_REGION.amazonaws.com"
