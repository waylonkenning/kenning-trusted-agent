#!/usr/bin/env bash
set -Eeuo pipefail

# Client-owned deployment helper. It uploads immutable artifacts to a private
# bucket, applies the parameterised CloudFormation stack, and publishes the
# portal configuration after the API and CloudFront outputs exist.

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REGION="${AWS_REGION:-$(aws configure get region 2>/dev/null || true)}"
REGION="${REGION:-us-east-1}"
TEMPLATE_PATH="$ROOT_DIR/infra/single-tenant/template.yaml"
COMMAND="${1:-}"
if [ -z "$COMMAND" ]; then
  echo "Usage: $0 deploy --parameters-file FILE [--stack-name NAME] [--artifacts-dir DIR]" >&2
  echo "       $0 init --api-url URL --tenant-id ID" >&2
  exit 2
fi
shift

STACK_NAME="${KTA_STACK_NAME:-kta-single-tenant}"
PARAMETERS_FILE="${KTA_PARAMETERS_FILE:-$ROOT_DIR/infra/single-tenant/client-parameters.json}"
ARTIFACTS_DIR="${KTA_ARTIFACTS_DIR:-$ROOT_DIR/.single-tenant-artifacts}"
API_URL=""
TENANT_ID=""
RETENTION_DAYS=""
LEGAL_HOLD_DEFAULT=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --stack-name)
      STACK_NAME="$2"
      shift 2
      ;;
    --parameters-file)
      PARAMETERS_FILE="$2"
      shift 2
      ;;
    --artifacts-dir)
      ARTIFACTS_DIR="$2"
      shift 2
      ;;
    --api-url)
      API_URL="$2"
      shift 2
      ;;
    --tenant-id)
      TENANT_ID="$2"
      shift 2
      ;;
    --retention-days)
      RETENTION_DAYS="$2"
      shift 2
      ;;
    --legal-hold-default)
      LEGAL_HOLD_DEFAULT="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 2
      ;;
  esac
done

read_parameter() {
  local key="$1"
  jq -r --arg key "$key" '.[$key] // empty' "$PARAMETERS_FILE"
}

require_parameter() {
  local key="$1"
  local value
  value="$(read_parameter "$key")"
  if [ -z "$value" ]; then
    echo "Parameter $key is required in $PARAMETERS_FILE" >&2
    exit 1
  fi
  printf '%s' "$value"
}

validate_https_url() {
  case "$1" in
    https://?*) ;;
    *) echo "Expected an HTTPS URL." >&2; exit 1 ;;
  esac
}

deploy_stack() {
  if [ ! -f "$PARAMETERS_FILE" ]; then
    echo "Parameter file not found: $PARAMETERS_FILE" >&2
    exit 1
  fi
  if [ ! -f "$TEMPLATE_PATH" ]; then
    echo "Template not found: $TEMPLATE_PATH" >&2
    exit 1
  fi

  local agency_slug environment_name artifact_bucket portal_domain portal_certificate
  agency_slug="$(require_parameter AgencySlug)"
  environment_name="$(require_parameter EnvironmentName)"
  artifact_bucket="$(require_parameter LambdaArtifactBucket)"
  portal_domain="$(read_parameter PortalDomain)"
  portal_certificate="$(read_parameter PortalCertificateArn)"
  if [ -n "$portal_domain" ] && [ -z "$portal_certificate" ]; then
    echo "PortalCertificateArn is required when PortalDomain is set." >&2
    exit 1
  fi
  if [ -n "$portal_certificate" ] && [ -z "$portal_domain" ]; then
    echo "PortalDomain is required when PortalCertificateArn is set." >&2
    exit 1
  fi

  local source_commit release_id release_version release_name
  source_commit="$(read_parameter ReleaseSourceCommit)"
  if [ -z "$source_commit" ] || [ "$source_commit" = "0000000000000000000000000000000000000000" ]; then
    source_commit="$(git -C "$ROOT_DIR" rev-parse HEAD)"
  fi
  if [[ ! "$source_commit" =~ ^[0-9a-f]{40}$ ]]; then
    echo "ReleaseSourceCommit must be a full lowercase Git SHA." >&2
    exit 1
  fi
  release_id="$(read_parameter ReleaseId)"
  release_id="${release_id:-client-${environment_name}-$(date -u +%Y%m%d%H%M%S)}"
  release_version="$(read_parameter ReleaseVersion)"
  release_version="${release_version:-0.1.0}"
  release_name="$(read_parameter ReleaseName)"
  release_name="${release_name:-$agency_slug}"

  mkdir -p "$ARTIFACTS_DIR"
  if [ ! -f "$ARTIFACTS_DIR/lambda.zip" ] || [ ! -f "$ARTIFACTS_DIR/citation-fetcher.zip" ] || [ ! -f "$ARTIFACTS_DIR/web.tar.gz" ]; then
    python3 "$ROOT_DIR/scripts/build_single_tenant_artifacts.py" \
      --output-dir "$ARTIFACTS_DIR" \
      --environment "$environment_name" \
      --source-commit "$source_commit" \
      --release-id "$release_id" \
      --release-version "$release_version" \
      --web-api-url same-origin
  fi

  local artifact_prefix lambda_key fetcher_key web_key
  artifact_prefix="single-tenant/${agency_slug}/${release_id}"
  lambda_key="${artifact_prefix}/lambda.zip"
  fetcher_key="${artifact_prefix}/citation-fetcher.zip"
  web_key="${artifact_prefix}/web.tar.gz"

  echo "Preparing private artifact bucket $artifact_bucket in $REGION"
  if ! aws s3api head-bucket --region "$REGION" --bucket "$artifact_bucket" >/dev/null 2>&1; then
    if [ "$REGION" = "us-east-1" ]; then
      aws s3api create-bucket --region "$REGION" --bucket "$artifact_bucket" >/dev/null
    else
      aws s3api create-bucket --region "$REGION" --bucket "$artifact_bucket" \
        --create-bucket-configuration "LocationConstraint=$REGION" >/dev/null
    fi
  fi
  # Apply the minimum release-bucket guardrails even when the bucket already
  # exists. Preserve a customer-managed KMS policy when one is configured.
  aws s3api put-public-access-block --region "$REGION" --bucket "$artifact_bucket" \
    --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
  if ! aws s3api get-bucket-encryption --region "$REGION" --bucket "$artifact_bucket" >/dev/null 2>&1; then
    aws s3api put-bucket-encryption --region "$REGION" --bucket "$artifact_bucket" \
      --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
  fi
  aws s3api put-bucket-versioning --region "$REGION" --bucket "$artifact_bucket" --versioning-configuration Status=Enabled
  aws s3 cp "$ARTIFACTS_DIR/lambda.zip" "s3://${artifact_bucket}/${lambda_key}" --region "$REGION" --sse AES256 >/dev/null
  aws s3 cp "$ARTIFACTS_DIR/citation-fetcher.zip" "s3://${artifact_bucket}/${fetcher_key}" --region "$REGION" --sse AES256 >/dev/null
  aws s3 cp "$ARTIFACTS_DIR/web.tar.gz" "s3://${artifact_bucket}/${web_key}" --region "$REGION" --sse AES256 >/dev/null

  local effective_parameters temp_dir
  temp_dir="$(mktemp -d)"
  trap 'rm -rf "$temp_dir"' RETURN
  effective_parameters="$temp_dir/parameters.json"
  jq \
    --arg stack "$STACK_NAME" \
    --arg bucket "$artifact_bucket" \
    --arg lambda_key "$lambda_key" \
    --arg fetcher_key "$fetcher_key" \
    --arg web_key "$web_key" \
    --arg version "$source_commit" \
    --arg source "$source_commit" \
    '. + {DeploymentStackName:$stack,LambdaArtifactBucket:$bucket,LambdaArtifactKey:$lambda_key,CitationFetcherArtifactKey:$fetcher_key,WebArtifactKey:$web_key,LambdaArtifactVersion:$version,ReleaseSourceCommit:$source}' \
    "$PARAMETERS_FILE" > "$effective_parameters"

  local parameter_overrides=()
  while IFS= read -r parameter; do
    parameter_overrides+=("$parameter")
  done < <(jq -r 'to_entries[] | "\(.key)=\(.value | tostring)"' "$effective_parameters")

  echo "Applying CloudFormation stack $STACK_NAME"
  aws cloudformation deploy \
    --region "$REGION" \
    --stack-name "$STACK_NAME" \
    --template-file "$TEMPLATE_PATH" \
    --capabilities CAPABILITY_NAMED_IAM \
    --no-fail-on-empty-changeset \
    --parameter-overrides "${parameter_overrides[@]}"

  local portal_bucket distribution_id deployed_api deployed_portal
  portal_bucket="$(aws cloudformation describe-stacks --region "$REGION" --stack-name "$STACK_NAME" --query 'Stacks[0].Outputs[?OutputKey==`PortalBucketName`].OutputValue | [0]' --output text)"
  distribution_id="$(aws cloudformation describe-stacks --region "$REGION" --stack-name "$STACK_NAME" --query 'Stacks[0].Outputs[?OutputKey==`PortalDistributionId`].OutputValue | [0]' --output text)"
  deployed_api="$(aws cloudformation describe-stacks --region "$REGION" --stack-name "$STACK_NAME" --query 'Stacks[0].Outputs[?OutputKey==`ApiEndpoint`].OutputValue | [0]' --output text)"
  deployed_portal="$(aws cloudformation describe-stacks --region "$REGION" --stack-name "$STACK_NAME" --query 'Stacks[0].Outputs[?OutputKey==`PortalUrl`].OutputValue | [0]' --output text)"

  rm -rf "$temp_dir/web"
  mkdir -p "$temp_dir/web"
  tar -xzf "$ARTIFACTS_DIR/web.tar.gz" -C "$temp_dir/web"
  jq -nr --arg api "$deployed_api" '"window.__KENNING_API_URL__ = " + ($api | @json) + ";"' > "$temp_dir/web/api-config.js"
  jq -n \
    --arg name "$(read_parameter PortalTitle)" \
    --arg primary_color "$(read_parameter PortalPrimaryColor)" \
    --arg logo_url "$(read_parameter PortalLogoUrl)" \
    '{name:($name // "Kenning Trusted Agent"),title:($name // "Kenning Trusted Agent"),primary_color:($primary_color // "#5A4AB3"),logo_url:($logo_url // "")}' \
    > "$temp_dir/web/branding.json"
  aws s3 sync "$temp_dir/web" "s3://${portal_bucket}/" --region "$REGION" --delete --sse AES256 --cache-control no-cache >/dev/null
  aws cloudfront create-invalidation --distribution-id "$distribution_id" --paths '/*' >/dev/null

  echo
  echo "Single-tenant deployment complete."
  echo "Stack: $STACK_NAME"
  echo "Region: $REGION"
  echo "Workspace: $agency_slug"
  echo "API: $deployed_api"
  echo "Portal: $deployed_portal"
  echo "Release: $release_id"
}

initialise_workspace() {
  if [ -z "$API_URL" ]; then
    echo "--api-url is required for init." >&2
    exit 2
  fi
  if [ -z "${KENNING_PAT:-}" ]; then
    echo "Set KENNING_PAT in the environment. The value is never written to disk." >&2
    exit 1
  fi
  TENANT_ID="${TENANT_ID:-${KTA_TENANT_ID:-}}"
  if [ -z "$TENANT_ID" ]; then
    echo "--tenant-id is required for init." >&2
    exit 2
  fi
  RETENTION_DAYS="${RETENTION_DAYS:-365}"
  LEGAL_HOLD_DEFAULT="${LEGAL_HOLD_DEFAULT:-false}"
  validate_https_url "$API_URL"
  local payload status
  payload="$(jq -cn \
    --arg tenant_id "$TENANT_ID" \
    --arg retention_days "$RETENTION_DAYS" \
    --arg legal_hold "$LEGAL_HOLD_DEFAULT" \
    '{tenant_id:$tenant_id,display_name:$tenant_id,default_environment:"production",retention:{audit_days:($retention_days|tonumber),proof_days:($retention_days|tonumber),approval_days:($retention_days|tonumber)},legal_hold_default:($legal_hold == "true"),environments:["production"]}')"
  status="$(curl --fail-with-body -sS -o /dev/null -w '%{http_code}' \
    -X PUT "${API_URL%/}/v1/tenants/${TENANT_ID}" \
    -H 'Accept: application/json' \
    -H "Authorization: Bearer $KENNING_PAT" \
    -H 'Content-Type: application/json' \
    --data "$payload")"
  if [ "$status" != "200" ]; then
    echo "Workspace initialisation failed with HTTP $status." >&2
    exit 1
  fi
  echo "Workspace initialised: $TENANT_ID (retention ${RETENTION_DAYS} days; legal hold ${LEGAL_HOLD_DEFAULT})."
}

case "$COMMAND" in
  deploy)
    deploy_stack
    ;;
  init)
    initialise_workspace
    ;;
  *)
    echo "Unknown command: $COMMAND" >&2
    exit 2
    ;;
esac
