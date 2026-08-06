#!/usr/bin/env bash
set -euo pipefail

# Guard integration test: verifies the Kenning Agent Guard evaluation and
# approval contract against a deployed environment.
#
# The script keeps PAT plaintext in process memory only and revokes every
# token on exit, including on failure. It uses a unique tenant per run so
# repeated runs never collide.
#
# Required:
#   KENNING_API_URL   Deployed HTTPS API URL.
# Optional:
#   AWS_REGION        Defaults to us-east-1.
#   TOKEN_TABLE_NAME  Defaults to kenning-agent-guard-tokens-prototype.
#
# The checks mirror the contract the OpenCode / Claude Code / Codex plugins
# rely on:
#   1. A safe command is allowed (allow/warn).
#   2. A destructive command requires approval and is blocked.
#   3. Approving then retrying with approval_id + action_hash yields allow
#      with approval_status=consumed.
#   4. A consumed approval cannot be replayed (approval_not_approved).
#   5. A different command under an existing approval is rejected
#      (approval_action_mismatch).
#   6. A catastrophic command is hard-denied (deny).

API_URL="${KENNING_API_URL:-}"
AWS_REGION="${AWS_REGION:-$(aws configure get region 2>/dev/null || true)}"
AWS_REGION="${AWS_REGION:-us-east-1}"
TOKEN_TABLE_NAME="${TOKEN_TABLE_NAME:-kenning-agent-guard-tokens-prototype}"
RUN_ID="${GITHUB_RUN_ID:-local-$(date -u +%Y%m%d%H%M%S)}"
TEST_TENANT="guard-integration-${RUN_ID}"
CWD="/tmp/guard-integration-${RUN_ID}"

if [ -z "$API_URL" ]; then
  echo "Set KENNING_API_URL to the deployed HTTPS API URL." >&2
  exit 1
fi
API_URL="${API_URL%/}"

EVAL_TOKEN_ID=""
APPROVE_TOKEN_ID=""
EVAL_PAT=""
APPROVE_PAT=""
PASS=0
FAIL=0

cleanup() {
  for token_id in "$EVAL_TOKEN_ID" "$APPROVE_TOKEN_ID"; do
    if [ -n "$token_id" ]; then
      AWS_REGION="$AWS_REGION" TOKEN_TABLE_NAME="$TOKEN_TABLE_NAME" \
        python3 scripts/manage_pat.py revoke --token-id "$token_id" >/dev/null 2>&1 || true
    fi
  done
}
trap cleanup EXIT

create_pat() {
  AWS_REGION="$AWS_REGION" TOKEN_TABLE_NAME="$TOKEN_TABLE_NAME" python3 scripts/manage_pat.py create "$@"
}

echo "Guard integration test"
echo "  API:    $API_URL"
echo "  Tenant: $TEST_TENANT"
echo "  Region: $AWS_REGION"
echo

# --- Disposable credentials -------------------------------------------------
EVAL_OUTPUT="$(create_pat \
  --name "guard-integration-eval" \
  --tenant-id "$TEST_TENANT" \
  --scopes "guard:evaluate,actions:write" \
  --expires-in-days 1)"
EVAL_PAT="$(printf '%s\n' "$EVAL_OUTPUT" | sed -n 's/^token: //p')"
EVAL_TOKEN_ID="$(printf '%s\n' "$EVAL_OUTPUT" | sed -n 's/^token_id: //p')"

APPROVE_OUTPUT="$(create_pat \
  --name "guard-integration-approve" \
  --tenant-id "$TEST_TENANT" \
  --scopes "approve:actions" \
  --expires-in-days 1)"
APPROVE_PAT="$(printf '%s\n' "$APPROVE_OUTPUT" | sed -n 's/^token: //p')"
APPROVE_TOKEN_ID="$(printf '%s\n' "$APPROVE_OUTPUT" | sed -n 's/^token_id: //p')"

if [ -z "$EVAL_PAT" ] || [ -z "$APPROVE_PAT" ]; then
  echo "FAIL: could not create disposable PATs." >&2
  exit 1
fi

# --- Helpers ----------------------------------------------------------------
# evaluate <label> <command> [approval_id] [action_hash]
# Prints the full JSON response body. The label makes the action_id unique
# per evaluation, matching how the plugins send a unique callID per tool call.
evaluate() {
  local label="$1"
  local command="$2"
  local approval_id="${3:-}"
  local action_hash="${4:-}"
  local payload
  payload="$(jq -n \
    --arg tenant "$TEST_TENANT" \
    --arg command "$command" \
    --arg cwd "$CWD" \
    --arg run "guard-integration-${RUN_ID}" \
    --arg action_id "action-${RUN_ID}-${label}" \
    --arg approval_id "$approval_id" \
    --arg action_hash "$action_hash" \
    '{
      context: {
        tenant_id: $tenant,
        environment: "development",
        agent_id: "guard-integration-agent",
        invoked_by: "guard-integration-test",
        run_id: $run,
        action_id: $action_id
      },
      mode: "enforce",
      intent: "Guard integration test.",
      action: {
        tool: "shell",
        operation: "execute",
        parameters: { command: $command, cwd: $cwd }
      }
    } + (if $approval_id != "" then {approval_id: $approval_id, action_hash: $action_hash} else {} end)')"
  curl --silent --show-error --max-time 20 \
    -X POST "$API_URL/v1/actions/evaluate" \
    -H "Authorization: Bearer $EVAL_PAT" \
    -H "X-Kenning-Tenant-Id: $TEST_TENANT" \
    -H "Content-Type: application/json" \
    -d "$payload"
}

# approve <approval_id> <action_hash>
approve() {
  local approval_id="$1"
  local action_hash="$2"
  curl --silent --show-error --max-time 20 \
    -X POST "$API_URL/v1/approvals/$approval_id/decision" \
    -H "Authorization: Bearer $APPROVE_PAT" \
    -H "X-Kenning-Tenant-Id: $TEST_TENANT" \
    -H "Content-Type: application/json" \
    -d "$(jq -n --arg h "$action_hash" '{decision: "approve", approver: "guard-integration", action_hash: $h}')"
}

check() {
  local name="$1"
  local condition="$2"
  if [ "$condition" = "true" ]; then
    echo "  PASS: $name"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: $name" >&2
    FAIL=$((FAIL + 1))
  fi
}

# --- Check 1: safe command is allowed ---------------------------------------
echo "Check 1: safe command is allowed"
R1="$(evaluate "safe" "printf 'safe\n' > /tmp/guard-integration-safe.txt")"
D1="$(jq -r '.decision' <<<"$R1")"
check "decision is allow or warn (got: $D1)" "$([ "$D1" = "allow" ] || [ "$D1" = "warn" ] && echo true || echo false)"

# --- Check 2: destructive command requires approval -------------------------
echo "Check 2: destructive command requires approval"
R2="$(evaluate "destructive" "rm -rf /tmp/guard-integration-target")"
D2="$(jq -r '.decision' <<<"$R2")"
AID2="$(jq -r '.approval.approval_id // empty' <<<"$R2")"
AH2="$(jq -r '.action_hash // empty' <<<"$R2")"
check "decision is require_approval (got: $D2)" "$([ "$D2" = "require_approval" ] && echo true || echo false)"
check "approval_id present" "$([ -n "$AID2" ] && echo true || echo false)"
check "reason includes DESTRUCTIVE_FILESYSTEM_OPERATION" "$(jq -e '.reason_codes | index("DESTRUCTIVE_FILESYSTEM_OPERATION")' <<<"$R2" >/dev/null 2>&1 && echo true || echo false)"

# --- Check 3: approve then retry yields allow/consumed ----------------------
echo "Check 3: approve then retry yields allow/consumed"
AP3="$(approve "$AID2" "$AH2")"
AP3_STATUS="$(jq -r '.approval.status // empty' <<<"$AP3")"
check "approval status is approved (got: $AP3_STATUS)" "$([ "$AP3_STATUS" = "approved" ] && echo true || echo false)"
R3="$(evaluate "destructive" "rm -rf /tmp/guard-integration-target" "$AID2" "$AH2")"
D3="$(jq -r '.decision' <<<"$R3")"
AS3="$(jq -r '.approval_status // empty' <<<"$R3")"
check "retry decision is allow (got: $D3)" "$([ "$D3" = "allow" ] && echo true || echo false)"
check "approval_status is consumed (got: $AS3)" "$([ "$AS3" = "consumed" ] && echo true || echo false)"

# --- Check 4: consumed approval cannot be replayed --------------------------
echo "Check 4: consumed approval cannot be replayed"
R4="$(evaluate "destructive" "rm -rf /tmp/guard-integration-target" "$AID2" "$AH2" || true)"
ERR4="$(jq -r '.error // empty' <<<"$R4")"
check "replay rejected with approval_not_approved (got: $ERR4)" "$([ "$ERR4" = "approval_not_approved" ] && echo true || echo false)"

# --- Check 5: action-hash mismatch rejected ---------------------------------
echo "Check 5: action-hash mismatch rejected"
R5A="$(evaluate "benign" "rm -rf /tmp/guard-integration-benign")"
AID5="$(jq -r '.approval.approval_id // empty' <<<"$R5A")"
AH5="$(jq -r '.action_hash // empty' <<<"$R5A")"
approve "$AID5" "$AH5" >/dev/null
R5B="$(evaluate "benign" "rm -rf /tmp/guard-integration-OTHER" "$AID5" "$AH5" || true)"
ERR5="$(jq -r '.error // empty' <<<"$R5B")"
check "tampered command rejected with approval_action_mismatch (got: $ERR5)" "$([ "$ERR5" = "approval_action_mismatch" ] && echo true || echo false)"

# --- Check 6: catastrophic command hard-denied ------------------------------
echo "Check 6: catastrophic command hard-denied"
R6="$(evaluate "catastrophic" "rm -rf /")"
D6="$(jq -r '.decision' <<<"$R6")"
check "decision is deny (got: $D6)" "$([ "$D6" = "deny" ] && echo true || echo false)"
check "reason includes CATASTROPHIC_FILESYSTEM_OPERATION" "$(jq -e '.reason_codes | index("CATASTROPHIC_FILESYSTEM_OPERATION")' <<<"$R6" >/dev/null 2>&1 && echo true || echo false)"

# --- Summary ----------------------------------------------------------------
echo
echo "Guard integration test: $PASS passed, $FAIL failed."
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
echo "Guard integration test passed for $API_URL"
