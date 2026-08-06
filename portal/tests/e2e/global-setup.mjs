import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { apiRequest, apiUrl } from './helpers.mjs'
import { stateFile } from './state.mjs'

const repoRoot = path.resolve(process.cwd(), '..')
const managePat = path.join(repoRoot, 'scripts', 'manage_pat.py')
const awsRegion = process.env.AWS_REGION || 'us-east-1'
const tokenTable = process.env.TOKEN_TABLE_NAME || 'kta-single-tenant-test-tokens'
const portalScopes = [
  'guard:evaluate', 'audit:read', 'audit:write', 'approve:actions', 'actions:write',
  'proof:read', 'proof:write', 'citation:verify', 'identity:read', 'identity:write',
  'policy:read', 'policy:write', 'policy:simulate', 'model:read', 'model:write',
  'tenant:read', 'tenant:write',
  'tenant:retention', 'token:admin', 'session:create',
].join(',')

function createPat(name, tenantId, scopes = portalScopes) {
  const output = execFileSync('python3', [managePat, 'create', '--name', name, '--tenant-id', tenantId, '--scopes', scopes, '--expires-in-days', '1'], {
    cwd: repoRoot,
    env: { ...process.env, AWS_REGION: awsRegion, TOKEN_TABLE_NAME: tokenTable },
    encoding: 'utf8',
  })
  const token = output.match(/^token: (.+)$/m)?.[1]?.trim()
  const tokenId = output.match(/^token_id: (.+)$/m)?.[1]?.trim()
  assert.ok(token, `PAT creation did not return a token:\n${output}`)
  assert.ok(tokenId, `PAT creation did not return a token_id:\n${output}`)
  return { token, tokenId }
}

async function seedApproval(state, label) {
  const suffix = label.toLowerCase().replace(/[^a-z0-9]+/g, '-')
  const actionId = `playwright-action-${suffix}-${Date.now().toString(36)}`
  const runId = `playwright-run-${suffix}-${Date.now().toString(36)}`
  const result = await apiRequest(state, '/v1/actions/evaluate', {
    method: 'POST',
    body: {
      context: {
        tenant_id: state.tenantId,
        environment: 'development',
        agent_id: `playwright-${suffix}-agent`,
        invoked_by: 'playwright-e2e',
        run_id: runId,
        action_id: actionId,
      },
      action: {
        tool: 'shell',
        intent: `Playwright ${label} approval`,
        parameters: { command: `rm -rf /tmp/kenning-playwright-${suffix}` },
      },
    },
  })
  assert.equal(result.decision, 'require_approval', `Expected a pending approval for ${label}`)
  assert.ok(result.approval?.approval_id, `No approval was created for ${label}`)
  return {
    approvalId: result.approval.approval_id,
    actionId: result.action.action_id,
    actionHash: result.action_hash,
    proofId: result.proof_id,
    intent: result.approval.intent,
  }
}

async function seedClassifiedEvaluation(state, label = 'classification') {
  const labelSuffix = label.toLowerCase().replace(/[^a-z0-9]+/g, '-')
  const suffix = `${labelSuffix}-${Date.now().toString(36)}`
  const actionId = `playwright-action-${suffix}`
  const result = await apiRequest(state, '/v1/actions/evaluate', {
    method: 'POST',
    body: {
      context: {
        tenant_id: state.tenantId,
        environment: 'development',
        agent_id: `playwright-${suffix}-agent`,
        invoked_by: 'playwright-e2e',
        run_id: `playwright-run-${suffix}`,
        action_id: actionId,
      },
      action: {
        tool: 'shell',
        classification: 'restricted',
        parameters: { command: 'ls -la' },
      },
    },
  })
  assert.equal(result.action_classification, 'restricted')
  return { actionId, classification: result.action_classification }
}

export async function createE2EState({ workerIndex = 0 } = {}) {
  const workerLabel = `w${workerIndex}-${process.pid}`
  const baseTenantId = process.env.E2E_TEST_TENANT_ID || `playwright-e2e-${Date.now()}`
  const tenantId = `${baseTenantId}-${workerLabel}`
  const resourceEnvironment = process.env.KENNING_ENV || process.env.KENNING_ENVIRONMENT || tokenTable.match(/tokens-(.+)$/)?.[1] || 'prototype'
  const awsAccountId = process.env.AWS_ACCOUNT_ID || process.env.DEVELOPMENT_AWS_ACCOUNT_ID || process.env.PRODUCTION_AWS_ACCOUNT_ID || '000000000000'
  let portalPat
  let platformPat
  let unassignedPat

  try {
    portalPat = createPat(`playwright-tenant-portal-${workerLabel}`, tenantId)
    platformPat = createPat(`playwright-platform-operator-${workerLabel}`, 'platform', 'admin')
    unassignedPat = createPat(`playwright-no-membership-${workerLabel}`, `${tenantId}-no-membership`)
    const state = {
      tenantId,
      workerLabel,
      portalPat: portalPat.token,
      portalTokenId: portalPat.tokenId,
      unassignedPat: unassignedPat.token,
      unassignedTokenId: unassignedPat.tokenId,
      platformPat: platformPat.token,
      platformTokenId: platformPat.tokenId,
      auditSecretArn: `arn:aws:secretsmanager:${awsRegion}:${awsAccountId}:secret:kenning/audit-sinks/${resourceEnvironment}/${tenantId}/playwright`,
      apiUrl,
      createdAt: new Date().toISOString(),
    }
    const tenantConfig = {
      tenant_id: tenantId,
      name: 'Kenning Playwright E2E tenant',
      status: 'active',
      default_environment: 'development',
      retention_enabled: true,
      retention_days: 30,
      legal_hold_enabled: false,
      data_residency_region: 'us-east-1',
      capture_policy: {
        store_original_action: true,
        redact_fields: ['credentials'],
        hash_fields: ['parameters.statement'],
        max_field_length: 2048,
      },
      audit_sink: { enabled: false },
      environments: [{ environment_id: 'development', status: 'active', mode: 'enforce', allowed_tools: ['shell', 'sql'] }],
    }
    await apiRequest(state, `/v1/tenants/${encodeURIComponent(tenantId)}`, { method: 'PUT', body: tenantConfig })
    await apiRequest(state, `/v1/tenants/${encodeURIComponent(tenantId)}/members`, {
      method: 'POST',
      body: {
        subject: portalPat.tokenId,
        email: 'playwright-owner@example.org',
        display_name: 'Playwright E2E Owner',
        role: 'admin',
        status: 'active',
      },
    })
    state.portalApproval = await seedApproval(state, `portal-${workerLabel}`)
    state.portalClassification = await seedClassifiedEvaluation(state, `classification-${workerLabel}`)
    state.portalDenyApproval = await seedApproval(state, `portal-deny-${workerLabel}`)
    state.operatorApproval = await seedApproval(state, `operator-${workerLabel}`)
    state.consoleApproval = await seedApproval(state, `console-${workerLabel}`)
    state.consoleDecisionApproval = await seedApproval(state, `console-decision-${workerLabel}`)
    state.denyApproval = await seedApproval(state, `deny-${workerLabel}`)
    return state
  } catch (error) {
    for (const tokenId of [portalPat?.tokenId, platformPat?.tokenId, unassignedPat?.tokenId].filter(Boolean)) {
      try {
        execFileSync('python3', [managePat, 'revoke', '--token-id', tokenId], { cwd: repoRoot, env: { ...process.env, AWS_REGION: awsRegion, TOKEN_TABLE_NAME: tokenTable }, stdio: 'ignore' })
      } catch {}
    }
    throw error
  }
}

export default async function globalSetup() {
  const state = await createE2EState({ workerIndex: 0 })
  fs.mkdirSync(path.dirname(stateFile), { recursive: true })
  fs.writeFileSync(stateFile, JSON.stringify(state, null, 2), { mode: 0o600 })
}
