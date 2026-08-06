import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { apiRequest } from './helpers.mjs'
import { readState, stateFile } from './state.mjs'

const repoRoot = path.resolve(process.cwd(), '..')
const managePat = path.join(repoRoot, 'scripts', 'manage_pat.py')
const awsRegion = process.env.AWS_REGION || 'us-east-1'
const tokenTable = process.env.TOKEN_TABLE_NAME || 'kta-single-tenant-test-tokens'

export async function cleanupE2EState(state) {
  if (!state) return
  try {
    const grants = await apiRequest({ ...state, portalPat: state.platformPat }, `/v1/platform/access-grants?tenant_id=${encodeURIComponent(state.tenantId)}`, { token: state.platformPat })
    for (const grant of grants.grants || []) {
      if (grant.status === 'active') {
        try {
          await apiRequest({ ...state, portalPat: state.platformPat }, `/v1/platform/access-grants/${encodeURIComponent(grant.grant_id)}/revoke`, { method: 'POST', token: state.platformPat, body: { reason: 'Playwright fixture cleanup' } })
        } catch {}
      }
    }
  } catch {}
  try {
    const tokens = await apiRequest(state, `/v1/tokens?tenant_id=${encodeURIComponent(state.tenantId)}`)
    const enrollmentPrefix = `agent-guard-enrollment-${state.tenantId}`
    for (const token of tokens.tokens || []) {
      if (token.status === 'active' && String(token.name || '').startsWith(enrollmentPrefix)) {
        try {
          await apiRequest(state, `/v1/tokens/${encodeURIComponent(token.token_id)}/revoke`, { method: 'POST', body: { tenant_id: state.tenantId } })
        } catch {}
      }
    }
  } catch {}
  for (const tokenId of [state.portalTokenId, state.platformTokenId, state.unassignedTokenId]) {
    try {
      execFileSync('python3', [managePat, 'revoke', '--token-id', tokenId], { cwd: repoRoot, env: { ...process.env, AWS_REGION: awsRegion, TOKEN_TABLE_NAME: tokenTable }, stdio: 'ignore' })
    } catch {}
  }
}

export default async function globalTeardown() {
  if (!fs.existsSync(stateFile)) return
  const state = readState()
  try {
    await cleanupE2EState(state)
  } finally {
    fs.rmSync(stateFile, { force: true })
  }
}
