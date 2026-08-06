/**
 * Shared utilities, constants, and API helpers for the Kenning portal.
 * Extracted from portal.jsx (#256) so view modules can import them
 * without circular dependencies.
 */

import * as pdfjsLib from 'pdfjs-dist'
import pdfWorker from 'pdfjs-dist/build/pdf.worker.min.mjs?url'

pdfjsLib.GlobalWorkerOptions.workerSrc = pdfWorker

export const configuredApiBase = (import.meta.env.VITE_KENNING_API_URL || window.__KENNING_API_URL__ || '').replace(/\/$/, '')
export const DEPLOYMENT_ENVIRONMENT = (document.querySelector('meta[name="kenning-deployment-environment"]')?.content || import.meta.env.VITE_KENNING_DEPLOYMENT_ENVIRONMENT || '').trim().toLowerCase()
export const API_BASE = configuredApiBase.toLowerCase() === 'same-origin' ? '' : configuredApiBase

export function apiUrl(path) {
  return `${API_BASE}${path}`
}

export async function request(path, options = {}, tenantId = '', csrfToken = '') {
  const headers = new Headers(options.headers || {})
  headers.set('Accept', 'application/json')
  if (options.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
  if (tenantId) headers.set('X-Kenning-Tenant-Id', tenantId)
  if (csrfToken) headers.set('X-Kenning-CSRF', csrfToken)
  const response = await fetch(apiUrl(path), { ...options, headers, credentials: 'include' })
  const contentType = response.headers.get('content-type') || ''
  const payload = contentType.includes('json') ? await response.json() : null
  if (!response.ok) {
    const error = new Error(payload?.message || payload?.error || `Request failed (${response.status})`)
    error.status = response.status
    error.payload = payload
    throw error
  }
  window.dispatchEvent(new Event('kenning:activity'))
  return payload
}

export async function sha256Hex(value) {
  const digest = await window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, '0')).join('')
}

export async function extractPdfText(file, onProgress) {
  const bytes = new Uint8Array(await file.arrayBuffer())
  const document = await pdfjsLib.getDocument({ data: bytes }).promise
  const pages = []
  for (let pageNumber = 1; pageNumber <= document.numPages; pageNumber += 1) {
    const page = await document.getPage(pageNumber)
    const content = await page.getTextContent()
    let pageText = ''
    for (const item of content.items) {
      if (!('str' in item)) continue
      pageText += item.str
      pageText += item.hasEOL ? '\n' : ' '
    }
    pages.push(pageText)
    onProgress?.({ phase: 'extracting', current: pageNumber, total: document.numPages })
  }
  return pages.join('\f')
}

export async function runConcurrent(items, worker, concurrency = 4, onResult) {
  let nextIndex = 0
  const results = new Array(items.length)
  async function consume() {
    while (nextIndex < items.length) {
      const index = nextIndex
      nextIndex += 1
      try {
        results[index] = await worker(items[index], index)
      } catch (error) {
        results[index] = {
          ...(items[index] && typeof items[index] === 'object' ? items[index] : {}),
          error: error.message || String(error),
        }
      }
      onResult?.(results[index], index, results)
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length || 1) }, consume))
  return results
}

export function formatDate(value) {
  if (!value) return '—'
  const date = typeof value === 'number' ? new Date(value) : new Date(value)
  if (Number.isNaN(date.getTime())) return String(value)
  return date.toLocaleDateString('en-NZ', { day: 'numeric', month: 'short', year: 'numeric' }) + ' ' + date.toLocaleTimeString('en-NZ', { hour: '2-digit', minute: '2-digit' })
}

export function splitValues(value) {
  return String(value || '').split(',').map((item) => item.trim()).filter(Boolean)
}

export function simulationSummary(result) {
  if (!result) return ''
  const decision = result.decision || result.simulated_decision || 'unknown'
  const risk = result.risk_score != null ? ` (risk ${result.risk_score})` : ''
  return `Decision: ${decision}${risk}`
}

export function eventSummary(row) {
  const tool = row.action?.tool || row.tool || '—'
  const command = row.action?.parameters?.command || ''
  return command ? `${tool}: ${command}` : tool
}

export const TOOL_OPTIONS = ['shell', 'sql', 'database', 'aws', 'azure', 'cloud', 'github', 'email', 'messaging', 'file', 'http', 'code_execution', 'browser', 'other']
export const ENVIRONMENT_OPTIONS = ['development', 'staging', 'production']
export const DECISION_OPTIONS = [
  { value: 'require_approval', label: 'Require approval' },
  { value: 'warn', label: 'Warn' },
  { value: 'rewrite', label: 'Rewrite' },
  { value: 'deny', label: 'Deny' },
  { value: 'allow', label: 'Allow' },
]

export const CONDITION_FIELDS = [
  { key: 'tool', label: 'Tool', type: 'glob', placeholder: 'shell' },
  { key: 'command', label: 'Command', type: 'glob', placeholder: 'rm *' },
  { key: 'environment', label: 'Environment', type: 'glob', placeholder: 'production' },
  { key: 'agent_id', label: 'Agent ID', type: 'glob', placeholder: 'agent-*' },
  { key: 'model_risk_at_least', label: 'Model risk tier at least', type: 'glob', placeholder: 'high' },
  { key: 'classification_at_least', label: 'Classification at least', type: 'glob', placeholder: 'restricted', hint: 'unclassified < in_confidence < sensitive < restricted < confidential < secret' },
  { key: 'invoked_by', label: 'Invoked by', type: 'glob', placeholder: 'ci-pipeline' },
  { key: 'risk_score', label: 'Risk score', type: 'number', placeholder: '80' },
  { key: 'contains_pii', label: 'Contains PII', type: 'boolean', placeholder: '' },
  { key: 'requires_impact_assessment', label: 'Impact assessment is overdue', type: 'boolean', placeholder: '' },
  { key: 'hour_of_day', label: 'Hour of day', type: 'time', placeholder: '22' },
]
export const CONDITION_FIELD_KEYS = CONDITION_FIELDS.map((field) => field.key)
export const OPERATOR_LABEL = { glob: 'matches pattern', number: 'threshold', boolean: 'is', time: 'boundary' }

export function conditionFieldDef(key) {
  return CONDITION_FIELDS.find((field) => field.key === key) || { key, label: key, type: 'glob', placeholder: '' }
}

export function serialiseConditions(rows) {
  const conditions = {}
  for (const row of rows) {
    if (!row.field || !row.value) continue
    const def = conditionFieldDef(row.field)
    if (def.type === 'glob') conditions[row.field] = row.value
    else if (def.type === 'number') conditions[`${row.field}_gte`] = Number(row.value)
    else if (def.type === 'boolean') conditions[row.field] = row.value === 'true'
    else if (def.type === 'time') conditions[`${row.field}_gte`] = Number(row.value)
  }
  return conditions
}

export function deserialiseConditions(conditions) {
  const rows = []
  const extra = {}
  for (const [key, value] of Object.entries(conditions || {})) {
    if (key === 'approver_groups') continue
    const baseKey = key.replace(/_(gte|lte|contains|in_list)$/, '')
    const def = conditionFieldDef(baseKey)
    if (CONDITION_FIELD_KEYS.includes(baseKey)) {
      rows.push({ field: baseKey, operator: OPERATOR_LABEL[def.type] || 'matches pattern', value: String(value) })
    } else {
      extra[key] = value
    }
  }
  return { rows, extra }
}

export function triggerDescription(rule) {
  const conditions = rule.conditions || {}
  const parts = []
  if (conditions.tool) parts.push(`tool matches "${conditions.tool}"`)
  if (conditions.command) parts.push(`command matches "${conditions.command}"`)
  if (conditions.environment) parts.push(`environment matches "${conditions.environment}"`)
  if (conditions.classification_at_least) parts.push(`classification is at least "${conditions.classification_at_least}"`)
  if (conditions.risk_score_gte != null) parts.push(`risk score ≥ ${conditions.risk_score_gte}`)
  if (conditions.contains_pii != null) parts.push(`PII is ${conditions.contains_pii}`)
  if (conditions.requires_impact_assessment != null) parts.push(`impact assessment is overdue: ${conditions.requires_impact_assessment}`)
  return parts.length ? `Applies when ${parts.join(' and ')}.` : 'Applies to all actions.'
}

export function conditionsSummary(rule) {
  const conditions = rule.conditions || {}
  const phrases = []
  for (const [key, value] of Object.entries(conditions)) {
    if (key === 'approver_groups') continue
    const baseKey = key.replace(/_(gte|lte|contains|in_list)$/, '')
    const def = conditionFieldDef(baseKey)
    if (key.endsWith('_gte')) phrases.push(`${def.label} ≥ ${value}`)
    else if (key.endsWith('_lte')) phrases.push(`${def.label} ≤ ${value}`)
    else phrases.push(`${def.label} ${OPERATOR_LABEL[def.type] || 'matches'} ${value}`)
  }
  return phrases
}

export const PRODUCT_OVERVIEWS = {
  'guard-overview': {
    eyebrow: 'Agent Guard',
    title: 'Agent Guard',
    summary: 'Evaluate agent actions before they run. Agent Guard checks shell commands, SQL statements, file operations, cloud changes, and more against your workspace policies and returns a clear decision: allow, warn, rewrite, require approval, or deny.',
    setup: 'Send a POST request to the evaluate endpoint with the action context. Start in observe mode to watch decisions before enforcing them.',
    api: [
      { method: 'POST', path: '/v1/actions/evaluate', description: 'Evaluate a proposed action against workspace policies' },
    ],
    mcp: { tool: 'evaluate_action', description: 'Evaluate a proposed action through the MCP transport' },
    auth: 'Bearer PAT or session cookie. Required scope: guard:evaluate.',
  },
  'proof-overview': {
    eyebrow: 'Agent Proof',
    title: 'Agent Proof',
    summary: 'Create structured records of agent decisions, evidence, approvals, and outcomes. Agent Proof connects the request, policy, approval, and result in one reviewable record with tamper-evident or KMS-signed receipts.',
    setup: 'Create a proof record after an action is evaluated. Use the proof ID to retrieve, verify integrity, or record the outcome.',
    api: [
      { method: 'POST', path: '/v1/proofs', description: 'Create a structured proof record' },
      { method: 'GET', path: '/v1/proofs/{proofId}', description: 'Retrieve a proof record' },
      { method: 'GET', path: '/v1/proofs/{proofId}/verify', description: 'Verify proof integrity and receipt signature' },
    ],
    mcp: { tool: 'create_proof, get_proof', description: 'Create and retrieve proof records through the MCP transport' },
    auth: 'Bearer PAT or session cookie. Required scopes: proof:write, proof:read.',
  },
  'citation-overview': {
    eyebrow: 'Citation Trust',
    title: 'Citation Trust',
    summary: 'Verify that cited sources exist, can be opened, and support the claims attributed to them. Citation Trust separates source existence, access, identity, claim support, currency, and quality into distinct findings.',
    setup: 'Extract citations from a report, then verify each citation. Use the findings to annotate, revise, or block a response when evidence falls below your standard.',
    api: [
      { method: 'POST', path: '/v1/citation-reports/extract', description: 'Extract citations from report text' },
      { method: 'POST', path: '/v1/citations/{citationId}/verify', description: 'Verify a single citation source' },
    ],
    mcp: null,
    auth: 'Bearer PAT or session cookie. Required scope: citation:verify.',
  },
  'identity-overview': {
    eyebrow: 'Agent Identity',
    title: 'Agent Identity',
    summary: 'Give each agent a named owner, purpose, version, environment, and set of limits. Agent Identity registers agents, enforces delegated authority, issues short-lived credentials, and supports revocation and federation.',
    setup: 'Register an agent with its owner, purpose, and approved tools. Use the agent ID in action evaluation to enforce delegated authority and separation of duties.',
    api: [
      { method: 'POST', path: '/v1/agents', description: 'Register a new agent' },
      { method: 'GET', path: '/v1/agents', description: 'List registered agents' },
      { method: 'POST', path: '/v1/workload-identity/authenticate', description: 'Authenticate via AWS IAM workload identity (SigV4 route)' },
    ],
    mcp: null,
    auth: 'Bearer PAT or session cookie. Required scopes: identity:read, identity:write.',
  },
}
