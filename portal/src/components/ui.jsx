import React, { useEffect, useState } from 'react'
import { CheckCircle, Copy, WarningCircle } from '@phosphor-icons/react'

function PortalMark() {
  return <div className="portal-mark"><span>K</span><div><strong>Kenning</strong><small>Trusted Agent</small></div></div>
}


function LoadingBlock({ lines = 3 }) {
  return <div className="portal-loading" aria-label="Loading">{Array.from({ length: lines }, (_, index) => <span key={index} />)}</div>
}


function ErrorNotice({ error, onRetry }) {
  if (!error) return null
  return <div className="portal-notice portal-notice-error" role="alert"><WarningCircle size={18} weight="bold" /><span>{error.message || String(error)}</span>{onRetry && <button type="button" onClick={onRetry}>Retry</button>}</div>
}


function EmptyState({ icon: Icon = WarningCircle, title, message, action }) {
  return <div className="portal-empty"><Icon size={24} /><h3>{title}</h3><p>{message}</p>{action}</div>
}


function Stat({ label, value, detail, tone = '' }) {
  return <div className={`portal-stat ${tone}`}><span>{label}</span><strong>{value}</strong><small>{detail}</small></div>
}


function PageHeading({ eyebrow, title, description, action }) {
  return <div className="portal-page-heading"><div><div className="portal-eyebrow">{eyebrow}</div><h1>{title}</h1>{description && <p>{description}</p>}</div>{action}</div>
}

function tableCellValue(value) {
  if (value === null || value === undefined || value === '') return '—'
  if (typeof value === 'boolean') return value ? 'Yes' : 'No'
  return value
}


function DataTable({ columns, rows, empty }) {
  if (!rows?.length) return <EmptyState title={empty || 'Nothing here yet'} message="This workspace has no records for the selected view." />
  return <div className="portal-table-wrap"><table className="portal-table"><thead><tr>{columns.map((column) => <th key={column.key}>{column.label}</th>)}</tr></thead><tbody>{rows.map((row, index) => <tr key={row.id || row.action_id || row.subject || row.policy_id || index}>{columns.map((column) => <td key={column.key}>{column.render ? column.render(row) : tableCellValue(row[column.key])}</td>)}</tr>)}</tbody></table></div>
}

function formatDate(value) {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })
}

function splitValues(value) {
  return String(value || '').split(',').map((item) => item.trim()).filter(Boolean)
}


function CopyButton({ text, label, buttonClassName = 'portal-copy-button', errorClassName = 'portal-copy-error', onCopied, initialCopyFailed = false }) {
  const [copied, setCopied] = useState(false)
  const [copyFailed, setCopyFailed] = useState(initialCopyFailed)

  useEffect(() => { setCopyFailed(initialCopyFailed) }, [initialCopyFailed])

  async function copy() {
    setCopyFailed(false)
    setCopied(false)
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      onCopied?.()
      setTimeout(() => setCopied(false), 1500)
    } catch {
      setCopyFailed(true)
    }
  }

  return <>
    <button className={buttonClassName} type="button" aria-label={label || 'Copy to clipboard'} onClick={copy}>{copied ? 'Copied' : copyFailed ? 'Try again' : 'Copy'}</button>
    {copyFailed && <span className={errorClassName} role="alert">Could not copy. Try again or use your browser’s copy command.</span>}
  </>
}

function CopyableCode({ code, title = 'Code example', copyLabel = 'Copy code', className = '' }) {
  return <div className={`code-example ${className}`.trim()}>
    <div className="code-example-toolbar">
      <span className="code-example-title">{title}</span>
      <CopyButton text={code} label={copyLabel} buttonClassName="code-copy-button" errorClassName="code-copy-error" />
    </div>
    <pre className="code-block"><code>{code}</code></pre>
  </div>
}

const PRODUCT_OVERVIEWS = {
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


export { PortalMark, LoadingBlock, ErrorNotice, EmptyState, Stat, PageHeading, DataTable, CopyButton, CopyableCode }
