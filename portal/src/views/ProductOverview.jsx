import React, { useContext, useState, useRef, useEffect } from 'react'
import { PortalContext } from '../PortalContext.jsx'
import { LoadingBlock, ErrorNotice, EmptyState, Stat, PageHeading, DataTable, CopyButton } from '../components/ui.jsx'
import { ConditionBuilder, ChainBuilder } from '../components/ConditionBuilder.jsx'
import ConfirmDialog from '../components/ConfirmDialog.jsx'
import {
  ArrowRight, ArrowsClockwise, ChartLineUp, CheckCircle, ClipboardText, Code,
  Eye, FileText, GearSix, Info, Key, LockKey, MagnifyingGlass, PencilSimple,
  PlugsConnected, Plus, ShieldCheck, SignOut, Trash, Upload, WarningCircle, X, XCircle,
} from '@phosphor-icons/react'
import { API_BASE, PRODUCT_OVERVIEWS } from '../lib.js'
import { useApiMutation } from '../hooks.js'

function ProductOverview({ productId, onOpenWizard }) {
  const { tenantId, membership } = useContext(PortalContext)
  const product = PRODUCT_OVERVIEWS[productId]
  const [mcpPat, setMcpPat] = useState(null)
  const [mcpConfig, setMcpConfig] = useState('')
  const [mcpBusy, setMcpBusy] = useState(false)
  const [mcpError, setMcpError] = useState(null)
  const [mcpCopyFailed, setMcpCopyFailed] = useState(false)
  const [mutate] = useApiMutation()
  const canManage = ['owner', 'admin', 'policy_admin'].includes(membership?.role)
  if (!product) return <div className="portal-panel"><p>Product information is not available.</p></div>
  const apiBase = API_BASE || window.location.origin
  const mcpEndpoint = `${apiBase}/mcp`
  async function copyFullConfig() {
    setMcpBusy(true)
    setMcpError(null)
    setMcpCopyFailed(false)
    try {
      const result = await mutate('/v1/tokens', { method: 'POST', body: JSON.stringify({ name: `mcp-${productId.replace(/-overview$/, '')}`, scopes: ['guard:evaluate', 'mcp:read'], expires_in_days: 90 }) }, { reload: false })
      const token = result?.token
      if (typeof token !== 'string' || !token.startsWith('kta_pat_')) throw new Error('Kenning did not return a usable workspace credential. Please try again.')
      const config = `{\n  "mcpServers": {\n    "kenning": {\n      "url": "${mcpEndpoint}",\n      "headers": { "Authorization": "Bearer ${token}" }\n    }\n  }\n}`
      setMcpPat(token)
      setMcpConfig(config)
      try { await navigator.clipboard.writeText(config) } catch { setMcpCopyFailed(true) }
    } catch (caught) { setMcpError(caught) } finally { setMcpBusy(false) }
  }
  return <>
    <PageHeading eyebrow={product.eyebrow} title={product.title} description={product.summary} />
    <div className="portal-content-grid">
      <section className="portal-panel portal-panel-wide">
        <div className="portal-eyebrow">Quick start</div>
        {productId === 'guard-overview' ? <>
          <h2>Connect your agent</h2>
          <p className="portal-overview-text">Use the setup wizard to create a scoped workspace credential and connect your coding agent. The credential is shown once and is not saved in browser storage.</p>
          {onOpenWizard && <button className="portal-primary-button" type="button" onClick={onOpenWizard}>Connect your agent <PlugsConnected size={16} /></button>}
          <p className="portal-field-note portal-connect-note">For custom integrations, use the API details below.</p>
        </> : <>
          <h2>Setup</h2>
          <p className="portal-overview-text">{product.setup}</p>
        </>}
        <div className="portal-eyebrow">Authentication</div>
        <p className="portal-overview-text">{product.auth}</p>
      </section>
      <section className="portal-panel portal-panel-wide">
        <div className="portal-eyebrow">API connection</div>
        <h2>Endpoints</h2>
        <div className="portal-overview-base"><span className="portal-overview-label">Base URL</span><code>{apiBase}</code><CopyButton text={apiBase} label="Copy base URL" /></div>
        <DataTable columns={[{ key: 'method', label: 'Method', render: (row) => <span className="portal-pill">{row.method}</span> }, { key: 'path', label: 'Path', render: (row) => <code>{row.path}</code> }, { key: 'description', label: 'Description' }]} rows={product.api} empty="No API endpoints documented" />
      </section>
      {product.mcp && <section className="portal-panel portal-panel-wide">
        <div className="portal-eyebrow">MCP connection</div>
        <h2>Model Context Protocol</h2>
        <div className="portal-overview-base"><span className="portal-overview-label">MCP endpoint</span><code>{mcpEndpoint}</code><CopyButton text={mcpEndpoint} label="Copy MCP endpoint" /></div>
        <p className="portal-overview-text">Tools: {product.mcp.tool}. {product.mcp.description}.</p>
        <div className="portal-overview-snippet"><div className="portal-overview-snippet-header"><span>Configuration example</span><CopyButton text={`{\n  "mcpServers": {\n    "kenning": {\n      "url": "${mcpEndpoint}",\n      "headers": { "Authorization": "Bearer <YOUR_PAT>" }\n    }\n  }\n}`} label="Copy MCP configuration" /></div><pre>{`{
  "mcpServers": {
    "kenning": {
      "url": "${mcpEndpoint}",
      "headers": { "Authorization": "Bearer <YOUR_PAT>" }
    }
  }
}`}</pre></div>
        {canManage && <div className="portal-overview-snippet"><div className="portal-overview-snippet-header"><span>Ready-to-paste config with a new PAT</span></div>{!mcpConfig ? <><p className="portal-field-note">Creates a 90-day PAT scoped to guard:evaluate and mcp:read, then copies the full config to your clipboard.</p><button className="portal-primary-button" type="button" onClick={copyFullConfig} disabled={mcpBusy}>{mcpBusy ? 'Creating PAT…' : 'Copy full config with PAT'} <Key size={16} /></button></> : <><p className="portal-field-note" role="status">{mcpCopyFailed ? 'The config was created, but the first copy did not work. Use Try again or copy the visible config manually.' : <>Config copied. PAT starts with <code>{mcpPat.slice(0, 12)}…</code> — the full value stays available only in this page session.</>}</p><pre>{mcpConfig}</pre><CopyButton text={mcpConfig} label="Copy full config with PAT" initialCopyFailed={mcpCopyFailed} onCopied={() => { setMcpCopyFailed(false) }} /></>}{mcpError && <ErrorNotice error={mcpError} />}</div>}
      </section>}
      <section className="portal-panel">
        <div className="portal-eyebrow">Reference</div>
        <h2>Documentation</h2>
        <p className="portal-overview-text">See the <a href="/openapi.json">OpenAPI contract</a> for request and response schemas and error codes.</p>
      </section>
    </div>
  </>
}

function simulationSummary(result) {
  const action = result.action || {}
  const tool = action.tool || 'action'
  const command = action.parameters?.command
  const env = action.environment ? ` in ${action.environment}` : ''
  const detail = command ? ` "${command}"` : ''
  const decision = (result.decision || 'unknown').replace(/_/g, ' ')
  return `For ${tool}${detail}${env}, the decision would be to ${decision}.`
}

function eventSummary(row) {
  const agent = row.agent_id || 'unknown agent'
  if (row.event_type === 'action.evaluated') {
    const tool = row.action?.tool || row.tool || 'action'
    const env = row.environment ? ` in ${row.environment}` : ''
    return `${agent}: ${tool} evaluated${env}`
  }
  if (row.event_type === 'approval.decided') {
    const approver = row.approver ? ` by ${row.approver}` : ''
    return `${agent}: approval ${row.status || 'decided'}${approver}`
  }
  return `${agent}: ${row.event_type}`
}


export default ProductOverview
