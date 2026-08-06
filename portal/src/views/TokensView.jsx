import React, { useContext, useState, useRef, useEffect } from 'react'
import { PortalContext } from '../PortalContext.jsx'
import { LoadingBlock, ErrorNotice, EmptyState, Stat, PageHeading, DataTable, CopyButton } from '../components/ui.jsx'
import { ConditionBuilder, ChainBuilder } from '../components/ConditionBuilder.jsx'
import ConfirmDialog from '../components/ConfirmDialog.jsx'
import {
  ArrowRight, ArrowsClockwise, ChartLineUp, CheckCircle, ClipboardText, Code,
  Eye, FileText, GearSix, Key, LockKey, MagnifyingGlass, PencilSimple,
  Plus, ShieldCheck, SignOut, Trash, Upload, WarningCircle, X, XCircle,
} from '@phosphor-icons/react'
import { splitValues, formatDate } from '../lib.js'
import { useApiMutation } from '../hooks.js'

function TokensView({ issuedToken, onTokenIssued }) {
  const { tenantId, membership, data, load, csrf } = useContext(PortalContext)
  const tokens = data.tokens?.tokens || []
  const [form, setForm] = useState({ name: '', scopes: 'guard:evaluate', groups: '', expires_in_days: '30', grant_admin_membership: false })
  const [mutate, { busy, error, setError }] = useApiMutation()
  const canManage = ['owner', 'admin'].includes(membership?.role)
  async function create(event) {
    event.preventDefault(); onTokenIssued(null)
    try {
      const result = await mutate('/v1/tokens', { method: 'POST', body: JSON.stringify({ name: form.name.trim(), scopes: splitValues(form.scopes), groups: splitValues(form.groups), expires_in_days: Number(form.expires_in_days) || 0 }) }, { reload: false })
      onTokenIssued(result)
      let provisioningError = null
      if (form.grant_admin_membership) {
        try { await mutate(`/v1/tenants/${encodeURIComponent(tenantId)}/members`, { method: 'POST', body: JSON.stringify({ subject: result.token_metadata.token_id, display_name: form.name.trim(), role: 'admin', status: 'active' }) }, { reload: false }) } catch (caught) { provisioningError = caught }
      }
      // Updating issuedToken triggers the access view reload with the recent
      // token ID, which uses the strong-read reconciliation path.
      setForm({ ...form, name: '', groups: '' })
      if (provisioningError) setError(new Error(`Access token issued, but workspace access was not added: ${provisioningError.message}`))
    } catch { /* error state handled by hook */ }
  }
  async function revoke(token) {
    try { await mutate(`/v1/tokens/${encodeURIComponent(token.token_id)}/revoke`, { method: 'POST', body: JSON.stringify({ tenant_id: tenantId }) }) } catch { /* error state handled by hook */ }
  }
  return <><PageHeading eyebrow="Workspace access" title="Access tokens" description="Issue, review, and turn off workspace access tokens from the same console that manages workspace access. The full value is shown once." action={<button className="portal-secondary-button" type="button" onClick={load}><ArrowsClockwise size={16} /> Refresh</button>} /><ErrorNotice error={error} />{issuedToken && <section className="portal-token-issued" role="status"><div><div className="portal-eyebrow">New access token — copy it now</div><strong>{issuedToken.token_metadata.name}</strong><p className="portal-field-note">The full token is shown only once.</p></div><code>{issuedToken.token}</code><CopyButton text={issuedToken.token} label="Copy access token" buttonClassName="portal-secondary-button" /></section>}<div className={`portal-content-grid ${canManage ? '' : 'portal-content-grid-single'}`}><section className="portal-panel portal-panel-wide"><div className="portal-panel-heading"><div><div className="portal-eyebrow">Issued credentials</div><h2>{tokens.length} workspace access token{tokens.length === 1 ? '' : 's'}</h2></div></div><DataTable columns={[{ key: 'name', label: 'Name' }, { key: 'token_id', label: 'Token ID' }, { key: 'scopes', label: 'Permissions', render: (row) => row.scopes?.join(', ') || '—' }, { key: 'expires_at', label: 'Expires', render: (row) => row.expires_at ? formatDate(Number(row.expires_at) * 1000) : 'Never' }, { key: 'status', label: 'Status', render: (row) => <span className={`portal-pill ${row.status === 'active' ? 'success' : row.status === 'revoked' ? 'danger' : ''}`}>{row.status}</span> }, { key: 'actions', label: 'Actions', render: (row) => canManage && row.status === 'active' ? <button className="portal-danger-button" type="button" onClick={() => revoke(row)} disabled={busy}>Revoke</button> : '—' }]} rows={tokens} empty="No workspace access tokens issued" /></section>{canManage && <section className="portal-panel"><div className="portal-eyebrow">Issue an access token</div><h2>New workspace access token</h2><form className="portal-stack-form" onSubmit={create}><label htmlFor="token-name">Name</label><input id="token-name" value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="research-agent" required /><label htmlFor="token-scopes">Permissions</label><input id="token-scopes" value={form.scopes} onChange={(event) => setForm({ ...form, scopes: event.target.value })} placeholder="guard:evaluate, proof:read" required /><p className="portal-field-note">Comma-separated. A token cannot give more access than the person who created it has.</p><label htmlFor="token-groups">Reviewer groups</label><input id="token-groups" value={form.groups} onChange={(event) => setForm({ ...form, groups: event.target.value })} placeholder="security, platform" /><label htmlFor="token-expires">Expires in days</label><input id="token-expires" type="number" min="0" max="3650" value={form.expires_in_days} onChange={(event) => setForm({ ...form, expires_in_days: event.target.value })} required /><label className="portal-checkbox-label"><input type="checkbox" checked={form.grant_admin_membership} onChange={(event) => setForm({ ...form, grant_admin_membership: event.target.checked })} /> Give this token admin access to the workspace</label><button className="portal-primary-button" type="submit" disabled={busy}>{busy ? 'Issuing…' : 'Issue access token'} <Key size={16} /></button></form></section>}</div></>
}


export default TokensView
