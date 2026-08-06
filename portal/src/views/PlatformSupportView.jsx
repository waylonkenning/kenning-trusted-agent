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
import { useApiMutation } from '../hooks.js'

function PlatformSupportView() {
  const { data, load, csrf } = useContext(PortalContext)
  const grants = data.platformGrants?.grants || []
  const [tenantId, setTenantId] = useState('')
  const [reason, setReason] = useState('')
  const [operation, setOperation] = useState('support')
  const [resource, setResource] = useState('tenant')
  const [result, setResult] = useState(null)
  const [mutate, { busy, error }] = useApiMutation()

  async function createGrant(event) {
    event.preventDefault(); setResult(null)
    try {
      await mutate('/v1/platform/access-grants', { method: 'POST', body: JSON.stringify({ tenant_id: tenantId, reason, operation, expires_in_seconds: 3600 }) }, { tenantId: '' })
      setReason('')
    } catch { /* error handled by hook */ }
  }

  async function readTenant(grant) {
    try { setResult(await mutate('/v1/platform/support/read', { method: 'POST', body: JSON.stringify({ grant_id: grant.grant_id, tenant_id: grant.tenant_id, resource }) }, { reload: false, tenantId: '' })) } catch { /* error handled by hook */ }
  }

  async function revoke(grant) {
    try { await mutate(`/v1/platform/access-grants/${encodeURIComponent(grant.grant_id)}/revoke`, { method: 'POST', body: JSON.stringify({ reason: 'Platform operator closed the support session' }) }, { tenantId: '' }) } catch { /* error handled by hook */ }
  }

  return <><PageHeading eyebrow="Platform operations" title="Platform support access" description="Create time-limited support access, perform an explicit read, and turn it off when the support task ends. This admin-only view is part of the same console, and every operation is approved by the server and recorded." action={<button className="portal-secondary-button" type="button" onClick={load} disabled={busy}><ArrowsClockwise size={16} /> Refresh</button>} /><ErrorNotice error={error} /><div className="portal-content-grid"><section className="portal-panel"><div className="portal-eyebrow">New support access</div><h2>Access with a recorded reason</h2><form className="portal-stack-form" onSubmit={createGrant}><label htmlFor="platform-tenant">Workspace ID</label><input id="platform-tenant" value={tenantId} onChange={(event) => setTenantId(event.target.value)} placeholder="workspace-001" required /><label htmlFor="platform-reason">Support reason</label><textarea id="platform-reason" value={reason} onChange={(event) => setReason(event.target.value)} minLength="10" maxLength="512" rows="4" required /><label htmlFor="platform-operation">What support can do</label><select id="platform-operation" value={operation} onChange={(event) => setOperation(event.target.value)}><option value="support">Support</option><option value="read">Read</option><option value="export">Export</option><option value="configuration">Configuration</option></select><button className="portal-primary-button" type="submit" disabled={busy}>{busy ? 'Creating…' : 'Create support access'} <ArrowRight size={16} /></button></form></section><section className="portal-panel"><div className="portal-panel-heading"><div><div className="portal-eyebrow">Support access history</div><h2>Active and historical grants</h2></div><button className="portal-secondary-button" type="button" onClick={load} disabled={busy}><ArrowsClockwise size={16} /> Refresh</button></div><div className="portal-stack-form"><label htmlFor="platform-resource">What to view</label><select id="platform-resource" value={resource} onChange={(event) => setResource(event.target.value)}><option value="tenant">Workspace configuration</option><option value="members">Memberships</option><option value="audit">Audit events</option><option value="metrics">Metrics</option></select></div>{grants.length ? <div className="portal-table-wrap"><table className="portal-table"><thead><tr><th>Workspace</th><th>Operation</th><th>Status</th><th>Expires</th><th>Actions</th></tr></thead><tbody>{grants.map((grant) => <tr key={grant.grant_id}><td>{grant.tenant_id}</td><td>{grant.operation}</td><td><span className={`portal-pill ${grant.status === 'active' ? 'success' : ''}`}>{grant.status}</span></td><td>{new Date(Number(grant.expires_at || 0) * 1000).toLocaleString()}</td><td><div className="portal-row-actions">{grant.status === 'active' && <><button className="portal-secondary-button" type="button" onClick={() => readTenant(grant)} disabled={busy}><ShieldCheck size={15} /> Read</button><button className="portal-danger-button" type="button" onClick={() => revoke(grant)} disabled={busy}>Revoke</button></>}</div></td></tr>)}</tbody></table></div> : <p className="portal-field-note">No support access available.</p>}</section></div>{result && <section className="portal-panel portal-proof-panel"><div className="portal-eyebrow">Support result</div><pre className="portal-proof-json">{JSON.stringify(result, null, 2)}</pre></section>}</>
}


export default PlatformSupportView
