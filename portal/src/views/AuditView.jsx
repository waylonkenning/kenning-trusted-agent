import React, { useContext, useState, useRef, useEffect } from 'react'
import { PortalContext } from '../PortalContext.jsx'
import { LoadingBlock, ErrorNotice, EmptyState, Stat, PageHeading, DataTable, CopyButton } from '../components/ui.jsx'
import { ConditionBuilder, ChainBuilder } from '../components/ConditionBuilder.jsx'
import ConfirmDialog from '../components/ConfirmDialog.jsx'
import {
  ArrowRight, ArrowsClockwise, ChartLineUp, CheckCircle, ClipboardText, Code,
  DownloadSimple, Eye, FileText, GearSix, Info, Key, LockKey, MagnifyingGlass, PencilSimple,
  Plus, ShieldCheck, SignOut, Trash, Upload, WarningCircle, X, XCircle,
} from '@phosphor-icons/react'
import { formatDate } from '../lib.js'
import { useApiMutation } from '../hooks.js'
import ProofVisual from './ProofVisual.jsx'

function AuditView() {
  const { tenantId, data, load } = useContext(PortalContext)
  const events = data.audit?.events || []
  const securityEvents = data.security?.events || []
  const [proof, setProof] = useState(null)
  const [apiRequest, { error }] = useApiMutation()
  async function exportAudit() {
    try {
      const exported = await apiRequest(`/v1/audit/export?tenant_id=${encodeURIComponent(tenantId)}&format=json`, {}, { reload: false })
      const blob = new Blob([JSON.stringify(exported, null, 2)], { type: 'application/json' })
      const link = document.createElement('a')
      link.href = URL.createObjectURL(blob)
      link.download = `${tenantId}-audit.json`
      link.click()
      URL.revokeObjectURL(link.href)
    } catch { /* error handled by hook */ }
  }
  async function inspectProof(proofId) {
    try { const [record, verification] = await Promise.all([apiRequest(`/v1/proofs/${encodeURIComponent(proofId)}`, {}, { reload: false }), apiRequest(`/v1/proofs/${encodeURIComponent(proofId)}/verify`, {}, { reload: false })]); setProof({ record, verification }) } catch { /* error handled by hook */ }
  }
  const citations = events.filter((row) => String(row.event_type || '').startsWith('citation.'))
  const classificationBadge = (row) => {
    if (row.event_type !== 'action.evaluated') return '—'
    const value = row.action_classification || row.action?.classification || 'unclassified'
    const tone = ['restricted', 'confidential', 'secret'].includes(value) ? 'warning' : value === 'sensitive' ? 'info' : ''
    return <span className={`portal-pill ${tone}`}>{String(value).replace(/_/g, ' ')}</span>
  }
  return <><PageHeading eyebrow="Complete decision history" title="Audit and proof" description="Searchable workspace events connect actions, approvals, Proof records, receipts, and results." action={<div className="portal-heading-actions"><button className="portal-secondary-button" type="button" onClick={exportAudit}><DownloadSimple size={16} /> Export</button><button className="portal-secondary-button" type="button" onClick={load}><ArrowsClockwise size={16} /> Refresh</button></div>} /><ErrorNotice error={error} /><section className="portal-panel"><DataTable columns={[{ key: 'event_type', label: 'Event type' }, { key: 'action_id', label: 'Action' }, { key: 'action_classification', label: 'Classification', render: classificationBadge }, { key: 'proof_id', label: 'Proof', render: (row) => row.proof_id ? <button className="portal-text-button" type="button" onClick={() => inspectProof(row.proof_id)}>{row.proof_id}</button> : '—' }, { key: 'invoked_by', label: 'Invoked by' }, { key: 'created_at', label: 'Time', render: (row) => formatDate(row.created_at) }]} rows={events} empty="No audit events recorded" /></section><section className="portal-panel"><div className="portal-eyebrow">Security history</div><h2>Admin and sign-in events</h2><DataTable columns={[{ key: 'event_type', label: 'Event' }, { key: 'status', label: 'Status' }, { key: 'invoked_by', label: 'Invoked by' }, { key: 'reason', label: 'Reason' }, { key: 'created_at', label: 'Time', render: (row) => formatDate(row.created_at) }]} rows={securityEvents} empty="No security events recorded" /></section>{proof && <ProofVisual proof={proof} />}{citations.length > 0 && <section className="portal-panel"><div className="portal-eyebrow">Citation Trust</div><h2>Recent citation findings</h2><DataTable columns={[{ key: 'response_id', label: 'Response' }, { key: 'citation_count', label: 'Citations' }, { key: 'status', label: 'Status' }, { key: 'created_at', label: 'Time', render: (row) => formatDate(row.created_at) }]} rows={citations} empty="No citation verification events" /></section>}</>
}


export default AuditView
