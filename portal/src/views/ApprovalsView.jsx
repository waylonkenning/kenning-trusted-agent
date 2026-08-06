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
import { request, formatDate } from '../lib.js'
import { useApiMutation } from '../hooks.js'

function ApprovalsView() {
  const { tenantId, data, load, csrf, membership, user } = useContext(PortalContext)
  const approvals = data.approvals?.approvals || []
  const grants = data.grants?.grants || []
  const [mutate, { busy, error }] = useApiMutation()
  const canDecide = ['owner', 'admin', 'approver'].includes(membership?.role)
  async function decide(row, decision, grantDuration) {
    const payload = { decision, action_hash: row.action_hash, approver: user?.subject }
    if (decision === 'approve' && grantDuration) payload.grant_duration = grantDuration
    // Multi-step chain (#245): target the current actionable step explicitly.
    if (Array.isArray(row.chain_steps) && row.chain_steps.length) payload.step = row.current_step || 1
    try {
      await mutate(`/v1/approvals/${encodeURIComponent(row.approval_id)}/decision`, { method: 'POST', body: JSON.stringify(payload) })
    } catch { /* error state handled by hook */ }
  }
  async function revokeGrant(grant) {
    if (!window.confirm(`Revoke grant ${grant.grant_id}? Matching actions will require approval again.`)) return
    try {
      await mutate(`/v1/grants/${encodeURIComponent(grant.grant_id)}/revoke`, { method: 'POST', body: JSON.stringify({}) })
    } catch { /* error state handled by hook */ }
  }
  const grantColumns = [
    { key: 'action', label: 'Action', render: (row) => <div>{row.action?.tool ? <strong>{row.action.tool}{row.action.parameters?.command ? `: ${row.action.parameters.command}` : ''}</strong> : <span className="portal-field-note">Action</span>}{row.environment ? <><br /><small className="portal-field-note">in {row.environment}</small></> : null}<br /><small>{row.grant_id}</small></div> },
    { key: 'created_by', label: 'Approved by', render: (row) => row.created_by || '—' },
    { key: 'duration', label: 'Duration', render: (row) => row.duration_seconds ? `${Math.round(row.duration_seconds / 60)} min` : '—' },
    { key: 'use_count', label: 'Uses', render: (row) => row.use_count || 0 },
    { key: 'status', label: 'Status', render: (row) => <span className={`portal-pill ${row.status === 'active' ? 'success' : row.status === 'revoked' ? 'danger' : 'warning'}`}>{row.status || 'active'}</span> },
    { key: 'expires_at', label: 'Expires', render: (row) => row.expires_at ? formatDate(Number(row.expires_at) * 1000) : '—' },
    { key: 'actions', label: 'Actions', render: (row) => (row.status || 'active') === 'active' ? <button className="portal-danger-button" type="button" onClick={() => revokeGrant(row)} disabled={busy}>Revoke</button> : '—' },
  ]
  return <><PageHeading eyebrow="Agent Guard" title="Approvals" description="Requests waiting for a person to approve or deny them." action={<button className="portal-secondary-button" type="button" onClick={load}><ArrowsClockwise size={16} /> Refresh</button>} /><ErrorNotice error={error} /><section className="portal-panel"><p className="portal-field-note">Each approval applies only to the exact action shown to the reviewer. Approve for a while to auto-approve identical actions for a time window.</p><DataTable columns={[{ key: 'approval_id', label: 'Approval', render: (row) => <div><strong>{row.agent_id}</strong>{row.action?.tool ? <span> — {row.action.tool}{row.action.parameters?.command ? `: ${row.action.parameters.command}` : ''}{row.environment ? ` in ${row.environment}` : ''}</span> : ''}<br /><small>{row.approval_id}</small></div> }, { key: 'triggering_rule', label: 'Triggered by', render: (row) => { const trigger = row.triggering_rule; if (!trigger) return <span className="portal-field-note">Rule information not recorded</span>; const selected = trigger.selected_rule; const reason = (row.reasons || []).find((r) => selected && (r.code === `POLICY_${String(selected.rule_id || '').toUpperCase()}` || r.code === selected.reason_code || r.code === selected.rule_id)); const others = (trigger.matched_rules || []).filter((m) => !(selected && m.policy_id === selected.policy_id && m.rule_id === selected.rule_id)); return <div>{selected ? <><span className={`portal-pill ${trigger.rule_source === 'kenning' ? 'info' : ''}`}>{trigger.rule_source === 'kenning' ? 'Kenning default' : 'Workspace policy'}</span> <strong>{selected.rule_id}</strong><br /><small className="portal-field-note">{selected.policy_id} v{selected.policy_version}</small>{reason?.message && <><br /><small className="portal-field-note">{reason.message}</small></>}</> : <span className="portal-field-note">Built-in Guard rule</span>}{others.length > 0 && <details><summary className="portal-field-note">Also matched ({others.length})</summary><ul className="portal-proof-limitations">{others.map((m, i) => <li key={i}>{m.policy_id} · {m.rule_id} → {m.decision}{m.applied ? '' : ' (not applied)'}</li>)}</ul></details>}</div> } }, { key: 'chain_progress', label: 'Approval steps', render: (row) => { if (!Array.isArray(row.chain_steps) || !row.chain_steps.length) return <span className="portal-field-note">Single step</span>; const current = row.current_step || 1; return <div>{row.chain_steps.map((step, i) => <div key={i} className="portal-chain-step"><span className={`portal-pill ${step.status === 'approved' ? 'success' : step.status === 'denied' ? 'danger' : (i + 1 === current ? 'info' : '')}`}>{step.status === 'approved' ? '✓' : step.status === 'denied' ? '✕' : (i + 1 === current ? '●' : '○')}</span> <small>{step.label || `Step ${i + 1}`}{step.approver ? ` — ${step.approver}` : ''}</small></div>)}<small className="portal-field-note">Step {Math.min(current, row.chain_steps.length)} of {row.chain_steps.length}</small></div> } }, { key: 'decision', label: 'Decision', render: (row) => <span className="portal-pill">{row.decision || row.status || 'pending'}</span> }, { key: 'requested_by', label: 'Requested by' }, { key: 'expires_at', label: 'Expires', render: (row) => row.expires_at ? formatDate(Number(row.expires_at) * 1000) : '—' }, ...(canDecide ? [{ key: 'actions', label: 'Actions', render: (row) => row.status === 'pending' ? <div className="portal-row-actions"><button className="portal-secondary-button" type="button" onClick={() => decide(row, 'approve')} disabled={busy}>Approve</button><select aria-label="Approve for a duration" className="portal-grant-select" defaultValue="" onChange={(event) => { if (event.target.value) { decide(row, 'approve', Number(event.target.value)); event.target.value = '' } }} disabled={busy}><option value="" disabled>Approve for…</option><option value="900">15 minutes</option><option value="3600">1 hour</option><option value="14400">4 hours</option></select><button className="portal-danger-button" type="button" onClick={() => decide(row, 'deny')} disabled={busy}>Deny</button></div> : '—' }] : [])]} rows={approvals} empty="No approval requests" /></section>
  <section className="portal-panel"><div className="portal-eyebrow">Auto-approval grants</div><h2>Active time-window approvals</h2><p className="portal-field-note">These grants auto-approve identical actions until they expire or are revoked. Every auto-approved action is still recorded in Agent Proof.</p><DataTable columns={grantColumns} rows={grants} empty="No approval grants" /></section></>
}


export default ApprovalsView
