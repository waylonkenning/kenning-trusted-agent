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
import { formatDate, eventSummary } from '../lib.js'

function Overview() {
  const { tenantId, load, data, setView } = useContext(PortalContext)
  const config = data.tenant
  const decisionCounts = data.metrics?.metrics?.decision_counts || {}
  const events = data.audit?.events || []
  const denied = decisionCounts.deny || 0
  const approval = data.pendingApprovals?.count || 0
  const envCount = config?.environment_count || 0
  return <>
    <PageHeading eyebrow="Workspace overview" title={config?.name || tenantId} description="A view of the checks, decisions, and evidence connected to this workspace." action={<button className="portal-secondary-button" type="button" onClick={load}><ArrowsClockwise size={16} /> Refresh</button>} />
    <div className="portal-stat-grid"><Stat label="Workspace status" value={config?.status || '—'} detail={envCount ? `${envCount} environment${envCount === 1 ? '' : 's'}` : <button className="portal-text-button" type="button" onClick={() => setView('settings')}>No environments — configure in Settings</button>} tone="positive" /><Stat label="Denied decisions" value={denied} detail="Current reporting period" tone={denied ? 'alert' : ''} /><Stat label="Awaiting approval" value={approval} detail={approval ? <button className="portal-text-button" type="button" onClick={() => setView('approvals')}>View pending approvals</button> : 'No pending requests'} /></div>
    <div className="portal-content-grid">
      <section className="portal-panel portal-panel-wide"><div className="portal-panel-heading"><div><div className="portal-eyebrow">Recent activity</div><h2>Decision record</h2></div><span className="portal-panel-meta">{events.length} shown</span></div><DataTable columns={[{ key: 'event_type', label: 'Activity', render: (row) => row.event_type === 'approval.decided' ? <button className="portal-text-button" type="button" onClick={() => setView('approvals')}>{eventSummary(row)}</button> : eventSummary(row) }, { key: 'decision', label: 'Decision', render: (row) => <span className={`portal-pill ${row.decision === 'deny' ? 'danger' : row.decision === 'allow' ? 'success' : ''}`}>{row.decision || row.status || 'recorded'}</span> }, { key: 'agent_id', label: 'Agent' }, { key: 'created_at', label: 'Time', render: (row) => formatDate(row.created_at) }]} rows={events} empty="No decision events recorded" /></section>
    </div>
  </>
}


export default Overview
