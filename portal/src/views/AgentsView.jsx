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

function AgentsView() {
  const { tenantId, data, load, csrf, membership, user } = useContext(PortalContext)
  const agents = data.agents?.agents || []
  const [form, setForm] = useState({ agent_id: '', purpose: '', tools: '', environments: 'development', authority: 'standard' })
  const [mutate, { busy, error }] = useApiMutation()
  const [assessmentRequest, { busy: assessmentBusy, error: assessmentError, setError: setAssessmentError }] = useApiMutation()
  const [documentationRequest, { busy: documentationBusy, error: documentationError }] = useApiMutation()
  const [selectedAgent, setSelectedAgent] = useState(null)
  const [assessments, setAssessments] = useState([])
  const [assessmentStatus, setAssessmentStatus] = useState('assessment overdue')
  const [assessmentForm, setAssessmentForm] = useState({ summary: '', impacts_on_individuals: '', impacts_on_society: '', mitigations: '', assessor: user?.subject || '' })
  const [documentationForm, setDocumentationForm] = useState({ design: '', resources: '', verification: '', operational: '' })
  const assessmentRequestVersion = useRef(0)
  const canManage = ['owner', 'admin', 'agent_integrations'].includes(membership?.role)
  const emptyAssessment = () => ({ summary: '', impacts_on_individuals: '', impacts_on_society: '', mitigations: '', assessor: user?.subject || '' })
  const emptyDocumentation = () => ({ design: '', resources: '', verification: '', operational: '' })
  async function register(event) {
    event.preventDefault()
    try {
      await mutate('/v1/agents', { method: 'POST', body: JSON.stringify({ agent_id: form.agent_id, owner: user?.subject, purpose: form.purpose, approved_tools: splitValues(form.tools), allowed_environments: splitValues(form.environments), maximum_authority: form.authority }) })
      setForm({ agent_id: '', purpose: '', tools: '', environments: 'development', authority: 'standard' })
    } catch { /* error handled by hook */ }
  }
  async function selectAgent(agent) {
    const requestVersion = ++assessmentRequestVersion.current
    setSelectedAgent(agent)
    setAssessmentForm(emptyAssessment())
    setDocumentationForm({ ...emptyDocumentation(), ...(agent.documentation || {}) })
    setAssessments([])
    setAssessmentStatus(agent.impact_assessment_status || 'assessment overdue')
    setAssessmentError(null)
    try {
      const result = await assessmentRequest(`/v1/agents/${encodeURIComponent(agent.agent_id)}/impact-assessments`, {}, { reload: false })
      if (requestVersion !== assessmentRequestVersion.current) return
      setAssessments(result.assessments || [])
      setAssessmentStatus(result.assessment_status || 'assessment overdue')
    } catch { /* error handled by hook */ }
  }
  async function saveDocumentation(event) {
    event.preventDefault()
    if (!selectedAgent) return
    try {
      const updated = await documentationRequest(`/v1/agents/${encodeURIComponent(selectedAgent.agent_id)}`, { method: 'PUT', body: JSON.stringify({ documentation: documentationForm }) }, { reload: false })
      setSelectedAgent(updated)
      setDocumentationForm({ ...emptyDocumentation(), ...(updated.documentation || {}) })
      await load()
    } catch { /* error handled by hook */ }
  }
  async function saveAssessment(event) {
    event.preventDefault()
    if (!selectedAgent) return
    const requestVersion = ++assessmentRequestVersion.current
    try {
      const created = await assessmentRequest(`/v1/agents/${encodeURIComponent(selectedAgent.agent_id)}/impact-assessments`, { method: 'POST', body: JSON.stringify(assessmentForm) }, { reload: false })
      const result = await assessmentRequest(`/v1/agents/${encodeURIComponent(selectedAgent.agent_id)}/impact-assessments`, {}, { reload: false })
      const history = result.assessments || []
      const assessmentsWithCreated = created?.assessment_id && !history.some((item) => item.assessment_id === created.assessment_id)
        ? [created, ...history]
        : history
      if (requestVersion !== assessmentRequestVersion.current) return
      setAssessments(assessmentsWithCreated)
      setAssessmentStatus(created?.status === 'completed' ? 'assessed' : result.assessment_status || 'assessed')
      setAssessmentForm(emptyAssessment())
      await load()
    } catch { /* error handled by hook */ }
  }
  const assessmentStatusPill = (status) => <span className={`portal-pill ${status === 'assessed' ? 'success' : 'danger'}`}>{status || 'assessment overdue'}</span>
  const agentColumns = [
    { key: 'agent_id', label: 'Agent' },
    { key: 'purpose', label: 'Purpose' },
    { key: 'maximum_authority', label: 'Maximum permission' },
    { key: 'status', label: 'Status', render: (row) => <span className="portal-pill success">{row.status || 'active'}</span> },
    { key: 'documentation_completeness', label: 'Life-cycle record', render: (row) => row.documentation_completeness || '0/4' },
    { key: 'impact_assessment_status', label: 'Impact assessment', render: (row) => assessmentStatusPill(row.impact_assessment_status) },
    { key: 'updated_at', label: 'Updated', render: (row) => formatDate(row.updated_at) },
    { key: 'actions', label: 'Actions', render: (row) => <button className="portal-text-button" type="button" onClick={() => selectAgent(row)}>View impact assessment</button> },
  ]
  return <>
    <PageHeading eyebrow="Agent Identity" title="Agents and connections" description="Register agents and set the permissions they use to reach Kenning Trusted Agent." action={<button className="portal-secondary-button" type="button" onClick={load}><ArrowsClockwise size={16} /> Refresh</button>} />
    <div className={`portal-content-grid ${canManage ? '' : 'portal-content-grid-single'}`}>
      <section className="portal-panel portal-panel-wide"><DataTable columns={agentColumns} rows={agents} empty="No agents registered" /></section>
      {canManage && <section className="portal-panel"><div className="portal-eyebrow">Register an agent</div><h2>Register an agent</h2><form className="portal-stack-form" onSubmit={register}><label htmlFor="agent-id">Agent ID</label><input id="agent-id" value={form.agent_id} onChange={(event) => setForm({ ...form, agent_id: event.target.value })} placeholder="procurement-agent" required /><label htmlFor="agent-purpose">Purpose</label><input id="agent-purpose" value={form.purpose} onChange={(event) => setForm({ ...form, purpose: event.target.value })} placeholder="Review supplier proposals" /><label htmlFor="agent-tools">Approved tools</label><input id="agent-tools" value={form.tools} onChange={(event) => setForm({ ...form, tools: event.target.value })} placeholder="sql, github" /><p className="portal-field-note">Comma-separated values.</p><label htmlFor="agent-environments">Environments</label><input id="agent-environments" value={form.environments} onChange={(event) => setForm({ ...form, environments: event.target.value })} placeholder="development, staging" /><label htmlFor="agent-authority">Maximum permission</label><select id="agent-authority" value={form.authority} onChange={(event) => setForm({ ...form, authority: event.target.value })}><option value="read">Read</option><option value="standard">Standard</option><option value="high">High</option></select><button className="portal-primary-button" type="submit" disabled={busy}>{busy ? 'Registering…' : 'Register agent'} <Plus size={16} /></button></form><ErrorNotice error={error} /></section>}
    </div>
    {selectedAgent && <section className="portal-panel" style={{ marginTop: '20px' }}>
      <div className="portal-panel-heading"><div><div className="portal-eyebrow">Agent life-cycle record</div><h2>{selectedAgent.agent_id}</h2></div><div>{assessmentStatusPill(assessmentStatus)}</div></div>
      <section className="portal-subform">
        <div className="portal-eyebrow">AI system life-cycle documentation · {selectedAgent.documentation_completeness || '0/4'}</div>
        <p className="portal-field-note">Record the design, resources, verification, and operational controls for this AI system. Changes are retained in the audit history.</p>
        <ErrorNotice error={documentationError} />
        {canManage && <form className="portal-stack-form" onSubmit={saveDocumentation}>
          <label htmlFor="agent-doc-design">Design</label>
          <textarea id="agent-doc-design" value={documentationForm.design} onChange={(event) => setDocumentationForm({ ...documentationForm, design: event.target.value })} rows="3" placeholder="Purpose, architecture, and intended use" />
          <label htmlFor="agent-doc-resources">Resources</label>
          <textarea id="agent-doc-resources" value={documentationForm.resources} onChange={(event) => setDocumentationForm({ ...documentationForm, resources: event.target.value })} rows="3" placeholder="Models, data, tools, and infrastructure" />
          <label htmlFor="agent-doc-verification">Verification</label>
          <textarea id="agent-doc-verification" value={documentationForm.verification} onChange={(event) => setDocumentationForm({ ...documentationForm, verification: event.target.value })} rows="3" placeholder="Testing, validation, and acceptance evidence" />
          <label htmlFor="agent-doc-operational">Operational</label>
          <textarea id="agent-doc-operational" value={documentationForm.operational} onChange={(event) => setDocumentationForm({ ...documentationForm, operational: event.target.value })} rows="3" placeholder="Monitoring, ownership, change, and incident controls" />
          <button className="portal-primary-button" type="submit" disabled={documentationBusy}>{documentationBusy ? 'Saving documentation…' : 'Save life-cycle documentation'} <ArrowRight size={16} /></button>
        </form>}
      </section>
      <div className="portal-panel-heading" style={{ marginTop: '24px' }}><div><div className="portal-eyebrow">Impact assessment</div><h2>Impact and safeguards</h2></div><div>{assessmentStatusPill(assessmentStatus)}</div></div>
      <p className="portal-field-note">Record the effects of this AI system on individuals, groups, and society. The completed assessment is retained in the audit history for 365 days.</p>
      {assessmentBusy && <div className="portal-field-note" role="status">Loading assessment history…</div>}
      <ErrorNotice error={assessmentError} />
      <DataTable columns={[{ key: 'created_at', label: 'Completed', render: (row) => formatDate(row.created_at) }, { key: 'assessor', label: 'Assessor' }, { key: 'summary', label: 'Summary' }, { key: 'status', label: 'Status', render: (row) => <span className="portal-pill success">{row.status}</span> }]} rows={assessments} empty="No impact assessments recorded" />
      {canManage && <form className="portal-stack-form" onSubmit={saveAssessment}><div className="portal-eyebrow">New assessment</div><label htmlFor="impact-summary">Summary</label><textarea id="impact-summary" value={assessmentForm.summary} onChange={(event) => setAssessmentForm({ ...assessmentForm, summary: event.target.value })} rows="3" required /><label htmlFor="impact-individuals">Impacts on individuals and groups</label><textarea id="impact-individuals" value={assessmentForm.impacts_on_individuals} onChange={(event) => setAssessmentForm({ ...assessmentForm, impacts_on_individuals: event.target.value })} rows="3" required /><label htmlFor="impact-society">Impacts on society</label><textarea id="impact-society" value={assessmentForm.impacts_on_society} onChange={(event) => setAssessmentForm({ ...assessmentForm, impacts_on_society: event.target.value })} rows="3" required /><label htmlFor="impact-mitigations">Mitigations</label><textarea id="impact-mitigations" value={assessmentForm.mitigations} onChange={(event) => setAssessmentForm({ ...assessmentForm, mitigations: event.target.value })} rows="3" required /><label htmlFor="impact-assessor">Assessor</label><input id="impact-assessor" value={assessmentForm.assessor} onChange={(event) => setAssessmentForm({ ...assessmentForm, assessor: event.target.value })} required /><button className="portal-primary-button" type="submit" disabled={assessmentBusy}>{assessmentBusy ? 'Saving assessment…' : 'Save impact assessment'} <Plus size={16} /></button></form>}
    </section>}
  </>
}

const TOOL_OPTIONS = ['shell', 'sql', 'database', 'aws', 'azure', 'cloud', 'github', 'email', 'messaging', 'finance', 'payments', 'file']
const ENVIRONMENT_OPTIONS = ['development', 'staging', 'production']
const DECISION_OPTIONS = [
  { value: 'require_approval', label: 'Require approval' },
  { value: 'warn', label: 'Warn' },
  { value: 'rewrite', label: 'Rewrite' },
  { value: 'deny', label: 'Deny' },
  { value: 'allow', label: 'Allow' },
]

const CONDITION_FIELDS = [
  { key: 'tool', label: 'Tool', type: 'glob', hint: 'e.g. shell, sql, aws — use * as a wildcard' },
  { key: 'environment', label: 'Environment', type: 'glob', hint: 'e.g. production, development' },
  { key: 'target', label: 'Target / resource', type: 'glob', hint: 'e.g. production/*, orders' },
  { key: 'agent_id', label: 'Agent', type: 'glob', hint: 'Agent identifier' },
  { key: 'invoked_by', label: 'Invoked by (user)', type: 'glob', hint: 'User or principal' },
  { key: 'operation', label: 'Operation / action type', type: 'glob' },
  { key: 'intent', label: 'Intent', type: 'glob' },
  { key: 'provider', label: 'Cloud provider', type: 'glob', hint: 'e.g. aws, gcp' },
  { key: 'region', label: 'Cloud region', type: 'glob', hint: 'e.g. us-east-1' },
  { key: 'query_scope', label: 'Query scope', type: 'glob' },
  { key: 'reversible', label: 'Reversible', type: 'boolean' },
  { key: 'dry_run_required', label: 'Dry-run / preview in progress', type: 'boolean' },
  { key: 'maximum_amount', label: 'Transaction amount exceeds', type: 'number', hint: 'Matches when the amount is above this value' },
  { key: 'minimum_amount', label: 'Transaction amount at least', type: 'number', hint: 'Matches when the amount reaches this value' },
  { key: 'maximum_scope', label: 'Affected resources exceed', type: 'number', hint: 'Matches when more resources than this are affected' },
  { key: 'start_time', label: 'Not before (time)', type: 'time' },
  { key: 'end_time', label: 'Not after (time)', type: 'time' },
]
const CONDITION_FIELD_KEYS = CONDITION_FIELDS.map((field) => field.key)
const OPERATOR_LABEL = { glob: 'matches pattern', number: 'threshold', boolean: 'is', time: 'boundary' }

function conditionFieldDef(key) {
  return CONDITION_FIELDS.find((field) => field.key === key)
}

function serialiseConditions(rows) {
  const out = {}
  for (const row of rows) {
    if (!row.field || row.value === '' || row.value == null) continue
    const def = conditionFieldDef(row.field)
    if (def?.type === 'boolean') out[row.field] = row.value === true || row.value === 'true'
    else if (def?.type === 'number') { const parsed = Number(row.value); out[row.field] = Number.isFinite(parsed) ? parsed : row.value }
    else out[row.field] = row.value
  }
  return out
}

function deserialiseConditions(conditions) {
  const rows = []
  const extra = {}
  for (const [key, value] of Object.entries(conditions || {})) {
    if (key === 'approver_groups') continue
    if (CONDITION_FIELD_KEYS.includes(key)) {
      const def = conditionFieldDef(key)
      rows.push({ field: key, operator: OPERATOR_LABEL[def.type] || 'matches pattern', value: def.type === 'boolean' ? String(Boolean(value)) : (typeof value === 'object' ? JSON.stringify(value) : String(value)) })
    } else {
      extra[key] = value
    }
  }
  return { rows, extra }
}


export default AgentsView
