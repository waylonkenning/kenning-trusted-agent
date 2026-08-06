import React, { useContext, useState, useRef, useEffect, useMemo } from 'react'
import { PortalContext } from '../PortalContext.jsx'
import { LoadingBlock, ErrorNotice, EmptyState, Stat, PageHeading, DataTable, CopyButton } from '../components/ui.jsx'
import { ConditionBuilder, ChainBuilder } from '../components/ConditionBuilder.jsx'
import ConfirmDialog from '../components/ConfirmDialog.jsx'
import {
  ArrowRight, ArrowsClockwise, ChartLineUp, CheckCircle, ClipboardText, Code,
  Eye, FileText, GearSix, Info, Key, LockKey, MagnifyingGlass, PencilSimple,
  Plus, ShieldCheck, SignOut, Trash, Upload, WarningCircle, X, XCircle,
} from '@phosphor-icons/react'
import { splitValues, formatDate, TOOL_OPTIONS, ENVIRONMENT_OPTIONS, DECISION_OPTIONS, OPERATOR_LABEL, conditionFieldDef, serialiseConditions, deserialiseConditions, simulationSummary } from '../lib.js'
import { useApiMutation } from '../hooks.js'

function PoliciesView({ hideHeading = false, hideList = false, hideBanner = false, simulationTarget = null, actionsRef = null }) {
  const { tenantId, data, load, csrf, membership, user } = useContext(PortalContext)
  const policies = data.policies?.policies || []
  const emptyRule = { rule_id: '', decision: 'require_approval', approver_groups: '', reason: '', conditions: [{ field: 'tool', operator: OPERATOR_LABEL.glob, value: '' }], approval_chain: [] }
  const emptyForm = { policy_id: '', name: '', mode: 'enforce', compliance_tags: '', test_cases: '' }
  const [form, setForm] = useState(emptyForm)
  const [rules, setRules] = useState([{ ...emptyRule }])
  const [showRuleJson, setShowRuleJson] = useState(false)
  const [editingPolicy, setEditingPolicy] = useState(null)
  const [showTestJson, setShowTestJson] = useState(false)
  const [testCaseForm, setTestCaseForm] = useState({ case_id: '', expected_decision: 'deny', tool: 'shell', command: '' })
  const [testCases, setTestCases] = useState([])
  const [simWizard, setSimWizard] = useState({ tool: 'shell', environment: 'development', command: '' })
  const [showSimJson, setShowSimJson] = useState(false)
  const [simulationForm, setSimulationForm] = useState({ policy_id: '', version: 1, action: '' })
  const [simulation, setSimulation] = useState(null)
  const [simulationError, setSimulationError] = useState(null)
  const [testResult, setTestResult] = useState(null)
  const simulationResultRef = useRef(null)
  const [mutate, { busy, error, setError }] = useApiMutation()
  const [selectedPolicy, setSelectedPolicy] = useState(null)
  const [pendingLifecycle, setPendingLifecycle] = useState(null)
  const canManage = ['owner', 'admin', 'policy_admin'].includes(membership?.role)
  const canSimulate = ['owner', 'admin', 'policy_admin'].includes(membership?.role)
  const simActionJson = useMemo(() => JSON.stringify({ action: { tool: simWizard.tool, parameters: { command: simWizard.command } }, context: { environment: simWizard.environment } }, null, 2), [simWizard])

  useEffect(() => {
    if (simulation) simulationResultRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
  }, [simulation])

  useEffect(() => {
    if (!simulationTarget) return
    setSimulationForm((current) => ({ ...current, policy_id: simulationTarget.id, version: simulationTarget.version || 1 }))
    setSimulation(null)
  }, [simulationTarget])

  function addTestCase(event) {
    event.preventDefault()
    if (!testCaseForm.case_id.trim()) return
    setTestCases((prev) => [...prev, { case_id: testCaseForm.case_id.trim(), expected_decision: testCaseForm.expected_decision, action: { tool: testCaseForm.tool, parameters: { command: testCaseForm.command } } }])
    setTestCaseForm({ case_id: '', expected_decision: 'deny', tool: 'shell', command: '' })
  }
  async function savePolicy(event) {
    event.preventDefault(); setError(null)
    try {
      let allTestCases = [...testCases]
      if (showTestJson && form.test_cases.trim()) {
        const parsed = JSON.parse(form.test_cases)
        if (!Array.isArray(parsed)) throw new Error('Reusable test cases must be a JSON array.')
        allTestCases = parsed
      }
      const builtRules = rules.map((rule, index) => {
        const conditions = serialiseConditions(rule.conditions)
        const groups = splitValues(rule.approver_groups)
        if (groups.length) conditions.approver_groups = groups
        const built = { rule_id: rule.rule_id.trim() || `portal-rule-${index + 1}`, decision: rule.decision, reason: rule.reason || 'Configured in the Kenning console.', conditions }
        // Multi-step approval chain (#245): serialise step rows when present.
        const chain = (rule.approval_chain || []).map((step) => ({ label: step.label || '', approver_groups: splitValues(step.approver_groups), separation_of_duties: step.separation_of_duties !== false }))
        if (chain.length) built.approval_chain = chain
        return built
      })
      const payload = { policy_id: form.policy_id || undefined, name: form.name, mode: form.mode, compliance_tags: splitValues(form.compliance_tags), created_by: editingPolicy?.created_by || user?.subject, updated_by: user?.subject, test_cases: allTestCases.length ? allTestCases : undefined, rules: builtRules }
      const endpoint = editingPolicy ? `/v1/policies/${encodeURIComponent(editingPolicy.policy_id)}` : '/v1/policies'
      const method = editingPolicy ? 'PUT' : 'POST'
      if (editingPolicy) payload.version = editingPolicy.version
      await mutate(endpoint, { method, body: JSON.stringify(payload) })
      setForm(emptyForm); setRules([{ ...emptyRule }]); setTestCases([]); setEditingPolicy(null)
    } catch (caught) { setError(caught) }
  }
  function editPolicy(policy) {
    const policyRules = (policy.rules && policy.rules.length) ? policy.rules : [{}]
    setEditingPolicy(policy)
    setForm({ policy_id: policy.policy_id || '', name: policy.name || '', mode: policy.mode || 'enforce', compliance_tags: (policy.compliance_tags || []).join(', '), test_cases: JSON.stringify(policy.test_cases || [], null, 2) })
    setRules(policyRules.map((rule, index) => {
      const { rows, extra } = deserialiseConditions(rule.conditions)
      const conditionRows = rows.length ? rows : [{ field: 'tool', operator: OPERATOR_LABEL.glob, value: '' }]
      // Multi-step approval chain (#245): deserialise stored steps back into rows.
      const chain = Array.isArray(rule.approval_chain) ? rule.approval_chain.map((step) => ({ label: step.label || '', approver_groups: (step.approver_groups || []).join(', '), separation_of_duties: step.separation_of_duties !== false })) : []
      return { rule_id: rule.rule_id || `portal-rule-${index + 1}`, decision: rule.decision || 'require_approval', approver_groups: (rule.approver_groups || rule.conditions?.approver_groups || []).join(', '), reason: rule.reason || '', conditions: conditionRows, approval_chain: chain, extra }
    }))
    setTestCases(policy.test_cases || [])
    setShowTestJson(false)
    setShowRuleJson(false)
    setSelectedPolicy(null)
    setError(null)
  }
  function cancelEdit() {
    setEditingPolicy(null); setForm(emptyForm); setRules([{ ...emptyRule }]); setTestCases([]); setShowTestJson(false); setShowRuleJson(false); setError(null)
  }
  async function deletePolicy(policy) {
    if (!window.confirm(`Delete draft policy “${policy.name || policy.policy_id}” version ${policy.version}? This cannot be undone.`)) return
    try {
      await mutate(`/v1/policies/${encodeURIComponent(policy.policy_id)}`, { method: 'DELETE', body: JSON.stringify({ version: policy.version, deleted_by: user?.subject }) })
      if (editingPolicy?.policy_id === policy.policy_id && editingPolicy?.version === policy.version) cancelEdit()
      if (selectedPolicy?.policy_id === policy.policy_id && selectedPolicy?.version === policy.version) setSelectedPolicy(null)
    } catch { /* error handled by hook */ }
  }
  async function publish(policy) {
    try { await mutate(`/v1/policies/${encodeURIComponent(policy.policy_id)}/publish`, { method: 'POST', body: JSON.stringify({ version: policy.version, published_by: user?.subject }) }) } catch { /* error handled by hook */ }
  }
  function requestLifecycle(policy, action) {
    setPendingLifecycle({ policy, action })
  }
  async function applyLifecycle() {
    if (!pendingLifecycle) return
    const { policy, action } = pendingLifecycle
    try {
      const path = action === 'delete'
        ? `/v1/policies/${encodeURIComponent(policy.policy_id)}`
        : `/v1/policies/${encodeURIComponent(policy.policy_id)}/${action}`
      const method = action === 'delete' ? 'DELETE' : 'POST'
      await mutate(path, { method, body: JSON.stringify({ version: policy.version, confirm: true, changed_by: user?.subject, deleted_by: user?.subject }) })
      setPendingLifecycle(null)
      if (selectedPolicy?.policy_id === policy.policy_id) setSelectedPolicy(null)
    } catch { /* error handled by hook */ }
  }
  async function simulate(event) {
    event.preventDefault(); setSimulationError(null); setSimulation(null)
    try {
      const policyId = simulationForm.policy_id.trim(); const version = Number(simulationForm.version)
      if (!policyId || !version) throw new Error('Policy ID and version are required.')
      const action = JSON.parse(showSimJson && simulationForm.action.trim() ? simulationForm.action : simActionJson)
      const starterSimulation = simulationTarget?.type === 'starter'
      const path = starterSimulation
        ? `/v1/tenants/${encodeURIComponent(tenantId)}/starter-rules/simulate`
        : `/v1/policies/${encodeURIComponent(policyId)}/simulate`
      const body = starterSimulation
        ? { ...action, rule_id: simulationTarget.id, context: { ...(action.context || {}), tenant_id: tenantId } }
        : { ...action, version, context: { ...(action.context || {}), tenant_id: tenantId } }
      setSimulation(await mutate(path, { method: 'POST', body: JSON.stringify(body) }, { reload: false }))
    } catch (caught) { setSimulationError(caught) }
  }
  async function runTests(policy) {
    setTestResult(null)
    try { setTestResult(await mutate(`/v1/policies/${encodeURIComponent(policy.policy_id)}/test`, { method: 'POST', body: JSON.stringify({ version: policy.version }) }, { reload: false })) } catch { /* error handled by hook */ }
  }
  function selectSimulation(policy) {
    setSimulationForm((current) => ({ ...current, policy_id: policy.policy_id, version: policy.version })); setSimulation(null)
  }
  useEffect(() => {
    if (actionsRef) actionsRef.current = { edit: editPolicy, delete: deletePolicy }
  })
  const policyColumns = [
    { key: 'policy_id', label: 'Policy', render: (row) => <button className="portal-text-button" type="button" onClick={() => setSelectedPolicy(row)}>{row.name || row.policy_id}{row.name ? <><br /><small>{row.policy_id}</small></> : null}</button> },
    { key: 'version', label: 'Version' },
    { key: 'status', label: 'Status', render: (row) => <span className={`portal-pill ${row.status === 'published' ? 'success' : row.status === 'suspended' ? 'warning' : ''}`}>{row.status || 'draft'}</span> },
    { key: 'compliance_tags', label: 'Compliance', render: (row) => row.compliance_tags?.length ? row.compliance_tags.join(', ') : 'Untagged' },
    { key: 'created_by', label: 'Created by' },
    { key: 'updated_at', label: 'Updated', render: (row) => formatDate(row.updated_at) },
    { key: 'actions', label: 'Actions', render: (row) => <div className="portal-row-actions">{canManage && row.status === 'draft' && <><button className="portal-secondary-button" type="button" onClick={() => editPolicy(row)}>Edit</button><button className="portal-danger-button" type="button" onClick={() => deletePolicy(row)} disabled={busy}>Delete</button><button className="portal-secondary-button" type="button" onClick={() => publish(row)}>Publish</button></>}{canManage && row.status === 'published' && <><button className="portal-secondary-button" type="button" onClick={() => requestLifecycle(row, 'suspend')}>Suspend</button><button className="portal-danger-button" type="button" onClick={() => requestLifecycle(row, 'delete')}>Delete</button></>}{canManage && row.status === 'suspended' && <><button className="portal-secondary-button" type="button" onClick={() => requestLifecycle(row, 'reactivate')}>Re-activate</button><button className="portal-danger-button" type="button" onClick={() => requestLifecycle(row, 'delete')}>Delete</button></>}{canSimulate ? <button className="portal-secondary-button" type="button" title="Test a single action against this policy without running it" onClick={() => selectSimulation(row)}>Simulate</button> : <button className="portal-secondary-button" type="button" disabled title="You need the Policy admin permission to test policies.">Simulate</button>}{canSimulate && (row.test_cases || []).length > 0 && <button className="portal-secondary-button" type="button" title="Run all saved test cases against this policy" onClick={() => runTests(row)} disabled={busy}>Run saved tests</button>}</div> },
  ]
  return <>
    {!hideHeading && <PageHeading eyebrow="Agent Guard" title="Policies" description="User-defined rules that control what agents may do in this workspace. Create, publish, test, and simulate them here. Kenning also ships built-in default rules for every workspace." action={<button className="portal-secondary-button" type="button" onClick={load}><ArrowsClockwise size={16} /> Refresh</button>} />}
    {!hideBanner && <div className="portal-notice portal-notice-info"><Info size={18} weight="bold" /><span>Built-in default rules (starter rules) apply to every agent in this workspace. Enable, disable, or restore them from the Starter rules section of the navigation.</span></div>}
    <ErrorNotice error={error} />
    {editingPolicy && <div className="portal-notice portal-notice-info" role="status"><Info size={18} weight="bold" /><span>Editing draft version {editingPolicy.version}. Save the changes to keep this draft, or cancel to return to a new policy.</span><button className="portal-text-button" type="button" onClick={cancelEdit}>Cancel edit</button></div>}
    <div className={`portal-content-grid ${canManage ? '' : 'portal-content-grid-single'}`}>
      {!hideList && <section className="portal-panel portal-panel-wide"><DataTable columns={policyColumns} rows={policies} empty="No policies configured" /></section>}
      {canManage && <section className="portal-panel"><div className="portal-eyebrow">{editingPolicy ? "Edit draft policy" : "New policy"}</div><h2>{editingPolicy ? "Continue editing this draft" : "Configure a rule"}</h2><form className="portal-stack-form" onSubmit={savePolicy}><label htmlFor="policy-id">Policy ID</label><input id="policy-id" value={form.policy_id} onChange={(event) => setForm({ ...form, policy_id: event.target.value })} placeholder="production-safety" /><label htmlFor="policy-name">Name</label><input id="policy-name" value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="Production safety" required /><label htmlFor="policy-mode">Mode</label><select id="policy-mode" value={form.mode} onChange={(event) => setForm({ ...form, mode: event.target.value })}><option value="enforce">Enforce</option><option value="observe">Observe</option></select><label htmlFor="policy-compliance-tags">Compliance tags</label><input id="policy-compliance-tags" value={form.compliance_tags} onChange={(event) => setForm({ ...form, compliance_tags: event.target.value })} placeholder="Privacy Act 2020:IPP 5, NZ Algorithm Charter:Transparency" /><p className="portal-field-note">Comma-separated labels for governance coverage. Tags are tenant metadata and do not by themselves prove compliance.</p>
<div className="portal-wizard-section"><div className="portal-wizard-header"><span>Rules ({rules.length})</span><div className="portal-heading-actions"><button className="portal-text-button" type="button" onClick={() => setShowRuleJson(!showRuleJson)}>{showRuleJson ? 'Hide JSON preview' : 'Show JSON preview'}</button><button className="portal-secondary-button" type="button" onClick={() => setRules([...rules, { ...emptyRule, rule_id: `portal-rule-${rules.length + 1}` }])}><Plus size={14} /> Add rule</button></div></div>
{rules.map((rule, ruleIndex) => <fieldset className="portal-rule-editor" key={ruleIndex}><legend>Rule {ruleIndex + 1}{rules.length > 1 && <button className="portal-text-button" type="button" onClick={() => setRules(rules.filter((_, i) => i !== ruleIndex))}>Remove rule</button>}</legend>
<label htmlFor={`rule-id-${ruleIndex}`}>Rule ID</label><input id={`rule-id-${ruleIndex}`} value={rule.rule_id} onChange={(event) => setRules(rules.map((r, i) => i === ruleIndex ? { ...r, rule_id: event.target.value } : r))} placeholder={`portal-rule-${ruleIndex + 1}`} />
<label>When this rule applies {rule.conditions.length > 1 && <span className="portal-field-note">(all conditions must match)</span>}</label>
<ConditionBuilder rows={rule.conditions} onChange={(rows) => setRules(rules.map((r, i) => i === ruleIndex ? { ...r, conditions: rows } : r))} />
<label htmlFor={`rule-decision-${ruleIndex}`}>Decision</label><select id={`rule-decision-${ruleIndex}`} value={rule.decision} onChange={(event) => setRules(rules.map((r, i) => i === ruleIndex ? { ...r, decision: event.target.value } : r))}><option value="require_approval">Require approval</option><option value="warn">Warn</option><option value="rewrite">Rewrite</option><option value="deny">Deny</option><option value="allow">Allow</option></select>
<label htmlFor={`rule-groups-${ruleIndex}`}>Approver groups</label><input id={`rule-groups-${ruleIndex}`} value={rule.approver_groups} onChange={(event) => setRules(rules.map((r, i) => i === ruleIndex ? { ...r, approver_groups: event.target.value } : r))} placeholder="security, platform" />
{rule.decision === 'require_approval' && <><label>Approval steps (optional)</label><ChainBuilder steps={rule.approval_chain || []} onChange={(steps) => setRules(rules.map((r, i) => i === ruleIndex ? { ...r, approval_chain: steps } : r))} /></>}
<label htmlFor={`rule-reason-${ruleIndex}`}>Rule reason</label><input id={`rule-reason-${ruleIndex}`} value={rule.reason} onChange={(event) => setRules(rules.map((r, i) => i === ruleIndex ? { ...r, reason: event.target.value } : r))} placeholder="Explain why this rule exists" />
</fieldset>)}
{showRuleJson && <pre className="portal-proof-json">{JSON.stringify(rules.map((rule, index) => ({ rule_id: rule.rule_id.trim() || `portal-rule-${index + 1}`, decision: rule.decision, reason: rule.reason, conditions: { ...serialiseConditions(rule.conditions), ...(splitValues(rule.approver_groups).length ? { approver_groups: splitValues(rule.approver_groups) } : {}) } })), null, 2)}</pre>}
</div>
<div className="portal-wizard-section"><div className="portal-wizard-header"><span>Reusable test cases</span><button className="portal-text-button" type="button" onClick={() => setShowTestJson(!showTestJson)}>{showTestJson ? 'Use guided builder' : 'Use raw JSON'}</button></div>{showTestJson ? <textarea id="policy-test-cases" value={form.test_cases} onChange={(event) => setForm({ ...form, test_cases: event.target.value })} placeholder='[{"case_id":"production-shell-denied","expected_decision":"deny"}]' /> : <>{testCases.length > 0 && <ul className="portal-test-case-list">{testCases.map((tc, i) => <li key={i}><code>{tc.case_id}</code> <span className="portal-pill">{tc.expected_decision}</span> <span className="portal-test-case-detail">{tc.action.tool}: {tc.action.parameters.command || '—'}</span> <button className="portal-text-button" type="button" onClick={() => setTestCases((prev) => prev.filter((_, j) => j !== i))}>Remove</button></li>)}</ul>}<div className="portal-test-case-builder"><input value={testCaseForm.case_id} onChange={(event) => setTestCaseForm({ ...testCaseForm, case_id: event.target.value })} placeholder="Test case ID" aria-label="Test case ID" /><select value={testCaseForm.tool} onChange={(event) => setTestCaseForm({ ...testCaseForm, tool: event.target.value })} aria-label="Tool">{TOOL_OPTIONS.map((t) => <option key={t} value={t}>{t}</option>)}</select><input value={testCaseForm.command} onChange={(event) => setTestCaseForm({ ...testCaseForm, command: event.target.value })} placeholder="Command or action details" aria-label="Command or action details" /><select value={testCaseForm.expected_decision} onChange={(event) => setTestCaseForm({ ...testCaseForm, expected_decision: event.target.value })} aria-label="Expected decision">{DECISION_OPTIONS.map((d) => <option key={d.value} value={d.value}>{d.label}</option>)}</select><button className="portal-secondary-button" type="button" onClick={addTestCase}><Plus size={14} /> Add</button></div></>}</div><button className="portal-primary-button" type="submit" disabled={busy}>{busy ? (editingPolicy ? 'Saving…' : 'Creating…') : (editingPolicy ? 'Save draft' : 'Create policy')} <Plus size={16} /></button></form></section>}
    </div>
    {selectedPolicy && <section className="portal-panel portal-panel-wide"><div className="portal-panel-heading"><div><div className="portal-eyebrow">Policy detail</div><h2>{selectedPolicy.name || selectedPolicy.policy_id}</h2></div><button className="portal-secondary-button" type="button" onClick={() => setSelectedPolicy(null)}>Back to list</button></div><dl className="portal-definition-list"><div><dt>Policy ID</dt><dd>{selectedPolicy.policy_id}</dd></div><div><dt>Version</dt><dd>{selectedPolicy.version}</dd></div><div><dt>Status</dt><dd><span className={`portal-pill ${selectedPolicy.status === 'published' ? 'success' : selectedPolicy.status === 'suspended' ? 'warning' : ''}`}>{selectedPolicy.status || 'draft'}</span></dd></div><div><dt>Mode</dt><dd>{selectedPolicy.mode || 'enforce'}</dd></div><div><dt>Compliance tags</dt><dd>{selectedPolicy.compliance_tags?.length ? selectedPolicy.compliance_tags.join(', ') : 'Untagged'}</dd></div><div><dt>Created by</dt><dd>{selectedPolicy.created_by || '—'}</dd></div><div><dt>Updated</dt><dd>{formatDate(selectedPolicy.updated_at)}</dd></div></dl><div className="portal-eyebrow">Rules</div>{(selectedPolicy.rules || []).length ? <div className="portal-starter-rule-list">{(selectedPolicy.rules || []).map((rule) => <article className="portal-starter-rule" key={rule.rule_id}><div className="portal-starter-rule-heading"><div><strong>{rule.rule_id}</strong><small>{rule.reason || 'No reason given'}</small></div><span className={`portal-pill ${rule.decision === 'deny' ? 'danger' : rule.decision === 'allow' ? 'success' : ''}`}>{rule.decision}</span></div><p className="portal-field-note">{triggerDescription(rule)}</p><ul className="portal-proof-limitations">{conditionsSummary(rule).map((phrase, i) => <li key={i}>{phrase}</li>)}</ul>{rule.approver_groups?.length > 0 && <p className="portal-field-note">Approver groups: {rule.approver_groups.join(', ')}</p>}<details><summary>Raw condition JSON</summary><pre className="portal-proof-json">{JSON.stringify(rule.conditions || {}, null, 2)}</pre></details></article>)}</div> : <p className="portal-field-note">No rules configured.</p>}{(selectedPolicy.test_cases || []).length > 0 && <><div className="portal-eyebrow">Test cases</div><ul className="portal-test-case-list">{(selectedPolicy.test_cases || []).map((tc, i) => <li key={i}><code>{tc.case_id || tc.name}</code> <span className="portal-pill">{tc.expected_decision}</span> <span className="portal-test-case-detail">{tc.action?.tool || '—'}: {tc.action?.parameters?.command || '—'}</span></li>)}</ul></>}</section>}
    {pendingLifecycle && <ConfirmDialog
      eyebrow="Confirm policy change"
      title={pendingLifecycle.action === 'delete' ? 'Delete this policy permanently?' : pendingLifecycle.action === 'suspend' ? 'Suspend this policy?' : 'Re-activate this policy?'}
      message={pendingLifecycle.action === 'delete' ? 'This removes every saved version of the published policy. The deletion cannot be undone, although the audit event remains recorded.' : pendingLifecycle.action === 'suspend' ? 'Suspending stops this policy from being evaluated without removing its history. You can re-activate it later.' : 'Re-activating makes this policy eligible for evaluation again.'}
      confirmLabel={busy ? 'Applying…' : pendingLifecycle.action === 'delete' ? 'Delete policy' : pendingLifecycle.action === 'suspend' ? 'Suspend policy' : 'Re-activate policy'}
      confirmClass={pendingLifecycle.action === 'delete' ? 'portal-danger-button' : 'portal-primary-button'}
      onCancel={() => setPendingLifecycle(null)}
      onConfirm={applyLifecycle}
      disabled={busy}
    />}
    <section className="portal-panel portal-policy-lab"><div className="portal-eyebrow">Test a policy</div><h2>Test without running the action</h2><p className="portal-field-note">Use the same request format an agent would send. Testing does not create an approval or run a tool.</p>{canSimulate ? <form className="portal-stack-form" onSubmit={simulate}><label htmlFor="simulation-policy-id">Policy ID</label><input id="simulation-policy-id" value={simulationForm.policy_id} onChange={(event) => setSimulationForm({ ...simulationForm, policy_id: event.target.value })} placeholder="production-safety" required /><label htmlFor="simulation-version">Version</label><input id="simulation-version" type="number" min="1" value={simulationForm.version} onChange={(event) => setSimulationForm({ ...simulationForm, version: event.target.value })} required /><div className="portal-wizard-section"><div className="portal-wizard-header"><span>Action to test</span><button className="portal-text-button" type="button" onClick={() => setShowSimJson(!showSimJson)}>{showSimJson ? 'Use guided inputs' : 'Use raw JSON'}</button></div>{showSimJson ? <textarea id="simulation-action" value={simulationForm.action} onChange={(event) => setSimulationForm({ ...simulationForm, action: event.target.value })} placeholder='{"action":{"tool":"shell","parameters":{"command":"ls"}},"context":{"environment":"development"}}' /> : <><label htmlFor="sim-tool">Tool</label><select id="sim-tool" value={simWizard.tool} onChange={(event) => setSimWizard({ ...simWizard, tool: event.target.value })}>{TOOL_OPTIONS.map((t) => <option key={t} value={t}>{t}</option>)}</select><label htmlFor="sim-environment">Environment</label><select id="sim-environment" value={simWizard.environment} onChange={(event) => setSimWizard({ ...simWizard, environment: event.target.value })}>{ENVIRONMENT_OPTIONS.map((e) => <option key={e} value={e}>{e}</option>)}</select><label htmlFor="sim-command">Command or action details</label><input id="sim-command" value={simWizard.command} onChange={(event) => setSimWizard({ ...simWizard, command: event.target.value })} placeholder="rm -rf /important/data" /><div className="portal-overview-snippet"><div className="portal-overview-snippet-header"><span>Generated request preview</span></div><pre>{simActionJson}</pre></div></>}</div><button className="portal-primary-button" type="submit" disabled={busy}>{busy ? 'Testing…' : 'Test this policy'} <ArrowRight size={16} /></button></form> : <div className="portal-notice portal-notice-info" role="status"><WarningCircle size={18} weight="bold" /><span>You need the Policy admin permission to test policies. Ask a workspace administrator to assign it.</span></div>}{simulationError && <ErrorNotice error={simulationError} />}{simulation && <div className="portal-result-block" ref={simulationResultRef} role="status" aria-live="polite"><div className="portal-eyebrow">Test result</div><p className="portal-field-note">{simulationSummary(simulation)}</p><details><summary>Raw response</summary><pre className="portal-proof-json">{JSON.stringify(simulation, null, 2)}</pre></details></div>}{testResult && <div className="portal-result-block"><div className="portal-eyebrow">Policy test results</div><p className="portal-field-note">{testResult.all_passed ? `All ${testResult.test_count} test case${testResult.test_count === 1 ? '' : 's'} passed.` : `${testResult.failed_count} of ${testResult.test_count} test cases failed.`}</p><details><summary>Raw response</summary><pre className="portal-proof-json">{JSON.stringify(testResult, null, 2)}</pre></details></div>}</section>
  </>
}

function triggerDescription(rule) {
  const conditions = rule.conditions || {}
  const parts = []
  if (conditions.tool) parts.push(conditions.tool)
  else parts.push('any tool')
  if (conditions.environment) parts.push(`in ${conditions.environment}`)
  if (conditions.target) parts.push(`targeting ${conditions.target}`)
  if (conditions.operation) parts.push(`(${conditions.operation})`)
  return `Applies when ${parts.join(' ')} is used.`
}

function conditionsSummary(rule) {
  const conditions = rule.conditions || {}
  const phrases = []
  for (const [key, value] of Object.entries(conditions)) {
    if (key === 'approver_groups' || value === '' || value == null) continue
    const def = conditionFieldDef(key)
    if (def) {
      if (def.type === 'boolean') phrases.push(`${def.label} is ${value === true || value === 'true' ? 'true' : 'false'}`)
      else if (def.type === 'number') phrases.push(`${def.label} ${value}`)
      else phrases.push(`${def.label} matches "${value}"`)
    } else {
      phrases.push(`${key} matches "${typeof value === 'object' ? JSON.stringify(value) : value}"`)
    }
  }
  return phrases.length ? phrases : ['Applies to every action (no conditions).']
}


export default PoliciesView
