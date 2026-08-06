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
import { formatDate, triggerDescription } from '../lib.js'
import { useApiMutation } from '../hooks.js'
import PoliciesView from './PoliciesView.jsx'
import StarterRulesView from './StarterRulesView.jsx'

function RulesView() {
  const { tenantId, data, load, csrf, membership, user } = useContext(PortalContext)
  const policies = data.policies?.policies || []
  const starter = data.starterRules || {}
  const starterRules = starter.rules || []
  const complianceCoverage = data.complianceCoverage || {}
  const [pendingLifecycle, setPendingLifecycle] = useState(null)
  const [simulationTarget, setSimulationTarget] = useState(null)
  const [testResult, setTestResult] = useState(null)
  const [mutate, { error }] = useApiMutation()
  const policyActions = useRef(null)
  const canManagePolicies = ['owner', 'admin', 'policy_admin'].includes(membership?.role)
  const canSimulate = ['owner', 'admin', 'policy_admin'].includes(membership?.role)
  const rows = [
    ...starterRules.map((rule) => ({ ...rule, rule_source: 'kenning', display_status: rule.enabled === false ? 'disabled' : 'enabled' })),
    ...policies.map((policy) => ({ ...policy, rule_source: 'workspace', display_status: policy.status || 'draft' })),
  ]
  const coverageColumns = [
    { key: 'tag', label: 'Compliance tag' },
    { key: 'policy_count', label: 'Policies' },
    { key: 'policy_ids', label: 'Policy IDs', render: (row) => row.policy_ids?.join(', ') || '—' },
  ]

  function requestLifecycle(policy, action) {
    setPendingLifecycle({ policy, action })
  }

  async function publish(policy) {
    try {
      await mutate(`/v1/policies/${encodeURIComponent(policy.policy_id)}/publish`, { method: 'POST', body: JSON.stringify({ version: policy.version, published_by: user?.subject }) })
    } catch { /* error handled by hook */ }
  }

  async function markReviewed(policy) {
    try {
      await mutate(`/v1/policies/${encodeURIComponent(policy.policy_id)}`, {
        method: 'PUT',
        body: JSON.stringify({ version: policy.version, last_reviewed_at: new Date().toISOString(), updated_by: user?.subject }),
      })
    } catch { /* error handled by hook */ }
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
    } catch { /* error handled by hook */ }
  }

  async function runTests(policy) {
    try {
      setTestResult(await mutate(`/v1/policies/${encodeURIComponent(policy.policy_id)}/test`, { method: 'POST', body: JSON.stringify({ version: policy.version }) }, { reload: false }))
    } catch { /* error handled by hook */ }
  }

  function simulateRule(row) {
    setSimulationTarget({ type: row.rule_source === 'kenning' ? 'starter' : 'policy', id: row.rule_source === 'kenning' ? row.rule_id : row.policy_id, version: row.version })
    window.setTimeout(() => document.querySelector('.portal-policy-lab')?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 0)
  }

  const ruleColumns = [
    { key: 'rule', label: 'Rule', render: (row) => row.rule_source === 'workspace' ? <strong>{row.name || row.policy_id}<small className="portal-table-subtext">{row.policy_id}</small></strong> : <strong>{row.name || row.rule_id}<small className="portal-table-subtext">{row.rule_id}</small></strong> },
    { key: 'source', label: 'Type', render: (row) => <span className={`portal-pill ${row.rule_source === 'kenning' ? 'info' : ''}`}>{row.rule_source === 'kenning' ? 'Kenning default' : 'Workspace'}</span> },
    { key: 'description', label: 'Description', render: (row) => <span>{row.description || row.rules?.[0]?.reason || 'Workspace rule'}</span> },
    { key: 'compliance_tags', label: 'Compliance', render: (row) => row.compliance_tags?.length ? row.compliance_tags.join(', ') : 'Untagged' },
    { key: 'conditions', label: 'Conditions', render: (row) => triggerDescription(row.rule_source === 'kenning' ? row : row.rules?.[0] || {}) },
    { key: 'decision', label: 'Decision', render: (row) => row.rule_source === 'kenning' ? row.decision : row.rules?.[0]?.decision || '—' },
    { key: 'status', label: 'Status', render: (row) => <span className={`portal-pill ${row.rule_source === 'kenning' ? (row.enabled === false ? '' : 'success') : row.status === 'published' ? 'success' : row.status === 'suspended' ? 'warning' : ''}`}>{row.display_status}</span> },
    { key: 'review', label: 'Policy review', render: (row) => {
      if (row.rule_source === 'kenning') return '—'
      const overdue = row.review_overdue !== false
      return <span className={`portal-pill ${overdue ? 'warning' : 'success'}`}>{overdue ? 'Review overdue' : `Reviewed ${formatDate(row.last_reviewed_at)}`}</span>
    } },
    { key: 'actions', label: 'Actions', render: (row) => row.rule_source === 'kenning' ? <div className="portal-row-actions"><button className="portal-secondary-button" type="button" onClick={() => document.getElementById('starter-rule-management')?.scrollIntoView({ behavior: 'smooth', block: 'start' })}>Edit default</button>{canSimulate ? <button className="portal-secondary-button" type="button" onClick={() => simulateRule(row)}>Simulate</button> : <button className="portal-secondary-button" type="button" disabled title="You need the Policy admin permission to test policies.">Simulate</button>}</div> : <div className="portal-row-actions">{canManagePolicies && row.status === 'draft' && <><button className="portal-secondary-button" type="button" onClick={() => { policyActions.current?.edit(row); document.querySelector('.portal-unified-management')?.scrollIntoView({ behavior: 'smooth', block: 'start' }) }}>Edit</button><button className="portal-danger-button" type="button" onClick={() => policyActions.current?.delete(row)}>Delete</button><button className="portal-secondary-button" type="button" onClick={() => publish(row)}>Publish</button></>}{canManagePolicies && row.status === 'published' && <><button className="portal-secondary-button" type="button" onClick={() => requestLifecycle(row, 'suspend')}>Suspend</button><button className="portal-danger-button" type="button" onClick={() => requestLifecycle(row, 'delete')}>Delete</button></>}{canManagePolicies && row.status === 'suspended' && <><button className="portal-secondary-button" type="button" onClick={() => requestLifecycle(row, 'reactivate')}>Re-activate</button><button className="portal-danger-button" type="button" onClick={() => requestLifecycle(row, 'delete')}>Delete</button></>}{canManagePolicies && row.rule_source === 'workspace' && <button className="portal-secondary-button" type="button" onClick={() => markReviewed(row)}>Mark reviewed</button>}{canSimulate ? <button className="portal-secondary-button" type="button" onClick={() => simulateRule(row)}>Simulate</button> : <button className="portal-secondary-button" type="button" disabled title="You need the Policy admin permission to test policies.">Simulate</button>}{canSimulate && row.test_cases?.length > 0 && <button className="portal-secondary-button" type="button" onClick={() => runTests(row)}>Run saved tests</button>}</div> },
  ]

  return <>
    <PageHeading eyebrow="Agent Guard" title="Rules" description="One place to understand and manage Kenning defaults and workspace policies. Defaults protect every agent; workspace rules add your own controls." action={<button className="portal-secondary-button" type="button" onClick={load}><ArrowsClockwise size={16} /> Refresh</button>} />
    <ErrorNotice error={error} />
    <section className="portal-panel portal-panel-wide portal-unified-rules"><div className="portal-panel-heading"><div><div className="portal-eyebrow">All Agent Guard rules</div><h2>{rows.length} rule{rows.length === 1 ? '' : 's'}</h2></div><span className="portal-panel-meta">{starterRules.filter((rule) => rule.enabled !== false).length} Kenning defaults enabled</span></div><DataTable columns={ruleColumns} rows={rows} empty="No rules configured" /></section>
    <section className="portal-panel portal-panel-wide" id="compliance-coverage"><div className="portal-panel-heading"><div><div className="portal-eyebrow">Governance metadata</div><h2>Compliance coverage</h2></div><span className="portal-panel-meta">{complianceCoverage.tagged_policies || 0} of {complianceCoverage.total_policies || 0} policies tagged</span></div><p className="portal-field-note">Policy labels help reviewers find coverage areas. They are tenant metadata and do not by themselves prove compliance.</p><DataTable columns={coverageColumns} rows={complianceCoverage.tags || []} empty="No compliance tags" /></section>
    <section className="portal-panel portal-unified-management"><div className="portal-eyebrow">Workspace rules</div><h2>Create and test policies</h2><PoliciesView hideHeading hideList hideBanner simulationTarget={simulationTarget} actionsRef={policyActions} /></section>
    <section className="portal-panel portal-unified-management" id="starter-rule-management"><div className="portal-eyebrow">Kenning defaults</div><h2>Enable, disable, remove, or restore defaults</h2><StarterRulesView hideHeading hideCrossReference /></section>
    {testResult && <section className="portal-panel portal-result-block"><div className="portal-eyebrow">Policy test results</div><p className="portal-field-note">{testResult.all_passed ? `All ${testResult.test_count} test cases passed.` : `${testResult.failed_count} of ${testResult.test_count} test cases failed.`}</p><details><summary>Raw response</summary><pre className="portal-proof-json">{JSON.stringify(testResult, null, 2)}</pre></details></section>}
    {pendingLifecycle && <ConfirmDialog
      eyebrow="Confirm policy change"
      title={pendingLifecycle.action === 'delete' ? 'Delete this policy permanently?' : pendingLifecycle.action === 'suspend' ? 'Suspend this policy?' : pendingLifecycle.action === 'reactivate' ? 'Re-activate this policy?' : 'Publish this policy?'}
      message={pendingLifecycle.action === 'delete' ? 'This removes every saved version of the published policy. The deletion cannot be undone, although the audit event remains recorded.' : pendingLifecycle.action === 'suspend' ? 'Suspending stops this policy from being evaluated without removing its history. You can re-activate it later.' : pendingLifecycle.action === 'reactivate' ? 'Re-activating makes this policy eligible for evaluation again.' : 'Publishing makes this policy eligible for evaluation by Agent Guard.'}
      confirmLabel={pendingLifecycle.action === 'delete' ? 'Delete policy' : pendingLifecycle.action === 'suspend' ? 'Suspend policy' : pendingLifecycle.action === 'reactivate' ? 'Re-activate policy' : 'Publish policy'}
      confirmClass={pendingLifecycle.action === 'delete' ? 'portal-danger-button' : 'portal-primary-button'}
      onCancel={() => setPendingLifecycle(null)}
      onConfirm={applyLifecycle}
    />}
  </>
}


export default RulesView
