import React, { useContext, useState, useRef, useEffect } from 'react'
import { PortalContext } from '../PortalContext.jsx'
import { LoadingBlock, ErrorNotice, EmptyState, Stat, PageHeading, DataTable, CopyButton } from '../components/ui.jsx'
import { ConditionBuilder, ChainBuilder } from '../components/ConditionBuilder.jsx'
import ConfirmDialog from '../components/ConfirmDialog.jsx'
import {
  ArrowRight, ArrowsClockwise, ChartLineUp, CheckCircle, ClipboardText, Code,
  Eye, FileText, GearSix, Info, Key, LockKey, MagnifyingGlass, PencilSimple,
  Plus, ShieldCheck, SignOut, Trash, Upload, WarningCircle, X, XCircle,
} from '@phosphor-icons/react'
import { request, triggerDescription } from '../lib.js'
import { useApiMutation } from '../hooks.js'

function StarterRulesView({ hideHeading = false, hideCrossReference = false }) {
  const { tenantId, data, load, updateData, csrf, membership } = useContext(PortalContext)
  const starter = data.starterRules || {}
  const [rules, setRules] = useState([])
  const [restoreId, setRestoreId] = useState('')
  const [form, setForm] = useState({ rule_id: '', name: '', description: '', decision: 'require_approval', reason: '', conditions: '{"tool":"shell","environment":"production"}' })
  const [mutate, { busy, error, setError }] = useApiMutation()
  const latestSavedConfig = useRef({ tenantId: '', version: 0 })
  const canManage = ['owner', 'admin'].includes(membership?.role)
  const defaults = starter.available_defaults || []
  useEffect(() => {
    if (latestSavedConfig.current.tenantId !== tenantId) {
      latestSavedConfig.current = { tenantId, version: 0 }
    }
    const incomingVersion = Number(starter.config_version || 0)
    if (incomingVersion && incomingVersion < latestSavedConfig.current.version) return
    if (incomingVersion > latestSavedConfig.current.version) latestSavedConfig.current.version = incomingVersion
    setRules(JSON.parse(JSON.stringify(starter.rules || [])))
  }, [starter.rules, starter.config_version, tenantId])

  function updateRule(index, patch) {
    setRules((current) => current.map((rule, itemIndex) => itemIndex === index ? { ...rule, ...patch } : rule))
  }

  function removeRule(index) {
    setRules((current) => current.filter((_, itemIndex) => itemIndex !== index))
  }

  function editConditions(index, value) {
    try { updateRule(index, { conditions: JSON.parse(value), conditionsText: undefined }) } catch { updateRule(index, { conditionsText: value }) }
  }

  async function save(event) {
    event.preventDefault()
    try {
      const payloadRules = rules.map((rule) => {
        if (rule.conditionsText !== undefined) throw new Error(`Conditions for ${rule.rule_id} must be valid JSON.`)
        const next = { ...rule }; delete next.conditionsText; return next
      })
      const result = await mutate(`/v1/tenants/${encodeURIComponent(tenantId)}/starter-rules`, { method: 'PUT', body: JSON.stringify({ rules: payloadRules }) }, { reload: false })
      latestSavedConfig.current = { tenantId, version: Number(result.config_version || latestSavedConfig.current.version || 0) }
      updateData?.((current) => ({ ...current, starterRules: result }))
      setRules(result.rules || []); await load()
    } catch (caught) { setError(caught) }
  }

  function restoreDefault() {
    const selected = defaults.find((rule) => rule.rule_id === restoreId)
    if (!selected || rules.some((rule) => rule.rule_id === selected.rule_id)) return
    setRules((current) => [...current, JSON.parse(JSON.stringify(selected))]); setRestoreId('')
  }

  function addCustom(event) {
    event.preventDefault(); setError(null)
    try {
      const conditions = JSON.parse(form.conditions || '{}')
      if (!form.rule_id.trim() || !form.name.trim()) throw new Error('Rule ID and name are required.')
      if (!conditions || Array.isArray(conditions) || typeof conditions !== 'object') throw new Error('Conditions must be a JSON object.')
      if (rules.some((rule) => rule.rule_id === form.rule_id.trim())) throw new Error('That starter rule ID already exists.')
      setRules((current) => [...current, { rule_id: form.rule_id.trim(), name: form.name.trim(), description: form.description.trim() || 'Workspace-defined check.', kind: 'custom', reason_code: `STARTER_${form.rule_id.toUpperCase().replace(/[^A-Z0-9]+/g, '_')}`, decision: form.decision, enabled: true, conditions, reason: form.reason.trim(), approver_groups: [] }])
      setForm({ rule_id: '', name: '', description: '', decision: 'require_approval', reason: '', conditions: '{"tool":"shell","environment":"production"}' })
    } catch (caught) { setError(caught) }
  }

  return <>
    {!hideHeading && <PageHeading eyebrow="Agent Guard" title="Starter rules" description="Built-in default rules supplied by Kenning and applied to every agent in this workspace. Enable, disable, remove, or restore them here. Changes are saved, versioned, and recorded." action={<button className="portal-secondary-button" type="button" onClick={load}><ArrowsClockwise size={16} /> Refresh</button>} />}
    {!hideCrossReference && <div className="portal-notice portal-notice-info"><Info size={18} weight="bold" /><span>For custom, user-defined rules, create and manage them from the Policies section of the navigation. Those policies live alongside these built-in defaults.</span></div>}
    <ErrorNotice error={error} />
    <div className={`portal-content-grid ${canManage ? '' : 'portal-content-grid-single'}`}>
      <section className="portal-panel portal-panel-wide">
        <div className="portal-panel-heading"><div><div className="portal-eyebrow">Current workspace rules</div><h2>{rules.length} starter rule{rules.length === 1 ? '' : 's'}</h2></div><span className="portal-panel-meta">{rules.filter((rule) => rule.enabled).length} enabled</span></div>
        <div className="portal-starter-rule-list">
          {rules.map((rule, index) => <article className="portal-starter-rule" key={rule.rule_id}>
            <div className="portal-starter-rule-heading"><div><strong>{rule.name || rule.rule_id}</strong><small>{rule.rule_id} · {rule.kind === 'builtin' ? 'Kenning built-in check' : 'Workspace rule'} · {rule.reason_code}</small></div><span className={`portal-pill ${rule.enabled ? (rule.decision === 'deny' ? 'danger' : rule.decision === 'allow' ? 'success' : '') : ''}`}>{rule.enabled ? rule.decision : 'disabled'}</span></div>
            <p className="portal-field-note">Compliance tags: {rule.compliance_tags?.length ? rule.compliance_tags.join(', ') : 'Untagged'}</p>
            {canManage ? <div className="portal-starter-rule-editor">
              <label><input type="checkbox" checked={rule.enabled !== false} onChange={(event) => updateRule(index, { enabled: event.target.checked })} /> Enabled</label>
              <label>Name<input value={rule.name || ''} onChange={(event) => updateRule(index, { name: event.target.value })} /></label>
              <label>Description<textarea value={rule.description || ''} onChange={(event) => updateRule(index, { description: event.target.value })} /></label>
              <label>Decision<select value={rule.decision} onChange={(event) => updateRule(index, { decision: event.target.value })}><option value="deny">Deny</option><option value="require_approval">Require approval</option><option value="warn">Warn</option><option value="rewrite">Rewrite</option><option value="allow">Allow</option></select></label>
              <label>When this rule applies<p className="portal-field-note">{triggerDescription(rule)}</p><details><summary>Raw condition JSON</summary><textarea value={rule.conditionsText !== undefined ? rule.conditionsText : JSON.stringify(rule.conditions || {}, null, 2)} onChange={(event) => editConditions(index, event.target.value)} /></details></label>
              <label>Compliance tags<input value={(rule.compliance_tags || []).join(', ')} onChange={(event) => updateRule(index, { compliance_tags: event.target.value.split(',').map((item) => item.trim()).filter(Boolean) })} placeholder="Privacy Act 2020:IPP 5, NZ Algorithm Charter:Transparency" /><span className="portal-field-note">Comma-separated labels. Remove a label to change the starter mapping.</span></label>
              <label>Reason for the exception<input value={rule.reason || ''} onChange={(event) => updateRule(index, { reason: event.target.value })} placeholder={rule.description || 'Use the check explanation'} /></label>
              <div className="portal-row-actions"><button className="portal-danger-button" type="button" onClick={() => removeRule(index)}>Remove rule</button></div>
            </div> : <div><p className="portal-field-note">{rule.description || 'Workspace check.'}</p><p className="portal-field-note">{triggerDescription(rule)}</p></div>}
          </article>)}
          {!rules.length && <EmptyState icon={ShieldCheck} title="No starter rules" message="Add a built-in check or create a workspace rule." />}
        </div>
        {canManage && <button className="portal-primary-button" type="button" onClick={save} disabled={busy}>{busy ? 'Saving…' : 'Save starter rules'} <ArrowRight size={16} /></button>}
      </section>
      {canManage && <section className="portal-panel">
        <div className="portal-eyebrow">Built-in checks</div><h2>Available defaults</h2><p className="portal-field-note">Removed built-in checks can be added back without code changes.</p>
        <div className="portal-stack-form"><label htmlFor="starter-restore-rule">Default rule</label><select id="starter-restore-rule" value={restoreId} onChange={(event) => setRestoreId(event.target.value)}><option value="">Choose a default rule</option>{defaults.filter((rule) => !rules.some((current) => current.rule_id === rule.rule_id)).map((rule) => <option key={rule.rule_id} value={rule.rule_id}>{rule.name}</option>)}</select><button className="portal-secondary-button" type="button" onClick={restoreDefault} disabled={!restoreId}>Add default rule <Plus size={16} /></button></div>
        <div className="portal-subform"><div className="portal-eyebrow">Add a workspace rule</div><h2>Workspace rule</h2><form className="portal-stack-form" onSubmit={addCustom}><label htmlFor="starter-rule-id">Rule ID</label><input id="starter-rule-id" value={form.rule_id} onChange={(event) => setForm({ ...form, rule_id: event.target.value })} placeholder="production-shell-review" required /><label htmlFor="starter-rule-name">Name</label><input id="starter-rule-name" value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="Production shell review" required /><label htmlFor="starter-rule-description">Description</label><textarea id="starter-rule-description" value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} placeholder="Explain the check." /><label htmlFor="starter-rule-decision">Decision</label><select id="starter-rule-decision" value={form.decision} onChange={(event) => setForm({ ...form, decision: event.target.value })}><option value="require_approval">Require approval</option><option value="deny">Deny</option><option value="warn">Warn</option><option value="rewrite">Rewrite</option><option value="allow">Allow</option></select><label htmlFor="starter-rule-reason">Reason</label><input id="starter-rule-reason" value={form.reason} onChange={(event) => setForm({ ...form, reason: event.target.value })} placeholder="Why this rule exists" /><label htmlFor="starter-rule-conditions">Conditions JSON</label><textarea id="starter-rule-conditions" value={form.conditions} onChange={(event) => setForm({ ...form, conditions: event.target.value })} required /><button className="portal-primary-button" type="submit">Add workspace rule <Plus size={16} /></button></form></div>
      </section>}
    </div>
  </>
}


export default StarterRulesView
