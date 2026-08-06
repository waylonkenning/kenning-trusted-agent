import React, { useContext, useState, useRef, useEffect } from 'react'
import { PortalContext } from '../PortalContext.jsx'
import { ErrorNotice, PageHeading, DataTable } from '../components/ui.jsx'
import { ArrowRight, ArrowsClockwise, BookOpenText, Plus } from '@phosphor-icons/react'
import { formatDate, splitValues } from '../lib.js'
import { useApiMutation } from '../hooks.js'
import CaptureAuditSettings from './CaptureAuditSettings.jsx'
import UserGuideView from './UserGuideView.jsx'

function tenantFormFromConfig(config) {
  return {
    name: config.name || '',
    default_environment: config.default_environment || 'development',
    retention_enabled: Boolean(config.retention_enabled),
    retention_days: config.retention_days || '',
    data_residency_region: config.data_residency_region || '',
    legal_hold_enabled: Boolean(config.legal_hold_enabled),
    legal_hold_reason: config.legal_hold_reason || '',
  }
}

function SettingsView() {
  const { tenantId, data, load, membership, refreshSession } = useContext(PortalContext)
  const config = data.tenant
  const environments = data.environments?.environments || []
  const managementReviews = data.managementReviews?.reviews || []
  const models = data.models?.models || []
  const suppliers = data.suppliers?.suppliers || []
  const nonconformities = data.nonconformities?.nonconformities || []
  const [form, setForm] = useState({ name: '', default_environment: 'development', retention_enabled: false, retention_days: '', data_residency_region: '', legal_hold_enabled: false, legal_hold_reason: '' })
  const [enabledProducts, setEnabledProducts] = useState([])
  const [environment, setEnvironment] = useState({ environment_id: '', name: '', mode: 'enforce', status: 'active', allowed_tools: '' })
  const [reviewForm, setReviewForm] = useState({ period_start: '', period_end: '', attendees: '', decisions: '', action_items: '' })
  const [modelForm, setModelForm] = useState({ model_id: '', name: '', vendor: '', version: '', risk_tier: 'medium', bias_tested: false, provenance: '', supplier_id: '' })
  const [supplierForm, setSupplierForm] = useState({ name: '', role: 'data_provider', risk_rating: 'medium' })
  const [nonconformityForm, setNonconformityForm] = useState({ title: '', description: '', severity: 'medium', source_event_id: '' })
  const [concernForm, setConcernForm] = useState({ description: '', anonymous: false })
  const [selectedModel, setSelectedModel] = useState(null)
  const [dataResources, setDataResources] = useState([])
  const [productsSaving, setProductsSaving] = useState(false)
  const [showGuide, setShowGuide] = useState(false)
  const [mutate, { busy, error }] = useApiMutation()
  const canManage = ['owner', 'admin', 'policy_admin'].includes(membership?.role)
  const formDirtyRef = useRef(false)
  const productsDirtyRef = useRef(false)
  const productsTenantIdRef = useRef('')
  const latestConfigVersionRef = useRef(0)

  useEffect(() => {
    if (!config) return
    if (productsTenantIdRef.current !== tenantId) {
      productsTenantIdRef.current = tenantId
      productsDirtyRef.current = false
    }
    const configVersion = Number(config.config_version) || 0
    if (configVersion < latestConfigVersionRef.current) return
    latestConfigVersionRef.current = configVersion
    if (!formDirtyRef.current) setForm(tenantFormFromConfig(config))
    if (!productsDirtyRef.current) {
      setEnabledProducts(Array.isArray(config.enabled_products) ? config.enabled_products : ['agent-guard', 'agent-proof', 'citation-trust', 'agent-identity'])
    }
  }, [config, tenantId])

  async function saveTenant(event) {
    event.preventDefault()
    try {
      const updated = await mutate(`/v1/tenants/${encodeURIComponent(tenantId)}`, {
        method: 'PUT',
        body: JSON.stringify({
          name: form.name,
          default_environment: form.default_environment,
          retention_enabled: form.retention_enabled,
          retention_days: form.retention_days ? Number(form.retention_days) : null,
          data_residency_region: form.data_residency_region,
          legal_hold_enabled: form.legal_hold_enabled,
          legal_hold_reason: form.legal_hold_reason,
        }),
      }, { reload: false })
      latestConfigVersionRef.current = Math.max(latestConfigVersionRef.current, Number(updated.config_version) || 0)
      formDirtyRef.current = false
      setForm(tenantFormFromConfig(updated))
      await load()
    } catch { /* error handled by hook */ }
  }

  async function saveEnvironment(event) {
    event.preventDefault()
    try {
      await mutate(`/v1/tenants/${encodeURIComponent(tenantId)}/environments/${encodeURIComponent(environment.environment_id)}`, {
        method: 'PUT',
        body: JSON.stringify({ ...environment, default_environment: environments.length ? config.default_environment : environment.environment_id, allowed_tools: splitValues(environment.allowed_tools) }),
      })
      setEnvironment({ environment_id: '', name: '', mode: 'enforce', status: 'active', allowed_tools: '' })
    } catch { /* error handled by hook */ }
  }

  async function saveManagementReview(event) {
    event.preventDefault()
    try {
      await mutate('/v1/management-reviews', {
        method: 'POST',
        body: JSON.stringify(reviewForm),
      })
      setReviewForm({ period_start: '', period_end: '', attendees: '', decisions: '', action_items: '' })
    } catch { /* error handled by hook */ }
  }

  async function saveModel(event) {
    event.preventDefault()
    try {
      await mutate('/v1/models', { method: 'POST', body: JSON.stringify(modelForm) })
      setModelForm({ model_id: '', name: '', vendor: '', version: '', risk_tier: 'medium', bias_tested: false, provenance: '', supplier_id: '' })
    } catch { /* error handled by hook */ }
  }

  async function saveSupplier(event) {
    event.preventDefault()
    try {
      await mutate('/v1/suppliers', { method: 'POST', body: JSON.stringify(supplierForm) })
      setSupplierForm({ name: '', role: 'data_provider', risk_rating: 'medium' })
    } catch { /* error handled by hook */ }
  }

  async function selectModel(model) {
    setSelectedModel(model)
    try {
      const result = await mutate(`/v1/models/${encodeURIComponent(model.model_id)}/data-resources`, {}, { reload: false })
      setDataResources(result.data_resources || [])
    } catch { /* error handled by hook */ }
  }

  async function saveDataResource(event) {
    event.preventDefault()
    if (!selectedModel) return
    const form = event.currentTarget
    const formData = new FormData(form)
    const payload = Object.fromEntries(formData.entries())
    try {
      const created = await mutate(`/v1/models/${encodeURIComponent(selectedModel.model_id)}/data-resources`, { method: 'POST', body: JSON.stringify(payload) }, { reload: false })
      setDataResources((current) => [created, ...current])
      form.reset()
    } catch { /* error handled by hook */ }
  }

  async function saveNonconformity(event) {
    event.preventDefault()
    try {
      await mutate('/v1/nonconformities', { method: 'POST', body: JSON.stringify(nonconformityForm) })
      setNonconformityForm({ title: '', description: '', severity: 'medium', source_event_id: '' })
    } catch { /* error handled by hook */ }
  }

  async function resolveNonconformity(record) {
    const correctiveAction = window.prompt('Corrective action')
    if (!correctiveAction) return
    try {
      await mutate(`/v1/nonconformities/${encodeURIComponent(record.nc_id)}/resolve`, { method: 'POST', body: JSON.stringify({ corrective_action: correctiveAction }) })
    } catch { /* error handled by hook */ }
  }

  async function reportConcern(event) {
    event.preventDefault()
    try {
      await mutate('/v1/concerns', { method: 'POST', body: JSON.stringify(concernForm) })
      setConcernForm({ description: '', anonymous: false })
    } catch { /* error handled by hook */ }
  }

  async function saveProducts(event) {
    event.preventDefault()
    if (!window.confirm('Changing products updates workspace access. Disabled product data and history are kept. Continue?')) return
    setProductsSaving(true)
    try {
      const updated = await mutate(`/v1/tenants/${encodeURIComponent(tenantId)}`, { method: 'PUT', body: JSON.stringify({ enabled_products: enabledProducts }) }, { reload: false })
      await refreshSession?.()
      await load()
      productsDirtyRef.current = false
      if (Array.isArray(updated?.enabled_products)) setEnabledProducts(updated.enabled_products)
    } catch { /* error handled by hook */ }
    finally { setProductsSaving(false) }
  }

  const productOptions = [
    { id: 'agent-guard', label: 'Agent Guard', description: 'Required base control for action checks, policies, approvals, and workspace credentials.' },
    { id: 'agent-proof', label: 'Agent Proof', description: 'Structured history, proof records, and signed receipts.' },
    { id: 'citation-trust', label: 'Citation Trust', description: 'Source and citation verification.' },
    { id: 'agent-identity', label: 'Agent Identity', description: 'Agent registrations, connections, and delegated credentials.' },
  ]

  if (showGuide) return <UserGuideView onBack={() => setShowGuide(false)} />

  return <>
    <PageHeading eyebrow="Workspace administration" title="Workspace settings" description="Manage workspace settings, how long data is kept, where it is stored, legal holds, and product access. Changes are specific to this workspace and recorded." action={<div className="portal-heading-actions"><button className="portal-primary-button" type="button" onClick={() => setShowGuide(true)}><BookOpenText size={16} /> Open user guide</button><button className="portal-secondary-button" type="button" onClick={load}><ArrowsClockwise size={16} /> Refresh</button></div>} />
    <ErrorNotice error={error} />
    <section className="portal-guide-entry" aria-label="Workspace user guide">
      <div><div className="portal-eyebrow">Workspace help</div><h2>Learn how the completed features work</h2><p>Open the user guide for step-by-step instructions, screenshots, and links to the completed Feature cards on the Delivery Board.</p></div>
      <button className="portal-secondary-button" type="button" onClick={() => setShowGuide(true)}>Browse guide <ArrowRight size={16} /></button>
    </section>
    <div className="portal-content-grid">
      <section className="portal-panel">
        <div className="portal-eyebrow">Configuration</div>
        <h2>{form.name || config?.name || tenantId}</h2>
        {canManage ? <form className="portal-stack-form" onChange={() => { formDirtyRef.current = true }} onSubmit={saveTenant}>
          <label htmlFor="tenant-name">Workspace name</label>
          <input id="tenant-name" value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} required />
          <label htmlFor="tenant-default">Default environment</label>
          <input id="tenant-default" value={form.default_environment} onChange={(event) => setForm({ ...form, default_environment: event.target.value })} required />
          <label htmlFor="tenant-region">Where data is stored</label>
          <input id="tenant-region" value={form.data_residency_region} onChange={(event) => setForm({ ...form, data_residency_region: event.target.value })} placeholder="us-east-1" required />
          <label><input type="checkbox" checked={form.retention_enabled} onChange={(event) => setForm({ ...form, retention_enabled: event.target.checked })} /> Keep data for a set period</label>
          {form.retention_enabled && <>
            <label htmlFor="tenant-retention">Retention days</label>
            <input id="tenant-retention" type="number" min="1" value={form.retention_days} onChange={(event) => setForm({ ...form, retention_days: event.target.value })} required />
          </>}
          <label><input type="checkbox" checked={form.legal_hold_enabled} onChange={(event) => setForm({ ...form, legal_hold_enabled: event.target.checked })} /> Keep data for a legal matter</label>
          {form.legal_hold_enabled && <>
            <label htmlFor="tenant-legal-hold">Legal hold reason</label>
            <input id="tenant-legal-hold" value={form.legal_hold_reason} onChange={(event) => setForm({ ...form, legal_hold_reason: event.target.value })} required />
          </>}
          <button className="portal-primary-button" type="submit" disabled={busy}>{busy ? 'Saving…' : 'Save workspace settings'} <ArrowRight size={16} /></button>
        </form> : <dl className="portal-definition-list">
          <div><dt>Status</dt><dd>{config?.status || '—'}</dd></div>
          <div><dt>Default environment</dt><dd>{config?.default_environment || '—'}</dd></div>
          <div><dt>Data location</dt><dd>{config?.data_residency_region || '—'}</dd></div>
          <div><dt>Retention</dt><dd>{config?.retention_enabled ? `${config.retention_days} days` : 'Not configured'}</dd></div>
          <div><dt>Legal matter hold</dt><dd>{config?.legal_hold_enabled ? 'Enabled' : 'Not enabled'}</dd></div>
        </dl>}
      </section>
      <section className="portal-panel">
        <div className="portal-eyebrow">Products</div>
        <h2>Workspace products</h2>
        <p className="portal-overview-text">Choose the products available to this workspace. Disabling a product removes its navigation and API access but keeps its records and history.</p>
        {canManage ? <form className="portal-stack-form" onSubmit={saveProducts}>
          <fieldset className="portal-product-options">
            <legend className="portal-field-note">Enabled products</legend>
            {productOptions.map((product) => <label className="portal-product-option" key={product.id}>
              <input type="checkbox" checked={enabledProducts.includes(product.id)} disabled={busy || productsSaving || product.id === 'agent-guard'} onChange={(event) => { productsDirtyRef.current = true; setEnabledProducts((current) => event.target.checked ? [...new Set([...current, product.id])] : current.filter((item) => item !== product.id)) }} />
              <span><strong>{product.label}</strong><small>{product.description}</small></span>
            </label>)}
          </fieldset>
          <p className="portal-field-note">Agent Guard stays enabled because it is the required base control.</p>
          <button className="portal-primary-button" type="submit" disabled={busy || productsSaving}>{busy || productsSaving ? 'Saving products…' : 'Save product access'} <ArrowRight size={16} /></button>
        </form> : <dl className="portal-definition-list">{productOptions.map((product) => <div key={product.id}><dt>{product.label}</dt><dd>{enabledProducts.includes(product.id) ? 'Enabled' : 'Disabled'}</dd></div>)}</dl>}
      </section>
      <section className="portal-panel portal-panel-wide">
        <div className="portal-eyebrow">AI governance</div>
        <h2>AI model registry</h2>
        <p className="portal-overview-text">Record the models used by registered agents, including risk tier, provenance, and bias-test status.</p>
        <DataTable columns={[{ key: 'model_id', label: 'Model' }, { key: 'name', label: 'Name' }, { key: 'vendor', label: 'Vendor' }, { key: 'version', label: 'Version' }, { key: 'risk_tier', label: 'Risk tier' }, { key: 'supplier_name', label: 'Supplier', render: (row) => row.supplier_name || '—' }, { key: 'bias_tested', label: 'Bias tested', render: (row) => row.bias_tested ? 'Yes' : 'No' }, { key: 'bound_agent_count', label: 'Bound agents' }, { key: 'actions', label: 'Actions', render: (row) => <button className="portal-text-button" type="button" onClick={() => selectModel(row)}>View data resources</button> }]} rows={models} empty="No AI models registered" />
        {canManage && <form className="portal-stack-form portal-subform" onSubmit={saveModel}>
          <div className="portal-eyebrow">Register a model</div>
          <label htmlFor="model-id">Model ID</label>
          <input id="model-id" value={modelForm.model_id} onChange={(event) => setModelForm({ ...modelForm, model_id: event.target.value })} placeholder="invoice-model" required />
          <label htmlFor="model-name">Model name</label>
          <input id="model-name" value={modelForm.name} onChange={(event) => setModelForm({ ...modelForm, name: event.target.value })} placeholder="Invoice classifier" required />
          <label htmlFor="model-vendor">Vendor</label>
          <input id="model-vendor" value={modelForm.vendor} onChange={(event) => setModelForm({ ...modelForm, vendor: event.target.value })} placeholder="Kenning Labs" required />
          <label htmlFor="model-version">Version</label>
          <input id="model-version" value={modelForm.version} onChange={(event) => setModelForm({ ...modelForm, version: event.target.value })} placeholder="2026.1" required />
          <label htmlFor="model-risk-tier">Risk tier</label>
          <select id="model-risk-tier" value={modelForm.risk_tier} onChange={(event) => setModelForm({ ...modelForm, risk_tier: event.target.value })}><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option></select>
          <label><input type="checkbox" checked={modelForm.bias_tested} onChange={(event) => setModelForm({ ...modelForm, bias_tested: event.target.checked })} /> Bias testing completed</label>
          <label htmlFor="model-provenance">Training data provenance</label>
          <textarea id="model-provenance" value={modelForm.provenance} onChange={(event) => setModelForm({ ...modelForm, provenance: event.target.value })} placeholder="Describe the training data origin" />
          <label htmlFor="model-supplier">Supplier</label>
          <select id="model-supplier" value={modelForm.supplier_id} onChange={(event) => setModelForm({ ...modelForm, supplier_id: event.target.value })}><option value="">No supplier linked</option>{suppliers.map((supplier) => <option key={supplier.supplier_id} value={supplier.supplier_id}>{supplier.name} · {supplier.risk_rating}</option>)}</select>
          <button className="portal-primary-button" type="submit" disabled={busy}>{busy ? 'Registering…' : 'Register model'} <ArrowRight size={16} /></button>
        </form>}
        {selectedModel && <section className="portal-subform">
          <div className="portal-panel-heading"><div><div className="portal-eyebrow">Data governance</div><h3>{selectedModel.name} · {selectedModel.version}</h3></div><span className="portal-pill">{dataResources.length} resources</span></div>
          <DataTable columns={[{ key: 'name', label: 'Resource' }, { key: 'category', label: 'Category' }, { key: 'source', label: 'Source' }, { key: 'acquisition_date', label: 'Acquired' }, { key: 'created_at', label: 'Registered', render: (row) => formatDate(row.created_at) }]} rows={dataResources} empty="No data resources registered" />
          {canManage && <form className="portal-stack-form" onSubmit={saveDataResource}>
            <div className="portal-eyebrow">Register a data resource</div>
            <label htmlFor="data-resource-name">Name</label>
            <input id="data-resource-name" name="name" placeholder="Invoice training set" required />
            <label htmlFor="data-resource-source">Source</label>
            <input id="data-resource-source" name="source" placeholder="Approved customer samples" required />
            <label htmlFor="data-resource-category">Category</label>
            <select id="data-resource-category" name="category" defaultValue="training"><option value="training">Training</option><option value="validation">Validation</option><option value="test">Test</option><option value="production">Production</option></select>
            <label htmlFor="data-resource-acquisition-date">Acquisition date</label>
            <input id="data-resource-acquisition-date" name="acquisition_date" type="date" />
            <label htmlFor="data-resource-provenance">Provenance</label>
            <textarea id="data-resource-provenance" name="provenance" placeholder="Where the resource came from" />
            <label htmlFor="data-resource-preparation-notes">Preparation notes</label>
            <textarea id="data-resource-preparation-notes" name="preparation_notes" placeholder="Preparation, redaction, and quality checks" />
            <button className="portal-primary-button" type="submit" disabled={busy}>{busy ? 'Registering…' : 'Register data resource'} <Plus size={16} /></button>
          </form>}
        </section>}
      </section>
      <section className="portal-panel portal-panel-wide">
        <div className="portal-eyebrow">Third-party governance</div>
        <h2>Supplier registry</h2>
        <p className="portal-overview-text">Record suppliers that provide data, models, platforms, or integration services. Each supplier is scoped to this workspace.</p>
        <DataTable columns={[{ key: 'name', label: 'Supplier' }, { key: 'role', label: 'Role' }, { key: 'risk_rating', label: 'Risk' }, { key: 'bound_model_count', label: 'Bound models' }]} rows={suppliers} empty="No suppliers registered" />
        {canManage && <form className="portal-stack-form portal-subform" onSubmit={saveSupplier}>
          <div className="portal-eyebrow">Register a supplier</div>
          <label htmlFor="supplier-name">Name</label>
          <input id="supplier-name" value={supplierForm.name} onChange={(event) => setSupplierForm({ ...supplierForm, name: event.target.value })} placeholder="Trusted Data Co" required />
          <label htmlFor="supplier-role">Role</label>
          <select id="supplier-role" value={supplierForm.role} onChange={(event) => setSupplierForm({ ...supplierForm, role: event.target.value })}><option value="data_provider">Data provider</option><option value="model_provider">Model provider</option><option value="platform_provider">Platform provider</option><option value="integrator">Integrator</option></select>
          <label htmlFor="supplier-risk-rating">Risk rating</label>
          <select id="supplier-risk-rating" value={supplierForm.risk_rating} onChange={(event) => setSupplierForm({ ...supplierForm, risk_rating: event.target.value })}><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option></select>
          <button className="portal-primary-button" type="submit" disabled={busy}>{busy ? 'Registering…' : 'Register supplier'} <Plus size={16} /></button>
        </form>}
      </section>
      <section className="portal-panel portal-panel-wide">
        <div className="portal-eyebrow">Corrective action</div>
        <h2>Nonconformities</h2>
        <p className="portal-overview-text">Track findings, corrective actions, and concerns in the tenant audit history.</p>
        <DataTable columns={[{ key: 'title', label: 'Finding' }, { key: 'severity', label: 'Severity' }, { key: 'status', label: 'Status', render: (row) => <span className={`portal-pill ${row.status === 'resolved' ? 'success' : 'danger'}`}>{row.status}</span> }, { key: 'created_at', label: 'Raised', render: (row) => formatDate(row.created_at) }, { key: 'actions', label: 'Actions', render: (row) => row.status === 'open' && canManage ? <button className="portal-text-button" type="button" onClick={() => resolveNonconformity(row)}>Resolve</button> : '—' }]} rows={nonconformities} empty="No nonconformities recorded" />
        {canManage && <form className="portal-stack-form portal-subform" onSubmit={saveNonconformity}>
          <div className="portal-eyebrow">Raise a finding</div>
          <label htmlFor="nonconformity-title">Title</label>
          <input id="nonconformity-title" value={nonconformityForm.title} onChange={(event) => setNonconformityForm({ ...nonconformityForm, title: event.target.value })} placeholder="Missing supplier evidence" required />
          <label htmlFor="nonconformity-description">Description</label>
          <textarea id="nonconformity-description" value={nonconformityForm.description} onChange={(event) => setNonconformityForm({ ...nonconformityForm, description: event.target.value })} placeholder="Describe the finding and its impact" required />
          <label htmlFor="nonconformity-severity">Severity</label>
          <select id="nonconformity-severity" value={nonconformityForm.severity} onChange={(event) => setNonconformityForm({ ...nonconformityForm, severity: event.target.value })}><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option></select>
          <label htmlFor="nonconformity-source-event">Source event ID <span className="portal-field-note">(optional)</span></label>
          <input id="nonconformity-source-event" value={nonconformityForm.source_event_id} onChange={(event) => setNonconformityForm({ ...nonconformityForm, source_event_id: event.target.value })} placeholder="evt-..." />
          <button className="portal-primary-button" type="submit" disabled={busy}>{busy ? 'Recording…' : 'Raise nonconformity'} <Plus size={16} /></button>
        </form>}
      </section>
      <section className="portal-panel">
        <div className="portal-eyebrow">Speak up</div>
        <h2>Report a concern</h2>
        <p className="portal-overview-text">Report a concern to the workspace audit history. You can submit it without attaching your identity.</p>
        <form className="portal-stack-form" onSubmit={reportConcern}>
          <label htmlFor="concern-description">Concern</label>
          <textarea id="concern-description" value={concernForm.description} onChange={(event) => setConcernForm({ ...concernForm, description: event.target.value })} placeholder="Describe the concern" required />
          <label><input type="checkbox" checked={concernForm.anonymous} onChange={(event) => setConcernForm({ ...concernForm, anonymous: event.target.checked })} /> Submit anonymously</label>
          <button className="portal-primary-button" type="submit" disabled={busy}>{busy ? 'Submitting…' : 'Submit concern'} <ArrowRight size={16} /></button>
        </form>
      </section>
      <section className="portal-panel">
        <div className="portal-eyebrow">Environment limits</div>
        <h2>Environments</h2>
        <DataTable columns={[{ key: 'environment_id', label: 'Environment' }, { key: 'mode', label: 'Mode' }, { key: 'status', label: 'Status' }, { key: 'allowed_tools', label: 'Allowed tools', render: (row) => row.allowed_tools?.join(', ') || 'All configured' }]} rows={environments} empty="No environment limits set" />
        {canManage && <form className="portal-stack-form portal-subform" onSubmit={saveEnvironment}>
          <div className="portal-eyebrow">Add or update</div>
          <label htmlFor="environment-id">Environment ID</label>
          <input id="environment-id" value={environment.environment_id} onChange={(event) => setEnvironment({ ...environment, environment_id: event.target.value })} placeholder="production" required />
          <label htmlFor="environment-name">Name</label>
          <input id="environment-name" value={environment.name} onChange={(event) => setEnvironment({ ...environment, name: event.target.value })} placeholder="Production" />
          <label htmlFor="environment-mode">Mode</label>
          <select id="environment-mode" value={environment.mode} onChange={(event) => setEnvironment({ ...environment, mode: event.target.value })}><option value="enforce">Enforce</option><option value="observe">Observe</option></select>
          <label htmlFor="environment-tools">Allowed tools</label>
          <input id="environment-tools" value={environment.allowed_tools} onChange={(event) => setEnvironment({ ...environment, allowed_tools: event.target.value })} placeholder="shell, sql" />
          <button className="portal-primary-button" type="submit" disabled={busy}>{busy ? 'Saving…' : 'Save environment'} <Plus size={16} /></button>
        </form>}
      </section>
      <section className="portal-panel portal-panel-wide">
        <div className="portal-eyebrow">Governance</div>
        <h2>Management reviews</h2>
        <p className="portal-overview-text">Record the decisions and actions from a management review. The review includes activity metrics from this workspace and remains in the audit history.</p>
        {canManage && <form className="portal-stack-form portal-subform" onSubmit={saveManagementReview}>
          <div className="portal-eyebrow">Record a review</div>
          <label htmlFor="management-review-period-start">Period start</label>
          <input id="management-review-period-start" type="date" value={reviewForm.period_start} onChange={(event) => setReviewForm({ ...reviewForm, period_start: event.target.value })} required />
          <label htmlFor="management-review-period-end">Period end</label>
          <input id="management-review-period-end" type="date" value={reviewForm.period_end} onChange={(event) => setReviewForm({ ...reviewForm, period_end: event.target.value })} required />
          <label htmlFor="management-review-attendees">Attendees</label>
          <textarea id="management-review-attendees" value={reviewForm.attendees} onChange={(event) => setReviewForm({ ...reviewForm, attendees: event.target.value })} placeholder="Names or roles" />
          <label htmlFor="management-review-decisions">Decisions</label>
          <textarea id="management-review-decisions" value={reviewForm.decisions} onChange={(event) => setReviewForm({ ...reviewForm, decisions: event.target.value })} placeholder="Decisions made in the review" />
          <label htmlFor="management-review-action-items">Action items</label>
          <textarea id="management-review-action-items" value={reviewForm.action_items} onChange={(event) => setReviewForm({ ...reviewForm, action_items: event.target.value })} placeholder="Actions, owners, and due dates" />
          <button className="portal-primary-button" type="submit" disabled={busy}>{busy ? 'Recording…' : 'Record management review'} <ArrowRight size={16} /></button>
        </form>}
        <div className="portal-eyebrow portal-subform">Review history</div>
        <DataTable
          columns={[
            { key: 'period', label: 'Period', render: (row) => `${row.period_start} – ${row.period_end}` },
            { key: 'created_at', label: 'Recorded', render: (row) => formatDate(row.created_at) },
            { key: 'attendees', label: 'Attendees', render: (row) => row.attendees || '—' },
            { key: 'decisions', label: 'Decisions', render: (row) => row.decisions || '—' },
            { key: 'action_items', label: 'Action items', render: (row) => row.action_items || '—' },
            { key: 'metrics', label: 'Metrics', render: (row) => {
              const metrics = row.metrics || {}
              return `${metrics.total_actions || 0} actions · ${metrics.approvals_required || 0} approvals · ${metrics.denials || 0} denials · ${metrics.policies_changed || 0} policy changes`
            } },
          ]}
          rows={managementReviews}
          empty="No management reviews recorded"
        />
      </section>
    </div>
    <CaptureAuditSettings config={config} canManage={canManage} />
  </>
}

export default SettingsView
