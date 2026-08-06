import React, { useContext, useState, useRef, useEffect } from 'react'
import { PortalContext } from '../PortalContext.jsx'
import { ErrorNotice } from '../components/ui.jsx'
import { ArrowRight } from '@phosphor-icons/react'
import { splitValues } from '../lib.js'
import { useApiMutation } from '../hooks.js'

function auditFormFromConfig(config) {
  const capture = config.capture_policy || {}
  const sink = config.audit_sink || {}
  return {
    store_original_action: capture.store_original_action !== false,
    redact_fields: (capture.redact_fields || []).join(', '),
    hash_fields: (capture.hash_fields || []).join(', '),
    max_field_length: capture.max_field_length || 4096,
    audit_enabled: Boolean(sink.enabled),
    audit_endpoint_url: sink.endpoint_url || '',
    audit_secret_arn: sink.secret_arn || '',
    audit_format: sink.format || 'json',
    audit_timeout_ms: sink.timeout_ms || 1000,
  }
}

function CaptureAuditSettings({ config, canManage }) {
  const { tenantId, load } = useContext(PortalContext)
  const [form, setForm] = useState({
    store_original_action: true,
    redact_fields: '',
    hash_fields: '',
    max_field_length: 4096,
    audit_enabled: false,
    audit_endpoint_url: '',
    audit_secret_arn: '',
    audit_format: 'json',
    audit_timeout_ms: 1000,
  })
  const [mutate, { busy, error }] = useApiMutation()
  const formDirtyRef = useRef(false)
  const latestConfigVersionRef = useRef(0)

  useEffect(() => {
    if (!config) return
    const configVersion = Number(config.config_version) || 0
    if (configVersion < latestConfigVersionRef.current) return
    latestConfigVersionRef.current = configVersion
    if (!formDirtyRef.current) setForm(auditFormFromConfig(config))
  }, [config])

  if (!canManage) return <section className="portal-panel"><div className="portal-eyebrow">Evidence controls</div><h2>Capture and audit delivery</h2><dl className="portal-definition-list"><div><dt>Original action</dt><dd>{config?.capture_policy?.store_original_action === false ? 'Not retained' : 'Retained'}</dd></div><div><dt>Redaction fields</dt><dd>{config?.capture_policy?.redact_fields?.join(', ') || 'None configured'}</dd></div><div><dt>Destination system</dt><dd>{config?.audit_sink?.enabled ? config.audit_sink.endpoint_url : 'Disabled'}</dd></div></dl></section>

  async function save(event) {
    event.preventDefault()
    try {
      const updated = await mutate(`/v1/tenants/${encodeURIComponent(tenantId)}`, {
        method: 'PUT',
        body: JSON.stringify({
          capture_policy: {
            store_original_action: form.store_original_action,
            redact_fields: splitValues(form.redact_fields),
            hash_fields: splitValues(form.hash_fields),
            max_field_length: Number(form.max_field_length),
          },
          audit_sink: {
            enabled: form.audit_enabled,
            endpoint_url: form.audit_endpoint_url,
            secret_arn: form.audit_secret_arn,
            format: form.audit_format,
            timeout_ms: Number(form.audit_timeout_ms),
          },
        }),
      }, { reload: false })
      latestConfigVersionRef.current = Math.max(latestConfigVersionRef.current, Number(updated.config_version) || 0)
      formDirtyRef.current = false
      setForm(auditFormFromConfig(updated))
      await load()
    } catch { /* error handled by hook */ }
  }

  return <section className="portal-panel portal-panel-wide"><div className="portal-eyebrow">Evidence controls</div><h2>Capture and audit delivery</h2><p className="portal-field-note">These controls determine what is saved in Proof and whether audit events that cannot be edited are sent to your security monitoring system. Credentials are referenced through AWS Secrets Manager.</p><form className="portal-stack-form" onChange={() => { formDirtyRef.current = true }} onSubmit={save}><label><input type="checkbox" checked={form.store_original_action} onChange={(event) => setForm({ ...form, store_original_action: event.target.checked })} /> Retain original actions</label><label htmlFor="capture-redact">Redact fields</label><input id="capture-redact" value={form.redact_fields} onChange={(event) => setForm({ ...form, redact_fields: event.target.value })} placeholder="credentials, parameters.secret" /><label htmlFor="capture-hash">Hash fields</label><input id="capture-hash" value={form.hash_fields} onChange={(event) => setForm({ ...form, hash_fields: event.target.value })} placeholder="parameters.statement" /><label htmlFor="capture-limit">Maximum captured field length</label><input id="capture-limit" type="number" min="64" max="16384" value={form.max_field_length} onChange={(event) => setForm({ ...form, max_field_length: event.target.value })} required /><label><input type="checkbox" checked={form.audit_enabled} onChange={(event) => setForm({ ...form, audit_enabled: event.target.checked })} /> Deliver audit events to a destination system</label>{form.audit_enabled && <><label htmlFor="audit-endpoint">HTTPS endpoint</label><input id="audit-endpoint" type="url" value={form.audit_endpoint_url} onChange={(event) => setForm({ ...form, audit_endpoint_url: event.target.value })} placeholder="https://siem.example.org/kenning" required /><label htmlFor="audit-secret">AWS Secrets Manager reference</label><input id="audit-secret" value={form.audit_secret_arn} onChange={(event) => setForm({ ...form, audit_secret_arn: event.target.value })} placeholder="arn:aws:secretsmanager:…" required /><label htmlFor="audit-format">Format</label><select id="audit-format" value={form.audit_format} onChange={(event) => setForm({ ...form, audit_format: event.target.value })}><option value="json">JSON</option><option value="ndjson">NDJSON</option></select><label htmlFor="audit-timeout">Delivery timeout (milliseconds)</label><input id="audit-timeout" type="number" min="250" max="2000" value={form.audit_timeout_ms} onChange={(event) => setForm({ ...form, audit_timeout_ms: event.target.value })} required /></>}<button className="portal-primary-button" type="submit" disabled={busy}>{busy ? 'Saving…' : 'Save evidence controls'} <ArrowRight size={16} /></button></form><ErrorNotice error={error} /></section>
}

export default CaptureAuditSettings
