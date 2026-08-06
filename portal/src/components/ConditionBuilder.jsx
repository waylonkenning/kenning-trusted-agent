import React from 'react'
import { Plus } from '@phosphor-icons/react'
import { CONDITION_FIELDS, OPERATOR_LABEL, conditionFieldDef } from '../lib.js'

function ConditionBuilder({ rows, onChange }) {
  function updateRow(index, patch) {
    onChange(rows.map((row, i) => {
      if (i !== index) return row
      const next = { ...row, ...patch }
      if (patch.field) {
        const def = conditionFieldDef(patch.field)
        next.operator = OPERATOR_LABEL[def?.type] || 'matches pattern'
        if (def?.type === 'boolean' && (next.value === '' || next.value == null)) next.value = 'true'
      }
      return next
    }))
  }
  return <div className="portal-condition-builder">
    {rows.length === 0 && <p className="portal-field-note">No conditions yet. This rule will match every action. Add a condition to narrow when it applies.</p>}
    {rows.map((row, index) => {
      const def = conditionFieldDef(row.field)
      const type = def?.type || 'glob'
      return <div className="portal-condition-row" key={index}>
        <select aria-label="Condition field" value={row.field} onChange={(event) => updateRow(index, { field: event.target.value })}>
          <option value="">Select a field…</option>
          {CONDITION_FIELDS.map((field) => <option key={field.key} value={field.key}>{field.label}</option>)}
        </select>
        <span className="portal-condition-operator" aria-hidden="true">{row.operator || OPERATOR_LABEL[type]}</span>
        {type === 'boolean'
          ? <select aria-label="Condition value" value={String(row.value)} onChange={(event) => updateRow(index, { value: event.target.value })}><option value="true">true</option><option value="false">false</option></select>
          : <input aria-label="Condition value" type={type === 'number' ? 'number' : type === 'time' ? 'datetime-local' : 'text'} value={row.value} placeholder={def?.hint || 'Value'} onChange={(event) => updateRow(index, { value: event.target.value })} />}
        <button className="portal-text-button" type="button" aria-label="Remove condition" onClick={() => onChange(rows.filter((_, i) => i !== index))}>Remove</button>
        {def?.hint && type === 'glob' && <small className="portal-condition-hint">{def.hint}</small>}
      </div>
    })}
    <button className="portal-secondary-button" type="button" onClick={() => onChange([...rows, { field: 'tool', operator: OPERATOR_LABEL.glob, value: '' }])}><Plus size={14} /> Add condition</button>
  </div>
}


function ChainBuilder({ steps, onChange }) {
  function updateStep(index, patch) {
    onChange(steps.map((step, i) => i === index ? { ...step, ...patch } : step))
  }
  return <div className="portal-chain-builder">
    {steps.length === 0 && <p className="portal-field-note">No approval chain. A single reviewer with the right permissions can approve this action. Add steps to require sequential sign-off (e.g. peer then manager).</p>}
    {steps.map((step, index) => <div className="portal-chain-step-editor" key={index}>
      <div className="portal-chain-step-heading"><strong>Step {index + 1}</strong>{steps.length > 0 && <button className="portal-text-button" type="button" onClick={() => onChange(steps.filter((_, i) => i !== index))}>Remove step</button>}</div>
      <input aria-label="Step label" value={step.label || ''} placeholder={`Step ${index + 1} label (e.g. Peer review)`} onChange={(event) => updateStep(index, { label: event.target.value })} />
      <input aria-label="Approver groups" value={step.approver_groups || ''} placeholder="Approver groups (comma-separated, blank = any approver)" onChange={(event) => updateStep(index, { approver_groups: event.target.value })} />
      <label className="portal-checkbox-label"><input type="checkbox" checked={step.separation_of_duties !== false} onChange={(event) => updateStep(index, { separation_of_duties: event.target.checked })} /> Require a different person for this step</label>
    </div>)}
    <button className="portal-secondary-button" type="button" onClick={() => onChange([...steps, { label: `Step ${steps.length + 1}`, approver_groups: '', separation_of_duties: true }])}><Plus size={14} /> Add approval step</button>
  </div>
}


export { ConditionBuilder, ChainBuilder }
