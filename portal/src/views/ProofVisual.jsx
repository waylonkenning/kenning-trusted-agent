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

function ProofVisual({ proof }) {
  const record = proof.record || {}
  const verification = proof.verification || {}
  const action = record.action || {}
  const agent = record.agent || {}
  const receipt = record.trusted_action_receipt || null
  const factors = record.decision_factors || []
  const evidence = record.evidence || []
  const gaps = record.evidence_gaps || []
  const limitations = record.limitations || []
  const recommendation = record.recommendation
  const [showRaw, setShowRaw] = useState(false)

  const actionParams = action.parameters || {}
  const actionDetail = actionParams.command || actionParams.statement || actionParams.path || actionParams.url || actionParams.query || ''
  const actionSummary = [action.tool, action.operation].filter(Boolean).join(' · ') || 'Action'
  const invokedBy = action.invoked_by || record.request?.summary || 'Not recorded'
  const environment = action.environment || record.policy_evaluations?.[0]?.identity?.environment || 'Not recorded'

  const evidenceById = {}
  evidence.forEach((item) => { evidenceById[item.evidence_id] = item })

  const statusTone = record.evidence_status === 'verified' ? 'success' : record.evidence_status === 'incomplete' ? 'warning' : ''

  return <section className="portal-panel portal-panel-wide portal-proof-visual">
    <div className="portal-panel-heading">
      <div><div className="portal-eyebrow">Proof record</div><h2>{record.proof_id || 'Unknown proof'}</h2>
        <p className="portal-field-note">{formatDate(record.created_at)} · {record.proof_uri || ''}</p></div>
      <div className="portal-proof-badges">
        <span className={`portal-pill ${verification.valid ? 'success' : 'danger'}`}>{verification.valid ? 'Record unchanged' : 'Record changed'}</span>
        <span className={`portal-pill ${statusTone}`}>{record.evidence_status || 'not provided'}</span>
        {receipt && <span className="portal-pill info">Signed receipt</span>}
      </div>
    </div>

    <div className="portal-proof-section">
      <div className="portal-eyebrow">What happened</div>
      <div className="portal-proof-action-card">
        <div className="portal-proof-action-summary">
          <strong>{actionSummary}</strong>
          {actionDetail && <code className="portal-proof-action-detail">{String(actionDetail).slice(0, 200)}{String(actionDetail).length > 200 ? '…' : ''}</code>}
        </div>
        <dl className="portal-definition-list">
          <div><dt>Agent</dt><dd>{agent.agent_id || action.agent_id || 'Not recorded'}</dd></div>
          <div><dt>Invoked by</dt><dd>{invokedBy}</dd></div>
          <div><dt>Environment</dt><dd>{environment}</dd></div>
          <div><dt>Action ID</dt><dd>{record.action_id || 'Not recorded'}</dd></div>
        </dl>
        {record.inputs_hash && <p className="portal-field-note">Action hash: <code>{record.inputs_hash}</code></p>}
      </div>
    </div>

    {(factors.length > 0 || recommendation) && <div className="portal-proof-section">
      <div className="portal-eyebrow">Why this action was taken</div>
      {recommendation && <p className="portal-proof-recommendation">{typeof recommendation === 'string' ? recommendation : (recommendation.summary || recommendation.text || JSON.stringify(recommendation))}</p>}
      {factors.length > 0 && <div className="portal-starter-rule-list">{factors.map((factor, i) => {
        const refs = factor.evidence_refs || factor.evidence_ids || []
        return <article className="portal-starter-rule" key={i}>
          <div className="portal-starter-rule-heading">
            <div><strong>{factor.factor || factor.name || `Factor ${i + 1}`}</strong>
              {factor.weight != null && <small>Weight: {factor.weight}</small>}</div>
            {factor.role && <span className="portal-pill">{factor.role}</span>}
          </div>
          {factor.description && <p className="portal-field-note">{factor.description}</p>}
          {refs.length > 0 && <p className="portal-field-note">Supported by: {refs.map((ref) => evidenceById[ref]?.claim || ref).join('; ')}</p>}
        </article>
      })}</div>}
    </div>}

    {(evidence.length > 0 || gaps.length > 0) && <div className="portal-proof-section">
      <div className="portal-eyebrow">Evidence</div>
      {evidence.length > 0 && <div className="portal-starter-rule-list">{evidence.map((item) => <article className="portal-starter-rule" key={item.evidence_id}>
        <div className="portal-starter-rule-heading">
          <div><strong>{item.claim || item.evidence_id}</strong><small>{item.evidence_id}</small></div>
          <span className={`portal-pill ${item.status === 'verified' ? 'success' : item.status === 'failed' ? 'danger' : ''}`}>{item.status || 'recorded'}</span>
        </div>
        {item.source && <p className="portal-field-note">Source: {item.source}</p>}
        {item.type && <p className="portal-field-note">Type: {item.type}</p>}
      </article>)}</div>}
      {gaps.length > 0 && <div className="portal-notice portal-notice-warning" role="status">
        <WarningCircle size={18} weight="bold" />
        <span>Evidence gaps: {gaps.map((gap) => typeof gap === 'string' ? gap : (gap.description || gap.factor || JSON.stringify(gap))).join('; ')}</span>
      </div>}
    </div>}

    {limitations.length > 0 && <div className="portal-proof-section">
      <div className="portal-eyebrow">Limitations</div>
      <ul className="portal-proof-limitations">{limitations.map((item, i) => <li key={i}>{typeof item === 'string' ? item : JSON.stringify(item)}</li>)}</ul>
    </div>}

    <div className="portal-proof-section">
      <div className="portal-eyebrow">Integrity and trust</div>
      <dl className="portal-definition-list">
        <div><dt>Verification</dt><dd>{verification.valid ? 'Record hash matches — unchanged since creation' : 'Record hash mismatch — may have been modified'}</dd></div>
        {verification.inputs_hash && <div><dt>Inputs hash</dt><dd><code>{verification.inputs_hash}</code></dd></div>}
        {verification.record_hash && <div><dt>Record hash</dt><dd><code>{verification.record_hash}</code></dd></div>}
        {receipt && <><div><dt>Receipt ID</dt><dd>{receipt.receipt_id || 'Not recorded'}</dd></div>
          <div><dt>Signing key</dt><dd>{receipt.signing_key_id || 'Not recorded'}</dd></div>
          <div><dt>Algorithm</dt><dd>{receipt.algorithm || 'Not recorded'}</dd></div>
          {receipt.signed_at && <div><dt>Signed at</dt><dd>{formatDate(receipt.signed_at)}</dd></div>}</>}
      </dl>
    </div>

    <div className="portal-proof-section">
      <button className="portal-text-button" type="button" onClick={() => setShowRaw(!showRaw)}>{showRaw ? 'Hide raw record' : 'Show raw record'}</button>
      {showRaw && <pre className="portal-proof-json">{JSON.stringify(record, null, 2)}</pre>}
    </div>
  </section>
}


export default ProofVisual
