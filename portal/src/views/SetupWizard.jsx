import React, { useContext, useState, useRef, useEffect } from 'react'
import { PortalContext } from '../PortalContext.jsx'
import { LoadingBlock, ErrorNotice, EmptyState, Stat, PageHeading, DataTable, CopyButton } from '../components/ui.jsx'
import { ConditionBuilder, ChainBuilder } from '../components/ConditionBuilder.jsx'
import ConfirmDialog from '../components/ConfirmDialog.jsx'
import {
  ArrowRight, ArrowsClockwise, ChartLineUp, CheckCircle, ClipboardText, Code,
  Eye, FileText, GearSix, Info, Key, LockKey, MagnifyingGlass, PencilSimple,
  PlugsConnected, Plus, ShieldCheck, SignOut, Trash, Upload, WarningCircle, X, XCircle,
} from '@phosphor-icons/react'
import { API_BASE } from '../lib.js'
import { useApiMutation } from '../hooks.js'
import { PortalMark } from '../components/ui.jsx'

function SetupWizard({ workspaceName, subject, onClose }) {
  const { tenantId } = useContext(PortalContext)
  const [step, setStep] = useState(0)
  const [enrollmentPat, setEnrollmentPat] = useState(null)
  const [patBusy, setPatBusy] = useState(false)
  const [mutate, { error: patError, setError }] = useApiMutation()
  const apiBase = API_BASE || window.location.origin
  const mcpEndpoint = `${apiBase}/mcp`
  const installerUrl = `${window.location.origin}/install/agent-guard/install.sh`
  const clients = [
    { id: 'opencode', label: 'OpenCode' },
    { id: 'claude-code', label: 'Claude Code' },
    { id: 'codex-cli', label: 'Codex CLI' },
  ]
  const patPlaceholder = enrollmentPat || '<YOUR_TENANT_SCOPED_PAT>'
  const installCommands = clients.map((item) => ({ ...item, command: `export KENNING_API_URL="${apiBase}"
export KENNING_PAT="${patPlaceholder}"
export KENNING_TENANT_ID="${tenantId}"
curl -fsSL ${installerUrl} | bash -s -- --client ${item.id}` }))
  const mcpConfig = `{\n  "mcpServers": {\n    "kenning": {\n      "url": "${mcpEndpoint}",\n      "headers": { "Authorization": "Bearer ${patPlaceholder}" }\n    }\n  }\n}`
  const agentInstructions = `# Kenning Agent Guard
Before executing a tool call, send the proposed action to Kenning Agent Guard.
Use the connection configured by the Kenning installer. Do not print or commit credentials.
If the response is require_approval or deny, stop and show the decision to the responsible person.`
  const steps = ['Welcome', 'Agent Guard', 'Connect']

  async function createEnrollmentPat() {
    setPatBusy(true)
    try {
      const result = await mutate('/v1/tokens', { method: 'POST', body: JSON.stringify({ name: `agent-guard-enrollment-${tenantId}`, scopes: ['guard:evaluate', 'mcp:read'], expires_in_days: 90 }) }, { reload: false })
      const token = result && typeof result === 'object' && !Array.isArray(result) ? result.token : null
      if (typeof token !== 'string' || !token.startsWith('kta_pat_')) {
        throw new Error('Kenning did not return a usable workspace credential. Please try again. If the problem continues, contact your workspace administrator.')
      }
      setEnrollmentPat(token)
    } catch (caught) { setError(caught) } finally { setPatBusy(false) }
  }

  function finish(value) {
    try { window.localStorage.setItem(`kenning.setup-wizard.${subject}.${tenantId}`, value) } catch { /* storage can be unavailable */ }
    onClose()
  }

  return (
    <div className="portal-wizard-overlay">
      <div className="portal-auth-card portal-wizard-card">
        <div className="portal-wizard-steps">
          {steps.map((label, i) => (
            <div key={label} className={`portal-wizard-step${i === step ? ' portal-wizard-step-active' : ''}${i < step ? ' portal-wizard-step-done' : ''}`}>
              <span className="portal-wizard-step-dot">{i < step ? <CheckCircle size={13} weight="fill" /> : i + 1}</span>
              <span>{label}</span>
            </div>
          ))}
        </div>
        {step === 0 && <>
          <PortalMark />
          <div className="portal-eyebrow">Workspace setup</div>
          <h1>Welcome to {workspaceName}.</h1>
          <p className="portal-auth-lede">Kenning keeps your AI agents safe and their work verifiable. Want a quick setup to get the most out of it? It takes about a minute.</p>
          <button className="portal-primary-button portal-button-wide" type="button" onClick={() => setStep(1)}>Yes, show me around <ArrowRight size={16} /></button>
          <button className="portal-text-link portal-wizard-skip" type="button" onClick={() => finish('dismissed')}>Skip for now</button>
        </>}
        {step === 1 && <>
          <div className="portal-wizard-icon"><ShieldCheck size={38} weight="fill" /></div>
          <div className="portal-eyebrow">Agent Guard</div>
          <h1>Protect your AI agent from dangerous calls.</h1>
          <p className="portal-auth-lede">Agent Guard checks every action your agent wants to run — shell commands, file writes, cloud changes — against your workspace policy before it runs. Dangerous calls are blocked or routed to you for approval.</p>
          <button className="portal-primary-button portal-button-wide" type="button" onClick={() => setStep(2)}>Yes, protect my agent <ArrowRight size={16} /></button>
          <button className="portal-text-link portal-wizard-skip" type="button" onClick={() => finish('dismissed')}>Not now</button>
        </>}
        {step === 2 && <>
          <div className="portal-wizard-icon"><PlugsConnected size={38} weight="fill" /></div>
          <div className="portal-eyebrow">Connect your agent</div>
          <h1>Connect your AI agent.</h1>
          <p className="portal-auth-lede">Create the workspace credential once, then choose the connection method that fits your coding agent. The PAT is held only in this page session and is never written to browser storage.</p>
          <div className="portal-wizard-section">
            <div className="portal-wizard-header"><span>Workspace credential</span>{enrollmentPat && <span className="portal-pill success">Created</span>}</div>
            {!enrollmentPat ? <>
              <p className="portal-field-note">This creates a 90-day PAT limited to <code>guard:evaluate</code> and <code>mcp:read</code>. Copy it when it appears; it cannot be retrieved again.</p>
              <button className="portal-primary-button" type="button" onClick={createEnrollmentPat} disabled={patBusy}>{patBusy ? 'Creating PAT…' : 'Create scoped PAT'} <Key size={16} /></button>
            </> : <>
              <div className="portal-overview-base"><span className="portal-overview-label">Personal access token</span><code>{enrollmentPat}</code><CopyButton text={enrollmentPat} label="Copy personal access token" /></div>
              <p className="portal-field-note" role="status">Copy this token now. For security, the full value is shown only during this setup session.</p>
            </>}
            {patError && <ErrorNotice error={patError} />}
          </div>
          <div className="portal-eyebrow">Supported installers</div>
          {installCommands.map((item) => <div className="portal-overview-snippet" key={item.id}>
            <div className="portal-overview-snippet-header"><span>{item.label}</span><CopyButton text={item.command} label={`Copy ${item.label} installer command`} /></div>
            <pre>{item.command}</pre>
          </div>)}
          <p className="portal-field-note">{enrollmentPat ? 'The commands above include the one-time token. Copy one and run it in your terminal.' : <>Create the scoped PAT above first; the commands will then include it.</>}</p>
          <p className="portal-field-note">For Codex CLI and Codex Desktop, the installer stores the connection in `.codex/kenning-guard-credentials.json` with mode `600`. It does not write the PAT to Codex TOML or require the shell variable after installation.</p>
          <div className="portal-eyebrow">MCP server (manual)</div>
          <div className="portal-overview-base"><span className="portal-overview-label">MCP endpoint</span><code>{mcpEndpoint}</code><CopyButton text={mcpEndpoint} label="Copy MCP endpoint" /></div>
          <div className="portal-overview-snippet">
            <div className="portal-overview-snippet-header"><span>Configuration</span><CopyButton text={mcpConfig} label="Copy MCP configuration" /></div>
            <pre>{mcpConfig}</pre>
          </div>
          <div className="portal-overview-snippet">
            <div className="portal-overview-snippet-header"><span>AGENTS.md instructions</span><CopyButton text={agentInstructions} label="Copy AGENTS.md instructions" /></div>
            <pre>{agentInstructions}</pre>
          </div>
          <details className="portal-wizard-section">
            <summary>Advanced / API details</summary>
            <p className="portal-field-note">Use the evaluate endpoint directly when you are integrating a custom client or need the full request/response contract.</p>
            <div className="portal-overview-base"><span className="portal-overview-label">Endpoint</span><code>{apiBase}/v1/actions/evaluate</code><CopyButton text={`${apiBase}/v1/actions/evaluate`} label="Copy evaluate endpoint" /></div>
            <p className="portal-field-note">Send <code>Authorization: Bearer &lt;PAT&gt;</code> and <code>X-Kenning-Tenant-Id: {tenantId}</code>. See the <a href="/openapi.json">OpenAPI contract</a> for schemas and error codes.</p>
          </details>
          <button className="portal-primary-button portal-button-wide" type="button" onClick={() => finish('done')}>Finish setup <CheckCircle size={16} /></button>
        </>}
      </div>
    </div>
  )
}


export default SetupWizard
