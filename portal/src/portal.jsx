import React, { useContext, useEffect, useMemo, useRef, useState } from 'react'
import { PortalContext } from './PortalContext.jsx'
import { request, apiUrl, DEPLOYMENT_ENVIRONMENT } from './lib.js'
import { useApiQuery } from './hooks.js'
import { LoadingBlock, ErrorNotice, PortalMark } from './components/ui.jsx'
import ReleaseMarker from './components/ReleaseMarker.jsx'
import SignIn from './auth/SignIn.jsx'
import EnvironmentBanner from './views/EnvironmentBanner.jsx'
import ProductOverview from './views/ProductOverview.jsx'
import Overview from './views/Overview.jsx'
import AgentsView from './views/AgentsView.jsx'
import PoliciesView from './views/PoliciesView.jsx'
import StarterRulesView from './views/StarterRulesView.jsx'
import RulesView from './views/RulesView.jsx'
import ApprovalsView from './views/ApprovalsView.jsx'
import MembersView from './views/MembersView.jsx'
import TokensView from './views/TokensView.jsx'
import PlatformSupportView from './views/PlatformSupportView.jsx'
import AuditView from './views/AuditView.jsx'
import CitationTrustView from './views/CitationTrustView.jsx'
import SettingsView from './views/SettingsView.jsx'
import UserGuideView from './views/UserGuideView.jsx'
import SetupWizard from './views/SetupWizard.jsx'
import './tokens.css'
import './portal.css'
import {
  ArrowRight,
  BookOpenText,
  ChartLineUp,
  CheckCircle,
  ClipboardText,
  Gear,
  Info,
  Key,
  ListChecks,
  LockKey,
  PlugsConnected,
  Quotes,
  ShieldCheck,
  SignOut,
  UsersThree,
} from '@phosphor-icons/react'

const NAV_SECTIONS = [
  {
    id: 'command-center',
    label: 'Overview',
    items: [{ id: 'overview', label: 'Overview', icon: ChartLineUp }],
  },
  {
    id: 'agent-identity',
    label: 'Agent Identity',
    productId: 'agent-identity',
    items: [
      { id: 'identity-overview', label: 'Connection details', icon: Info },
      { id: 'agents', label: 'Agents and connections', icon: PlugsConnected },
    ],
  },
  {
    id: 'agent-guard',
    label: 'Agent Guard',
    productId: 'agent-guard',
    items: [
      { id: 'guard-overview', label: 'Connection details', icon: Info },
      { id: 'rules', label: 'Rules', icon: ListChecks },
      { id: 'approvals', label: 'Approvals', icon: CheckCircle },
      { id: 'access', label: 'Access tokens', icon: Key },
    ],
  },
  {
    id: 'agent-proof',
    label: 'Agent Proof',
    productId: 'agent-proof',
    items: [
      { id: 'proof-overview', label: 'Connection details', icon: Info },
      { id: 'audit', label: 'History and proof', icon: ClipboardText },
    ],
  },
  {
    id: 'citation-trust',
    label: 'Citation Trust',
    productId: 'citation-trust',
    items: [
      { id: 'citation-overview', label: 'Connection details', icon: Info },
      { id: 'citation-trust', label: 'Citation findings', icon: Quotes },
    ],
  },
  {
    id: 'workspace',
    label: 'Workspace settings',
    items: [
      { id: 'members', label: 'Members', icon: UsersThree },
      { id: 'settings', label: 'Workspace settings', icon: Gear },
      { id: 'user-guide', label: 'User guide', icon: BookOpenText },
    ],
  },
]

const PLATFORM_NAV_ITEM = { id: 'platform-support', label: 'Platform support', icon: ShieldCheck }
const PLATFORM_NAV_SECTION = { id: 'platform-support', label: 'Platform support', items: [PLATFORM_NAV_ITEM] }

function navigationSectionsForSession(session, activeTenant = '') {
  if (!session?.memberships?.length) return session?.platform_admin ? [PLATFORM_NAV_SECTION] : []
  const membership = session.memberships.find((item) => item.tenant_id === activeTenant) || session.memberships[0]
  const entitlements = Array.isArray(membership?.product_entitlements)
    ? new Set(membership.product_entitlements)
    : Array.isArray(session.product_entitlements) ? new Set(session.product_entitlements) : null
  const sections = entitlements ? NAV_SECTIONS.filter((section) => !section.productId || entitlements.has(section.productId)) : NAV_SECTIONS
  return session.platform_admin ? [...sections, PLATFORM_NAV_SECTION] : sections
}

export function ConfirmAccount({ inviteToken = '' }) {
  const [username, setUsername] = useState('')
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [resending, setResending] = useState(false)
  const [error, setError] = useState(null)
  const [message, setMessage] = useState('')

  async function confirm(event) {
    event.preventDefault()
    setBusy(true)
    setError(null)
    setMessage('')
    try {
      const result = await request('/auth/confirm', {
        method: 'POST',
        body: JSON.stringify({ username: username.trim(), confirmation_code: code.trim() }),
      })
      setMessage(result?.message || 'Account confirmed. You can now sign in.')
      setCode('')
    } catch (caught) {
      setError(caught)
    } finally {
      setBusy(false)
    }
  }

  async function resend() {
    if (!username.trim()) return
    setResending(true)
    setError(null)
    setMessage('')
    try {
      const result = await request('/auth/confirm/resend', {
        method: 'POST',
        body: JSON.stringify({ username: username.trim() }),
      })
      setMessage(result?.message || 'A new confirmation code has been sent.')
    } catch (caught) {
      setError(caught)
    } finally {
      setResending(false)
    }
  }

  const signInHref = `/app${inviteToken ? `?invite=${encodeURIComponent(inviteToken)}` : ''}`
  return <main className="portal-auth-shell">
    <div className="portal-auth-card">
      <PortalMark />
      <div className="portal-eyebrow">Account confirmation</div>
      <h1>Confirm your account.</h1>
      <p className="portal-auth-lede">Enter the email address you used to sign up and the confirmation code sent by Kenning. You can request a new code if the first one expired.</p>
      <form className="portal-auth-form" onSubmit={confirm}>
        <label htmlFor="confirmation-email">Email address</label>
        <input id="confirmation-email" type="email" value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="email" placeholder="you@example.com" required />
        <label htmlFor="confirmation-code">Confirmation code</label>
        <input id="confirmation-code" type="text" inputMode="numeric" pattern="[0-9]*" maxLength="12" value={code} onChange={(event) => setCode(event.target.value.replace(/[^0-9]/g, ''))} autoComplete="one-time-code" placeholder="123456" required />
        <button className="portal-primary-button portal-button-wide" type="submit" disabled={busy || !username.trim() || !code.trim()}>{busy ? 'Confirming…' : 'Confirm account'} <ArrowRight size={16} /></button>
      </form>
      <button className="portal-secondary-button portal-button-wide portal-auth-secondary-action" type="button" onClick={resend} disabled={busy || resending || !username.trim()}>{resending ? 'Sending…' : 'Send a new code'}</button>
      {message && <div className="portal-notice portal-notice-info portal-confirm-success" role="status">{message}{message.includes('confirmed') && <a className="portal-text-link" href={signInHref}>Sign in <ArrowRight size={15} /></a>}</div>}
      <ErrorNotice error={error} />
      <a className="portal-text-link portal-auth-recovery-link" href={signInHref}>Back to sign in <ArrowRight size={15} /></a>
    </div>
  </main>
}

function PortalApp() {
  const [config, setConfig] = useState(null)
  const [session, setSession] = useState(null)
  const [activeTenant, setActiveTenant] = useState('')
  const [csrf, setCsrf] = useState('')
  const [view, setView] = useState('overview')
  const [issuedToken, setIssuedToken] = useState(null)
  const [generatedInvite, setGeneratedInvite] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [passkeyMessage, setPasskeyMessage] = useState('')
  const [inviteToken] = useState(() => new URLSearchParams(window.location.search).get('invite') || '')
  const [acceptingInvite, setAcceptingInvite] = useState(false)
  const [inviteError, setInviteError] = useState(null)
  const [showWizard, setShowWizard] = useState(false)
  const [sessionExpired, setSessionExpired] = useState(null)
  const [authError] = useState(() => new URLSearchParams(window.location.search).get('auth_error') || '')

  useEffect(() => {
    // Remove credentials persisted by older portal versions.
    try { window.localStorage.removeItem('kenning.portal.remembered-pat.v1') } catch { /* storage can be unavailable */ }
  }, [])

  async function loadSession() {
    setLoading(true)
    setError(null)
    try {
      const authConfig = await request('/auth/config')
      setConfig(authConfig)
      const me = await request('/v1/me')
      const csrfResponse = await request('/auth/csrf')
      setSession(me)
      setCsrf(csrfResponse.csrf_token || '')
      const activeMemberships = me.memberships || []
      setActiveTenant((current) => activeMemberships.some((item) => item.tenant_id === current) ? current : activeMemberships[0]?.tenant_id || '')
      if (me.platform_admin && !activeMemberships.length) setView('platform-support')
    } catch (caught) {
      if (caught.status === 401 || caught.status === 403) setSession(null)
      else setError(caught)
    } finally { setLoading(false) }
  }

  useEffect(() => { loadSession() }, [])

  useEffect(() => {
    if (!session || !activeTenant) return
    const subject = session.user?.subject || ''
    if (!subject) return
    try {
      if (window.localStorage.getItem('kenning.setup-wizard.suppress')) return
      if (!window.localStorage.getItem(`kenning.setup-wizard.${subject}.${activeTenant}`)) setShowWizard(true)
    } catch { /* storage can be unavailable */ }
  }, [session, activeTenant])

  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    if (params.has('auth_error')) {
      params.delete('auth_error')
      const query = params.toString()
      window.history.replaceState({}, document.title, `${window.location.pathname}${query ? `?${query}` : ''}${window.location.hash}`)
    }
    if (params.get('passkey') !== 'added') return
    setPasskeyMessage('Passkey registration completed. You can now use it for future sign-ins.')
    window.history.replaceState({}, document.title, `${window.location.pathname}${window.location.hash}`)
  }, [])

  useEffect(() => {
    if (!session) return undefined
    setSessionExpired(null)
    const inactivitySeconds = Number(session.session_inactivity_timeout_seconds || config?.session_inactivity_seconds || 1800)
    const absoluteExpiry = Number(session.session_expires_at || 0) * 1000
    let timer
    const signOutOnExpiry = async () => {
      const reason = absoluteExpiry && Date.now() >= absoluteExpiry - 1000 ? 'absolute' : 'inactivity'
      setSessionExpired(reason)
      try { await request('/auth/logout', { method: 'POST' }, '', csrf) } catch { /* the server will reject an already expired session */ }
      if (config?.oidc_enabled && !['localhost', '127.0.0.1'].includes(window.location.hostname)) {
        window.location.assign(apiUrl('/auth/logout'))
        return
      }
      setSession(null)
      setCsrf('')
      setIssuedToken(null)
      setGeneratedInvite(null)
    }
    const reset = () => {
      window.clearTimeout(timer)
      const inactivityDeadline = Date.now() + inactivitySeconds * 1000
      const deadline = absoluteExpiry ? Math.min(inactivityDeadline, absoluteExpiry) : inactivityDeadline
      timer = window.setTimeout(signOutOnExpiry, Math.max(1000, deadline - Date.now()))
    }
    window.addEventListener('pointerdown', reset)
    window.addEventListener('keydown', reset)
    window.addEventListener('kenning:activity', reset)
    reset()
    return () => {
      window.clearTimeout(timer)
      window.removeEventListener('pointerdown', reset)
      window.removeEventListener('keydown', reset)
      window.removeEventListener('kenning:activity', reset)
    }
  }, [session, csrf, config])

  const membership = useMemo(() => session?.memberships?.find((item) => item.tenant_id === activeTenant), [session, activeTenant])
  async function signOut() {
    try { await request('/auth/logout', { method: 'POST' }, '', csrf) } catch { /* expired sessions are already signed out */ }
    if (config?.oidc_enabled && !['localhost', '127.0.0.1'].includes(window.location.hostname)) {
      window.location.assign(apiUrl('/auth/logout'))
      return
    }
    setSession(null)
    setCsrf('')
    setIssuedToken(null)
    setGeneratedInvite(null)
  }

  async function acceptInvitation() {
    setAcceptingInvite(true)
    setInviteError(null)
    try {
      await request('/v1/invitations/accept', { method: 'POST', body: JSON.stringify({ token: inviteToken }) }, '', csrf)
      await loadSession()
    } catch (caught) {
      setInviteError(caught)
      setAcceptingInvite(false)
    }
  }

  useEffect(() => {
    if (!session) return
    const allowedViews = navigationSectionsForSession(session, activeTenant).flatMap((section) => section.items.map((item) => item.id))
    if (allowedViews.length && !allowedViews.includes(view)) setView(allowedViews[0])
  }, [session, activeTenant, view])

  if (loading && !session) return <main className="portal-auth-shell"><div className="portal-auth-card"><PortalMark /><LoadingBlock lines={4} /></div></main>
  if (!session) return <SignIn config={config} onSignedIn={loadSession} inviteToken={inviteToken} sessionExpired={sessionExpired} authError={authError} loadError={error} />
  if (!session.memberships?.length && !session.platform_admin) return <main className="portal-auth-shell"><div className="portal-auth-card"><PortalMark /><div className="portal-eyebrow">{inviteToken ? 'Workspace invitation' : 'No workspace access'}</div><h1>{inviteToken ? 'You have been invited to join a workspace.' : 'You are signed in, but you do not have access to a workspace yet.'}</h1>{inviteToken ? <><p className="portal-auth-lede">Accept the invitation to activate your workspace access. Your membership and role are checked by the server.</p><button className="portal-primary-button portal-button-wide" type="button" onClick={acceptInvitation} disabled={acceptingInvite}>{acceptingInvite ? 'Accepting invitation…' : 'Accept invitation'} <ArrowRight size={16} /></button><ErrorNotice error={inviteError} /></> : <p className="portal-auth-lede">Ask a workspace owner or administrator to add your account. Workspace access is checked by the server.</p>}<button className="portal-secondary-button portal-button-wide" type="button" onClick={signOut}><SignOut size={17} /> Sign out</button></div></main>

  const contextValue = { tenantId: activeTenant, membership, user: session.user, data: {}, load: async () => {}, refreshSession: loadSession, csrf, setView }
  return <PortalContext.Provider value={contextValue}><PortalWorkspace config={config} session={session} activeTenant={activeTenant} setActiveTenant={setActiveTenant} view={view} setView={setView} issuedToken={issuedToken} onTokenIssued={setIssuedToken} generatedInvite={generatedInvite} onInvitationGenerated={setGeneratedInvite} showWizard={showWizard} setShowWizard={setShowWizard} signOut={signOut} passkeyMessage={passkeyMessage} /></PortalContext.Provider>
}

function PortalWorkspace({ config, session, activeTenant, setActiveTenant, view, setView, issuedToken, onTokenIssued, generatedInvite, onInvitationGenerated, showWizard, setShowWizard, signOut, passkeyMessage }) {
  const parentContext = useContext(PortalContext)
  const recentTokenId = view === 'access' ? String(issuedToken?.token_metadata?.token_id || '') : ''
  const encoded = encodeURIComponent(activeTenant)
  const paths = useMemo(() => ({
    overview: [['tenant', `/v1/tenants/${encoded}`], ['metrics', `/v1/metrics?tenant_id=${encoded}`], ['audit', `/v1/audit?tenant_id=${encoded}&limit=8`], ['pendingApprovals', `/v1/approvals?tenant_id=${encoded}&status=pending&limit=100`]],
    agents: [['agents', '/v1/agents']],
    rules: [['policies', '/v1/policies'], ['starterRules', `/v1/tenants/${encoded}/starter-rules`], ['complianceCoverage', `/v1/compliance/coverage?tenant_id=${encoded}`]],
    approvals: [['approvals', `/v1/approvals?tenant_id=${encoded}&limit=20`], ['grants', `/v1/grants?tenant_id=${encoded}&limit=50`]],
    members: [['members', `/v1/tenants/${encoded}/members`], ['invitations', `/v1/tenants/${encoded}/invitations`]],
    audit: [['audit', `/v1/audit?tenant_id=${encoded}&limit=100`], ['security', `/v1/security/events?tenant_id=${encoded}&limit=50`]],
    access: [['tokens', `/v1/tokens?tenant_id=${encoded}${recentTokenId ? `&token_id=${encodeURIComponent(recentTokenId)}` : ''}`]],
    settings: [['tenant', `/v1/tenants/${encoded}`], ['environments', `/v1/tenants/${encoded}/environments`], ['managementReviews', `/v1/management-reviews?tenant_id=${encoded}`], ['models', '/v1/models'], ['suppliers', '/v1/suppliers'], ['nonconformities', `/v1/nonconformities?tenant_id=${encoded}&status=all`]],
    'citation-trust': [['audit', `/v1/audit?tenant_id=${encoded}&limit=50`]],
    'platform-support': [['platformGrants', '/v1/platform/access-grants?limit=100']],
  }[view] || []), [encoded, recentTokenId, view])
  const { data, loading, error, reload, updateData } = useApiQuery(paths, [view, recentTokenId])
  const navigationSections = navigationSectionsForSession(session, activeTenant)
  const navigationItems = navigationSections.flatMap((section) => section.items)
  const openNonconformityCount = (data.nonconformities?.nonconformities || []).filter((item) => item.status === 'open').length
  const current = navigationItems.find((item) => item.id === view) || navigationItems[0]
  const Icon = current.icon
  const contextValue = { ...parentContext, data, load: reload, updateData }
  const showInitialLoading = loading && !Object.keys(data).length && view !== 'user-guide'
  const viewProps = { issuedToken, onTokenIssued, generatedInvite, onInvitationGenerated }
  const wizardWorkspaceName = parentContext.membership?.display_name || activeTenant
  return <PortalContext.Provider value={contextValue}><div className="portal-root"><header className="portal-topbar"><PortalMark /><div className="portal-topbar-meta"><span>Kenning console</span><ReleaseMarker />{config?.passkeys_enabled && <a className="portal-icon-button" href={apiUrl('/auth/passkeys')} aria-label="Add or manage passkey" title="Add or manage passkey"><Key size={18} /> <span>Passkey</span></a>}{config?.reauth_enabled && <a className="portal-text-button" href={apiUrl('/auth/reauth?return_to=/app')}><LockKey size={16} /> Sign in again</a>}<button className="portal-icon-button" type="button" onClick={signOut} title="Sign out"><SignOut size={18} /> <span>Sign out</span></button></div></header><EnvironmentBanner /><div className="portal-shell"><aside className="portal-sidebar"><div className="portal-workspace-label">{session.memberships.length ? 'Workspace' : 'Scope'}</div>{session.memberships.length ? <select className="portal-workspace-select" value={activeTenant} onChange={(event) => { setActiveTenant(event.target.value); setView('overview') }} aria-label="Select workspace">{session.memberships.filter((item) => item.status === 'active').map((item) => <option key={item.tenant_id} value={item.tenant_id}>{item.display_name || item.tenant_id}</option>)}</select> : <div className="portal-workspace-select portal-workspace-static">Platform support</div>}{session.memberships.length > 0 && <button className={`portal-sidebar-guide ${view === 'user-guide' ? 'active' : ''}`} type="button" onClick={() => setView('user-guide')} aria-label="Open user guide"><BookOpenText size={17} weight={view === 'user-guide' ? 'fill' : 'regular'} /><span>Help &amp; user guide</span><ArrowRight size={15} /></button>}<div className="portal-user-block"><span className="portal-avatar">{(session.user?.display_name || session.user?.subject || 'U').slice(0, 1).toUpperCase()}</span><div><strong>{session.user?.display_name || session.user?.subject}</strong><small>{session.platform_admin ? 'platform admin' : parentContext.membership?.role?.replace('_', ' ') || 'member'}</small></div></div><nav className="portal-nav" aria-label="Kenning console navigation">{navigationSections.map((section) => <div className="portal-nav-section" key={section.id}><div className="portal-nav-section-label">{section.label}</div>{section.items.map((item) => { const NavIcon = item.icon; return <button className={view === item.id ? 'active' : ''} type="button" key={item.id} onClick={() => setView(item.id)}><NavIcon size={17} weight={view === item.id ? 'fill' : 'regular'} />{item.label}{item.id === 'settings' && openNonconformityCount > 0 && <span className="portal-pill danger" aria-label={`${openNonconformityCount} open nonconformities`}>{openNonconformityCount}</span>}</button> })}</div>)}</nav><div className="portal-sidebar-footer"><ShieldCheck size={17} /><span>All controls are managed here.</span></div></aside><main className="portal-main"><div className="portal-mobile-heading"><Icon size={19} /> {current.label}</div>{passkeyMessage && <div className="portal-notice portal-notice-info" role="status"><CheckCircle size={18} weight="bold" /><span>{passkeyMessage}</span></div>}<ErrorNotice error={error} onRetry={() => { reload() }} />{showInitialLoading ? <LoadingBlock lines={6} /> : view === 'platform-support' ? <PlatformSupportView {...viewProps} /> : view === 'user-guide' ? <UserGuideView onBack={() => setView('settings')} /> : view === 'guard-overview' || view === 'proof-overview' || view === 'citation-overview' || view === 'identity-overview' ? <ProductOverview productId={view} onOpenWizard={() => setShowWizard(true)} /> : view === 'citation-trust' ? <CitationTrustView {...viewProps} /> : view === 'overview' ? <Overview {...viewProps} /> : view === 'agents' ? <AgentsView {...viewProps} /> : view === 'rules' ? <RulesView {...viewProps} /> : view === 'approvals' ? <ApprovalsView {...viewProps} /> : view === 'members' ? <MembersView {...viewProps} /> : view === 'audit' ? <AuditView {...viewProps} /> : view === 'access' ? <TokensView {...viewProps} /> : <SettingsView {...viewProps} />}</main></div>{showWizard && parentContext.membership && <SetupWizard workspaceName={wizardWorkspaceName} subject={session.user?.subject || ''} onClose={() => setShowWizard(false)} />}</div></PortalContext.Provider>
}

export default PortalApp
