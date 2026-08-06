import React, { useState } from 'react'
import { ArrowRight, Info, Key, LockKey, ShieldCheck, WarningCircle } from '@phosphor-icons/react'
import { LoadingBlock, ErrorNotice, PortalMark } from '../components/ui.jsx'
import { request, apiUrl } from '../lib.js'
import EnvironmentBanner from '../views/EnvironmentBanner.jsx'

const AUTH_ERROR_MESSAGES = {
  invalid_oidc_callback: 'The sign-in response was incomplete.',
  invalid_oidc_state: 'That sign-in attempt expired or is no longer valid.',
  expired_oidc_state: 'That sign-in attempt expired or is no longer valid.',
  oidc_provider_error: 'The sign-in provider did not complete the request.',
  oidc_authentication_failed: 'We could not complete sign-in.',
  invalid_auth_configuration: 'Sign-in is temporarily unavailable.',
}

function SignIn({ config, onSignedIn, inviteToken, sessionExpired, authError, loadError }) {
  const [pat, setPat] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  async function submit(event) {
    event.preventDefault()
    if (!pat.trim()) return
    setBusy(true)
    setError(null)
    const presentedPat = pat.trim()
    try {
      await request('/auth/session', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${presentedPat}`,
          // Compatibility fallback for embedded browsers that strip
          // Authorization during a cross-origin session exchange.
          'X-Kenning-PAT': presentedPat,
        },
        body: JSON.stringify({ personal_access_token: presentedPat }),
      })
      setPat('')
      await onSignedIn()
    } catch (caught) {
      if (caught.status === 401 || caught.status === 403) {
        setPat('')
      }
      setError(caught)
    } finally {
      setBusy(false)
    }
  }

  const inviteQuery = inviteToken ? `?invite=${encodeURIComponent(inviteToken)}` : ''
  const signInHref = apiUrl(`/auth/login?return_to=/app${inviteToken ? `&invite=${encodeURIComponent(inviteToken)}` : ''}`)
  const showPatLogin = config?.pat_bootstrap_enabled === true
  const authErrorMessage = authError ? (AUTH_ERROR_MESSAGES[authError] || 'We could not complete sign-in.') : ''
  const signInLabel = authErrorMessage
    ? 'Start sign-in again'
    : inviteToken
      ? 'Create account or sign in'
      : config?.passkeys_enabled
        ? 'Sign in with username or passkey'
        : 'Sign in with your organisation'

  return <main className="portal-auth-shell">
    <EnvironmentBanner />
    <div className="portal-auth-card">
      <PortalMark />
      <div className="portal-eyebrow">{inviteToken ? 'Workspace invitation' : 'Kenning console'}</div>
      {sessionExpired === 'inactivity' && <div className="portal-notice portal-notice-info" role="status"><Info size={18} weight="bold" /><span>Your session expired because there was no activity. Sign in to continue where you left off.</span></div>}
      {sessionExpired === 'absolute' && <div className="portal-notice portal-notice-info" role="status"><Info size={18} weight="bold" /><span>Your session reached its maximum lifetime. Sign in to continue.</span></div>}
      {authErrorMessage && <div className="portal-notice portal-notice-error" role="alert"><WarningCircle size={18} weight="bold" /><span>{authErrorMessage} Choose “{signInLabel}” to try again.</span></div>}
      <ErrorNotice error={loadError} onRetry={loadError ? onSignedIn : undefined} />
      {inviteToken ? <div className="portal-invitation-guidance" role="status">
        <h1>Create an account or sign in.</h1>
        <p className="portal-auth-lede">You’ve been invited to join a Kenning workspace. New here? Choose the account-creation option on the next screen, confirm the code sent to your email, then return here. Already have an account? Sign in and your invitation will be applied.</p>
        <p className="portal-field-note">You do not need a personal access token to accept this invitation. Keep this link until setup is complete.</p>
      </div> : <>
        <h1>Sign in to manage your workspace.</h1>
        <p className="portal-auth-lede">{config?.passkeys_enabled ? 'Use your username and password or a passkey to enter the console. Your workspace access and role are checked by the server on every request.' : 'Sign in with your organisation’s login to enter the console. Your workspace access and role are checked by the server on every request.'}</p>
      </>}
      {config?.oidc_enabled && <a className="portal-primary-button portal-button-wide" href={signInHref}><LockKey size={18} weight="bold" /> {signInLabel} <ArrowRight size={16} /></a>}
      {config?.oidc_enabled && <a className="portal-text-link portal-auth-recovery-link" href={`/confirm${inviteQuery}`}>Already signed up? Enter your confirmation code <ArrowRight size={15} /></a>}
      {showPatLogin ? <>
        <div className="portal-notice portal-notice-info"><WarningCircle size={18} weight="bold" /><span>Temporary PAT sign-in is enabled only for a controlled setup. Do not use it for normal human sign-in.</span></div>
        <div className="portal-divider"><span>Temporary access</span></div>
        <form className="portal-auth-form" onSubmit={submit}>
          <label htmlFor="portal-pat">Personal access token</label>
          <input id="portal-pat" type="password" value={pat} onChange={(event) => setPat(event.target.value)} placeholder="kta_pat_…" autoComplete="off" spellCheck="false" />
          <button className="portal-primary-button portal-button-wide" type="submit" disabled={busy || !pat.trim()}>{busy ? 'Opening Kenning console…' : 'Open Kenning console'} <ArrowRight size={16} /></button>
        </form>
      </> : <p className="portal-field-note portal-human-auth-note">Use email, password, confirmation code, or passkey to sign in. PATs are for agents and API clients.</p>}
      <p className="portal-field-note portal-human-auth-note">Console sessions stay active while you are using them and expire after a period of inactivity or a maximum lifetime set by your deployment.</p>
      <ErrorNotice error={error} />
    </div>
  </main>
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


export default SignIn
