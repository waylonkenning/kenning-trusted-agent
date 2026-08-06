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
import { formatDate } from '../lib.js'
import { useApiMutation } from '../hooks.js'

function MembersView({ generatedInvite, onInvitationGenerated }) {
  const { tenantId, membership, data, load } = useContext(PortalContext)
  const [subject, setSubject] = useState('')
  const [role, setRole] = useState('viewer')
  const [editing, setEditing] = useState('')
  const [mutate, { busy, error, setError }] = useApiMutation()
  const memberships = data.members?.memberships || []
  const canManage = ['owner', 'admin'].includes(membership?.role)
  const invitations = data.invitations?.invitations || []
  const [inviteForm, setInviteForm] = useState({ role: 'viewer', expires_in_days: '7', max_uses: '1' })
  async function invite(event) {
    event.preventDefault()
    try {
      await mutate(`/v1/tenants/${encodeURIComponent(tenantId)}/members`, { method: 'POST', body: JSON.stringify({ subject, role, status: 'invited' }) })
      setSubject('')
    } catch { /* error handled by hook */ }
  }
  async function updateMember(row, next) {
    setEditing(row.subject)
    try { await mutate(`/v1/tenants/${encodeURIComponent(tenantId)}/members/${encodeURIComponent(row.subject)}`, { method: 'PATCH', body: JSON.stringify(next) }) } catch { /* error handled by hook */ } finally { setEditing('') }
  }
  async function generateInvitation(event) {
    event.preventDefault()
    onInvitationGenerated(null)
    try {
      const result = await mutate(`/v1/tenants/${encodeURIComponent(tenantId)}/invitations`, { method: 'POST', body: JSON.stringify({ role: inviteForm.role, expires_in_days: Number(inviteForm.expires_in_days) || 7, max_uses: Number(inviteForm.max_uses) || 1 }) })
      onInvitationGenerated(result)
    } catch { /* error handled by hook */ }
  }
  async function revokeInvitation(invitation) {
    try { await mutate(`/v1/tenants/${encodeURIComponent(tenantId)}/invitations/${encodeURIComponent(invitation.invitation_id)}/revoke`, { method: 'POST', body: JSON.stringify({}) }) } catch { /* error handled by hook */ }
  }
  const invitationColumns = [{ key: 'invitation_id', label: 'Invitation' }, { key: 'role', label: 'Role' }, { key: 'uses', label: 'Uses', render: (row) => `${row.use_count ?? 0}/${row.max_uses ?? 1}` }, { key: 'expires_at', label: 'Expires', render: (row) => row.expires_at ? formatDate(Number(row.expires_at) * 1000) : '—' }, { key: 'status', label: 'Status', render: (row) => <span className={`portal-pill ${row.status === 'active' ? 'success' : row.status === 'revoked' ? 'danger' : ''}`}>{row.status}</span> }, { key: 'actions', label: 'Actions', render: (row) => row.status === 'active' ? <button className="portal-danger-button" type="button" onClick={() => revokeInvitation(row)} disabled={busy}>Revoke</button> : '—' }]
  const memberColumns = [{ key: 'subject', label: 'User' }, { key: 'email', label: 'Email' }, { key: 'role', label: 'Role', render: (row) => canManage && row.role !== 'owner' ? <select className="portal-inline-select" defaultValue={row.role} onChange={(event) => updateMember(row, { role: event.target.value })} disabled={editing === row.subject} aria-label={`Change role for ${row.subject}`}><option value="viewer">Viewer</option><option value="auditor">Auditor</option><option value="approver">Approver</option><option value="policy_admin">Policy admin</option><option value="agent_integrations">Agent integrations</option><option value="admin">Admin</option></select> : row.role }, { key: 'status', label: 'Status', render: (row) => canManage && row.role !== 'owner' ? <select className="portal-inline-select" defaultValue={row.status} onChange={(event) => updateMember(row, { status: event.target.value })} disabled={editing === row.subject} aria-label={`Change status for ${row.subject}`}><option value="active">Active</option><option value="invited">Invited</option><option value="suspended">Suspended</option><option value="revoked">Revoked</option></select> : <span className={`portal-pill ${row.status === 'active' ? 'success' : ''}`}>{row.status}</span> }, { key: 'updated_at', label: 'Updated', render: (row) => formatDate(row.updated_at) }]
  const roleOptions = <><option value="viewer">Viewer</option><option value="auditor">Auditor</option><option value="approver">Approver</option><option value="policy_admin">Policy admin</option><option value="agent_integrations">Agent integrations</option><option value="admin">Admin</option></>
  return (
    <>
      <PageHeading eyebrow="Workspace access" title="Members" description="Manage workspace members and their roles. Role changes are recorded in the workspace history." action={<button className="portal-secondary-button" type="button" onClick={load}><ArrowsClockwise size={16} /> Refresh</button>} />
      <div className={`portal-content-grid ${canManage ? '' : 'portal-content-grid-single'}`}>
        <section className="portal-panel portal-panel-wide">
          <DataTable columns={memberColumns} rows={memberships} empty="No workspace members" />
          <ErrorNotice error={error} />
        </section>
        {canManage && (
          <section className="portal-panel">
            <div className="portal-eyebrow">Invite member</div>
            <h2>Grant workspace access</h2>
            <form className="portal-stack-form" onSubmit={invite}>
              <label htmlFor="member-subject">Person or service ID</label>
              <input id="member-subject" value={subject} onChange={(event) => setSubject(event.target.value)} placeholder="user@example.org" required />
              <label htmlFor="member-role">Role</label>
              <select id="member-role" value={role} onChange={(event) => setRole(event.target.value)}>{roleOptions}</select>
              <button className="portal-primary-button" type="submit" disabled={busy}>{busy ? 'Inviting…' : 'Create invitation'} <ArrowRight size={16} /></button>
            </form>
            <ErrorNotice error={error} />
          </section>
        )}
      </div>
      {canManage && (
        <div className="portal-content-grid" style={{ marginTop: '20px' }}>
          <section className="portal-panel portal-panel-wide">
            <div className="portal-panel-heading">
              <div>
                <div className="portal-eyebrow">Invitation links</div>
                <h2>Onboard a new member</h2>
              </div>
            </div>
            <p className="portal-field-note">Generate a shareable link. A new member opens it, creates their account, and joins the workspace with the role you choose — no need to know their account in advance.</p>
            {generatedInvite && (
              <div className="portal-token-issued" role="status">
                <div>
                  <div className="portal-eyebrow">New invitation link — copy it now</div>
                  <strong>{generatedInvite.invitation_id}</strong>
                  <p className="portal-field-note">Joins as {generatedInvite.role}. The full link is shown only once.</p>
                </div>
                <code>{generatedInvite.link}</code>
                <CopyButton text={generatedInvite.link} label="Copy invitation link" buttonClassName="portal-secondary-button" />
              </div>
            )}
            <DataTable columns={invitationColumns} rows={invitations} empty="No invitation links" />
          </section>
          <section className="portal-panel">
            <div className="portal-eyebrow">New invitation link</div>
            <h2>Generate a link</h2>
            <form className="portal-stack-form" onSubmit={generateInvitation}>
              <label htmlFor="invite-role">Role</label>
              <select id="invite-role" value={inviteForm.role} onChange={(event) => setInviteForm({ ...inviteForm, role: event.target.value })}>{roleOptions}</select>
              <label htmlFor="invite-expires">Expires in days</label>
              <input id="invite-expires" type="number" min="1" max="90" value={inviteForm.expires_in_days} onChange={(event) => setInviteForm({ ...inviteForm, expires_in_days: event.target.value })} required />
              <label htmlFor="invite-uses">Max uses</label>
              <input id="invite-uses" type="number" min="1" max="1000" value={inviteForm.max_uses} onChange={(event) => setInviteForm({ ...inviteForm, max_uses: event.target.value })} required />
              <p className="portal-field-note">A single-use link is safest. Increase max uses to onboard a whole team with one link.</p>
              <button className="portal-primary-button" type="submit" disabled={busy}>{busy ? 'Generating…' : 'Generate invitation link'} <ArrowRight size={16} /></button>
            </form>
            <ErrorNotice error={error} />
          </section>
        </div>
      )}
    </>
  )
}


export default MembersView
