import React from 'react'
import { createRoot } from 'react-dom/client'
import PortalApp, { ConfirmAccount } from './portal.jsx'

const path = window.location.pathname.replace(/\/+$/, '') || '/'
const inviteToken = new URLSearchParams(window.location.search).get('invite') || ''
const root = document.getElementById('root')

createRoot(root).render(path === '/confirm' ? <ConfirmAccount inviteToken={inviteToken} /> : <PortalApp />)
