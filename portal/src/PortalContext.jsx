import { createContext, useContext } from 'react'

// PortalContext carries the shared portal session state so view components can
// read it directly instead of receiving every value as a prop.
// Values: tenantId, csrf, membership, user, data, load, refreshSession, setView.
export const PortalContext = createContext(null)

// usePortal returns the shared portal session state for the active view.
export function usePortal() {
  return useContext(PortalContext)
}
