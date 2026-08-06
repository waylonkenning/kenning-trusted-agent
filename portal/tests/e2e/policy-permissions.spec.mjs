import { test, expect } from './fixtures.mjs'
import { portalUrl } from './helpers.mjs'

test.use({ viewport: { width: 1024, height: 768 } })

test('viewer sees why policy simulation is unavailable', async ({ page }) => {
  const origin = new URL(portalUrl).origin
  const session = {
    user: { subject: 'viewer@example.test', display_name: 'Viewer' },
    memberships: [{ tenant_id: 'viewer-tenant', display_name: 'Viewer tenant', role: 'viewer', status: 'active' }],
    platform_admin: false,
    session_expires_at: Math.floor(Date.now() / 1000) + 3600,
    session_inactivity_timeout_seconds: 1800,
  }
  const fulfill = (route, payload) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(payload) })

  await page.route('**/*', async (route) => {
    const url = new URL(route.request().url())
    if (url.origin !== origin || (!url.pathname.startsWith('/auth/') && !url.pathname.startsWith('/v1/'))) return route.continue()
    if (url.pathname === '/auth/config') return fulfill(route, { oidc_enabled: false, session_inactivity_seconds: 1800, reauth_enabled: false })
    if (url.pathname === '/auth/csrf') return fulfill(route, { csrf_token: 'test-csrf' })
    if (url.pathname === '/v1/me') return fulfill(route, session)
    if (url.pathname === '/v1/policies') return fulfill(route, { policies: [{ policy_id: 'viewer-policy', version: 1, status: 'published', created_by: 'administrator', updated_at: '2026-07-18T00:00:00Z' }] })
    if (url.pathname === '/v1/tenants/viewer-tenant') return fulfill(route, { tenant_id: 'viewer-tenant', name: 'Viewer tenant', status: 'active', default_environment: 'development' })
    if (url.pathname === '/v1/metrics') return fulfill(route, { metrics: {} })
    if (url.pathname === '/v1/audit') return fulfill(route, { events: [] })
    return fulfill(route, {})
  })

  await page.goto(portalUrl, { waitUntil: 'domcontentloaded' })
  await page.evaluate(() => { try { window.localStorage.setItem('kenning.setup-wizard.suppress', '1') } catch { /* storage can be unavailable */ } })
  await page.getByRole('button', { name: 'Rules', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Rules', exact: true })).toBeVisible()
  await expect(page.getByRole('status')).toContainText('Policy admin permission')
  await expect(page.getByRole('button', { name: 'Test this policy' })).toHaveCount(0)
  await expect(page.locator('button[title="You need the Policy admin permission to test policies."]')).toBeDisabled()
})
