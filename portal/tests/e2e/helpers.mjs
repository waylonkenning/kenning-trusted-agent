import assert from 'node:assert/strict'

export const portalUrl = process.env.E2E_PORTAL_URL || 'http://127.0.0.1:5199/app'
export const platformUrl = process.env.E2E_PLATFORM_URL || portalUrl
export const docsBaseUrl = (process.env.E2E_DOCS_BASE_URL || 'http://127.0.0.1:5199').replace(/\/+$/, '')
export const apiUrl = (process.env.E2E_API_URL || 'http://127.0.0.1:3000').replace(/\/$/, '')
export const portalApiMode = (process.env.E2E_PORTAL_API_MODE || 'same-origin').trim().toLowerCase()
export const sessionExchangeUrl = portalApiMode === 'direct' ? `${apiUrl}/auth/session` : '/auth/session'

export async function apiRequest(state, path, options = {}) {
  const token = options.token || state.portalPat
  const headers = new Headers(options.headers || {})
  headers.set('Accept', 'application/json')
  headers.set('Authorization', `Bearer ${token}`)
  let body = options.body
  if (body !== undefined && body !== null && typeof body !== 'string') {
    headers.set('Content-Type', 'application/json')
    body = JSON.stringify(body)
  }
  const response = await fetch(`${apiUrl}${path}`, {
    method: options.method || 'GET',
    headers,
    body,
  })
  const text = await response.text()
  let payload = null
  try { payload = text ? JSON.parse(text) : null } catch { payload = text }
  assert.equal(response.ok, true, `${options.method || 'GET'} ${path} returned ${response.status}: ${JSON.stringify(payload)}`)
  return payload
}

async function exchangePatForTestSession(page, pat) {
  await page.evaluate(async ({ presentedPat, exchangeUrl }) => {
    const response = await fetch(exchangeUrl, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${presentedPat}`,
        'X-Kenning-PAT': presentedPat,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ personal_access_token: presentedPat }),
      credentials: 'include',
    })
    if (!response.ok) throw new Error(`Test session bootstrap failed (${response.status})`)
  }, { presentedPat: pat, exchangeUrl: sessionExchangeUrl })
}

export async function signInWithPat(page, pat, entryUrl = portalUrl) {
  await page.goto(entryUrl, { waitUntil: 'domcontentloaded' })
  await exchangePatForTestSession(page, pat)
  await page.reload({ waitUntil: 'domcontentloaded' })
}

export async function signInPortal(page, state) {
  await page.goto(portalUrl, { waitUntil: 'domcontentloaded' })
  // Suppress the first-run setup wizard for console tests; a fresh browser
  // context would otherwise show it once per workspace and cover the console.
  await page.evaluate(() => { try { window.localStorage.setItem('kenning.setup-wizard.suppress', '1') } catch { /* storage can be unavailable */ } })
  await exchangePatForTestSession(page, state.portalPat)
  await page.reload({ waitUntil: 'domcontentloaded' })
  await page.getByRole('button', { name: 'Overview', exact: true }).waitFor()
  // The navigation renders as soon as the session is established, while the
  // initial Overview requests are still in flight. Wait for the view data so
  // a test switching screens cannot race that first load.
  await page.getByRole('heading', { name: 'Decision record' }).waitFor()
}

export async function failNextClipboardWrite(page) {
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write'], { origin: new URL(page.url()).origin })
  await page.evaluate(() => {
    const clipboard = navigator.clipboard
    let failNextWrite = true
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: {
        readText: () => clipboard.readText(),
        writeText: async (value) => {
          if (failNextWrite) {
            failNextWrite = false
            throw new Error('clipboard blocked')
          }
          return clipboard.writeText(value)
        },
      },
    })
  })
}

export function approvalRow(page, approvalId) {
  return page.locator('tr').filter({ hasText: approvalId })
}
