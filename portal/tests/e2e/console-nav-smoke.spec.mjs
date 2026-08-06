import { test, expect } from './fixtures.mjs'
import { signInPortal } from './helpers.mjs'

/**
 * Console navigation smoke test.
 *
 * Clicks every sidebar navigation button and asserts the target view renders
 * without browser page errors. This catches the class of bug where a view
 * component crashes on mount (missing import, undefined hook, bad prop) —
 * the exact failure mode that broke Agent Guard Rules, Agent Proof History,
 * and Agent Guard Connection details in the portal view extraction refactor.
 *
 * See: https://github.com/waylonkenning/kenning-trusted-agent/issues/264
 * See: https://github.com/waylonkenning/kenning-trusted-agent/issues/265
 */

// Every nav button label in the tenant console, grouped by section.
// Order matches NAV_SECTIONS in src/portal.jsx.
const NAV_BUTTONS = [
  // Overview
  { label: 'Overview', heading: 'Decision record' },
  // Agent Identity
  { label: 'Connection details', heading: 'Agent Identity', section: 'Agent Identity' },
  { label: 'Agents and connections', heading: 'Agents and connections' },
  // Agent Guard
  { label: 'Connection details', heading: 'Agent Guard', section: 'Agent Guard' },
  { label: 'Rules', heading: 'Rules' },
  { label: 'Approvals', heading: 'Approvals' },
  { label: 'Access tokens', heading: 'Access tokens' },
  // Agent Proof
  { label: 'Connection details', heading: 'Agent Proof', section: 'Agent Proof' },
  { label: 'History and proof', heading: 'Audit and proof' },
  // Citation Trust
  { label: 'Connection details', heading: 'Citation Trust', section: 'Citation Trust' },
  { label: 'Citation findings', heading: 'Citation findings' },
  // Workspace settings
  { label: 'Members', heading: 'Members' },
  { label: 'Workspace settings', heading: 'Workspace settings' },
  { label: 'User guide', heading: 'User guide' },
]

test('every console nav button renders its view without page errors', async ({ page, e2e }) => {
  test.setTimeout(120_000)

  const pageErrors = []
  page.on('pageerror', (error) => pageErrors.push(error.message))

  await signInPortal(page, e2e)

  // Verify all nav sections are visible
  for (const sectionLabel of ['Overview', 'Agent Identity', 'Agent Guard', 'Agent Proof', 'Citation Trust', 'Workspace settings']) {
    await expect(
      page.locator('.portal-nav-section-label').filter({ hasText: sectionLabel }),
      `nav section "${sectionLabel}" should be visible`,
    ).toBeVisible()
  }

  // Click each nav button and verify the view renders
  for (const nav of NAV_BUTTONS) {
    // Some labels repeat across sections (e.g. "Connection details" appears 4×).
    // Scope to the correct section when specified.
    let button
    if (nav.section) {
      const section = page.locator('.portal-nav-section').filter({ hasText: nav.section })
      button = section.getByRole('button', { name: nav.label, exact: true })
    } else {
      button = page.getByRole('button', { name: nav.label, exact: true })
    }

    await button.click()

    // The view heading should appear — proves the component mounted and rendered
    await expect(
      page.getByRole('heading', { name: nav.heading, exact: true }).first(),
      `"${nav.label}" view should render heading "${nav.heading}"`,
    ).toBeVisible({ timeout: 15_000 })

    // No browser errors should have fired during navigation
    expect(
      pageErrors,
      `page errors after clicking "${nav.label}": ${pageErrors.join('; ')}`,
    ).toEqual([])
  }
})

test('console nav buttons have accessible names and keyboard focus', async ({ page, e2e }) => {
  await signInPortal(page, e2e)

  // Every nav button should have a non-empty accessible name
  const navButtons = page.locator('.portal-nav button')
  const count = await navButtons.count()
  expect(count).toBeGreaterThanOrEqual(12)

  for (let i = 0; i < count; i++) {
    const button = navButtons.nth(i)
    const name = await button.getAttribute('aria-label') || await button.textContent()
    expect(name?.trim().length, `nav button ${i} should have a non-empty accessible name`).toBeGreaterThan(0)
  }

  // Verify that a navigation button can receive keyboard focus.
  const firstButton = navButtons.first()
  await firstButton.focus()
  await expect(firstButton).toBeFocused()
})
