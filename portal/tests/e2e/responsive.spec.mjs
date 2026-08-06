import { test, expect } from './fixtures.mjs'
import { docsBaseUrl, platformUrl, portalUrl, signInPortal, signInWithPat } from './helpers.mjs'

test.use({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 3, isMobile: true })

async function expectNoHorizontalOverflow(page) {
  const dimensions = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    content: document.documentElement.scrollWidth,
  }))
  expect(dimensions.content, `horizontal overflow: ${JSON.stringify(dimensions)}`).toBeLessThanOrEqual(dimensions.viewport + 1)
}

test('tenant portal mobile navigation keeps every tenant screen within the viewport', async ({ page, e2e }) => {
  await signInPortal(page, e2e)
  const guideShortcut = page.getByRole('button', { name: 'Open user guide', exact: true })
  await expect(guideShortcut).toBeVisible()
  await expect(guideShortcut).toBeInViewport()
  await guideShortcut.click()
  await expect(page.getByRole('heading', { name: 'User guide', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Back to settings', exact: true }).click()
  for (const section of ['Agent Identity', 'Agent Guard', 'Agent Proof', 'Citation Trust', 'Workspace settings']) {
    await expect(page.locator('.portal-nav-section-label').filter({ hasText: section })).toBeVisible()
  }
  for (const [label, heading] of [
    ['Overview', 'Workspace overview'],
    ['Agents and connections', 'Agents and connections'],
    ['Rules', 'Rules'],
    ['Approvals', 'Approvals'],
    ['Citation findings', 'Citation findings'],
    ['Members', 'Members'],
    ['History and proof', 'Audit and proof'],
    ['Access tokens', 'Access tokens'],
    ['Workspace settings', 'Workspace settings'],
    ['User guide', 'User guide'],
  ]) {
    await page.getByRole('button', { name: label, exact: true }).click()
    await expect(page.locator('.portal-mobile-heading')).toContainText(label)
    if (heading !== 'Workspace overview') await expect(page.getByRole('heading', { name: heading, exact: true })).toBeVisible()
    await expectNoHorizontalOverflow(page)
  }
})

test('mobile unified console shells have no page-level overflow', async ({ page, e2e }) => {
  await signInWithPat(page, e2e.platformPat, platformUrl)
  await expect(page.getByRole('heading', { name: 'Platform support access' })).toBeVisible()
  await expectNoHorizontalOverflow(page)
  await page.getByRole('button', { name: 'Sign out' }).click()
  await expect(page.getByRole('heading', { name: 'Sign in to manage your workspace.' })).toBeVisible()

  await page.goto(`${docsBaseUrl}/operator.html`, { waitUntil: 'domcontentloaded' })
  await expect(page).toHaveURL(/\/app\/?$/)
  await expect(page.getByRole('heading', { name: 'Sign in to manage your workspace.' })).toBeVisible()
  await expectNoHorizontalOverflow(page)

  await page.goto(`${docsBaseUrl}/console.html`, { waitUntil: 'domcontentloaded' })
  await expect(page).toHaveURL(/\/app\/?$/)
  await expect(page.getByRole('heading', { name: 'Sign in to manage your workspace.' })).toBeVisible()
  await expectNoHorizontalOverflow(page)
})
