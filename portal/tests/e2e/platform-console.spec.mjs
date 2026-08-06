import { test, expect } from './fixtures.mjs'
import { platformUrl, signInWithPat } from './helpers.mjs'

test('platform admin uses the unified console for support grants', async ({ page, e2e }) => {
  await signInWithPat(page, e2e.platformPat, platformUrl)
  await expect(page.getByRole('button', { name: 'Platform support', exact: true })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Platform support access' })).toBeVisible()

  await page.getByLabel('Workspace ID').fill(e2e.tenantId)
  await page.getByLabel('Support reason').fill('Playwright verifies bounded support access')
  await page.getByLabel('What support can do').selectOption('support')
  await page.getByRole('button', { name: 'Create support access' }).click()
  const grantRow = page.locator('tr').filter({ hasText: e2e.tenantId })
  await expect(grantRow).toBeVisible()
  await expect(grantRow.getByText('active', { exact: true })).toBeVisible()

  for (const resource of ['tenant', 'members', 'audit', 'metrics']) {
    await page.getByLabel('What to view').selectOption(resource)
    await grantRow.getByRole('button', { name: 'Read' }).click()
    await expect(page.getByText('Support result')).toBeVisible()
    await expect(page.locator('.portal-proof-json')).toContainText(e2e.tenantId)
  }

  await grantRow.getByRole('button', { name: 'Revoke' }).click()
  await expect(grantRow.getByText('revoked', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Sign out' }).click()
  await expect(page.getByRole('heading', { name: 'Sign in to manage your workspace.' })).toBeVisible()
})
