import { test, expect } from './fixtures.mjs'
import { failNextClipboardWrite, signInPortal } from './helpers.mjs'

test.setTimeout(120000)

test('single tenant console manages credentials and policy simulation', async ({ page, e2e }) => {
  await signInPortal(page, e2e)

  await page.getByRole('button', { name: 'Access tokens', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Access tokens', exact: true })).toBeVisible()

  const tokenName = `unified-console-token-${Date.now().toString(36)}`
  await page.getByLabel('Name', { exact: true }).fill(tokenName)
  await page.getByLabel('Permissions', { exact: true }).fill('proof:read')
  await page.getByLabel('Expires in days', { exact: true }).fill('1')
  await page.getByRole('button', { name: 'Issue access token' }).click()
  await expect(page.getByText('New access token — copy it now')).toBeVisible()
  await expect(page.locator('.portal-token-issued code')).toHaveText(/^kta_pat_/)
  await expect(page.locator('.portal-token-issued')).toContainText(tokenName)
  await failNextClipboardWrite(page)
  const copyToken = page.locator('.portal-token-issued').getByRole('button', { name: 'Copy access token', exact: true })
  await copyToken.click()
  const copyError = page.locator('.portal-token-issued').getByRole('alert')
  await expect(copyError).toContainText('Could not copy.')
  await expect(copyToken).toHaveText('Try again')
  await copyToken.click()
  await expect(copyError).toHaveCount(0)
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toMatch(/^kta_pat_/)

  const policyId = `unified-policy-${Date.now().toString(36)}`
  await page.getByRole('button', { name: 'Rules', exact: true }).click()
  await page.locator('#policy-id').fill(policyId)
  await page.locator('#policy-name').fill('Unified console policy')
  await page.getByLabel('Condition field', { exact: true }).first().selectOption('classification_at_least')
  await page.getByLabel('Condition value', { exact: true }).first().fill('restricted')
  await page.getByRole('button', { name: 'Create policy' }).click()
  const policyRow = page.locator('tr').filter({ hasText: policyId })
  const policyDeadline = Date.now() + 45000
  while (!(await policyRow.first().isVisible().catch(() => false))) {
    if (Date.now() > policyDeadline) break
    await page.waitForTimeout(1000)
    const refetch = page.waitForResponse((response) => {
      const url = new URL(response.url())
      return response.request().method() === 'GET' && url.pathname.endsWith('/v1/policies')
    })
    await page.getByRole('button', { name: 'Refresh', exact: true }).click()
    await refetch
  }
  await expect(policyRow).toBeVisible()
  await policyRow.getByRole('button', { name: 'Simulate' }).click()
  await expect(page.locator('#simulation-policy-id')).toHaveValue(policyId)
  await page.getByRole('button', { name: 'Test this policy' }).click()
  await expect(page.getByText('Test result')).toBeVisible()

  const tokenListRefresh = page.waitForResponse((response) => {
    const url = new URL(response.url())
    return response.request().method() === 'GET' && url.pathname.endsWith('/v1/tokens')
  })
  await page.getByRole('button', { name: 'Access tokens', exact: true }).click()
  await tokenListRefresh
  const tokenRow = page.locator('tr').filter({ hasText: tokenName })
  // The token index is eventually consistent in the deployed environment; if the
  // issued token is not listed yet, refresh until it appears rather than failing.
  const tokenDeadline = Date.now() + 45000
  while (!(await tokenRow.first().isVisible().catch(() => false))) {
    if (Date.now() > tokenDeadline) break
    // Avoid hammering the eventually consistent token index while it catches up.
    await page.waitForTimeout(1000)
    const refetch = page.waitForResponse((response) => {
      const url = new URL(response.url())
      return response.request().method() === 'GET' && url.pathname.endsWith('/v1/tokens')
    })
    await page.getByRole('button', { name: 'Refresh' }).click()
    await refetch
  }
  await expect(tokenRow).toBeVisible()
  await expect(tokenRow.getByRole('button', { name: 'Revoke' })).toBeVisible()
  await tokenRow.getByRole('button', { name: 'Revoke' }).click()
  await expect(tokenRow.getByText('revoked', { exact: true })).toBeVisible()
})
