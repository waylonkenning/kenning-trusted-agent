import { test, expect } from './fixtures.mjs'
import { docsBaseUrl } from './helpers.mjs'

test('legacy operator approval URL forwards to the unified tenant console', async ({ page }) => {
  await page.goto(`${docsBaseUrl}/operator.html`, { waitUntil: 'domcontentloaded' })
  await expect(page).toHaveURL(/\/app\/?$/)
  await expect(page.getByRole('heading', { name: 'Sign in to manage your workspace.' })).toBeVisible()
})
