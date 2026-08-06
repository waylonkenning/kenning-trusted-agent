import { expect, test } from '@playwright/test'

test('public portal sign-in page works without AWS credentials', async ({ page }) => {
  await page.route('**/auth/config', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ oidc_enabled: false, pat_bootstrap_enabled: false, session_inactivity_seconds: 1800 }),
    })
  })
  await page.route('**/v1/me', async (route) => {
    await route.fulfill({ status: 401, contentType: 'application/json', body: JSON.stringify({ error: 'unauthorized' }) })
  })
  await page.goto('/app/', { waitUntil: 'domcontentloaded' })
  await expect(page.getByRole('heading', { name: 'Sign in to manage your workspace.' })).toBeVisible()
  await expect(page.getByText('Use email, password, confirmation code, or passkey to sign in.')).toBeVisible()
  await expect(page.locator('input[type="password"]')).toHaveCount(0)
  await expect(page.locator(`a[href*="execute-api"], a[href*="cloudfront"], a[href*="${'kenning' + '.co.nz'}"]`)).toHaveCount(0)
})
