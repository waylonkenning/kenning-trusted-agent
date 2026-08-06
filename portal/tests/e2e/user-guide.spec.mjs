import { test, expect } from './fixtures.mjs'
import { signInPortal } from './helpers.mjs'

const completedFeatureIssueNumbers = [
  13, 27, 28, 29, 30, 31, 40, 41, 52, 53, 57, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 74,
  119, 121, 122, 141, 176, 186, 242, 243, 244, 245, 246, 273, 274, 275, 276, 277, 279, 280, 281, 282, 283, 298,
]

test('workspace user guide is directly discoverable and covers every completed feature card', async ({ page, e2e }) => {
  await signInPortal(page, e2e)

  await expect(page.getByRole('button', { name: 'User guide', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'User guide', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'User guide', exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'User guide', exact: true })).toHaveClass(/active/)
  await page.getByRole('button', { name: 'Back to settings', exact: true }).click()
  await page.getByRole('button', { name: 'Workspace settings', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Workspace settings', exact: true })).toBeVisible()
  await page.locator('.portal-page-heading').getByRole('button', { name: 'Open user guide', exact: true }).click()

  await expect(page.getByRole('heading', { name: 'User guide', exact: true })).toBeVisible()
  await expect(page.locator('.portal-guide-topic')).toHaveCount(completedFeatureIssueNumbers.length)
  for (const issue of completedFeatureIssueNumbers) {
    await expect(page.locator(`[data-issue-number="${issue}"]`)).toHaveCount(1)
  }
  await expect(page.locator('.portal-guide-screenshot img')).toBeVisible()

  await page.locator('#user-guide-search').fill('release identity')
  await expect(page.locator('.portal-guide-topic')).toHaveCount(1)
  await expect(page.locator('[data-issue-number="298"]')).toBeVisible()
  await page.locator('#user-guide-search').fill('')
  await page.locator('[data-issue-number="298"]').click()
  await expect(page.locator('.portal-guide-article')).toContainText('Read the release identity and changelog')

  await page.getByRole('button', { name: 'Back to settings', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Workspace settings', exact: true })).toBeVisible()
})
