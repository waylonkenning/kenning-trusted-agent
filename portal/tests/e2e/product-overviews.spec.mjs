import { test, expect } from './fixtures.mjs'
import { apiRequest, failNextClipboardWrite, signInPortal } from './helpers.mjs'

const PRODUCTS = [
  { section: 'Agent Identity', title: 'Agent Identity', endpoint: '/v1/agents' },
  { section: 'Agent Guard', title: 'Agent Guard', endpoint: '/v1/actions/evaluate' },
  { section: 'Agent Proof', title: 'Agent Proof', endpoint: '/v1/proofs' },
  { section: 'Citation Trust', title: 'Citation Trust', endpoint: '/v1/citation-reports/extract' },
]

for (const product of PRODUCTS) {
  test(`product connection details render setup and API guidance for ${product.title}`, async ({ page, e2e }) => {
    await signInPortal(page, e2e)
    await page
      .locator('.portal-nav-section')
      .filter({ hasText: product.section })
      .getByRole('button', { name: 'Connection details' })
      .click()
    await expect(page.getByRole('heading', { name: product.title, exact: true })).toBeVisible()
    const quickStartHeading = product.title === 'Agent Guard' ? 'Connect your agent' : 'Setup'
    await expect(page.getByRole('heading', { name: quickStartHeading, exact: true })).toBeVisible()
    await expect(page.getByRole('heading', { name: 'Endpoints' })).toBeVisible()
    await expect(page.getByText(product.endpoint, { exact: true }).first()).toBeVisible()
    await expect(page.getByRole('link', { name: 'API reference' })).toBeVisible()
  })
}

test('product connection config keeps a new credential recoverable after a blocked copy', async ({ page, e2e }) => {
  await signInPortal(page, e2e)
  await page
    .locator('.portal-nav-section')
    .filter({ hasText: 'Agent Guard' })
    .getByRole('button', { name: 'Connection details' })
    .click()
  await expect(page.getByRole('heading', { name: 'Agent Guard', exact: true })).toBeVisible()

  await failNextClipboardWrite(page)
  let tokenId = ''
  try {
    const createToken = page.waitForResponse((response) => {
      const url = new URL(response.url())
      return response.request().method() === 'POST' && url.pathname.endsWith('/v1/tokens')
    })
    const createButton = page.getByRole('button', { name: 'Copy full config with PAT', exact: true })
    await createButton.click()
    const created = await createToken
    expect(created.ok()).toBe(true)
    const payload = await created.json()
    tokenId = payload.token_metadata?.token_id || ''
    expect(payload.token).toMatch(/^kta_pat_/)

    const config = page.locator('.portal-overview-snippet pre').filter({ hasText: payload.token })
    await expect(config).toBeVisible()
    expect(await page.evaluate(() => Object.values(localStorage).join('\n'))).not.toContain(payload.token)
    await expect(page.getByRole('alert')).toContainText('Could not copy.')
    const copyButton = page.getByRole('button', { name: 'Copy full config with PAT', exact: true })
    await expect(copyButton).toHaveText('Try again')
    await copyButton.click()
    await expect(page.getByRole('alert')).toHaveCount(0)
    await expect(copyButton).toHaveText('Copied')
    await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toContain(payload.token)
  } finally {
    if (tokenId) await apiRequest(e2e, `/v1/tokens/${encodeURIComponent(tokenId)}/revoke`, { method: 'POST', body: { tenant_id: e2e.tenantId } }).catch(() => {})
  }
})

test('citation findings view renders its dashboard and validates an empty report upload', async ({ page, e2e }) => {
  await signInPortal(page, e2e)
  await page
    .locator('.portal-nav-section')
    .filter({ hasText: 'Citation Trust' })
    .getByRole('button', { name: 'Citation findings' })
    .click()
  await expect(page.getByRole('heading', { name: 'Citation findings', exact: true })).toBeVisible()
  await expect(page.getByText('Responses verified')).toBeVisible()
  await expect(page.getByText('Needs review')).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Recent citation findings' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Check a real report' })).toBeVisible()

  // Uploading an empty text file exercises the client-side extraction guard
  // (no external network call), surfacing the report verifier's error path.
  await page.locator('#citation-report-upload').setInputFiles({
    name: 'empty.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from(''),
  })
  await expect(page.getByRole('alert')).toContainText(/No text could be extracted/i)
})

test('citation findings verifies a report and shows transport failures', async ({ page, e2e }) => {
  await signInPortal(page, e2e)
  await page
    .locator('.portal-nav-section')
    .filter({ hasText: 'Citation Trust' })
    .getByRole('button', { name: 'Citation findings', exact: true })
    .click()
  await expect(page.getByRole('heading', { name: 'Citation findings', exact: true })).toBeVisible()

  let failCitationTransport = false
  const reportManifest = {
    report_id: 'e2e-report-385',
    report_name: 'citation-e2e-report.txt',
    page_count: 1,
    content_sha256: '0'.repeat(64),
    citation_count: 1,
    citations: [{
      citation_id: 'citation-e2e-1',
      url: 'https://example.com/evidence',
      claim: 'The evidence supports the example claim.',
      page: 1,
      claim_support_required: true,
      category: 'in_text',
    }],
    reference_claims: [],
    reference_markers: [],
    bibliographic_references: [],
    extraction: { truncated: false, citation_categories: { in_text: 1 } },
  }
  await page.route('**/v1/citation-reports/extract', async (route) => {
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(reportManifest) })
  })
  await page.route('**/mcp/citation-trust', async (route) => {
    if (failCitationTransport) {
      await route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({ message: 'Citation Trust is temporarily unavailable.' }),
      })
      return
    }
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        result: {
          structuredContent: {
            citations: [{ source_verified: true, supports_claim: true, source_score: 100, confidence: 1 }],
          },
        },
      }),
    })
  })

  await page.locator('#citation-report-upload').setInputFiles({
    name: 'citation-e2e-report.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('The evidence supports the example claim. https://example.com/evidence'),
  })
  const reportSummary = page.locator('.portal-report-summary')
  await expect(reportSummary).toHaveClass(/success/)
  await expect(reportSummary).toContainText('1 URLs found')
  await expect(page.locator('.portal-report-details')).toContainText('https://example.com/evidence')
  await expect(page.locator('.portal-report-details')).toContainText('verified')
  await expect(page.locator('.portal-report-details')).toContainText('supported')

  failCitationTransport = true
  await page.locator('#citation-report-upload').setInputFiles({
    name: 'citation-e2e-transport-failure.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('The evidence supports the example claim. https://example.com/evidence'),
  })
  await expect(reportSummary).toHaveClass(/failure/)
  await expect(reportSummary).toContainText('1 transport failures')
  await expect(page.locator('.portal-report-details')).toContainText('transport failed')
  await expect(page.locator('.portal-report-details')).toContainText('transport failure')
})
