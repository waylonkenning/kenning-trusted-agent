import { test, expect } from './fixtures.mjs'
import { apiRequest, approvalRow, failNextClipboardWrite, portalUrl, signInPortal, signInWithPat } from './helpers.mjs'

test('authenticated console shows a persistent environment indicator banner', async ({ page, e2e }) => {
  await signInPortal(page, e2e)
  const banner = page.locator('.portal-env-banner')
  await expect(banner).toBeVisible()
  const text = (await banner.textContent() || '').trim().toUpperCase()
  expect(text).not.toContain('ENVIRONMENT NOT CONFIGURED')
  expect(['DEVELOPMENT', 'PRODUCTION'].some((label) => text.includes(label))).toBeTruthy()
})

test('authenticated console shows the release identity and changelog link', async ({ page, e2e }) => {
  await signInPortal(page, e2e)
  const releaseLink = page.getByRole('link', { name: /View changelog for release/ })
  await expect(releaseLink).toBeVisible()
  await expect(releaseLink).toHaveAttribute('href', '/CHANGELOG.md')
  await expect(releaseLink).toContainText(/\d+\.\d+\.\d+/)
})

test('console surfaces partial view load failures and recovers with retry', async ({ page, e2e }) => {
  let allowMetrics = false
  await page.route('**/v1/metrics**', async (route) => {
    if (!allowMetrics) {
      await route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({ message: 'Temporary metrics outage' }),
      })
      return
    }
    await route.continue()
  })

  await signInPortal(page, e2e)
  const alert = page.getByRole('alert')
  await expect(alert).toContainText('Some workspace data could not be loaded. Retry to refresh this view.')
  await expect(page.getByRole('heading', { name: 'Decision record', exact: true })).toBeVisible()

  allowMetrics = true
  await alert.getByRole('button', { name: 'Retry', exact: true }).click()
  await expect(alert).toHaveCount(0)
  await expect(page.getByRole('heading', { name: 'Decision record', exact: true })).toBeVisible()
})

test('authenticated tenant users can start passkey registration and see completion status', async ({ page, e2e }) => {
  await signInPortal(page, e2e)
  const passkey = page.getByRole('link', { name: 'Add or manage passkey' })
  await expect(passkey).toBeVisible()
  await expect(passkey).toHaveAttribute('href', /\/auth\/passkeys$/)
  await page.goto('/app?passkey=added', { waitUntil: 'domcontentloaded' })
  await expect(page.getByRole('status')).toContainText('Passkey registration completed')
})

test('Agent Guard connection details open the Connect your agent wizard', async ({ page, e2e }) => {
  await signInPortal(page, e2e)
  const guardSection = page.locator('.portal-nav-section').filter({ hasText: 'Agent Guard' })
  await guardSection.getByRole('button', { name: 'Connection details', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Agent Guard', exact: true })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Connect your agent', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Connect your agent', exact: true }).click()
  await expect(page.getByRole('heading', { name: /Welcome to/ })).toBeVisible()
})

test('tenant administrator can operate every tenant portal view', async ({ page, e2e }) => {
  test.setTimeout(120_000)
  await signInPortal(page, e2e)

  const tenantPath = `/v1/tenants/${encodeURIComponent(e2e.tenantId)}`
  const waitForApi = (method, path) => page.waitForResponse((response) => {
    const url = new URL(response.url())
    return response.request().method() === method && url.pathname.endsWith(path)
  })
  const saveConfiguration = async () => {
    const put = waitForApi('PUT', tenantPath)
    const get = waitForApi('GET', tenantPath)
    await page.getByRole('button', { name: 'Save workspace settings' }).click()
    await Promise.all([put, get])
  }
  const saveEvidenceControls = async () => {
    const put = waitForApi('PUT', tenantPath)
    const get = waitForApi('GET', tenantPath)
    await page.getByRole('button', { name: 'Save evidence controls' }).click()
    await Promise.all([put, get])
  }

  await expect(page.getByRole('button', { name: 'Overview' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Workspace settings' })).toBeVisible()
  for (const section of ['Agent Identity', 'Agent Guard', 'Agent Proof', 'Citation Trust', 'Workspace settings']) {
    await expect(page.locator('.portal-nav-section-label').filter({ hasText: section })).toBeVisible()
  }
  await expect(page.getByLabel('Select workspace')).toHaveValue(e2e.tenantId)
  await page.getByRole('button', { name: 'Refresh' }).click()
  await expect(page.getByRole('heading', { name: 'Decision record' })).toBeVisible()

  await page.getByRole('button', { name: 'Agents and connections' }).click()
  await expect(page.getByRole('heading', { name: 'Agents and connections' })).toBeVisible()
  const agentId = `portal-agent-${Date.now().toString(36)}`
  await page.getByLabel('Agent ID').fill(agentId)
  await page.getByLabel('Purpose').fill('Playwright tenant portal validation')
  await page.getByLabel('Approved tools').fill('shell, sql')
  await page.getByRole('button', { name: 'Register agent' }).click()
  await expect(page.getByText(agentId, { exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Refresh' }).click()
  await expect(page.getByText(agentId, { exact: true })).toBeVisible()
  const agentRow = page.locator('tr').filter({ hasText: agentId })
  await agentRow.getByRole('button', { name: 'View impact assessment', exact: true }).click()
  await expect(page.getByRole('heading', { name: agentId, exact: true })).toBeVisible()
  await page.getByLabel('Summary', { exact: true }).fill('The agent reviews supplier proposals and recommends a preferred supplier.')
  await page.getByLabel('Impacts on individuals and groups', { exact: true }).fill('Reviewers and supplier contacts may be affected by an incorrect recommendation.')
  await page.getByLabel('Impacts on society', { exact: true }).fill('Repeated recommendations may influence supplier access and market concentration.')
  await page.getByLabel('Mitigations', { exact: true }).fill('Use human review, record the evidence, and monitor outcomes for disparate impact.')
  await page.getByLabel('Assessor', { exact: true }).fill('playwright-e2e')
  const assessmentPost = page.waitForResponse((response) => response.request().method() === 'POST' && new URL(response.url()).pathname.endsWith(`/v1/agents/${agentId}/impact-assessments`))
  await page.getByRole('button', { name: 'Save impact assessment', exact: true }).click()
  expect((await assessmentPost).ok()).toBe(true)
  await expect(page.getByText('assessed', { exact: true }).first()).toBeVisible()
  await expect(page.getByText('The agent reviews supplier proposals and recommends a preferred supplier.', { exact: true })).toBeVisible()

  await page.getByRole('button', { name: 'Rules' }).click()
  await expect(page.getByRole('heading', { name: 'Rules', exact: true })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Compliance coverage', exact: true })).toBeVisible()
  let latestStarterRulesResponse = null
  let serveStaleStarterRules = false
  await page.route('**/v1/tenants/*/starter-rules', async (route) => {
    if (route.request().method() !== 'GET') {
      await route.continue()
      return
    }
    const response = await route.fetch()
    const payload = await response.json()
    if (!serveStaleStarterRules) latestStarterRulesResponse = payload
    await route.fulfill({
      response,
      body: JSON.stringify(serveStaleStarterRules && latestStarterRulesResponse ? latestStarterRulesResponse : payload),
    })
  })
  const rulesTable = page.locator('.portal-unified-rules')
  const builtinRuleRow = rulesTable.locator('tr').filter({ hasText: 'CREDENTIAL_EXPOSURE' })
  await expect(builtinRuleRow).toBeVisible()
  await expect(builtinRuleRow.getByText('Kenning default', { exact: true })).toBeVisible()
  await expect(builtinRuleRow).toContainText('NZ Algorithm Charter:Accountability')
  await page.route('**/v1/tenants/*/starter-rules/simulate', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ decision: 'deny', simulation: true, simulated_rule_id: 'CREDENTIAL_EXPOSURE', reason_codes: ['CREDENTIAL_EXPOSURE'] }) }))
  await builtinRuleRow.getByRole('button', { name: 'Simulate', exact: true }).click()
  await page.getByRole('button', { name: 'Test this policy', exact: true }).click()
  await expect(page.getByText('Test result', { exact: true })).toBeVisible()
  await page.unroute('**/v1/tenants/*/starter-rules/simulate')
  const policyId = `portal-policy-${Date.now().toString(36)}`
  await page.locator('#policy-id').fill(policyId)
  await page.locator('#policy-name').fill('Playwright portal policy')
  await page.locator('#policy-compliance-tags').fill('NZ Algorithm Charter:Transparency, Privacy Act 2020:IPP 5')
  await page.getByLabel('Condition value', { exact: true }).first().fill('shell')
  await expect(page.locator('#policy-id')).toHaveValue(policyId)
  await page.getByRole('button', { name: 'Create policy' }).click()
  const policyRow = rulesTable.locator('tr').filter({ hasText: policyId })
  await expect(policyRow).toBeVisible()
  await expect(policyRow.getByText('Workspace', { exact: true })).toBeVisible()
  await expect(policyRow).toContainText('Privacy Act 2020:IPP 5')
  await expect(page.locator('#compliance-coverage')).toContainText(policyId)
  const publishResponse = page.waitForResponse((response) => response.request().method() === 'POST' && new URL(response.url()).pathname.endsWith(`/v1/policies/${policyId}/publish`))
  await policyRow.getByRole('button', { name: 'Edit', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Continue editing this draft', exact: true })).toBeVisible()
  await expect(page.locator('#policy-name')).toHaveValue('Playwright portal policy')
  await page.locator('#policy-name').fill('Edited Playwright portal policy')
  await page.getByRole('button', { name: 'Save draft', exact: true }).click()
  await expect(policyRow).toContainText('Edited Playwright portal policy')

  const deletePolicyId = `portal-draft-delete-${Date.now().toString(36)}`
  await page.locator('#policy-id').fill(deletePolicyId)
  await page.locator('#policy-name').fill('Draft to delete')
  await page.getByRole('button', { name: 'Create policy', exact: true }).click()
  const deletePolicyRow = rulesTable.locator('tr').filter({ hasText: deletePolicyId })
  await expect(deletePolicyRow).toBeVisible()
  page.once('dialog', async (dialog) => {
    expect(dialog.message()).toContain('This cannot be undone')
    await dialog.accept()
  })
  await deletePolicyRow.getByRole('button', { name: 'Delete', exact: true }).click()
  await expect(deletePolicyRow).toHaveCount(0)

  await policyRow.getByRole('button', { name: 'Publish' }).click()
  expect((await publishResponse).ok()).toBe(true)
  await expect(policyRow.getByText('published', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Refresh' }).click()
  await expect(page.locator('tr').filter({ hasText: policyId }).getByText('published', { exact: true })).toBeVisible()

  await expect(page.getByRole('heading', { name: 'Enable, disable, remove, or restore defaults', exact: true })).toBeVisible()
  const starterRuleId = `portal-starter-${Date.now().toString(36)}`
  await page.getByLabel('Rule ID').last().fill(starterRuleId)
  await page.getByLabel('Name').last().fill('Portal starter review')
  await page.getByLabel('Conditions JSON').last().fill('{"tool":"shell","environment":"production"}')
  await page.getByRole('button', { name: 'Add workspace rule' }).click()
  await expect(page.locator('.portal-starter-rule').filter({ hasText: starterRuleId })).toBeVisible()
  const starterPut = waitForApi('PUT', `${tenantPath}/starter-rules`)
  const starterGet = waitForApi('GET', `${tenantPath}/starter-rules`)
  await page.getByRole('button', { name: 'Save starter rules' }).click()
  await Promise.all([starterPut, starterGet])
  await expect(page.locator('.portal-starter-rule').filter({ hasText: starterRuleId })).toBeVisible()
  const customStarter = page.locator('.portal-starter-rule').filter({ hasText: starterRuleId })
  await customStarter.getByRole('button', { name: 'Remove rule' }).click()
  const removedPut = waitForApi('PUT', `${tenantPath}/starter-rules`)
  const removedGet = waitForApi('GET', `${tenantPath}/starter-rules`)
  serveStaleStarterRules = true
  await page.getByRole('button', { name: 'Save starter rules' }).click()
  await Promise.all([removedPut, removedGet])
  serveStaleStarterRules = false
  await expect(page.getByText(starterRuleId, { exact: true })).toHaveCount(0)

  await page.getByRole('button', { name: 'Approvals', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Approvals', exact: true })).toBeVisible()
  const approval = approvalRow(page, e2e.portalApproval.approvalId)
  await expect(approval).toBeVisible()
  await expect(approval.getByText('Kenning default', { exact: true })).toBeVisible()
  await expect(approval).toContainText('DESTRUCTIVE_FILESYSTEM_OPERATION')
  await expect(approval.getByText('1970')).toHaveCount(0)
  await approval.getByRole('button', { name: 'Approve' }).click()
  await expect(approval.getByText('approved', { exact: true })).toBeVisible()
  await expect(approval.getByRole('button', { name: 'Approve' })).toHaveCount(0)
  await page.getByRole('button', { name: 'Refresh' }).click()
  await expect(approval.getByText('approved', { exact: true })).toBeVisible()

  await page.getByRole('button', { name: 'Members' }).click()
  await expect(page.getByRole('heading', { name: 'Members', exact: true })).toBeVisible()
  const memberSubject = `playwright-viewer-${Date.now().toString(36)}`
  await page.locator('#member-subject').fill(memberSubject)
  await page.locator('#member-role').selectOption('viewer')
  await page.getByRole('button', { name: 'Create invitation' }).click()
  await expect(page.getByText(memberSubject, { exact: true })).toBeVisible()
  const memberRow = page.locator('tr').filter({ hasText: memberSubject })
  const memberPath = `${tenantPath}/members/${encodeURIComponent(memberSubject)}`
  const memberPatch = waitForApi('PATCH', memberPath)
  const memberGet = waitForApi('GET', `${tenantPath}/members`)
  await memberRow.getByRole('combobox').nth(0).selectOption('approver')
  await Promise.all([memberPatch, memberGet])
  await expect(memberRow.getByRole('combobox').nth(0)).toHaveValue('approver')
  const statusPatch = waitForApi('PATCH', memberPath)
  const statusGet = waitForApi('GET', `${tenantPath}/members`)
  await memberRow.getByRole('combobox').nth(1).selectOption('active')
  await Promise.all([statusPatch, statusGet])
  await expect(memberRow.getByRole('combobox').nth(1)).toHaveValue('active')
  await page.getByRole('button', { name: 'Refresh' }).click()
  await expect(page.locator('tr').filter({ hasText: memberSubject })).toBeVisible()

  await page.getByRole('button', { name: 'History and proof' }).click()
  await expect(page.getByRole('heading', { name: 'Audit and proof' })).toBeVisible()
  const classificationRow = page.locator('.portal-table tbody tr').filter({ hasText: e2e.portalClassification.actionId })
  await expect(classificationRow).toContainText('restricted')
  await expect(page.locator('.portal-table').getByRole('button', { name: e2e.portalApproval.proofId, exact: true })).toBeVisible()
  await page.getByRole('button', { name: e2e.portalApproval.proofId }).click()
  await expect(page.getByText('Record unchanged')).toBeVisible()
  const downloadPromise = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Export' }).click()
  const download = await downloadPromise
  expect(download.suggestedFilename()).toBe(`${e2e.tenantId}-audit.json`)
  await page.getByRole('button', { name: 'Refresh' }).click()
  await expect(page.locator('.portal-table').getByRole('button', { name: e2e.portalApproval.proofId, exact: true })).toBeVisible()

  await page.getByRole('button', { name: 'Workspace settings' }).click()
  await expect(page.getByRole('heading', { name: 'Workspace settings' })).toBeVisible()
  await page.getByRole('button', { name: 'Refresh' }).click()
  await expect(page.getByLabel('Workspace name')).toBeVisible()
  await expect(page.getByRole('heading', { name: 'AI model registry', exact: true })).toBeVisible()
  const modelId = `portal-model-${Date.now().toString(36)}`
  await page.getByLabel('Model ID', { exact: true }).fill(modelId)
  await page.getByLabel('Model name', { exact: true }).fill('Portal test model')
  await page.getByLabel('Vendor', { exact: true }).fill('Kenning Labs')
  await page.getByLabel('Version', { exact: true }).fill('2026.1')
  await page.getByLabel('Risk tier', { exact: true }).selectOption('high')
  const modelPost = waitForApi('POST', '/v1/models')
  const modelGet = waitForApi('GET', '/v1/models')
  await page.getByRole('button', { name: 'Register model', exact: true }).click()
  await Promise.all([modelPost, modelGet])
  await expect(page.locator('tr').filter({ hasText: modelId })).toBeVisible()
  const agentProofCheckbox = page.getByLabel('Agent Proof')
  await expect(page.getByRole('heading', { name: 'Workspace products' })).toBeVisible()
  await expect(agentProofCheckbox).toBeChecked()
  await agentProofCheckbox.uncheck()
  page.once('dialog', async (dialog) => {
    expect(dialog.message()).toContain('Changing products updates workspace access')
    await dialog.accept()
  })
  const productsPut = waitForApi('PUT', tenantPath)
  const productsGet = waitForApi('GET', tenantPath)
  await page.getByRole('button', { name: 'Save product access' }).click()
  await Promise.all([productsPut, productsGet])
  await expect(agentProofCheckbox).not.toBeChecked()
  await expect(page.locator('.portal-nav-section-label').filter({ hasText: 'Agent Proof' })).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'History and proof', exact: true })).toHaveCount(0)
  await agentProofCheckbox.check()
  page.once('dialog', async (dialog) => await dialog.accept())
  const productsReenablePut = waitForApi('PUT', tenantPath)
  const productsReenableGet = waitForApi('GET', tenantPath)
  await page.getByRole('button', { name: 'Save product access' }).click()
  await Promise.all([productsReenablePut, productsReenableGet])
  await expect(agentProofCheckbox).toBeChecked()
  await expect(page.locator('.portal-nav-section-label').filter({ hasText: 'Agent Proof' })).toBeVisible()

  const agentIdentityCheckbox = page.getByLabel('Agent Identity')
  await expect(agentIdentityCheckbox).toBeChecked()
  await agentIdentityCheckbox.uncheck()
  page.once('dialog', async (dialog) => await dialog.accept())
  const identityDisabledPut = waitForApi('PUT', tenantPath)
  const identityDisabledGet = waitForApi('GET', tenantPath)
  await page.getByRole('button', { name: 'Save product access' }).click()
  await Promise.all([identityDisabledPut, identityDisabledGet])
  await expect(agentIdentityCheckbox).not.toBeChecked()
  await expect(page.locator('.portal-nav-section-label').filter({ hasText: 'Agent Identity' })).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Agents and connections', exact: true })).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Access tokens', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Access tokens', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Access tokens', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Workspace settings', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Workspace settings', exact: true })).toBeVisible()
  await expect(page.getByLabel('Agent Proof')).toBeChecked()
  await expect(agentIdentityCheckbox).not.toBeChecked()
  await agentIdentityCheckbox.check()
  page.once('dialog', async (dialog) => await dialog.accept())
  const identityReenablePut = waitForApi('PUT', tenantPath)
  const identityReenableGet = waitForApi('GET', tenantPath)
  await page.getByRole('button', { name: 'Save product access' }).click()
  await Promise.all([identityReenablePut, identityReenableGet])
  await expect(agentIdentityCheckbox).toBeChecked()
  await expect(page.locator('.portal-nav-section-label').filter({ hasText: 'Agent Identity' })).toBeVisible()

  const updatedName = `Playwright tenant updated ${Date.now().toString(36)}`
  await page.getByLabel('Workspace name').fill(updatedName)
  await saveConfiguration()
  await expect(page.getByText(updatedName, { exact: true })).toBeVisible()
  await expect(page.getByLabel('Retention days')).toHaveValue('30')
  await page.getByLabel('Keep data for a legal matter').check()
  await page.getByLabel('Legal hold reason').fill('Playwright retention-control check')
  await saveConfiguration()
  await expect(page.getByLabel('Keep data for a legal matter')).toBeChecked()
  await page.getByLabel('Keep data for a legal matter').uncheck()
  await saveConfiguration()
  await expect(page.getByLabel('Keep data for a legal matter')).not.toBeChecked()

  await page.locator('#environment-id').fill('staging')
  await page.locator('#environment-name').fill('Staging')
  await page.locator('#environment-tools').fill('shell, sql')
  await expect(page.locator('#environment-id')).toHaveValue('staging')
  await expect(page.locator('#environment-name')).toHaveValue('Staging')
  const environmentPut = waitForApi('PUT', `${tenantPath}/environments/staging`)
  const environmentGet = waitForApi('GET', `${tenantPath}/environments`)
  await page.getByRole('button', { name: 'Save environment' }).click()
  await Promise.all([environmentPut, environmentGet])
  await expect(page.getByText('staging', { exact: true })).toBeVisible()

  await page.getByLabel('Redact fields').fill('credentials, target')
  await page.getByLabel('Hash fields').fill('parameters.statement')
  await page.getByLabel('Maximum captured field length').fill('2048')
  await saveEvidenceControls()
  await expect(page.getByRole('button', { name: 'Save evidence controls' })).toBeVisible()
  const auditSink = page.getByLabel('Deliver audit events to a destination system')
  await auditSink.check()
  await page.getByLabel('HTTPS endpoint').fill('https://siem.example.org/kenning')
  await page.getByLabel('AWS Secrets Manager reference').fill(e2e.auditSecretArn)
  await page.getByLabel('Format').selectOption('ndjson')
  await page.getByLabel('Delivery timeout (milliseconds)').fill('750')
  await saveEvidenceControls()
  await expect(auditSink).toBeChecked()
  await auditSink.uncheck()
  await saveEvidenceControls()
  await expect(auditSink).not.toBeChecked()

  await page.getByRole('button', { name: 'Sign out' }).click()
  await expect(page.getByRole('heading', { name: 'Sign in to manage your workspace.' })).toBeVisible()
})

test('tenant administrator can manage ISO governance records', async ({ page, e2e }) => {
  test.setTimeout(120_000)
  await signInPortal(page, e2e)

  await page.getByRole('button', { name: 'Agents and connections', exact: true }).click()
  const agentId = `iso-agent-${Date.now().toString(36)}`
  await page.getByLabel('Agent ID', { exact: true }).fill(agentId)
  await page.getByLabel('Purpose', { exact: true }).fill('Maintain ISO governance evidence')
  await page.getByRole('button', { name: 'Register agent', exact: true }).click()
  await expect(page.getByText(agentId, { exact: true })).toBeVisible()
  const agentRow = page.locator('tr').filter({ hasText: agentId })
  await agentRow.getByRole('button', { name: 'View impact assessment', exact: true }).click()
  await page.getByLabel('Design', { exact: true }).fill('The agent maintains governance evidence for approved systems.')
  await page.getByLabel('Resources', { exact: true }).fill('It uses the tenant model registry, audit stream, and supplier records.')
  await page.getByLabel('Verification', { exact: true }).fill('Unit and browser tests verify the evidence workflow.')
  await page.getByLabel('Operational', { exact: true }).fill('The workspace owner reviews changes during management review.')
  const documentationPut = page.waitForResponse((response) => response.request().method() === 'PUT' && new URL(response.url()).pathname.endsWith(`/v1/agents/${agentId}`))
  await page.getByRole('button', { name: 'Save life-cycle documentation', exact: true }).click()
  expect((await documentationPut).ok()).toBe(true)
  await expect(page.getByText('4/4', { exact: true }).first()).toBeVisible()

  await page.getByRole('button', { name: 'Workspace settings', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Supplier registry', exact: true })).toBeVisible()
  const supplierName = `ISO supplier ${Date.now().toString(36)}`
  await page.locator('#supplier-name').fill(supplierName)
  const supplierPost = page.waitForResponse((response) => response.request().method() === 'POST' && new URL(response.url()).pathname.endsWith('/v1/suppliers'))
  const supplierGet = page.waitForResponse((response) => response.request().method() === 'GET' && new URL(response.url()).pathname.endsWith('/v1/suppliers'))
  await page.getByRole('button', { name: 'Register supplier', exact: true }).click()
  await Promise.all([supplierPost, supplierGet])
  await expect(page.getByText(supplierName, { exact: true })).toBeVisible()
  const supplierResponse = await apiRequest(e2e, '/v1/suppliers')
  const supplier = supplierResponse.suppliers.find((item) => item.name === supplierName)
  expect(supplier?.supplier_id).toBeTruthy()

  const modelId = `iso-model-${Date.now().toString(36)}`
  await page.getByLabel('Model ID', { exact: true }).fill(modelId)
  await page.getByLabel('Model name', { exact: true }).fill('ISO governance model')
  await page.getByLabel('Vendor', { exact: true }).fill('Kenning Labs')
  await page.getByLabel('Version', { exact: true }).fill('1.0')
  await page.locator('#model-supplier').selectOption(supplier.supplier_id)
  const modelPost = page.waitForResponse((response) => response.request().method() === 'POST' && new URL(response.url()).pathname.endsWith('/v1/models'))
  const modelGet = page.waitForResponse((response) => response.request().method() === 'GET' && new URL(response.url()).pathname.endsWith('/v1/models'))
  await page.getByRole('button', { name: 'Register model', exact: true }).click()
  await Promise.all([modelPost, modelGet])
  const modelRow = page.locator('tr').filter({ hasText: modelId })
  await expect(modelRow).toBeVisible()
  await expect(modelRow).toContainText(supplierName)
  await expect(modelRow.getByText('0', { exact: true })).toBeVisible()

  const resourcesGet = page.waitForResponse((response) => response.request().method() === 'GET' && new URL(response.url()).pathname.endsWith(`/v1/models/${modelId}/data-resources`))
  await modelRow.getByRole('button', { name: 'View data resources', exact: true }).click()
  await resourcesGet
  await expect(page.getByRole('heading', { name: /ISO governance model · 1\.0/ })).toBeVisible()
  const resourceName = 'ISO-approved training set'
  await page.locator('#data-resource-name').fill(resourceName)
  await page.locator('#data-resource-source').fill('Approved tenant samples')
  const resourcePost = page.waitForResponse((response) => response.request().method() === 'POST' && new URL(response.url()).pathname.endsWith(`/v1/models/${modelId}/data-resources`))
  await page.getByRole('button', { name: 'Register data resource', exact: true }).click()
  expect((await resourcePost).ok()).toBe(true)
  await expect(page.getByText(resourceName, { exact: true })).toBeVisible()

  const findingTitle = `ISO finding ${Date.now().toString(36)}`
  await page.locator('#nonconformity-title').fill(findingTitle)
  await page.locator('#nonconformity-description').fill('Supplier evidence requires a corrective action record.')
  const findingPost = page.waitForResponse((response) => response.request().method() === 'POST' && new URL(response.url()).pathname.endsWith('/v1/nonconformities'))
  const findingGet = page.waitForResponse((response) => response.request().method() === 'GET' && new URL(response.url()).pathname.endsWith('/v1/nonconformities'))
  await page.getByRole('button', { name: 'Raise nonconformity', exact: true }).click()
  await Promise.all([findingPost, findingGet])
  const findingRow = page.locator('tr').filter({ hasText: findingTitle })
  await expect(findingRow).toBeVisible()
  await expect(page.locator('.portal-nav .portal-pill.danger')).toBeVisible()
  page.once('dialog', async (dialog) => await dialog.accept('Add supplier evidence to the review checklist.'))
  const resolvePost = page.waitForResponse((response) => response.request().method() === 'POST' && new URL(response.url()).pathname.includes('/v1/nonconformities/') && new URL(response.url()).pathname.endsWith('/resolve'))
  await findingRow.getByRole('button', { name: 'Resolve', exact: true }).click()
  expect((await resolvePost).ok()).toBe(true)
  await expect(findingRow.getByText('resolved', { exact: true })).toBeVisible()

  await page.locator('#concern-description').fill('The supplier evidence process needs a second reviewer.')
  await page.getByLabel('Submit anonymously', { exact: true }).check()
  const concernPost = page.waitForResponse((response) => response.request().method() === 'POST' && new URL(response.url()).pathname.endsWith('/v1/concerns'))
  await page.getByRole('button', { name: 'Submit concern', exact: true }).click()
  expect((await concernPost).ok()).toBe(true)
})

test('tenant administrator can deny an action and return to the sign-in screen', async ({ page, e2e }) => {
  await signInPortal(page, e2e)
  await page.getByRole('button', { name: 'Approvals', exact: true }).click()
  const approval = approvalRow(page, e2e.portalDenyApproval.approvalId)
  await expect(approval).toBeVisible()
  const decisionResponse = page.waitForResponse((response) => {
    const url = new URL(response.url())
    return response.request().method() === 'POST' && url.pathname.endsWith(`/v1/approvals/${e2e.portalDenyApproval.approvalId}/decision`)
  })
  await approval.getByRole('button', { name: 'Deny' }).click()
  const decision = await decisionResponse
  expect(decision.ok()).toBe(true)
  expect((await decision.json()).approval.status).toBe('denied')
  // The queue intentionally returns pending and approved items only; a denied
  // request disappears after the successful decision and remains in audit.
  await expect(approval).toHaveCount(0)
  await page.getByRole('button', { name: 'Sign out' }).click()
  await expect(page.getByRole('heading', { name: 'Sign in to manage your workspace.' })).toBeVisible()
})

test('overview shows the configured environment count', async ({ page, e2e }) => {
  const tenant = await apiRequest(e2e, `/v1/tenants/${encodeURIComponent(e2e.tenantId)}`)
  const count = Number(tenant.environment_count ?? (Array.isArray(tenant.environments) ? tenant.environments.length : 0))
  const label = `${count} environment${count === 1 ? '' : 's'}`
  if (new URL(portalUrl).hostname === 'localhost') {
    await page.route(`**/v1/tenants/${encodeURIComponent(e2e.tenantId)}`, async (route) => {
      if (route.request().method() !== 'GET') return route.continue()
      const response = await route.fetch()
      const payload = await response.json()
      if (payload && typeof payload === 'object' && payload.environment_count === undefined) {
        const environments = Array.isArray(payload.environments) ? payload.environments : []
        return route.fulfill({ response, body: JSON.stringify({ ...payload, environment_ids: environments.map((item) => item.environment_id).filter(Boolean).sort(), environment_count: environments.length }) })
      }
      return route.fulfill({ response })
    })
  }
  await signInPortal(page, e2e)
  await expect(page.getByText(label, { exact: true })).toBeVisible()
})

test('tenant administrator can suspend, re-activate, and delete a published policy', async ({ page, e2e }) => {
  const policyId = `portal-lifecycle-${Date.now().toString(36)}`
  const created = await apiRequest(e2e, '/v1/policies', {
    method: 'POST',
    body: {
      context: { tenant_id: e2e.tenantId },
      policy_id: policyId,
      name: 'Portal lifecycle policy',
      rules: [{ rule_id: 'portal-lifecycle-rule', tool: 'shell', decision: 'deny', reason: 'Lifecycle test policy.' }],
    },
  })
  await apiRequest(e2e, `/v1/policies/${encodeURIComponent(policyId)}/publish`, {
    method: 'POST',
    body: { version: created.version },
  })

  try {
    await signInPortal(page, e2e)
    await page.getByRole('button', { name: 'Rules', exact: true }).click()
    await expect(page.getByRole('heading', { name: 'Rules', exact: true })).toBeVisible()
    const policyRow = page.locator('tr').filter({ hasText: policyId })
    await expect(policyRow).toBeVisible()
    await expect(policyRow.getByText('published', { exact: true })).toBeVisible()

    await policyRow.getByRole('button', { name: 'Suspend', exact: true }).click()
    await expect(page.getByRole('alertdialog')).toContainText('without removing its history')
    await page.getByRole('button', { name: 'Suspend policy', exact: true }).click()
    await expect(policyRow.getByText('suspended', { exact: true })).toBeVisible()

    await policyRow.getByRole('button', { name: 'Re-activate', exact: true }).click()
    await expect(page.getByRole('alertdialog')).toContainText('eligible for evaluation again')
    await page.getByRole('button', { name: 'Re-activate policy', exact: true }).click()
    await expect(policyRow.getByText('published', { exact: true })).toBeVisible()

    await policyRow.getByRole('button', { name: 'Delete', exact: true }).click()
    await expect(page.getByRole('alertdialog')).toContainText('cannot be undone')
    await page.getByRole('button', { name: 'Delete policy', exact: true }).click()
    await expect(policyRow).toHaveCount(0)
  } finally {
    await apiRequest(e2e, `/v1/policies/${encodeURIComponent(policyId)}`, {
      method: 'DELETE',
      body: { version: created.version, confirm: true },
    }).catch(() => {})
  }
})

test('authenticated identity without membership receives the no-workspace screen', async ({ page, e2e }) => {
  await signInWithPat(page, e2e.unassignedPat)
  await expect(page.getByRole('heading', { name: 'You are signed in, but you do not have access to a workspace yet.' })).toBeVisible()
  await page.getByRole('button', { name: 'Sign out' }).click()
  await expect(page.getByRole('heading', { name: 'Sign in to manage your workspace.' })).toBeVisible()
})

test('tenant portal does not expose invalid PAT entry through human sign-in', async ({ page }) => {
  await page.goto('/app', { waitUntil: 'domcontentloaded' })
  await expect(page.getByLabel('Personal access token')).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Open Kenning console' })).toHaveCount(0)
  await expect(page.getByRole('heading', { name: 'Sign in to manage your workspace.' })).toBeVisible()
})

test('tenant administrator can create and revoke a shareable invitation link', async ({ page, e2e }) => {
  await signInPortal(page, e2e)
  await page.getByRole('button', { name: 'Members' }).click()
  await expect(page.getByRole('heading', { name: 'Members', exact: true })).toBeVisible()

  const tenantPath = `/v1/tenants/${encodeURIComponent(e2e.tenantId)}`
  const createInvitation = page.waitForResponse((response) => {
    const url = new URL(response.url())
    return response.request().method() === 'POST' && url.pathname.endsWith(`${tenantPath}/invitations`)
  })
  await page.locator('#invite-role').selectOption('approver')
  await page.locator('#invite-expires').fill('14')
  await page.locator('#invite-uses').fill('1')
  await page.getByRole('button', { name: 'Generate invitation link' }).click()
  const created = await createInvitation
  expect(created.ok()).toBe(true)
  const invitation = await created.json()
  expect(invitation.token).toContain('kta_invite_')
  const invitationUrl = new URL(invitation.link)
  expect(invitationUrl.pathname).toBe('/app')
  expect(invitationUrl.searchParams.get('invite')).toBe(invitation.token)

  // The one-time link is surfaced for copying.
  await expect(page.locator('.portal-token-issued')).toBeVisible()
  await expect(page.locator('.portal-token-issued .portal-eyebrow')).toContainText('copy it now')
  await expect(page.locator('.portal-token-issued code')).toContainText('kta_invite_')

  await failNextClipboardWrite(page)
  const copyLink = page.locator('.portal-token-issued').getByRole('button', { name: 'Copy invitation link', exact: true })
  await copyLink.click()
  const copyError = page.locator('.portal-token-issued').getByRole('alert')
  await expect(copyError).toContainText('Could not copy.')
  await expect(copyLink).toHaveText('Try again')
  await copyLink.click()
  await expect(copyError).toHaveCount(0)
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe(invitation.link)

  // The invitation appears in the listing with the chosen role.
  const invitationRow = page.locator('tr').filter({ hasText: invitation.invitation_id })
  await expect(invitationRow).toBeVisible()
  await expect(invitationRow.getByText('approver', { exact: true })).toBeVisible()

  // Revoking flips the status without a reload.
  const revokeInvitation = page.waitForResponse((response) => {
    const url = new URL(response.url())
    return response.request().method() === 'POST' && url.pathname.endsWith(`${tenantPath}/invitations/${invitation.invitation_id}/revoke`)
  })
  await invitationRow.getByRole('button', { name: 'Revoke' }).click()
  const revoked = await revokeInvitation
  expect(revoked.ok()).toBe(true)
  await expect(invitationRow.getByText('revoked', { exact: true })).toBeVisible()
})

test('new user can enroll from a shareable invitation link', async ({ page, e2e }) => {
  // An admin creates an invitation for the workspace.
  const invitation = await apiRequest(e2e, `/v1/tenants/${encodeURIComponent(e2e.tenantId)}/invitations`, {
    method: 'POST',
    body: { role: 'viewer', expires_in_days: 7, max_uses: 1 },
  })
  expect(invitation.token).toContain('kta_invite_')

  // A recipient with no membership opens the invitation link. The hosted
  // Cognito enrollment path must be reachable and the invite must survive the
  // sign-in redirect before the test uses the deterministic PAT session.
  await page.goto(invitation.link, { waitUntil: 'domcontentloaded' })
  const signInLink = page.getByRole('link', { name: 'Create account or sign in' })
  await expect(signInLink).toBeVisible()
  const signInUrl = new URL(await signInLink.getAttribute('href'), page.url())
  expect(signInUrl.pathname).toBe('/auth/login')
  expect(signInUrl.searchParams.get('invite')).toBe(invitation.token)
  await signInLink.click()
  const createAccountLink = page.getByRole('link', { name: 'Create an account' })
  await expect(createAccountLink).toBeVisible()
  const signUpUrl = new URL(await createAccountLink.getAttribute('href'), page.url())
  expect(signUpUrl.pathname).toBe('/signup')
  await createAccountLink.click()
  await expect(page.getByRole('heading', { name: 'Sign up' })).toBeVisible()

  // Use the existing unassigned identity for the rest of the test so CI does
  // not depend on a real confirmation email arriving in a mailbox.
  await signInWithPat(page, e2e.unassignedPat, invitation.link)

  // They land on the invitation acceptance screen rather than the dead-end.
  await expect(page.getByRole('heading', { name: 'You have been invited to join a workspace.' })).toBeVisible()
  await page.getByRole('button', { name: 'Accept invitation' }).click()

  // Accepting activates the membership and presents first-run setup guidance.
  await expect(page.getByRole('button', { name: 'Overview', exact: true })).toBeVisible()
  await expect(page.getByRole('heading', { name: /Welcome to/ })).toBeVisible()
})

test('first-run setup wizard walks a new member through protecting their agent', async ({ page, e2e }) => {
  // Sign in without dismissing the wizard; a fresh browser context shows it once.
  await signInWithPat(page, e2e.portalPat, portalUrl)

  // Step 1: welcome.
  await expect(page.getByRole('heading', { name: /Welcome to/ })).toBeVisible()
  await page.getByRole('button', { name: 'Yes, show me around' }).click()

  // Step 2: protect your agent.
  await expect(page.getByRole('heading', { name: 'Protect your AI agent from dangerous calls.' })).toBeVisible()
  await page.getByRole('button', { name: 'Yes, protect my agent' }).click()

  // Step 3: connect — create a scoped PAT, then show all supported installers and instructions.
  await expect(page.getByRole('heading', { name: 'Connect your AI agent.' })).toBeVisible()
  await page.getByRole('button', { name: 'Create scoped PAT', exact: true }).click()
  await expect(page.locator('code').filter({ hasText: /^kta_pat_/ }).first()).toBeVisible()
  await expect(page.getByRole('button', { name: 'Copy personal access token', exact: true })).toBeVisible()
  expect(await page.evaluate(() => Object.values(localStorage).join('\n'))).not.toContain('kta_pat_')
  await expect(page.locator('code').filter({ hasText: '/mcp' }).first()).toBeVisible()
  await expect(page.getByText(/--client opencode/).first()).toBeVisible()
  const claudeInstaller = page.locator('.portal-overview-snippet').filter({ hasText: 'Claude Code' })
  await expect(claudeInstaller).toContainText(/KENNING_PAT="kta_pat_/)
  await expect(claudeInstaller).not.toContainText('<YOUR_TENANT_SCOPED_PAT>')
  await failNextClipboardWrite(page)
  await claudeInstaller.getByRole('button', { name: 'Copy Claude Code installer command', exact: true }).click()
  const copyError = page.getByRole('alert').filter({ hasText: 'Could not copy.' })
  await expect(copyError).toBeVisible()
  await expect(claudeInstaller.getByRole('button', { name: 'Copy Claude Code installer command', exact: true })).toHaveText('Try again')
  await claudeInstaller.getByRole('button', { name: 'Copy Claude Code installer command', exact: true }).click()
  await expect(copyError).toHaveCount(0)
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toContain('KENNING_PAT="kta_pat_')
  await expect(page.getByText(/--client claude-code/).first()).toBeVisible()
  await expect(page.getByText(/--client codex-cli/).first()).toBeVisible()
  await expect(page.getByText(/KENNING_API_URL/).first()).toBeVisible()
  await expect(page.getByText(/KENNING_PAT/).first()).toBeVisible()
  await expect(page.getByText(/KENNING_TENANT_ID/).first()).toBeVisible()
  await expect(page.getByText('AGENTS.md instructions', { exact: true })).toBeVisible()
  await expect(page.getByText(/Before executing a tool call/)).toBeVisible()
  await page.getByText('Advanced / API details', { exact: true }).click()
  await expect(page.getByText(/\/v1\/actions\/evaluate$/)).toBeVisible()
  await page.getByRole('button', { name: 'Finish setup' }).click()

  // The wizard closes and the console is usable; the wizard does not reappear.
  await expect(page.getByRole('heading', { name: 'Decision record' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Yes, show me around' })).toHaveCount(0)
})

test('first-run setup wizard explains when scoped PAT creation returns no credential', async ({ page, e2e }) => {
  await page.route('**/v1/tokens', async (route) => {
    if (route.request().method() !== 'POST') {
      await route.continue()
      return
    }
    await route.fulfill({ status: 201, contentType: 'application/json', body: 'null' })
  })

  await signInWithPat(page, e2e.portalPat, portalUrl)
  await expect(page.getByRole('heading', { name: /Welcome to/ })).toBeVisible()
  await page.getByRole('button', { name: 'Yes, show me around' }).click()
  await page.getByRole('button', { name: 'Yes, protect my agent' }).click()
  await expect(page.getByRole('heading', { name: 'Connect your AI agent.' })).toBeVisible()

  await page.getByRole('button', { name: 'Create scoped PAT', exact: true }).click()
  await expect(page.getByRole('alert')).toContainText('Kenning did not return a usable workspace credential')
  await expect(page.getByRole('button', { name: 'Create scoped PAT', exact: true })).toBeEnabled()
  await expect(page.locator('code').filter({ hasText: /^kta_pat_/ })).toHaveCount(0)
  await expect(page.locator('.portal-overview-snippet').first()).toContainText('<YOUR_TENANT_SCOPED_PAT>')
})

test('tenant administrator can record a management review and mark a policy reviewed', async ({ page, e2e }) => {
  test.setTimeout(120_000)
  const policyId = `portal-review-${Date.now().toString(36)}`
  const created = await apiRequest(e2e, '/v1/policies', {
    method: 'POST',
    body: {
      context: { tenant_id: e2e.tenantId },
      policy_id: policyId,
      name: 'Portal management review policy',
      rules: [{ rule_id: 'portal-review-rule', tool: 'shell', decision: 'deny', reason: 'Review status test policy.' }],
    },
  })
  await apiRequest(e2e, `/v1/policies/${encodeURIComponent(policyId)}/publish`, {
    method: 'POST',
    body: { version: created.version },
  })

  try {
    await signInPortal(page, e2e)
    await page.getByRole('button', { name: 'Workspace settings', exact: true }).click()
    await expect(page.getByRole('heading', { name: 'Management reviews', exact: true })).toBeVisible()
    await page.getByLabel('Period start', { exact: true }).fill('2026-01-01')
    await page.getByLabel('Period end', { exact: true }).fill(new Date().toISOString().slice(0, 10))
    await page.getByLabel('Attendees', { exact: true }).fill('Playwright reviewer')
    await page.getByLabel('Decisions', { exact: true }).fill('Keep production approval controls.')
    await page.getByLabel('Action items', { exact: true }).fill('Review evidence before the next meeting.')
    const reviewPost = page.waitForResponse((response) => response.request().method() === 'POST' && new URL(response.url()).pathname.endsWith('/v1/management-reviews'))
    const reviewGet = page.waitForResponse((response) => response.request().method() === 'GET' && new URL(response.url()).pathname.endsWith('/v1/management-reviews'))
    await page.getByRole('button', { name: 'Record management review', exact: true }).click()
    await Promise.all([reviewPost, reviewGet])
    await expect(page.getByText('Playwright reviewer', { exact: true })).toBeVisible()

    await page.getByRole('button', { name: 'Rules', exact: true }).click()
    await expect(page.getByRole('heading', { name: 'Rules', exact: true })).toBeVisible()
    const policyRow = page.locator('tr').filter({ hasText: policyId })
    await expect(policyRow).toBeVisible()
    await expect(policyRow.getByText('Review overdue', { exact: true })).toBeVisible()
    const policyReviewPut = page.waitForResponse((response) => response.request().method() === 'PUT' && new URL(response.url()).pathname.endsWith(`/v1/policies/${policyId}`))
    await policyRow.getByRole('button', { name: 'Mark reviewed', exact: true }).click()
    expect((await policyReviewPut).ok()).toBe(true)
    await expect(policyRow.getByText(/Reviewed/)).toBeVisible()
  } finally {
    await apiRequest(e2e, `/v1/policies/${encodeURIComponent(policyId)}`, {
      method: 'DELETE',
      body: { version: created.version, confirm: true },
    }).catch(() => {})
  }
})
