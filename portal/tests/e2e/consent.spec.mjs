import { test, expect } from './fixtures.mjs'
import { apiRequest } from './helpers.mjs'

test('tenant administrators can record, query, and revoke consent', async ({ e2e }) => {
  const suffix = Date.now().toString(36)
  const subject = `playwright-consent-${suffix}`
  const purpose = 'service-delivery'
  const dataScope = 'contact'

  const created = await apiRequest(e2e, '/v1/consents', {
    method: 'POST',
    body: { subject, purpose, data_scope: dataScope },
  })
  expect(created.status).toBe('active')
  expect(created.subject).toBe(subject)
  expect(created.purpose).toBe(purpose)
  expect(created.data_scope).toBe(dataScope)

  const listed = await apiRequest(e2e, `/v1/consents?subject=${encodeURIComponent(subject)}&status=active`)
  expect(listed.consents).toHaveLength(1)
  expect(listed.consents[0].consent_id).toBe(created.consent_id)

  const revoked = await apiRequest(e2e, `/v1/consents/${encodeURIComponent(created.consent_id)}/revoke`, {
    method: 'POST',
    body: {},
  })
  expect(revoked.status).toBe('revoked')
  expect(revoked.idempotent).toBe(false)

  const repeated = await apiRequest(e2e, `/v1/consents/${encodeURIComponent(created.consent_id)}/revoke`, {
    method: 'POST',
    body: {},
  })
  expect(repeated.status).toBe('revoked')
  expect(repeated.idempotent).toBe(true)
})
