# Portal end-to-end coverage

The Playwright suite tests the self-hosted authenticated portal against an
operator-selected API. Each worker creates a disposable tenant and short-lived
PATs in the configured AWS account, then revokes them during teardown.

Run from `portal/`:

```bash
npm run test:e2e:local
```

Set `E2E_API_URL`, `E2E_PORTAL_URL`, `TOKEN_TABLE_NAME`, and AWS credentials for
your deployment. The local runner defaults to `http://127.0.0.1:3000` for the
API and `http://127.0.0.1:5199/app` for the portal. No Kenning-hosted service
is used by default.

Coverage includes sign-in, workspace navigation, agent connections, policy
creation and simulation, approvals, invitations, access-token recovery,
audit and proof review, citation findings, settings, responsive layouts, and
the OpenAPI asset.
