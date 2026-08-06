# Development guide

Use a clean checkout, a supported Python and Node.js version, and tracked
dependency manifests. Keep the public test path credential-free.

## Commands

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
npm --prefix portal ci
.venv/bin/python scripts/run_required_tests.py
node --test tests/*.mjs
npx --yes @apidevtools/swagger-cli validate docs/openapi.json
npm --prefix portal run build
npm --prefix portal run lint
```

`tests/` contains the backend and in-process API suite. `portal/tests/e2e/`
contains browser tests for an operator-owned deployed API. The browser suite
requires AWS credentials, a disposable test tenant, and explicit `E2E_API_URL`;
it has no default endpoint.

## Working rules

- Add a test for new backend behavior and an E2E test for a new user flow.
- Do not add Kenning-hosted URLs or customer identifiers to examples.
- Keep secrets in the environment or an operator secret store.
- Do not record PATs, browser state, customer payloads, or raw logs in Git.
- Keep API changes aligned with `docs/openapi.json` and run its validator.
- Use AWS CodePipeline and CodeBuild for maintainer release automation. Public
  validation must not receive production credentials.

## Integration boundaries

Agent Guard integrations are enforcement adapters, not a replacement for
underlying tool permissions. Review each client's hook/plugin behavior,
credential storage, uninstall path, and supported versions before production
use. MCP is an API surface; an integration hook remains the enforcement point
for a built-in client tool.
