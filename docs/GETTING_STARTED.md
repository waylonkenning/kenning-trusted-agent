# Getting started

This guide runs Kenning Trusted Agent without a Kenning account or a live AWS
environment. It uses the in-process API harness for local requests and the
public portal for a local browser build.

## Requirements

- Python 3.11–3.14;
- Node.js 22 and npm;
- Git; and
- `gitleaks` only when running the full publication scan.

Install the tracked dependencies from the repository root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
npm --prefix portal ci
```

## Run the credential-free checks

```bash
.venv/bin/python scripts/validate_single_tenant_package.py --skip-cloudformation
.venv/bin/python scripts/run_required_tests.py
node --test tests/*.mjs
npm --prefix portal run build
npm --prefix portal run lint
```

The default test suite uses fake persistence and local signing clients. It
does not create AWS resources and does not call a Kenning-hosted service.

## Make one local request

Start the local API harness in one terminal:

```bash
.venv/bin/python scripts/run_local_api.py
```

The command prints a loopback URL and a disposable test PAT. In another
terminal, use the printed values:

```bash
curl --fail-with-body -sS "$LOCAL_API_URL/health"
curl --fail-with-body -sS -X POST "$LOCAL_API_URL/v1/actions/evaluate" \
  -H "Authorization: Bearer $LOCAL_TEST_PAT" \
  -H 'Content-Type: application/json' \
  -d '{"context":{"tenant_id":"local-api-test"},"action":{"tool":"filesystem","operation":"read","target":"/tmp/example.txt"}}'
```

Set `LOCAL_API_URL` and `LOCAL_TEST_PAT` from the harness output. The harness
uses only loopback networking and in-memory data. Stop it with Ctrl-C.

## Start the portal

With the local API running, start Vite in a second terminal:

```bash
KENNING_API_PROXY_TARGET="$LOCAL_API_URL" npm --prefix portal run dev
```

Open `http://127.0.0.1:5173/app/`. The portal is an authenticated application
shell. Complete sign-in against an AWS single-tenant deployment to exercise
OIDC and workspace administration; the local harness is intended for API and
integration checks, not for simulating Cognito.

## Next step

Use [Deployment](DEPLOYMENT.md) for an AWS account that you own. Keep PATs,
parameter files, browser state, and generated artifacts outside Git.
