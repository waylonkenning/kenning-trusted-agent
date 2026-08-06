# Kenning Trusted Agent

Kenning Trusted Agent is a self-hosted control plane for AI-agent identity,
policy decisions, approvals, audit records, and tamper-evident proof.

Release `1.0.0` is the first public release. It supports one isolated AWS
single-tenant deployment per customer account. The repository does not include
the Kenning marketing website or any Kenning-hosted environment.

## Included

- Python Lambda control plane and MCP endpoints in [`app/`](app/).
- Authenticated React workspace console in [`portal/`](portal/).
- Customer-owned AWS CloudFormation package in [`infra/single-tenant/`](infra/single-tenant/).
- Agent Guard, OpenCode, Claude Code, and Codex CLI integrations in
  [`integrations/`](integrations/).
- SDK and API contract in [`sdk/`](sdk/) and [`docs/openapi.json`](docs/openapi.json).

The deployment defaults to customer-owned AWS resources. It does not contain
hosted API URLs, hosted portal URLs, Kenning account IDs, or a default email
recipient.

## Local validation

Use Python 3.11 or later and Node.js 22 or later.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
npm --prefix portal ci

.venv/bin/python scripts/validate_single_tenant_package.py --skip-cloudformation
.venv/bin/python scripts/run_required_tests.py
npm --prefix portal run build
npm --prefix portal run lint
```

The same metadata is tracked in [`pyproject.toml`](pyproject.toml). See
[`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md) for the local API
harness and first request.

The browser suite requires AWS credentials for a test account and an API URL
for the deployment under test:

```bash
E2E_API_URL="https://your-api.example.invalid" \
TOKEN_TABLE_NAME="your-test-token-table" \
npm --prefix portal run test:e2e:local
```

The suite never uses a Kenning-hosted endpoint by default.

## Deploy one AWS tenant

The single-tenant package creates the API, Lambda functions, DynamoDB tables,
KMS receipt key, Cognito user pool, private portal bucket, CloudFront
distribution, alarms, and optional customer-managed CodePipeline.

1. Install AWS CLI v2, `jq`, `tar`, Python 3.11+, Node.js 22+, and npm.
2. Copy [`infra/single-tenant/client-parameters.example.json`](infra/single-tenant/client-parameters.example.json)
   to a local parameters file.
3. Set the customer workspace values and a private artifact bucket.
4. Validate and deploy:

```bash
python3 scripts/validate_single_tenant_package.py --region "$AWS_REGION"
./scripts/deploy_single_tenant.sh deploy \
  --stack-name kta-example-agency \
  --parameters-file infra/single-tenant/client-parameters.json \
  --artifacts-dir .single-tenant-artifacts
```

The deployment command builds immutable Lambda and portal artifacts, applies
the CloudFormation stack, publishes the API configuration, and prints the
customer API and portal URLs. Keep parameter files and PATs out of Git.

See [`docs/SINGLE_TENANT_DEPLOYMENT.md`](docs/SINGLE_TENANT_DEPLOYMENT.md) for
bootstrap, validation, and operational details.

Read [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) before creating AWS resources.
It defines ownership, data flow, cost variables, teardown, and the support
boundary.

## Configuration

The portal reads the API base URL from `VITE_KENNING_API_URL` at build time.
For a CloudFront deployment, use `same-origin` and let the deployment script
configure the API origin. For local development, set `E2E_API_URL` or
`KENNING_API_PROXY_TARGET` to the API you own.

Agent integrations read `KENNING_API_URL`, `KENNING_PAT`, and
`KENNING_TENANT_ID` from the environment. Credentials are not written to the
repository by the installer.

## Project status

AWS single tenant is the supported deployment target for this release. Azure
single tenant support is planned for a later release.

## Project policies

- [Contributing](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security](SECURITY.md)
- [Support](SUPPORT.md)
- [Governance](GOVERNANCE.md)
- [Privacy](docs/PRIVACY.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Community](docs/COMMUNITY.md)
- [Third-party notices](docs/THIRD_PARTY_NOTICES.md)
- [Trademark statement](docs/TRADEMARKS.md)

The public repository contains the application and authenticated portal. The
Kenning marketing website and its contact workflow remain private.

## License

Copyright © 2026 Waylon Kenning. Licensed under the [MIT License](LICENSE).
