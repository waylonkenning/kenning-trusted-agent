# Deployment guide

Kenning Trusted Agent has one supported deployment target in release 1.0:
one AWS account and one isolated workspace per deployment. Azure single-tenant
support is planned for a later release. The project does not provide a hosted
Kenning endpoint and does not require Kenning infrastructure.

## Choose a path

| Path | Use it for | Credentials and data |
| --- | --- | --- |
| Local API harness | Development and unit/integration checks | Loopback only; in-memory fixtures |
| Customer-owned AWS single tenant | A real portal, API, Cognito login, audit store, and CloudFront deployment | The operator's AWS account, identity provider, and customer data |
| Kenning-managed hosted service | Not part of this release | No hosted endpoint is included |

The authoritative AWS entry point is
[`scripts/deploy_single_tenant.sh`](../scripts/deploy_single_tenant.sh) and its
parameterised CloudFormation package. Do not add a GitHub Actions deployment
workflow. An operator may run the package manually or create the optional AWS
CodePipeline in the customer account.

## Ownership and data flow

The AWS account owner controls the region, network, identity provider, DNS,
TLS certificate, data retention, backups, logs, alerting, and deletion. The
deployment creates API Gateway, Lambda, DynamoDB, KMS, Cognito, S3, CloudFront,
and CloudWatch resources. Citation Trust can fetch operator-approved external
source URLs; disable that feature or provide a reviewed private transport for
an isolated network.

The application sends no contact-form data, analytics, error reports, or
credentials to Kenning by default. Optional external audit sinks and source
retrieval are operator-configured integrations. Review their endpoints,
secrets, retention, and legal basis before enabling them.

## Configuration classes

- Public: source code, example parameters, region, release version, and
  non-secret portal branding.
- Sensitive: tenant IDs, resource names, API URLs, account IDs, domains, and
  audit configuration. Keep them in operator configuration and logs under
  access control.
- Secret: PATs, OAuth client secrets, OIDC secret ARNs, KMS signing material,
  webhook credentials, and AWS role credentials. Use environment variables,
  Secrets Manager, or short-lived role sessions. Never commit them.

Start with [`examples/single-tenant.env.example`](../examples/single-tenant.env.example)
and [`infra/single-tenant/client-parameters.example.json`](../infra/single-tenant/client-parameters.example.json).

## Cost and teardown

The package uses on-demand DynamoDB, Lambda, API Gateway, S3, CloudFront,
Cognito, KMS, and CloudWatch resources. AWS charges vary by region, traffic,
retention, logs, alarms, and citation retrieval. Obtain a current estimate in
the target account before deployment; no fixed price is implied by this
repository.

Follow [Operations](OPERATIONS.md) before deletion. Export required evidence,
revoke credentials, disable optional pipelines and roles, confirm legal holds,
and remove retained resources in a reviewed change window. A CloudFormation
stack update is the normal upgrade path; a rollback restores the previous
immutable artifact where the stack and schema remain compatible.

## Support boundary

The community supports the public source and reproducible self-hosting path.
The AWS account owner supports account guardrails, quotas, DNS, certificates,
identity, backups, logs, network routes, and incident response. See
[`SUPPORT.md`](../SUPPORT.md) for the issue and vulnerability channels.
