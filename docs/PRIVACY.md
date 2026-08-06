# Privacy statement

This source project does not operate a central Kenning service. A person who
downloads, builds, or deploys it does not send data to Kenning by default.

## Local use

The local harness stores test records in memory. The portal uses browser
storage only for local UI preferences and setup-wizard dismissal. It is tested
not to persist personal access token values. The browser sends API payloads to
the API origin configured by the operator.

## Self-hosted use

The self-hosted operator controls the AWS account, API, identity provider,
DynamoDB records, CloudWatch logs, S3 objects, backups, KMS keys, browser
origins, source retrieval, and optional audit sinks. The operator must define
the lawful purpose, retention period, access controls, deletion process, legal
holds, backup lifecycle, and data-residency rules for the deployment.

Audit and proof records can contain action metadata, tenant identifiers,
identity references, policy results, and bounded request fields. Configure
capture redaction and retention before accepting customer data. Do not put
credentials or unnecessary personal data in actions, logs, screenshots, or
issues.

## Optional network integrations

Citation Trust retrieves operator-approved source URLs. An external audit sink
can receive configured events. These are opt-in deployment integrations. Review
their endpoints, authentication, payloads, retention, and deletion behavior.
There is no default analytics, advertising, telemetry, contact-form delivery,
or error-reporting endpoint to Kenning.

## Deletion requests

The self-hosted operator handles deletion and legal-hold requests. Use the
tenant retention controls, export required evidence first, remove backups and
logs according to the approved schedule, and delete retained cloud resources
only after the legal and recovery review.
