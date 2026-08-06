# Security policy

## Supported versions

The latest minor release is the supported version. Security fixes are
backported only when the maintainer can validate the affected supported line.
Use the exact release tag when reporting an issue.

Do not report a suspected vulnerability in a public issue.

Use a private GitHub security advisory for
`waylonkenning/kenning-trusted-agent`, or contact Waylon Kenning through the
GitHub profile. Include the affected version, a minimal reproduction, impact,
and a safe contact method. Do not attach customer data or live infrastructure
details.

Do not include credentials, customer data, or live infrastructure identifiers
in a report.

## Response and disclosure

The maintainer will acknowledge a private report when practical, reproduce it
in an isolated environment, and coordinate a fix or mitigation. The timeline
depends on severity, exploitability, and the affected deployment. Disclosure
is coordinated after a fix is available; the reporter is credited when they
agree. Never publish a secret as proof of a vulnerability.

Self-hosted operators must also rotate affected credentials, preserve relevant
logs privately, assess their own account and customer impact, and follow their
incident-response obligations.
