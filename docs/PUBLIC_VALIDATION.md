# Public validation

`infra/public-validation/buildspec.yml` and
[`scripts/public_validation.sh`](../scripts/public_validation.sh) define the
credential-free validation path for public changes.

The gate runs documentation inventory, single-tenant package structure,
Python tests, JavaScript tests, OpenAPI validation, portal build and lint, and
secret scanning. It must not receive AWS credentials, PATs, customer data,
production URLs, or private release variables.

The deployed browser suite is separate. Run it only against an operator-owned
AWS single-tenant deployment with disposable credentials and teardown checks.
It is not a public pull-request requirement.
