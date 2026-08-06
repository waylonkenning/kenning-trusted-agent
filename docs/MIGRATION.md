# Migration notes

## First public release: 1.0.0

The public repository starts with a fresh single-commit history and contains
the application, authenticated portal, SDK, integrations, infrastructure,
tests, and self-hosting documentation. The private marketing website and
Kenning-managed deployment material are outside the public boundary.

Deployments from the pre-public prototype should be treated as an upgrade
project. Export audit and release evidence, verify DynamoDB schema and
retention settings, build the 1.0.0 artifacts, and test in an isolated stack
before changing a live stack. Do not copy private environment values into the
public parameter example.

The supported public path is AWS single tenant. Azure deployment is not
included in 1.0.0.
