# Kenning Trusted Agent changelog

This file records user-visible changes in each release. Release names are
selected in order from the [New Zealand release name catalogue](docs/RELEASE_NAMES_NZ.json).
The build system carries the same release ID, version, and name through the
development candidate, production promotion, portal, and API health response.

## Unreleased

- Record future changes here before a public tag.

## 1.0.0 · [`v1.0.0`](https://github.com/waylonkenning/kenning-trusted-agent/releases/tag/v1.0.0)

Released 6 August 2026.

- Published the application, authenticated portal, SDK, integrations, tests,
  AWS single-tenant package, and public governance documents.
- Separated the public application from the private marketing website and its
  contact-delivery workflow.
- Added local credential-free validation, deployment guidance, privacy and
  threat-model documentation, dependency notices, and release procedures.

## Waitomo · 0.1.92 · `development-aws-92`

Released 1 August 2026.

- Restored the authenticated portal shell after the refactor.
- Completed the portal request-hook migration and added a lint gate for the
  migrated code.
- Stabilised disposable-tenant browser setup and freshly issued token
  visibility in the deployed policy flow.
- Added installer coverage for OpenCode, Claude Code, and Codex CLI.
- Hardened Lambda release metadata verification and non-fatal GitHub release
  asset uploads.
- Reconciled the ISO 42001 mapping draft and its control totals.
