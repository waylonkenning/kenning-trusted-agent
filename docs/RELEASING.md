# Public release guide

Release 1.0.0 was published on 6 August 2026 from the single commit pointed
to by tag `v1.0.0` on 6 August 2026. Resolve the exact source commit with
`git rev-parse v1.0.0`. The GitHub release
is the public source of the release archive and notes.

## Maintainer release gates

1. Review the issue and pull request scope, dependency changes, asset
   provenance, API contract, migration impact, and security changes.
2. Run `bash scripts/public_validation.sh` from a clean checkout with no
   private credentials or customer data.
3. Build immutable artifacts with `scripts/build_single_tenant_artifacts.py`
   and record SHA-256 checksums.
4. Push the approved source to `main`. The private maintainer AWS CodePipeline
   builds and validates development artifacts. It does not use GitHub Actions.
5. Verify the deployed source identity and browser/API gates in development.
6. Promote the exact candidate through the manual production approval stage,
   when a maintainer release is intended. Do not rebuild for production.
7. Publish the tag, changelog entry, migration notes, and redacted release
   record together.

The public repository never receives AWS roles, PATs, Cognito secrets, signing
keys, production URLs, customer data, or private release evidence.

## Versioning and support

Use Semantic Versioning for the public API and SDK. Document breaking changes
in `CHANGELOG.md` and `docs/MIGRATION.md`. The latest minor release receives
normal maintenance. Security fixes are backported only when the fix applies
cleanly and the supported version remains within the maintainer support
window. Older versions are best-effort after a new minor release.

## Rollback

Rollback means redeploying a previously validated immutable artifact and
restoring compatible configuration. It does not reverse a data migration or
erase audit records. Record the artifact digest, source commit, operator, and
verification result in private release evidence.
