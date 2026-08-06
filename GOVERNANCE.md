# Governance

Waylon Kenning is the initial copyright holder and project maintainer. The
maintainer owns the release process, security response, repository settings,
and decisions that affect compatibility or user safety.

## Contributions

Contributors propose changes through issues and pull requests. Maintainers
may request tests, documentation, threat-model updates, or a migration note
before merge. A maintainer may reject a change that introduces unsafe data
egress, an undisclosed hosted dependency, a credential path, or an unsupported
security claim.

## Releases

Maintainers approve public releases after the checks in
[docs/RELEASING.md](docs/RELEASING.md). AWS CodePipeline and CodeBuild remain
the maintainer release system. Production promotion requires a separate manual
approval and reuses the exact candidate validated in development.

## Becoming a maintainer

Maintainer access is granted by the current maintainer after sustained,
high-quality contributions, reliable review, and agreement to protect private
security and customer information. Access can be reduced or removed when
needed to protect the project.

## Conflicts and changes

Raise a governance concern privately with the maintainer. This document may
change through a reviewed pull request; changes to copyright ownership,
license, or security reporting require explicit maintainer approval.
