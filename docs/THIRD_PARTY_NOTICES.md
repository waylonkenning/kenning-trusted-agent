# Third-party notices

The release contains third-party dependencies. This list identifies direct
runtime and development dependencies. Transitive dependencies are recorded in
[SBOM.json](SBOM.json).

## Python

| Package | Use | License |
| --- | --- | --- |
| boto3 | AWS SDK | Apache License 2.0 |
| coverage | Test coverage | Apache License 2.0 |
| pytest | Test runner | MIT |

The exact versions are resolved from the install command and the operator's
lock or package cache. Run `python scripts/generate_sbom.py` after installation
to record the installed Python versions.

## Portal JavaScript

| Package family | Use | License |
| --- | --- | --- |
| React and React DOM | UI runtime | MIT |
| Vite and `@vitejs/plugin-react` | Build tool | MIT |
| `@phosphor-icons/react` | Icons | MIT |
| `pdfjs-dist` | PDF rendering | Apache License 2.0 |
| Playwright | Browser tests | Apache License 2.0 |
| ESLint and its plugins | Linting | MIT |

Run `npm --prefix portal ci` and
`npm --prefix portal sbom --sbom-format=cyclonedx` for the npm resolver's
current dependency inventory. Review registry license metadata before
changing a direct dependency. The npm lockfile does not by itself prove that
every bundled asset is redistributable.

## Generated and downloaded material

PDF.js worker code, browser binaries, fonts, icons, and customer-provided
logos are not relicensed by the MIT license. Review their upstream notices and
customer permissions when packaging or deploying them.
