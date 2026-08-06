# Third-party notices

Nemesis is built from and integrates third-party software and rule material.
This inventory is populated only with **actual** dependencies, rules, and
integrated engines that ship in or are executed by the product.

The current source-use license and the licenses of every integrated engine,
parser grammar, and rule set must be reviewed together before any public
package or community SDK release. No legal terms are changed by this
engineering inventory.

## Runtime dependencies

The canonical package manifest (`@orthic-labs/nemesis`, PR05) declares no
runtime dependencies yet; every future dependency must be listed here with its
license and provenance before release.

## Integrated engines and rule material

| Engine / material | Source | License | Provenance | Status |
|---|---|---|---|---|
| ast-grep (structural provider) | https://github.com/ast-grep/ast-grep | MIT | adapter invocation only; no DSL fork | integrated |
| OpenGrep (SAST/taint provider) | https://github.com/opengrep/opengrep | LGPL-2.1 | adapter invocation; rule pack `nemesis-core.yml` is original | integrated |
| OSV-Scanner (dependency provider) | https://github.com/google/osv-scanner | Apache-2.0 | adapter invocation only | integrated |
| Syft (SBOM provider) | https://github.com/anchore/syft | Apache-2.0 | adapter invocation only | integrated |
| gitleaks (secrets provider) | https://github.com/gitleaks/gitleaks | MIT | adapter invocation only | integrated |
| Semgrep (optional depth) | https://github.com/semgrep/semgrep | LGPL-2.1 | adapter invocation only | optional |
| CodeQL (optional depth) | https://github.com/github/codeql | MIT (queries) | imported SARIF only | optional |
| Trivy (container/IaC) | https://github.com/aquasecurity/trivy | Apache-2.0 | adapter invocation only | optional |

Rule packs under `registry/rules/` are original Nemesis material. Any rule text,
grammar, or methodology adapted from an external project must be listed here
with its license and attribution before it ships.

## Rule packs and fixtures

The benchmark fixture corpus (`bench/fixtures/`) is original Nemesis material.
Any rule text, grammar, or methodology adapted from an external project
(including OpenGrep, ast-grep, Semgrep, CodeQL, and Decepticon concepts) must
be listed here with its license and attribution before it ships.

> This file is intentionally a placeholder at PR04. It is populated only with
> actual dependencies and rules; do not add entries for tools that are merely
> referenced or planned.
