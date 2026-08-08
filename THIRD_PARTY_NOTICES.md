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

No external engine binary, parser grammar, or creator prompt archive is shipped
in the current package. Optional executables invoked from a host installation
are excluded from this shipped-content notice & remain tracked by generated
distribution inventory. Rule packs under `registry/rules/` are original Nemesis
material.

## Rule packs and fixtures

The benchmark fixture corpus (`bench/fixtures/`) is original Nemesis material.
Any rule text, grammar, or methodology adapted from an external project
(including OpenGrep, ast-grep, Semgrep, CodeQL, and Decepticon concepts) must
be listed here with its license and attribution before it ships.

