# Third-party notices

Legion is built from and integrates third-party software and rule material.
This inventory is populated only with **actual** dependencies, rules, and
integrated engines that ship in or are executed by the product.

The current source-use license and the licenses of every integrated engine,
parser grammar, and rule set must be reviewed together before any public
package or community SDK release. No legal terms are changed by this
engineering inventory.

## Runtime dependencies

The canonical package manifest (`@orthic-labs/legion`) declares no SEO-specific
runtime dependency on the donor projects below. Their SaaS shells, databases,
agent topologies, hosted services, and provider credentials are not vendored.
Every future runtime dependency must be listed here with license and provenance
before release.

## Integrated engines and rule material

No external SEO engine binary is shipped. Legion's SEO implementation and prose
are Legion-native, but selected concepts/methodologies were researched against
these MIT-licensed public projects and then reconciled with Legion's own source
contracts and current official platform guidance:

- `AgriciDaniel/claude-seo` — MIT. Donor concepts reviewed include SERP-overlap
  clustering, search-experience/page-type analysis, drift/metadata checks and
  crawler-purpose corrections. Legion does not vendor its Claude-specific agent
  topology or runtime.
- `every-app/open-seo` — MIT. Donor concepts reviewed include durable project
  context, longitudinal rank tracking, coherent provider data planes, market
  defaults, on-demand SERP depth and adversarial `badseo` fixture patterns.
  Legion does not vendor its SaaS/database/billing/Cloudflare application shell.
- `seranking/seo-skills` — MIT. Used as a public benchmark for specialist SEO
  coverage and terminology; no executable dependency is vendored.

The governed SEO source manifest is `skills/seo/config/source-manifest.json`.
Donor concepts never override current Google/Bing/platform documentation,
Legion authority/effect controls, or the user-supplied SEO implementation and
control sources.

## Rule packs and fixtures

The benchmark fixture corpus (`bench/fixtures/`) and SEO regression fixtures under
`skills/seo/tests/fixtures/` are original Legion material unless a fixture states
otherwise. Any future rule text, grammar, fixture, or methodology adapted from an
external project must be listed here with its license and attribution before it ships.
