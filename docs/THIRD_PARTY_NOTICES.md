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

## Apple development methodology and references

`ios-development` and `macos-development` contain original Legion guidance with substantive rules, decision branches, and examples adapted from pinned public sources. Each bundle carries its own [source manifest](../skills/ios-development/config/source-manifest.json) or [source manifest](../skills/macos-development/config/source-manifest.json), [third-party notice](../skills/ios-development/references/third-party-notices.md) or [third-party notice](../skills/macos-development/references/third-party-notices.md), and exact local license snapshots under `skills/*-development/references/licenses/`.

Adapted MIT inputs include Paul Hudson's four `twostraws` skills, Antoine van der Lee's SwiftUI, concurrency, testing, Core Data, and Xcode build skills, Peter Steinberger's profiling guidance, Krzysztof Zabłocki's Inject and Sourcery boundaries, Paul Solt's DocSetQuery lookup method, Charles Pisciotta's xcbeautify workflow, and Rudrank Riyam's App Store Connect skill rules. Local notices preserve copyright and permission text from each inspected pin; upstream code, scripts, binaries, assets, installers, plugin metadata, credentials, and live MCP configuration are excluded.

Xopoko's `AppStoreConnectCLI` is Apache-2.0 at pinned commit `2af677324e72d7c1684f9d75d57599e64f8c582a`. Only ascctl contract guidance is rewritten into local release guidance. The complete Apache-2.0 text is bundled in each Apple skill's notices. No Xopoko source or generated client is distributed, so no modified upstream file or change annotation is shipped. Its separately listed Apache-licensed dependencies (`swift-argument-parser` and `swift-crypto`) are not bundled.

MobileBuildMCP's pinned license is MIT, not Apache-2.0, and its bounded build/test, simulator/device, debugging, and profiling rules are implemented in Legion's native Rust Apple CLI/MCP surface. The exact notice remains at `skills/*-development/references/licenses/mobilebuildmcp-MIT.txt`. The distinct `rorkai-app-store-connect-cli` Go CLI is also MIT; its operation lookup, upload, checksum, redaction, and processing rules are implemented in Legion's native Rust App Store Connect adapter, with exact notices at `skills/*-development/references/licenses/rorkai-app-store-connect-cli-MIT.txt`. The separate `rorkai-app-store-connect-cli-skills` repository remains a distinct MIT source for release/TestFlight/signing guidance. AXe and CodexMonitor remain optional external references. DocSetQuery and xcbeautify contribute rewritten method rules; Legion's native Rust docset reader is an independent implementation, and no donor tool code or Apple documentation is redistributed. OpenAI's inventoried Apple plugin manifests declare MIT, but no LICENSE text exists inside either Apple plugin directory; only ledger-marked independent Legion workflows are represented, with no OpenAI text, code, scripts, metadata, or assets copied. Public Zablocki guidance, commercial RocketSim, gated AppCreator payloads, paid courses, Point-Free subscription material, and Swift Evolution specification text are excluded.

Tool reference does not authorize installation, telemetry, credentials, account changes, publishing, or network services. Apple documentation remains subject to its own terms; DocSetQuery's MIT license does not license documentation it processes. Detailed per-file and per-rule dispositions remain in `docs/apple-absorption/*.json`; the companion trace [README](apple-absorption/README.md) explains coverage and deliberate exclusions.

## Rule packs and fixtures

The benchmark fixture corpus (`bench/fixtures/`) and SEO regression fixtures under
`skills/seo/tests/fixtures/` are original Legion material unless a fixture states
otherwise. Any future rule text, grammar, fixture, or methodology adapted from an
external project must be listed here with its license and attribution before it ships.
