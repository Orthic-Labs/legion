# Apple source absorption trace

Reviewed 2026-10-05. This directory records source-bound absorption for iOS/macOS guidance. `source-inventory.json` is the pinned denominator: 362 inventoried files across 15 source entries. Lane ledgers preserve per-file review state; each substantive `rules[]` row records source line range, summary, `kept`/`merged`/`rejected` disposition, operational destination(s) where supplied, and reason. Metadata-only files remain explicit with empty rules when no content was eligible. Native adapter ledgers are additional source-bound receipts for implementation lanes.

## Lane coverage

| Ledger | Files / rules | Operational destination family |
| --- | ---: | --- |
| `architecture.json` | 15 / 62 | `skills/{ios,macos}-development/references/architecture/**` |
| `build.json` | 46 / 122 | `skills/{ios,macos}-development/references/build-optimization/**` |
| `concurrency.json` | 40 / 762 | `skills/{ios,macos}-development/references/concurrency/**` |
| `ios.json` | 76 / 89 | `skills/ios-development/references/ios-workflows/**`, system integration, SwiftUI quality |
| `macos.json` | 42 / 115 | `skills/macos-development/references/macos-workflows/**`, native workflows |
| `persistence.json` | 25 / 127 | `skills/{ios,macos}-development/references/persistence/**` with exact section anchors |
| `release.json` | 40 / 41 | `skills/{ios,macos}-development/references/release/**` |
| `swiftui.json` | 69 / 740 | `skills/{ios,macos}-development/references/swiftui/**` |
| `testing.json` | 23 / 122 | `skills/{ios,macos}-development/references/testing/**` |
| `native/app-store.json` | 25 / 10 | `engine/crates/legion-apple/src/app_store*.rs`, `app_store_upload.rs` |

`persistence.json` is the detailed storage absorption ledger: SwiftData entrypoint, model, predicate, CloudKit, indexing, and inheritance rules route to separate SwiftData sections; Core Data stack, context, fetch, save, batch, history, migration, model configuration, CloudKit, performance, testing, audit, and glossary rules route to separate Core Data/migration/testing sections. Mirrored iOS/macOS destinations are intentional. Existing data is preserved; no blanket migration, store deletion, in-memory fallback, or CloudKit enablement is introduced.

## Disposition policy

- `kept` preserves a source rule when it remains accurate and scoped to its destination.
- `merged` rewrites compatible substance into Legion-owned prose/examples, records its destination, and removes donor orchestration, installer, credential, telemetry, or framework-specific assumptions.
- `rejected` records source lines that are foreign to Apple development ownership, executable donor payloads, unsafe defaults, gated material, or unsupported framework-specific detail; rejection is deliberate, not an unreviewed omission.
- Source license and provenance are separate from content disposition. Exact MIT or Apache text for adapted and verified reference sources lives inside each Apple bundle under `references/licenses/`; OpenAI plugin manifests remain metadata-only because no LICENSE text is present in inventoried plugin directories.

## Deliberate exclusions

No donor repository is vendored as a subtree. Bounded MobileBuildMCP build/test, simulator/device, debugging, and profiling operations are implemented in native Rust; App Store Connect discovery, aliases, pagination, credential transport, uploads, checksums, and processing-state handling are implemented in native Rust. Upstream binaries, source trees, assets, plugin/agent manifests, MCP configuration, executable donor scripts, installers, credentials, proprietary or commercial RocketSim material, gated AppCreator payloads, paid courses, Point-Free subscription material, unlicensed public articles, and Swift Evolution specification text remain excluded. Rorkai commercial/account mutations outside release verification, Xopoko generated client/dependencies, Inject source-rewriting/TCA snippets, Sourcery security-weakening examples, DocSetQuery source, and Apple documentation processed by DocSetQuery remain excluded; Legion's native Rust docset reader is independent. AXe and CodexMonitor remain optional external references; native operations use host-owned planning and Guard execution semantics.

This trace records source inspection and authored dispositions. It makes no claim that all builds, tests, or semantic review have passed; validation remains with repository integration owner.
