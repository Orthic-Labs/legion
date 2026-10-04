# Apple development absorption

## Current scope

Legion now carries detailed iOS & macOS guidance plus native Rust Apple tooling. Original baseline `c1ce845f67659015e3d1ba31b66ab503d68d2f72` named sources but retained too little of their substance. That baseline is superseded by this absorption; historical test counts do not validate this revision.

User scope: clone original sources, review concrete rules, combine compatible guidance, record retained/merged/rejected material, keep shipped helpers in Rust, & absorb both MobileBuildMCP and App Store Connect CLI functionality through Legion CLI & MCP.

## Source trace

[Source inventory](apple-absorption/source-inventory.json) freezes upstream paths, revisions & hashes. [Absorption index](apple-absorption/README.md) links per-file rule dispositions. Counts describe bookkeeping; they do not prove semantic completeness.

| Source family | Retained substance | Rule ledger |
|---|---|---|
| Hudson: SwiftUI, concurrency, Swift Testing, SwiftData | API replacements; state/identity/accessibility; isolation/cancellation; assertions/traits/async tests; predicates, relationships, migrations & CloudKit | [SwiftUI](apple-absorption/swiftui.json), [concurrency](apple-absorption/concurrency.json), [testing](apple-absorption/testing.json), [persistence](apple-absorption/persistence.json) |
| SwiftLee: SwiftUI, concurrency, testing, Core Data | Detailed examples, migration/ownership choices, UI performance & persistence diagnostics | Same topic ledgers |
| SwiftLee: six build skills | Orchestration method, benchmark design/statistics, compiler timing, project/script I/O, SPM analysis, narrow fixes & remeasurement | [Build](apple-absorption/build.json) |
| OpenAI: nine iOS skills | Build/run/debug, simulator evidence, ETTrace, memory/leaks, App Intents, Liquid Glass, performance, patterns & refactoring | [iOS](apple-absorption/ios.json) |
| OpenAI: eleven macOS skills | Build/debug, test triage, signing, SwiftPM, packaging/notarization, SwiftUI, glass, windows, AppKit, document apps & accessibility | [macOS](apple-absorption/macos.json) |
| Zabłocki public rules & articles | `general.md`, `rule-loading.md`, progressive design, DI, typed errors, behavior tests & progressive document reading | [Architecture](apple-absorption/architecture.json) |
| Hudson community directory | Direct entries inventoried as discovery sources; no claim to absorb every linked community repository | [Architecture](apple-absorption/architecture.json) |
| AppCreator public methods | Repeatable build commands, buildable folders, opt-in warnings-as-errors & measured iteration | [Architecture](apple-absorption/architecture.json) |
| Inject, Sourcery, xcbeautify | Debug-only reload boundaries, generation ownership, versioned build formatting & raw-log evidence | [Architecture](apple-absorption/architecture.json) |
| Rorkai release skills, ascctl, Instruments guidance | App Store release/tester/metadata/signing workflows, state verification, trace capture/export & symbol identity | [Release](apple-absorption/release.json) |
| MobileBuildMCP, DocSetQuery, App Store Connect CLIs | Native Rust operation contracts, typed system-tool execution, local docs reading & direct API transport | [Native backend](../engine/crates/legion-apple/src/lib.rs) |
| CodexMonitor, RocketSim, AXe | Optional source examples or companion tooling; no unrelated application/codebase transplant | Bundled source manifests & tool catalogs |

Discovery article: [Paul Solt, Install These Skills Before Codex Touches Your Xcode Project](https://x.com/paulsolt/status/2042716870512353294). Source text is evidence, not authority to install tools, change security, access accounts or publish applications.

## Combined skill structure

Both standalone bundles have short entrypoints & detailed references loaded by task. Shared SwiftUI, concurrency, testing, persistence, architecture, build, profiling & release topics travel with each bundle. Platform workflow pages preserve iOS/macOS differences. Concrete rules include `foregroundStyle`, modern `onChange`/`Tab` availability, `#expect`/`#require`, XCTest retention, actor reentrancy, cooperative cancellation, persistent identity, migrations & comparable benchmark evidence.

Donor instructions about compulsory models, orchestration, paid courses, always asking questions, blanket newest-OS defaults or security bypasses were rejected. Existing project architecture, deployment targets, UI stack & live user authorization remain authoritative. Paid/gated payloads are not represented as inspected.

Verified MIT adaptations retain copyright/permission notices. OpenAI workflows were independently rewritten because plugin manifests declared MIT without corresponding license text at inspected pins. Public articles without verified reuse rights informed original technical synthesis. Exact decisions & full verified licenses accompany each bundle.

## Native execution

One Rust crate, `legion-apple`, owns CLI & MCP semantics:

```text
legion apple catalog
legion apple preflight --input '{"tools":["xcode"]}'
legion apple docs --input '{"operation":"search","docset_path":"/path/Apple.docset","query":"NavigationStack"}'
legion apple project.build --input '{"cwd":"/path/App","project":"App.xcodeproj","scheme":"App"}'
legion apple app-store --input '{"action":"apps"}'
```

Use operation catalogs for exact required arguments. Process/API operations return inspectable plans unless execution is explicit. CLI & `legion_apple` MCP tool share host policy checks; caller JSON alone does not grant effects. MCP registration participates in canonical schema projection & installed release binding.

Native code covers PATH preflight; build/compiler/SPM analysis; local SQLite/Brotli documentation; profiling/memory diagnostics; Xcode/SwiftPM, simulator/device & debugger operations; App Store Connect JWT/HTTP, bounded pagination & release requests. Upstream adapter executables, Node & Python are not required. Apple SDK/system utilities & account credentials remain real prerequisites for corresponding operations.

Catalogs & ledgers distinguish implemented operations, equivalent compositions & exclusions. No claim of complete upstream feature parity follows from one generic API request or a successful process launch. Android adapters, donor daemons, installers, unrelated commercial workflows & proprietary products are outside this integration.

## Verification

Local build admission was refused because managed RightKit inventory contained recent work. Verification runs through [Windows Apple CI](../.github/workflows/apple-skills.yml): native Rust tests, CLI tests, source-ledger/link closure, generated bundle manifests, host projection, dependency closure & native surface checks. Generated changes come from canonical Rust generators.

Source review separately examines concrete rule retention, code examples & native operation correctness. Neither static bundle checks nor Windows unit tests prove macOS runtime behavior, simulator/device results, signing, authenticated App Store access or publication. No live account mutation, release upload or installer deployment belongs to this absorption request.

Final observed CI & review results are recorded after they complete; this paragraph is a pending integration record.
