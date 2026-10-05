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

Source review separately examines concrete rule retention, code examples & native operation correctness. Neither static bundle checks nor Windows unit tests prove macOS runtime behavior, simulator/device results, signing, authenticated App Store access or publication. No live account mutation or App Store release upload belongs to this absorption request. Later explicit user requests authorized Legion installer deployment on Mac & Windows.

At `fddf7d8b717ed4b8590fdf2fdd6cf6af31c05c3b`, [Windows Apple CI passed](https://github.com/Orthic-Labs/legion/actions/runs/37241327474): 126 selected tests (55 native backend, 7 source integrity, 5 CLI, 3 real stdio MCP integration, 42 script compatibility, 11 Apple policy, 2 schema & 1 authority binding). Canonical projection, manifest, dependency closure, native surface, plugin parity & zero-generated-drift checks also passed.

Independent read-only Oracle review passed after target-bound authorization, SwiftPM write/network grants & App Store publication classification were repaired. A separate SwiftUI forward check confirmed availability branches for `foregroundStyle`, `onChange`, `Tab` & `enumerated()` collection use. This records source assurance & Windows verification; macOS/device/account execution remains outside those results. Detailed source trace now covers 363 inventoried files & 2,181 rule/group dispositions.

## Installed-skill follow-up, 2026-10-05

The installed 0.3.21 iOS/macOS bundles already contain the restored knowledge requested after baseline review: CloudKit uniqueness/default/relationship restrictions; confirmation closure completion, assertions & serialization; compiler flags, timing interpretation & package graph checks; AppKit representable/coordinator teardown, panels & window recipes; ETTrace symbol/artifact selection, memgraph retaining paths, TestFlight processing & metadata workflows. Both public Zabłocki rule files have individual architecture-ledger entries; all 25 rorkai entrypoints have individual retained or rejected dispositions. These checks establish retention of the named gaps, rather than an exhaustive semantic-parity certification.

Actual installed CLI use exposed remaining executable-guidance defects. Preflight accepts catalog ID `xcode`, not executable name `xcodebuild`. Build-analysis takes operation & log path inside JSON; it has no `--operation` or `--threshold-ms` flags. Native `project.build` accepts ordinary typed build inputs, but not arbitrary Swift flags or timing-summary options. Both bundles now use repository/system Xcode commands for those diagnostic captures, retain concrete flags & raw-log/exit-status requirements, & feed logs into the native parser. Donor-only benchmark options are identified explicitly. Assertion examples now interpolate errors correctly. Source manifests explicitly list both public rule-file URLs.

On macOS, installed preflight found Xcode & Swift; Xcode reported 27.0 (27A266a). Installed compiler/timing/statistics analyzers successfully processed bounded synthetic inputs, retaining a 125 ms diagnostic, two timing categories & an 11-second median respectively. These are adapter checks, not measured app benchmarks. `xcrun devicectl list devices` showed paired physical iPhone 16 Pro Max available. Native Legion device execution was denied because this CLI invocation lacked host policy context; no native device-execution pass, app build, installation, launch or runtime acceptance is claimed. Phone discovery needed no change to HeardRight.

## Semantic retention corrections, 2026-10-05

Independent source review found that several broad ledger entries still overstated concrete retention. This revision adds operational procedures for Inject, Sourcery, optional existing DocSetQuery export/sanitize/index tools, xcbeautify renderers, reducer composition, dependency construction timing, release readiness repairs & optional external asc workflows. Native Rust operations remain distinct from external compatibility commands; export/index/workflow features are not claimed as native parity.

Corrections cover build diagnostic capture & compiler-cache settings; test conformance/fixture rules; Core Data startup, app groups, query generations, save merging, sorting, FRC sections, lifecycle cleanup & isolated edit cancellation; deferred migration & CloudKit diagnostics; App Intent parameter projection, shortcut chaining, one-shot handoff & widget configuration; SwiftUI identity, platform availability, Mac windows/glass & profiler procedures. Concurrency examples now distinguish language-mode, executor, structured-group & cancellation semantics. Unsupported donor API spellings are replaced by supported procedures, & compiler/SDK availability is distinguished from deployment availability.

`asc-wall-submit` was incorrectly described as App Store submission. Its pinned source creates a Wall of Apps showcase pull request in an external repository. The release ledger now rejects that workflow explicitly. Optional raw `asc` procedures retain telemetry opt-outs, selected-version help checks & explicit effect scope; ordinary user-authorized work does not gain a blanket contract requirement.

Baseline `ad010ff3d89820bc4cfa29526697726192f0a430` passed [full CI](https://github.com/Orthic-Labs/legion/actions/runs/37283638166) (7,329 passing Rust tests), [Apple checks](https://github.com/Orthic-Labs/legion/actions/runs/37282198422), [Mac installer qualification](https://github.com/Orthic-Labs/legion/actions/runs/37283644186) & [Windows installer qualification](https://github.com/Orthic-Labs/legion/actions/runs/37283708187). Qualified 0.3.21 payloads were installed on both machines; all 319 Apple bundle files matched source in payload, Codex & Claude projections. Mac global setup reported an unrelated optional Pi projection issue; scoped Codex/Claude setup & native CLI/MCP checks passed.

Those baseline results do not validate this subsequent source revision. Delivery requires this revision’s canonical manifests, full GitHub gate & exact qualified installer replacement; CI runs and installation receipts identify their source revision. Source-ledger counts remain trace bookkeeping, not proof of exhaustive semantic parity or compiled Apple application examples.

Installed acceptance at `d54bea8cf41ecbacee7cfd2a626f3719e0ed3c54` supersedes that pending-delivery
state: qualified 0.3.21 payloads are installed on Mac & Windows. [Portable readback](plans/legion-installed-readback-d54bea8c.json)
records both actual bare & plugin-root transports, canonical tool discovery, Apple catalog/apps-plan/
simulator-plan replies & all 1,036 manifest files matching payload, Codex & Claude roots.
Full CI passed 7,336 tests with zero failures. These results establish installed skill retention &
native parser/planning/transport behavior; device/app/account execution has separate acceptance.

Installer follow-up closes aggregate setup & same-version upgrade blockers: normal 0.3.21
installers exit 0 on both hosts. Mac uses `a6c628a4`; Windows uses `f8513d20`, whose additional
change is Windows first-install directory bootstrap. Global setup & Claude/Codex projections
are complete; all 1,036 files match each host, both actual MCP transports & native Minimize pass.
[Full CI](https://github.com/Orthic-Labs/legion/actions/runs/37333623783) passes 7,340 tests;
[Windows qualification](https://github.com/Orthic-Labs/legion/actions/runs/37339666898) reruns
full gate plus 49 focused tests & installer rollback/upgrade cases.
[Mac qualification](https://github.com/Orthic-Labs/legion/actions/runs/37333624477) passes 141
focused tests & mixed-client installation. [Current installed evidence](plans/legion-installed-readback-2026-10-05.json)
records exact platform identities. iOS chat resumed HeardRight device/app work.
