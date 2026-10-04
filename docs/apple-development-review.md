# Apple development skills review

## Purpose and delivery state

This note supports a Codex review of two consolidated Legion capabilities: `ios-development` and `macos-development`. It records the original article, source-to-feature mapping, reuse and licensing decisions, integration files, setup design, and the distinction between repository checks and actual Apple-platform validation.

The implementation is an original synthesis of selected public material, with independent platform guidance. It is not an installation of every linked skill, a verbatim merge of donor manuals, or a replacement for Legion's existing authority and routing model. Each capability is self-contained and uses small on-demand references.

Baseline implementation: commit `c1ce845f67659015e3d1ba31b66ab503d68d2f72`, titled `feat(skills): add consolidated iOS and macOS development capabilities`. The user subsequently approved adding an explicit setup layer to both skills and requested commit/push to `main` plus this review note. The setup enhancement is included in the commit containing this note. Resolve that commit with `git log -1 --format=%H -- docs/apple-development-review.md`; its delivery and CI status are reported separately after remote verification, avoiding a self-referential commit hash in this file.

## Original article

Paul Solt, **Install These Skills Before Codex Touches Your Xcode Project**:

https://x.com/paulsolt/status/2042716870512353294?s=46

The article was read through the browser. A separate web fetch was blocked. The article is the discovery source; pinned upstream repositories and official documentation are the technical and rights sources. The article's recommendation to install tools does not itself authorize installing them, granting account access, changing security settings, or publishing an app.

Coverage includes Paul Hudson's four skills; SwiftLee's four core skills and six build-analysis/optimization skills; OpenAI's iOS and macOS plugin bundles; Krzysztof Zabłocki's public architecture/testing guidance, Inject and Sourcery; and the supporting tools listed below. Gated AppCreator material, paid course payloads and Point-Free subscriber content remain excluded and unverified.

## How to read the mapping

- **Adapted** means selected methodology was reconciled into original concise prose. It does not mean the complete donor skill or its scripts were imported.
- **Referenced** means a source informed a coverage check or an optional tool is documented. Its code, binary, configuration, assets and complete skill text are not bundled.
- **Excluded** means the material was not imported or represented as inspected.
- Reference filenames below are relative to each skill's `references/` directory unless a platform is specified. Shared topics are duplicated deliberately so either installed skill works alone.
- Exact upstream revisions, license evidence and treatment are in each skill's `config/source-manifest.json`. Source review was recorded on 2026-10-04. The pins identify inspected evidence, not a promise that every installed tool should use that historical version.

## Paul Hudson mapping

All four repositories are MIT-licensed methodological sources. The shipped notices retain Paul Hudson's copyright and the MIT permission/disclaimer text.

| Original skill | Pinned repository | Treatment and destination |
|---|---|---|
| `swiftui-pro` | [SwiftUI-Agent-Skill](https://github.com/twostraws/SwiftUI-Agent-Skill/tree/be297ff80dddec529af1f9b1f1f114aab6c9d11c) | Adapted review method in `swiftui.md`, platform references and `testing.md`: state ownership, API availability, navigation, accessibility and measured performance |
| `swift-concurrency-pro` | [Swift-Concurrency-Agent-Skill](https://github.com/twostraws/Swift-Concurrency-Agent-Skill/tree/bee3f69ba17142da148d3c5406f148ed62592b69) | Adapted into `concurrency.md`: actor isolation, transfer, task lifetimes, cancellation and diagnosis |
| `swift-testing-pro` | [Swift-Testing-Agent-Skill](https://github.com/twostraws/Swift-Testing-Agent-Skill/tree/2d6bba14a3c8bf3694f218b92fffe617c41ae43e) | Adapted into `testing.md`: deterministic, behavior-focused unit tests, parameterization and async test design |
| `swiftdata-pro` | [SwiftData-Agent-Skill](https://github.com/twostraws/SwiftData-Agent-Skill/tree/922d989473a9914210b41529a1ac5636aff4b8c1) | Adapted into `persistence.md`: schema, relationships, fetches, migrations and CloudKit constraints |

Nested duplicate entrypoints present in some upstream trees are packaging copies of the same named skills, not additional capabilities. The synthesis drops donor-local blanket iOS 26/Swift 6.2 defaults and the assertion that this user always prefers SwiftData.

## SwiftLee mapping

Antoine van der Lee's repositories are MIT-licensed methodological sources. The shipped notices retain his copyright and MIT terms.

| Original skill | Pinned repository | Treatment and destination |
|---|---|---|
| `swiftui-expert-skill` | [SwiftUI-Agent-Skill](https://github.com/AvdLee/SwiftUI-Agent-Skill/tree/9897311e3e42cc77e87603226e74bea711092fbd) | Adapted into `swiftui.md`, `macos-platform.md` and other platform guidance: state, view boundaries, scenes, windows, documents and accessibility |
| `swift-concurrency` | [Swift-Concurrency-Agent-Skill](https://github.com/AvdLee/Swift-Concurrency-Agent-Skill/tree/d5770817d2622e1585b1f7eaebc791a9cb0959c8) | Adapted diagnostic-first isolation/migration guidance in `concurrency.md` |
| `swift-testing-expert` | [Swift-Testing-Agent-Skill](https://github.com/AvdLee/Swift-Testing-Agent-Skill/tree/798e9b1a2bcac164d4f0c781908199e754f0bab6) | Adapted into `testing.md`: parallel isolation, traits, parameterization, async waiting and incremental migration |
| `core-data-expert` | [Core-Data-Agent-Skill](https://github.com/AvdLee/Core-Data-Agent-Skill/tree/855ca7d0df50e82b00c12881dd9cd23c19ef5f49) | Adapted into `persistence.md`: contexts, object IDs, merge/history ownership, migrations and store tests |

The [Xcode-Build-Optimization-Agent-Skill repository](https://github.com/AvdLee/Xcode-Build-Optimization-Agent-Skill/tree/6bd7b596cd688b1127ded00e812b1b6937ec35d6) provides six distinct entrypoints:

| Original build skill | Adapted coverage |
|---|---|
| `xcode-build-orchestrator` | Select a reproducible symptom and route the investigation in `performance.md` and `toolchain.md`; no donor agent orchestration imported |
| `xcode-build-benchmark` | Separate clean/cold, warm/no-op and source-edit incremental cases; preserve configuration, destination, caches and raw measurements |
| `xcode-compilation-analyzer` | Isolate compiler/type-checking hotspots using actual diagnostics before syntax or module changes |
| `xcode-project-analyzer` | Inspect target dependencies, scripts, inputs/outputs, configuration and generated-file invalidation |
| `spm-build-analysis` | Distinguish package resolution and SwiftPM work from app build phases; use the repository's package workflow |
| `xcode-build-fixer` | Change a proven bottleneck narrowly, preserve correctness, rerun comparable baselines and tests, report tradeoffs |

This is methodological coverage, not feature parity with upstream executable analyzers or benchmark scripts. The SwiftUI source tree also includes the maintainer helper `.agents/skills/update-swiftui-apis/SKILL.md`; it is not installed as a third Legion capability and does not authorize global API rewrites.

## OpenAI bundle mapping

Sources are [build-ios-apps](https://github.com/openai/plugins/tree/5fd93af4cd0c623e020d0cc7e9ce178b4ac1f70f/plugins/build-ios-apps) and [build-macos-apps](https://github.com/openai/plugins/tree/5fd93af4cd0c623e020d0cc7e9ce178b4ac1f70f/plugins/build-macos-apps), both pinned at `5fd93af4cd0c623e020d0cc7e9ce178b4ac1f70f`.

Their manifests declare MIT, but the inspected repository tree did not provide corresponding root or Apple-bundle LICENSE text. They are reference-only coverage sources. No OpenAI skill text, code, scripts, metadata or assets were copied. This conservative decision is about incomplete notice provenance, not a claim that reuse is prohibited.

The pinned README and recursive tree were reconciled against all nine iOS and eleven macOS skill entrypoints. All entries below are **reference-only** coverage sources; the destinations contain independent prose rather than imported OpenAI payloads.

| iOS entrypoint | Destination and retained limit |
|---|---|
| `ios-debugger-agent` | `ios-platform.md`, `toolchain.md`, `testing.md`: target discovery, build/run/debug, logs and bounded runtime checks; no configured MCP shipped |
| `ios-simulator-browser` | `ios-platform.md`, `testing.md`, `swiftui.md`: simulator identity, UI evidence and preview-versus-runtime distinction; browser mirroring server and package hot-reload implementation are not bundled |
| `ios-ettrace-performance` | `performance.md`: optional compatible ETTrace workflow, target/symbol identity and representative profiling; ETTrace tooling/scripts not bundled |
| `ios-memgraph-leaks` | `performance.md`: allocations/leaks and memgraph investigation with private local artifacts; capture/diff/parser scripts not bundled |
| `ios-app-intents` | `system-integration.md`: App Intents, entities, stable IDs, authentication and actual system-surface verification |
| `swiftui-liquid-glass` | `swiftui.md`: conditional API/SDK availability and accessibility-aware adoption; no blanket newest-OS target |
| `swiftui-performance-audit` | `swiftui.md`, `performance.md`: measured updates, identity, body work and profiling |
| `swiftui-ui-patterns` | `swiftui.md`, `ios-platform.md`: state ownership, navigation, native controls and adaptation |
| `swiftui-view-refactor` | `swiftui.md`, `architecture.md`: bounded view decomposition while preserving behavior and architecture |

| macOS entrypoint | Destination and retained limit |
|---|---|
| `build-run-debug` | `toolchain.md`, `macos-platform.md`, `testing.md`: repository build wrapper, target/binary/PID identity, launch and debugger evidence; no mandatory generated Run-button script/configuration |
| `test-triage` | `testing.md`: focused reproducer, regression checks and actual target context |
| `signing-entitlements` | `release.md`, `macos-platform.md`: inspect signatures, nested code, sandbox and entitlements; no authority to change identities or accounts |
| `swiftpm-macos` | `toolchain.md`, `macos-platform.md`, `release.md`: package discovery, existing commands, app bundle/resources and packaging boundaries |
| `packaging-notarization` | `release.md`: distinguish local preparation, Developer ID/hardened runtime, notarization and App Store distribution; submissions require authorization |
| `swiftui-patterns` | `swiftui.md`, `macos-platform.md`: native scenes, menus, Settings, toolbars, selection and commands |
| `liquid-glass` | `swiftui.md`: conditional adoption preserving platform standards and accessibility |
| `window-management` | `macos-platform.md`: scene/window ownership, restoration, focus, keyboard and document behavior |
| `appkit-interop` | `macos-platform.md`: representable lifecycle/coordinators, responder chain, panels and desktop integration |
| `view-refactor` | `swiftui.md`, `architecture.md`, `macos-platform.md`: stable view/scene/selection boundaries with limited scope |
| `telemetry` | `performance.md`: privacy-aware local Logger/signposts and runtime logs; no analytics provider or remote telemetry opt-in |

The profiling references do not bundle a memgraph parser, ETTrace executable, Instruments automation script or general desktop-control mechanism. Optional tool availability and actual task requirements determine execution.

## Architecture and testing sources

Krzysztof Zabłocki's public articles are reference-only:

- [Stop Getting Average Code From Your LLM](https://merowing.info/posts/stop-getting-average-code-from-your-llm/)
- [Exhaustive Testing in TCA](https://merowing.info/posts/exhaustive-testing-in-tca/)
- [The Composable Architecture Best Practices](https://merowing.info/posts/the-composable-architecture-best-practices/)

They inform project-specific conventions, testable dependencies and behavior-focused tests in `architecture.md` and `testing.md`. Public readability is not a redistribution license. No article prose, private rules, course templates or paid lessons were copied. TCA, Dependencies, GRDB, protocols and closure-based dependencies remain contextual choices; none is made mandatory. Existing architecture and persistence remain authoritative unless the user's task calls for a change.

Inject and Sourcery are separately licensed optional tools, covered below. Their inclusion does not import a whole course or imply that hot reload/code generation is required.

## Supporting tool mapping

| Original tool or reference | Treatment and role | Rights and limits |
|---|---|---|
| [XcodeBuildMCP, now MobileBuildMCP](https://github.com/getsentry/MobileBuildMCP/tree/d13ff0c707b0681769cf31da0eb42c4f94ceafff) | Referenced optional Apple build/test/run/debug adapter in `toolchain.md`; inspect live tool names/schemas and project pins | MIT verified; no server, binary or configuration imported. Telemetry, workspace daemons and macro-validation behavior require explicit scrutiny |
| [AXe](https://github.com/cameroncooke/AXe/tree/30f4bfa9bc81817906a60fadedbc913d7314b7e1) | Referenced optional iOS Simulator accessibility/HID and UI evidence adapter | MIT verified; not macOS desktop automation and not proof of full accessibility compliance |
| [DocSetQuery](https://github.com/PaulSolt/DocSetQuery/tree/ba68aabe2c84e907789d4c0043f97568ec8cdcfd) | Referenced local docset extraction/search; match selected Xcode and SDK | MIT tool license verified; Apple or other processed documentation has separate rights |
| [CodexMonitor](https://github.com/Dimillian/CodexMonitor/tree/dd61b9abd37de5ded86e82b9fe8a83fd49d46fa5) | Referenced optional Tauri/Rust workspace and agent/Git UI | MIT verified; no replacement orchestration, daemon, remote-access setup or session-reading authority imported |
| [RocketSim CLI](https://www.rocketsim.app/docs/features/agentic-development/rocketsim-cli/) | Referenced optional simulator inspection/interaction through an existing licensed running app | Commercial app; redistribution rights unverified. No proprietary skill payload copied. It does not replace Xcode compilation |
| [xcbeautify](https://github.com/cpisciotta/xcbeautify/tree/513e4b12c3f6c965d1d3b66bd5cd9d635f03112d) | Referenced log formatting; raw logs and build exit status remain authoritative | MIT verified; optional formatter absence must not block the build |
| [agent-scripts](https://github.com/steipete/agent-scripts/tree/444751eadeb7dabc00634326614ba2483642984f) | Narrow profiling methodology adapted into `performance.md` | MIT verified with Peter Steinberger notice retained; no personal agent policies, unrelated skills or broad script installation |
| [Inject](https://github.com/krzysztofzablocki/Inject/tree/67e3ee9a2b7e40d6af72d07cf1b0d5c04399e809) | Referenced optional debug-only hot reload | MIT verified; separate InjectionIII and build/linker configuration need review; not correctness verification |
| [Sourcery](https://github.com/krzysztofzablocki/Sourcery/tree/f9d80ddec1d42b83b776064162ce0a93a0289334) | Referenced deterministic generation for approved templates | MIT verified; no generator or templates bundled; inspect generated changes and regeneration behavior |
| [Xopoko AppStoreConnectCLI](https://github.com/Xopoko/AppStoreConnectCLI/tree/2af677324e72d7c1684f9d75d57599e64f8c582a) | Referenced `ascctl` OpenAPI discovery/template/dry-run/execution workflow in release guidance | Apache-2.0 verified; no code copied. Do not confuse its commands with `asc` |
| [rorkai App Store Connect CLI skills](https://github.com/rorkai/app-store-connect-cli-skills/tree/9a093fa52177d1b784fcbb06f9abfef4974e7701) | Referenced `asc`-oriented signing, build, TestFlight and release playbooks | MIT verified; this is a different CLI ecosystem. Every external mutation remains scoped and authorized |

Tools are possible adapters, not blanket dependencies. Native Xcode/SwiftPM and repository-owned scripts remain valid routes. Upstream instructions to prefer a specific MCP do not override host availability, repository pins, task scope or authorization.

## Deliberate reconciliation decisions

1. **Keep project targets.** Inspect the actual SDK, deployment minimum, Swift language mode, strict-concurrency/default-isolation settings and repository instructions. Do not globally impose the newest iOS/Swift versions.
2. **Keep architecture and storage.** Preserve UIKit/AppKit/SwiftUI, XCTest, Core Data/SwiftData and Rust/Tauri/Cargo hosts. Migration or a rewrite is product work, not automatic cleanup.
3. **Correct Observation assumptions.** `@ObservationIgnored` can avoid an `@AppStorage` macro conflict but does not itself guarantee observable UI updates. Use appropriate view-level storage or an explicit bridge and test redraw behavior. `@Query` is a SwiftUI view mechanism, not a generic store-fetch API.
4. **Correct task-group failure claims.** A standard throwing task group's child failure does not itself promptly cancel siblings; consuming/propagating that error or explicitly cancelling determines cancellation. Throwing-discarding groups have different failure behavior. Cancellation is cooperative and group scope exit awaits children. See [SE-0381](https://github.com/swiftlang/swift-evolution/blob/main/proposals/0381-task-group-discard-results.md).
5. **Measure the right thing.** Separate build latency from runtime performance and distinguish cold, no-op and edit-triggered builds. Capture the real binary, PID, configuration and symbols before profiling.
6. **Preserve evidence.** A formatted log is not an exit status. A successful launch is not behavioral verification. Simulator results do not establish physical-device correctness or signed distribution readiness.
7. **Keep optional development changes contained.** Hot reload, generated code, telemetry and validation settings have explicit boundaries. Never weaken signing, script sandboxing or macro validation to make a benchmark green.
8. **Preserve Legion ownership.** Platform expertise composes with Architect, Debugger, QA and Designer. It neither duplicates their authority nor creates a separate harness. Audit remains user-invoked.

## Setup layer under review

Both skill entrypoints now require this task-scoped lifecycle for execution/tool-dependent work:

1. **Detect** the host, existing project commands, available tools, versions and selected target.
2. **Select** the smallest toolset required by this task; do not install an entire article's recommendations.
3. **Reuse** a compatible configured tool or repository wrapper before proposing changes.
4. **Set up only with authorization** when a missing selected capability genuinely blocks the task. Describe the tool, source/version, prerequisite, destination and relevant permissions or side effects. Use a verified source-specific recipe; do not guess an installer.
5. **Verify** the installed executable/server identity, version, available schema and a bounded task-relevant check. An installer exit code alone is insufficient. Continue the authorized task and report what remains unverified.

This is an agent-executed setup playbook plus a read-only preflight helper, not a bulk installer. No installation or Apple account change is performed by adding these files. Setup approval does not imply credential creation, persistent network access, telemetry opt-in, security changes, signing-identity changes, simulator erasure, uploads, notarization submission or publication. Those remain separate effects under the current task and host policy.

Each bundle now includes:

- `references/tool-setup.md`: official recipes, client-specific MCP fragments, permission boundaries, preservation/idempotency rules, persistence and failure handling
- `config/tool-catalog.json`: all 11 helper identities, source URLs, platforms, setup scope, acquisition recipes, verification commands and version policy
- `scripts/tool_preflight.py`: original Python 3.8+ PATH-only inspection; no tool execution, network, installations, client-config reads or writes

The catalog distinguishes `asc` from `ascctl` and retains historical `xcodebuildmcp` detection. Optional means selected for the task; the agent owns discovery and a concrete setup proposal. Compatible installations are reused across both skills and repeated invocations. CLI binaries persist per environment; MCP registrations persist per chosen client scope; project packages persist in project files. New machines/containers need fresh checks. The helper only reports candidates, never compatible/authenticated/ready status.

MobileBuildMCP and `asc` command telemetry are explicitly opted out before invocation unless separately authorized, with version/effective-config checks. Existing client entries, comments, project pins, unrelated settings and later user edits must be preserved. Setup does not silently import upstream skill packs or create accounts. Provenance/notices now describe original setup guidance rather than inaccurate link-only treatment. No upstream executable payload or live user configuration is bundled.

Source and recipe checks establish documented acquisition paths, not successful installation on a Mac. An agent follows the recipes with the host's existing approved tools; the helper does not install anything itself.

## Repository integration and files

The baseline commit adds 48 files/changes with 3,786 insertions and two deletions. Each skill directory contains:

- `SKILL.md`: compact entrypoint, platform scope, progressive reference loading and effect boundaries
- `agents/openai.yaml`: host-facing skill metadata
- `dependencies.json`: no unconditional installed-tool dependencies
- `config/tool-catalog.json`, `references/tool-setup.md`, `scripts/tool_preflight.py`: the setup layer described above
- `config/source-manifest.json`: provenance, commit pins, rights receipts, dispositions and excluded material
- `evals/evals.json`: trigger, non-trigger and static behavior expectations
- `references/route-resources.json`: workflow- and adapter-scoped host requirements
- `references/architecture.md`, `concurrency.md`, `performance.md`, `persistence.md`, `release.md`, `swiftui.md`, `system-integration.md`, `testing.md`, `toolchain.md`, `tauri-rust-interop.md` and `third-party-notices.md`
- The corresponding `references/ios-platform.md` or `references/macos-platform.md`

Integration outside the bundles:

- `skills/manifests/ios-development.json` and `skills/manifests/macos-development.json`
- `src/registry/capabilities.json`, `src/registry/host-projection.json`, `src/registry/plugin-surface.json`, `src/registry/routing/domains.json` and `src/registry/skills/index.json`
- `tests/fixtures/routing/semantic-routing-v1.json`
- `engine/bins/legion-dev/src/generators/skill_catalog.rs`
- `tests/apple_tool_preflight_test.py` and `tests/apple_skill_scenarios_test.py`
- `README.md`, `docs/architecture/skills.md` and `docs/THIRD_PARTY_NOTICES.md`

The baseline source paths above are a review map, not a substitute for checking the final commit diff. Shared reference duplication is intentional; there must be no sibling-skill relative dependency, symlink or separately installed source bundle required for either capability to work.

## Verification and limitations

The note author inspected repository instructions, both skill entrypoints, reference content, manifests, notices, eval structure, the baseline commit stat and preserved upstream inventory. Source mapping and license evidence are recorded in the manifests. These inspections establish documentation provenance and intent; they do not execute Apple tools or prove runtime outcomes.

The working environment for this review is Linux. No macOS/iOS build, device run, simulator interaction, signing operation, notarization, App Store Connect mutation, profiler execution or optional-tool installation is claimed here. Actual Apple-platform validation must be performed on the relevant authorized Mac/SDK/runtime and target app. Gated material, private repositories, paid courses and proprietary skill payloads were not verified.

Existing eval files include static expectations. Their presence is not evidence that an agent completed behavioral trials. Generated catalog tests are not Apple runtime tests. An independent Codex review is requested; this note does not claim that it has already passed.

### Reproducible verification record (2026-10-04)

All checks below passed against the completed setup files and regenerated artifacts:

1. Built the repository's actual `legion-dev` Rust generator/checker with `cargo build --locked --manifest-path engine/Cargo.toml -p legion-dev`, using the task-local Rust toolchain/cache. No generator results were hand-edited.
2. Regenerated Codex sidecars, skill catalog, host projection, the two local skill manifests, provider manifest, qualification catalogs and structural plugin projection. Each new setup file is covered by its skill manifest.
3. Ran all **20 steps** declared by `package.json`'s `legion:check`, invoking the built `legion-dev` binary with the same subcommands/arguments. Naming, authority, config, portability, version, schemas, dependency closure, publication/import/distribution/release contracts, generated-artifact drift and native CLI surface checks passed. This uses the real checker in place of the unavailable RightKit wrapper, not a reimplementation of the checks.
4. `cargo test --locked --manifest-path engine/Cargo.toml -p legion-dev -p legion-host -p legion-catalog -p legion-harness`: **71 passed, 0 failed** (14 generator/checker tests, 46 host tests, 10 host integration tests and one catalog test). Existing compiler warnings remain; they were not hidden or expanded into unrelated cleanup. This is the focused four-package suite, not every test in the workspace.
5. `python3 tests/apple_tool_preflight_test.py -v`: **10 passed**, exercising both standalone bundles. Tests cover existing-install reuse, historical MCP executable detection, missing PATH versus possible MCP availability, unsupported environments, project/manual checks, repeated-use idempotency, distinct `asc`/`ascctl`, unknown-ID rejection, byte-identical shared setup content, and an executable fixture that proves the helper does not execute discovered tools or change config/files.
6. `python3 tests/apple_skill_scenarios_test.py -v`: **6 static source/eval checks passed**: Tauri preservation, older iOS/Core Data support, MCP schema mismatch, task-group timeout, `ascctl` versus `asc`/account authority, and conditional Liquid Glass. These test documented expectations, not live agent behavior or native app execution.
7. Standalone-copy/local-reference resolution, source-notice/manifests, public routing metadata and complete 11-tool setup catalog checks are included in the Rust suite. `git diff --check` passed.

An independent read-only source review found default `asc` command telemetry insufficiently addressed; both setup recipes and catalogs were corrected to require process-scoped opt-out before invocation, with version/effective-setting verification. The final review and remote delivery status are reported outside this file after they are observed.

The baseline is `c1ce845f67659015e3d1ba31b66ab503d68d2f72`. The setup commit is the commit containing this note; use Git history to obtain its exact SHA. Remote `main` SHA and CI results must be verified after pushing, and are not pre-claimed here. No Apple-tool installation, MCP connection, account authentication or native runtime validation was performed by these repository checks. The user's later Codex review remains separate.

## Codex review checklist

Review the final diff and current files, not just this narrative. Separate concrete outcome/safety defects from optional improvements.

- [ ] There are exactly two public Apple development capabilities; each installs and reads independently
- [ ] Registry/manifests/catalog projections are generated consistently and routing fixtures cover both positive and negative requests
- [ ] The original article and every original named skill/tool has an explicit adapted, referenced or excluded mapping
- [ ] The nine iOS and eleven macOS OpenAI mappings accurately state partial coverage and explicitly omitted executable workflows
- [ ] Copyright notices, license text, pins and reuse descriptions match actual bundled content
- [ ] No paid/gated/AppCreator/Point-Free material is copied or falsely represented as verified
- [ ] Host prerequisites bind only to selected execution workflows; source review stays usable without Xcode
- [ ] Both entrypoints require detect/select/reuse/authorized-setup/verify and the setup references are linked and bundled
- [ ] Setup recipes identify canonical projects and distinguish current MobileBuildMCP from historical XcodeBuildMCP and `ascctl` from `asc`
- [ ] Setup recipes do not silently install dependencies, add persistent access, enable telemetry, bypass validation or exceed the user's approved effect scope
- [ ] Project pins, existing build wrappers, target deployment versions and host architecture take precedence
- [ ] Observation and task-group cancellation caveats are technically accurate and tested expectations cover them
- [ ] Tauri/Rust, UIKit/AppKit, XCTest and existing storage are preserved when they are the actual host
- [ ] Build/profiling guidance measures comparable workloads and retains exit status, raw logs and target identity
- [ ] Native app behavior, simulator/device evidence and release verification are distinguished accurately
- [ ] Requested focused repository checks passed with recorded command/output evidence; all unavailable checks are disclosed
- [ ] The pushed `main` commit matches the verified local commit and the working tree is in the claimed state

Report blocking findings with severity, exact file/line, a concrete failure case and the smallest correction. Record unavailable evidence as a limitation rather than converting it into a pass. Do not install tools, access credentials, submit releases or change repository state merely to perform the read-only review.
