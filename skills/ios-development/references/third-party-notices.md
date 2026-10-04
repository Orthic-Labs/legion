# Apple Development Bundle: Third-Party Notices

Reviewed 2026-10-04. Applies to the original consolidated `ios-development` and `macos-development` guidance. Each bundle carries its own copy of this notice and `config/source-manifest.json` so native installation remains self-contained.

## Composition and scope

The bundle uses original concise prose that adapts selected public MIT-licensed methods. It does not contain copied upstream manuals, executable scripts, binaries, assets, MCP configuration, private course material, or credentials. Donor recommendations were reconciled rather than merged verbatim: project deployment targets, architecture and data layer take precedence; cancellation and Observation caveats are corrected; optional tools carry no installation, telemetry, network, or publishing permission.

## MIT-licensed methodological inputs

- [twostraws/SwiftUI-Agent-Skill](https://github.com/twostraws/SwiftUI-Agent-Skill/tree/be297ff80dddec529af1f9b1f1f114aab6c9d11c) — SwiftUI review checklist: API availability, accessibility, navigation, state, performance. [Pinned license](https://github.com/twostraws/SwiftUI-Agent-Skill/blob/be297ff80dddec529af1f9b1f1f114aab6c9d11c/LICENSE)
- [twostraws/Swift-Concurrency-Agent-Skill](https://github.com/twostraws/Swift-Concurrency-Agent-Skill/tree/bee3f69ba17142da148d3c5406f148ed62592b69) — Task ownership, isolation, Sendable, structured concurrency and cancellation review. [Pinned license](https://github.com/twostraws/Swift-Concurrency-Agent-Skill/blob/bee3f69ba17142da148d3c5406f148ed62592b69/LICENSE)
- [twostraws/Swift-Testing-Agent-Skill](https://github.com/twostraws/Swift-Testing-Agent-Skill/tree/2d6bba14a3c8bf3694f218b92fffe617c41ae43e) — Swift Testing review and deterministic test design. [Pinned license](https://github.com/twostraws/Swift-Testing-Agent-Skill/blob/2d6bba14a3c8bf3694f218b92fffe617c41ae43e/LICENSE)
- [twostraws/SwiftData-Agent-Skill](https://github.com/twostraws/SwiftData-Agent-Skill/tree/922d989473a9914210b41529a1ac5636aff4b8c1) — SwiftData modeling, predicates, relationships, schema and CloudKit constraints. [Pinned license](https://github.com/twostraws/SwiftData-Agent-Skill/blob/922d989473a9914210b41529a1ac5636aff4b8c1/LICENSE)
- [AvdLee/SwiftUI-Agent-Skill](https://github.com/AvdLee/SwiftUI-Agent-Skill/tree/9897311e3e42cc77e87603226e74bea711092fbd) — State ownership, macOS scenes/windows/documents, accessibility, view decomposition and profiling. [Pinned license](https://github.com/AvdLee/SwiftUI-Agent-Skill/blob/9897311e3e42cc77e87603226e74bea711092fbd/LICENSE)
- [AvdLee/Swift-Concurrency-Agent-Skill](https://github.com/AvdLee/Swift-Concurrency-Agent-Skill/tree/d5770817d2622e1585b1f7eaebc791a9cb0959c8) — Diagnostic-first concurrency repair and Swift migration verification. [Pinned license](https://github.com/AvdLee/Swift-Concurrency-Agent-Skill/blob/d5770817d2622e1585b1f7eaebc791a9cb0959c8/LICENSE)
- [AvdLee/Swift-Testing-Agent-Skill](https://github.com/AvdLee/Swift-Testing-Agent-Skill/tree/798e9b1a2bcac164d4f0c781908199e754f0bab6) — Testing migration, parallelism, traits, parameterization and async waiting. [Pinned license](https://github.com/AvdLee/Swift-Testing-Agent-Skill/blob/798e9b1a2bcac164d4f0c781908199e754f0bab6/LICENSE)
- [AvdLee/Core-Data-Agent-Skill](https://github.com/AvdLee/Core-Data-Agent-Skill/tree/855ca7d0df50e82b00c12881dd9cd23c19ef5f49) — Existing Core Data stack, context isolation, migrations, history and store tests. [Pinned license](https://github.com/AvdLee/Core-Data-Agent-Skill/blob/855ca7d0df50e82b00c12881dd9cd23c19ef5f49/LICENSE)
- [AvdLee/Xcode-Build-Optimization-Agent-Skill](https://github.com/AvdLee/Xcode-Build-Optimization-Agent-Skill/tree/6bd7b596cd688b1127ded00e812b1b6937ec35d6) — Benchmark-first build-time diagnosis, scoped fixes and before/after evidence. [Pinned license](https://github.com/AvdLee/Xcode-Build-Optimization-Agent-Skill/blob/6bd7b596cd688b1127ded00e812b1b6937ec35d6/LICENSE)
- [steipete/agent-scripts](https://github.com/steipete/agent-scripts/tree/444751eadeb7dabc00634326614ba2483642984f) — Narrow Instruments/xctrace performance workflow: target binary verification, representative workload and evidence. [Pinned license](https://github.com/steipete/agent-scripts/blob/444751eadeb7dabc00634326614ba2483642984f/LICENSE)

The following upstream copyright notices and shared MIT terms are retained for the adapted methods. No endorsement by these authors is implied.

Copyright (c) 2026 Paul Hudson.
Copyright (c) 2026 Antoine van der Lee
Copyright (c) 2026 Peter Steinberger

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Reference-only sources and optional tools

The manifest records the exact inspected pins and license evidence. Merely referencing an external tool does not redistribute it or authorize its execution.

- [getsentry-mobilebuildmcp](https://github.com/getsentry/MobileBuildMCP): MIT. Optional detected MCP/CLI adapter for build, test, simulator/device lifecycle, log capture and debugging; renamed from XcodeBuildMCP. Original capability and official-source setup guidance only. No upstream binary, dependency payload, manual, script, or live client configuration vendored; recipes do not grant install/enable/run authorization.
- [cameroncooke-axe](https://github.com/cameroncooke/AXe): MIT. Optional iOS Simulator accessibility/HID inspection and UI evidence. Original capability and official-source setup guidance only. No upstream binary, dependency payload, manual, script, or live client configuration vendored; recipes do not grant install/enable/run authorization.
- [paulsolt-docsetquery](https://github.com/PaulSolt/DocSetQuery): MIT. Optional local docset extraction/search; tool license does not license Apple documentation it processes. Original capability and official-source setup guidance only. No upstream binary, dependency payload, manual, script, or live client configuration vendored; recipes do not grant install/enable/run authorization.
- [cpisciotta-xcbeautify](https://github.com/cpisciotta/xcbeautify): MIT. Optional xcodebuild output formatter; preserve raw log and build exit status. Original capability and official-source setup guidance only. No upstream binary, dependency payload, manual, script, or live client configuration vendored; recipes do not grant install/enable/run authorization.
- [krzysztofzablocki-inject](https://github.com/krzysztofzablocki/Inject): MIT. Optional debug-only hot reload; separate InjectionIII dependency and linker/settings changes need review. Original capability and official-source setup guidance only. No upstream binary, dependency payload, manual, script, or live client configuration vendored; recipes do not grant install/enable/run authorization.
- [krzysztofzablocki-sourcery](https://github.com/krzysztofzablocki/Sourcery): MIT. Optional deterministic code generation for existing approved template workflow. Original capability and official-source setup guidance only. No upstream binary, dependency payload, manual, script, or live client configuration vendored; recipes do not grant install/enable/run authorization.
- [xopoko-appstoreconnectcli](https://github.com/Xopoko/AppStoreConnectCLI): Apache-2.0. Optional ascctl OpenAPI-first App Store Connect adapter; distinct from asc CLI. Original capability and official-source setup guidance only. No upstream binary, dependency payload, manual, script, or live client configuration vendored; recipes do not grant install/enable/run authorization.
- [rorkai-app-store-connect-cli-skills](https://github.com/rorkai/app-store-connect-cli-skills): MIT. Optional release/TestFlight/signing metadata playbooks for asc CLI, distinct from Xopoko ascctl. Original capability and official-source setup guidance only. No upstream binary, dependency payload, manual, script, or live client configuration vendored; recipes do not grant install/enable/run authorization.
- [openai-build-ios-apps](https://github.com/openai/plugins): MIT (plugin manifest declaration only). Coverage cross-check for App Intents, simulator debugging, SwiftUI performance, ETTrace and memgraph workflows. No upstream skill text, code, scripts, metadata, or assets copied. Platform guidance is independent original prose checked against platform APIs.
- [openai-build-macos-apps](https://github.com/openai/plugins): MIT (plugin manifest declaration only). Coverage cross-check for native scenes, AppKit, shell build/debug, SwiftPM packaging, logging, signing and notarization. No upstream skill text, code, scripts, metadata, or assets copied. Platform guidance is independent original prose checked against platform APIs.
- [dimillian-codexmonitor](https://github.com/Dimillian/CodexMonitor): MIT, verified at dd61b9abd37de5ded86e82b9fe8a83fd49d46fa5. Optional Tauri/Rust workspace and Git/agent UI. No app code, configuration, remote daemon, session access, or network setup imported or authorized.
- [rocketsim-cli](https://www.rocketsim.app/docs/features/agentic-development/rocketsim-cli/): redistribution-license-not-verified. Optional commercial app's version-matched simulator inspection/interaction CLI and skill; app must already be running. No proprietary skill payload or app content imported. Use only an existing licensed installation when authorized; not an Xcode build replacement.
- [zablocki-public-guidance](https://merowing.info/posts/stop-getting-average-code-from-your-llm/): redistribution-license-not-verified. Public architectural/testing context: project-specific conventions, testable dependencies and behavior-focused tests. Original high-level synthesis only; no article prose, course templates, rule packs, or TCA framework adoption imported.
- [swift-primary-concurrency](https://github.com/swiftlang/swift-evolution/blob/main/proposals/0381-task-group-discard-results.md): not-imported. Primary language source for distinguishing standard throwing and throwing-discarding task-group failure semantics. No specification text or code copied.

OpenAI's two Apple plugin manifests declare MIT, but neither their directories nor the repository root contained accompanying LICENSE text at the inspected commit. They are coverage references only; their text and assets are not vendored. The RocketSim app/skill, unlicensed or unverified repositories, and public articles are not presumed open licensed. Apache-2.0 applies to Xopoko's ascctl, which is referenced only; copying it later would require its full license and applicable notices/change annotations. Licenses of optional tool dependencies and of documentation processed by DocSetQuery remain separate.

## Excluded material

Gated AppCreator payloads, full paid courses, and Point-Free subscription material were not available and are not imported or represented as reviewed. These bundles do not grant access to them.
