# Apple development bundle: third-party notices

Reviewed 2026-10-05. This bundle contains original Legion guidance with substantive rules, decision branches, and examples adapted from pinned public sources. Adapted prose is rewritten for Legion ownership and safety boundaries; upstream code, scripts, binaries, plugin metadata, assets, installers, credentials, and live MCP configuration are excluded.

`config/source-manifest.json` records each source pin, disposition, inspection receipt, and local notice path. The ledger files under `docs/apple-absorption/` record per-file and per-rule keep/merge/reject decisions. Local files below are exact license text snapshots from the inspected pins; they do not imply author endorsement.

## Adapted MIT sources

- `twostraws-swiftui-agent-skill` — commit `be297ff80dddec529af1f9b1f1f114aab6c9d11c`; SwiftUI state, availability, accessibility, navigation, and performance rules. [Exact MIT notice](licenses/twostraws-MIT.txt).
- `twostraws-swift-concurrency-agent-skill` — commit `bee3f69ba17142da148d3c5406f148ed62592b69`; ownership, isolation, Sendable, structured concurrency, and cancellation rules. [Exact MIT notice](licenses/twostraws-MIT.txt).
- `twostraws-swift-testing-agent-skill` — commit `2d6bba14a3c8bf3694f218b92fffe617c41ae43e`; deterministic Swift Testing rules and examples. [Exact MIT notice](licenses/twostraws-MIT.txt).
- `twostraws-swiftdata-agent-skill` — commit `922d989473a9914210b41529a1ac5636aff4b8c1`; SwiftData model, predicate, relationship, index, migration, and CloudKit rules/examples. [Exact MIT notice](licenses/twostraws-MIT.txt).
- `avdlee-swiftui-agent-skill` — commit `9897311e3e42cc77e87603226e74bea711092fbd`; state, scenes, accessibility, decomposition, and profiling rules. [Exact MIT notice](licenses/avdlee-MIT.txt).
- `avdlee-swift-concurrency-agent-skill` — commit `d5770817d2622e1585b1f7eaebc791a9cb0959c8`; diagnostic-first concurrency migration rules. [Exact MIT notice](licenses/avdlee-MIT.txt).
- `avdlee-swift-testing-agent-skill` — commit `798e9b1a2bcac164d4f0c781908199e754f0bab6`; testing migration, parallelism, traits, parameterization, and async waiting. [Exact MIT notice](licenses/avdlee-MIT.txt).
- `avdlee-core-data-agent-skill` — commit `855ca7d0df50e82b00c12881dd9cd23c19ef5f49`; Core Data context, save/fetch/batch, history, migration, store, and testing rules/examples. [Exact MIT notice](licenses/avdlee-MIT.txt).
- `avdlee-xcode-build-optimization-agent-skill` — commit `6bd7b596cd688b1127ded00e812b1b6937ec35d6`; benchmark-first build diagnosis and evidence rules. [Exact MIT notice](licenses/avdlee-MIT.txt).
- `steipete-agent-scripts` — commit `444751eadeb7dabc00634326614ba2483642984f`; profiling target, capture, symbolication, and evidence rules. Upstream scripts are excluded. [Exact MIT notice](licenses/steipete-MIT.txt).
- `krzysztofzablocki-inject` — commit `67e3ee9a2b7e40d6af72d07cf1b0d5c04399e809`; debug-only hot-reload boundary and authorization rules. Framework snippets and scripts are excluded. [Exact MIT notice](licenses/inject-MIT.txt).
- `krzysztofzablocki-sourcery` — commit `f9d80ddec1d42b83b776064162ce0a93a0289334`; generator fit, template ownership, deterministic invocation, and output traceability. [Exact MIT notice](licenses/sourcery-MIT.txt).
- `getsentry-mobilebuildmcp` — commit `d13ff0c707b0681769cf31da0eb42c4f94ceafff`; bounded build/test, simulator/device, debugging, and profiling rules implemented in Legion's native Rust Apple CLI/MCP. [Exact MIT notice](licenses/mobilebuildmcp-MIT.txt).
- `paulsolt-docsetquery` — commit `ba68aabe2c84e907789d4c0043f97568ec8cdcfd`; local-first documentation lookup, sanitization, caching, and citation rules inform Legion's independent native Rust reader. DocSetQuery source and Apple documentation are not redistributed. [Exact MIT notice](licenses/docsetquery-MIT.txt).
- `cpisciotta-xcbeautify` — commit `513e4b12c3f6c965d1d3b66bd5cd9d635f03112d`; optional formatter and raw-log/build-status correctness rules. Formatter code and binaries are excluded. [Exact MIT notice](licenses/xcbeautify-MIT.txt).
- `rorkai-app-store-connect-cli-skills` — commit `9a093fa52177d1b784fcbb06f9abfef4974e7701`; release, TestFlight, signing, metadata, and notarization rules. [Exact MIT notice](licenses/rorkai-MIT.txt).
- `rorkai-app-store-connect-cli` — commit `107242d3087360c7b54f2691656e2c6d70acfb9b`; Go CLI operation lookup, bounded uploads, checksum verification, redaction, and processing-state rules implemented in Legion's native Rust App Store Connect adapter. [Exact MIT notice](licenses/rorkai-app-store-connect-cli-MIT.txt).

## Adapted Apache source

- `xopoko-appstoreconnectcli` — commit `2af677324e72d7c1684f9d75d57599e64f8c582a`; ascctl/OpenAPI-first release contract guidance is rewritten into local release guidance. [Change notice](licenses/xopoko-CHANGES.md). No source, generated client, dependencies, binaries, or packaging metadata are distributed, so no modified upstream file is shipped. [Complete Apache License 2.0 text](licenses/xopoko-Apache-2.0.txt). The upstream repository separately lists Apache-licensed `swift-argument-parser` and `swift-crypto`; those dependency texts are not bundled because no Xopoko code is bundled.

## Reference-only sources

- `cameroncooke-axe` — commit `30f4bfa9bc81817906a60fadedbc913d7314b7e1`; only capability and official-source setup references remain. [Exact MIT notice](licenses/axe-MIT.txt).
- `dimillian-codexmonitor` — commit `dd61b9abd37de5ded86e82b9fe8a83fd49d46fa5`; optional Tauri/Rust workspace reference only. [Exact MIT notice](licenses/codexmonitor-MIT.txt).
- `openai-build-ios-apps` and `openai-build-macos-apps` — commit `5fd93af4cd0c623e020d0cc7e9ce178b4ac1f70f`; inventoried plugin manifests declare MIT, but no LICENSE text is present in either Apple plugin directory. Only ledger-marked independent Legion workflows are represented; no OpenAI prose, code, scripts, metadata, or assets are copied, and no local license notice is asserted.

## Deliberate exclusions

RocketSim commercial material, public unlicensed guidance, gated AppCreator payloads, paid courses, Point-Free subscription material, and Swift Evolution specification text are excluded. Tool references do not authorize installation, telemetry, credentials, account changes, publishing, or network services. Apple platform documentation remains subject to its own terms; DocSetQuery's MIT license does not license documentation it processes.

Source inspection and authoring produced these notices; this file does not claim that all tests or semantic review have passed.
