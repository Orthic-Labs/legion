# Xcode build optimization router

Use this reference for measured Apple build-time diagnosis, scoped remediation, and remeasurement. Start with [build orchestration](build-optimization/orchestration.md); platform examples below select an iOS simulator/device or macOS destination.

## Route by evidence

| Need | Reference |
| --- | --- |
| Baseline, repeated clean/incremental runs, cache conditions | [benchmarking](build-optimization/benchmarking.md) |
| Swift type-checking, compiler timing, mixed-language hotspots | [compilation analysis](build-optimization/compilation-analysis.md) |
| Targets, schemes, settings, scripts, assets, fixed overhead | [project analysis](build-optimization/project-analysis.md) |
| Package graph, plugins, pins, macros, module variants | [SPM analysis](build-optimization/spm-analysis.md) |
| Scoped settings, scripts, source, or package changes | [fixing](build-optimization/fixing.md) |
| Full baseline → analysis → prioritized plan → verification | [orchestration](build-optimization/orchestration.md) |
| Source citations, evidence provenance, and tool-version qualifiers | [source/evidence map](build-optimization/sources.md) |

## Shared contract

Measure wall-clock wait, retain raw `xcodebuild` logs, separate clean, cached-clean, zero-change, and touched-file incremental runs, and record command, destination, configuration, scheme, toolchain, host, cache state, and variance. Aggregated timing categories are diagnostic workload; they are not wall-clock unless evidence shows a serial critical path. Analyze before changing project/source/package files, preserve one logical fix per change, and rerun same benchmark contract after each meaningful optimization.

Use [artifacts](build-optimization/artifacts.md), [settings](build-optimization/settings.md), and [recommendation format](build-optimization/orchestration.md#recommendation-record) for durable evidence. Donor helper behavior is implemented by Legion's native Rust tooling; no Python/JS/shell helper is shipped here.

## Scope

This route covers native Xcode projects/workspaces and Swift packages used by Apple targets. Keep platform, simulator/device, Debug/Release, architecture, signing, and package-resolution states distinct. Do not infer that a package on disk is linked, that a formatter exit status means a build succeeded, or that a faster cold clean build proves a faster developer edit loop.

## Platform benchmark examples

Use native `project.build` for ordinary selected system-tool execution, then send captured output to pure `build-analysis`; analyzer output alone never claims a build ran. Commands below inspect build plans. Execution requires `--execute` with host-authorized `--policy-context`; save returned `stdout` as raw evidence. For timing or compiler diagnostics, use the repository's existing authorized Xcode wrapper or native `xcodebuild` on its authorized host, then parse its captured log. Do not pass arbitrary Xcode flags through `project.build`; its schema remains the typed ordinary-build contract.

### iOS

```bash
legion apple project.build \
  --input '{"workspace":"App.xcworkspace","scheme":"MyApp","configuration":"Debug","destination":"platform=iOS Simulator,name=iPhone 16"}'
legion apple build-analysis \
  --input '{"operation":"timing.parse","input_path":".build-benchmark/ios-clean-1.log"}'
```

Use an explicit iOS device destination when device signing/build behavior is under test; do not substitute a macOS destination for an iOS result.

### macOS

```bash
legion apple project.build \
  --input '{"workspace":"App.xcworkspace","scheme":"MyMacApp","configuration":"Debug","destination":"platform=macOS"}'
legion apple build-analysis \
  --input '{"operation":"timing.parse","input_path":".build-benchmark/macos-clean-1.log"}'
```

Use macOS target/scheme settings and `platform=macOS`; do not route a macOS diagnosis through an iOS simulator.

## Platform compiler examples

Keep diagnostic flags and thresholds fixed across repeated runs. Capture them through the authorized wrapper or native `xcodebuild` route in [compiler capture](build-optimization/compilation-analysis.md#evidence-and-flags), then parse its existing raw log with native Rust:

```bash
legion apple build-analysis \
  --input '{"operation":"compiler.parse","input_path":".build-benchmark/compiler.log","threshold_ms":100}'
```

Apply `-Xfrontend -warn-long-function-bodies`, `-Xfrontend -warn-long-expression-type-checking`, `-Xfrontend -debug-time-compilation`, `-Xfrontend -debug-time-function-bodies`, `-Xswiftc -driver-time-compilation`, or `-Xfrontend -stats-output-dir` only through that authorized wrapper or native `xcodebuild` invocation when the selected toolchain supports them; preserve exact flags in evidence. `build-analysis` only parses supplied output and never injects flags or runs a build.

Primary references: [Apple incremental builds](https://developer.apple.com/documentation/xcode/improving-the-speed-of-incremental-builds), [Apple coding practices](https://developer.apple.com/documentation/xcode/improving-build-efficiency-with-good-coding-practices), and [Apple explicit module dependencies](https://developer.apple.com/documentation/xcode/building-your-project-with-explicit-module-dependencies).
