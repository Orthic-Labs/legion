# Xcode build optimization router

Use this reference for measured iOS build-time diagnosis, scoped remediation, and remeasurement. Shared guidance lives under [build-optimization/](build-optimization/); macOS uses an identical copy with its own platform route.

## Route by evidence

| Need | Reference |
| --- | --- |
| Baseline, repeated clean/incremental runs, cache conditions | [benchmarking](build-optimization/benchmarking.md) |
| Swift type-checking, compiler timing, mixed-language hotspots | [compilation analysis](build-optimization/compilation-analysis.md) |
| Targets, schemes, settings, scripts, assets, fixed overhead | [project analysis](build-optimization/project-analysis.md) |
| Package graph, plugins, pins, macros, module variants | [SPM analysis](build-optimization/spm-analysis.md) |
| Scoped settings, scripts, source, or package changes | [fixing](build-optimization/fixing.md) |
| Full baseline → analysis → prioritized plan → verification | [orchestration](build-optimization/orchestration.md) |

## Shared contract

Measure wall-clock wait, retain raw `xcodebuild` logs, separate clean, cached-clean, zero-change, and touched-file incremental runs, and record command, destination, configuration, scheme, toolchain, host, cache state, and variance. Aggregated timing categories are diagnostic workload; they are not wall-clock unless evidence shows a serial critical path. Analyze before changing project/source/package files, preserve one logical fix per change, and rerun the same benchmark contract after each meaningful optimization.

Use [artifacts](build-optimization/artifacts.md), [settings](build-optimization/settings.md), and [recommendation format](build-optimization/orchestration.md#recommendation-record) for durable evidence. Donor helper behavior is a port specification for Legion's native Rust tooling; no Python/JS/shell helper is shipped here.

## Scope

This route covers native Xcode projects/workspaces and Swift packages used by iOS targets. Keep simulator/device, Debug/Release, architecture, signing, and package-resolution states distinct. Do not infer that a package on disk is linked, that a formatter exit status means a build succeeded, or that a faster cold clean build proves a faster developer edit loop.

Primary references: [Apple incremental builds](https://developer.apple.com/documentation/xcode/improving-the-speed-of-incremental-builds), [Apple coding practices](https://developer.apple.com/documentation/xcode/improving-build-efficiency-with-good-coding-practices), and [Apple explicit module dependencies](https://developer.apple.com/documentation/xcode/building-your-project-with-explicit-module-dependencies).
