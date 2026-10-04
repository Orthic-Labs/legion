# Project and target analysis

Audit project-level causes of build wait: target graph, scheme order, settings, scripts, modules, assets, and no-op overhead. Keep Debug and Release findings separate.

## Target, scheme, and module checks

Confirm target dependencies are explicit, accurate, and free of stale edges; scheme uses Dependency Order; and oversized monoliths do not serialize work that can be split. Check `DEFINES_MODULE` and self-contained public headers for custom frameworks/libraries. Compare explicit-module behavior with current Xcode; repeated module builds often indicate option drift. Compare `SWIFT_OPTIMIZATION_LEVEL`, `SWIFT_COMPILATION_MODE`, `OTHER_SWIFT_FLAGS`, preprocessor macros, language mode, and target overrides across dependents. Keep project-level values unless target-specific difference is justified.

## Build settings audit

Use [settings](settings.md) as a performance-only checklist with `[x]`/`[ ]`, actual value, expected value, and risk. Exclude language migration settings such as `SWIFT_STRICT_CONCURRENCY`, `SWIFT_UPCOMING_FEATURE_*`, `SWIFT_APPROACHABLE_CONCURRENCY`, and intentional non-`DEBUG` compilation conditions. Explicit modules may improve scheduling but can regress from scan overhead; benchmark before recommending.

## Run Script phases

For every phase ask whether it needs to run on incremental, Debug, simulator, or unchanged inputs. Declare precise input/output files; use `.xcfilelist` for long lists; enable dependency analysis once metadata is correct; guard release-only uploads/network tools. Detect `alwaysOutOfDate = 1`, missing I/O, timestamp-only formatter/linter writes, and scripts that block compilation. Never claim a guard safe without checking output, configuration, and target semantics.

## Zero-change overhead

Benchmark immediate no-edit rebuilds. Investigate `PhaseScriptExecution`, `CodeSign`, `ValidateEmbeddedBinary`, `CopySwiftLibs`, `RegisterWithLaunchServices`, `ProcessInfoPlistFile`, and `ExtractAppIntentsMetadata`. A no-op build above roughly five seconds on Apple Silicon is a signal to inspect script, signing, validation, and target count. `ExtractAppIntentsMetadata` can run across first-party, CocoaPods, and SPM targets; if project does not use App Intents, report measured `xcode-behavior` cost without promising repo-local suppression.

Enable Task Backtraces in Scheme Editor → Build → Build Debugging when supported by installed Xcode. Use backtraces to identify exact input that caused a task rerun; record version/UI path, because availability varies.

## Assets and dependencies

`CompileAssetCatalog` is single-threaded per target and multiple catalogs in one target run sequentially. If critical-path evidence supports it, split resources into separate bundles/targets for parallel compilation; check catalogs do not rebuild when unchanged. Compilation cache does not cover `CompileAssetCatalogVariant`.

If CocoaPods is present, avoid Podfile/Pods.xcodeproj micro-optimizations and focus on first-party settings; migration to SPM is a package-manager decision requiring measurement and explicit scope, not an automatic fix.

## Findings

For each issue state evidence, affected targets/files/settings, clean/incremental scope, wall-clock impact, confidence, risk, and actionability: `repo-local`, `package-manager`, `xcode-behavior`, or `upstream`. Prioritize serial scripts, invalidation, duplicate module variants, planning time, and critical-path assets over cosmetic settings cleanup.
