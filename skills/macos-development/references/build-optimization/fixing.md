# Applying scoped fixes

Apply one logical change at a time, keep exact files/targets, preserve reversibility, and remeasure with original command/target/cache conditions. A user request authorizes in-scope implementation; an approval checkbox from a donor plan is not a Legion prerequisite. If plan is supplied, honor only items explicitly selected by user or plan owner.

## Settings

Edit the target/configuration `buildSettings` block after matching target and configuration, then inspect `xcodebuild -showBuildSettings`. Candidate settings follow [settings](settings.md): Debug `dwarf`, `singlefile`, active arch only; cache and eager linking where supported; integrated driver and Clang modules; Release whole-module, optimized, all architectures, dSYM, and no testability. Do not disable signing, macro/plugin validation, sandboxing, or correctness for speed.

## Script phases

Declare precise inputs/outputs; move long lists to `.xcfilelist`; enable dependency analysis only after declarations are accurate. Guard release-only work with a configuration check such as `[[ "$CONFIGURATION" != "Release" ]] && exit 0`, but verify simulator/device and output semantics before applying. Never skip a generator whose output is required by current target.

## Source fixes

Use diagnostics to target explicit annotations, typed intermediate values, decomposed chains/result builders, explicit closure returns, narrow delegate protocols, `final` only after searching subclass use, narrower access, smaller SwiftUI subviews, and simpler generic constraints. Preserve API, behavior, visibility contracts, and Objective-C exposure. Re-run compilation and relevant tests after each logical change.

## SPM fixes

Move shared contracts downward, split oversized modules by responsibility, separate interfaces from implementations, remove unjustified `@_exported import`, align options across dependents, isolate macro-heavy code, and pin branch dependencies only after tag/revision evidence. Verify package links in `project.pbxproj` and run package resolution after an authorized change.

## Remeasure and classify

Record changed files, baseline/post medians, min/max, variance, and failed hypotheses. Compare standard clean, cached clean when enabled, zero-change, and touched-file incremental. A slower cold clean with faster cached-clean may be net positive for branch switching; report both. Distinguish median improvement from outlier reduction. Keep recommended settings when they match current toolchain best practice even if immediate improvement is absent, but label no measured wait-time effect. Revert speculative changes only when cumulative relevant metrics regress or an individual change has no benefit and no non-performance reason to keep it.

For a focused build sanity check, preserve the selected workspace/project, scheme, configuration, destination, and DerivedData conditions while running the equivalent of `xcodebuild -project App.xcodeproj -scheme MyApp -configuration Debug -destination 'platform=macOS' build`; inspect exit status and raw output before re-running the benchmark contract. The upstream helper command is a port specification for Legion's native Rust CLI, not a shipped Python dependency.

Status values: `Kept`, `Kept (best practice)`, `Reverted`, `Blocked`, `No improvement`; include reason and evidence. Use [patterns](patterns.md) for concrete before/after shapes.
