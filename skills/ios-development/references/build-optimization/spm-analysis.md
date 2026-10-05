# Swift Package Manager analysis

Treat package analysis as evidence collection. Separate package graph/plugin issues from Xcode project settings; do not rewrite manifests or dependency sources without an authorized, measured plan.

## Verify graph membership

Inspect `Package.swift`, `Package.resolved`, local/remote packages, package plugins, binary targets, build logs, and timing output. Before naming a local package, confirm `XCLocalSwiftPackageReference` in `project.pbxproj`; a `Vendor/` directory alone has no build impact. For remote packages, confirm `XCRemoteSwiftPackageReference` plus at least one `XCSwiftPackageProductDependency` linked to a target.

## Graph and plugin checks

Trace dependency direction (Common/Core → Services/Domain → Features/UI), downstream invalidation, hidden transitive edges, and cycles. Features should not depend directly on each other; extract shared protocols/DTOs to a lower contract module. SPM supports cyclic packages in modern toolchains, but target cycles still require refactoring. Check build-tool/command plugins for repeated work when inputs are unchanged and fixed overhead even when they return quickly. Record checkout/fetch cost for CI and fresh machines, binary extraction cost, and test targets that depend on an app instead of module under test.

Flag roughly 200+ file modules, “And”/“Utils” responsibilities, unnecessary transitive dependencies, and `@_exported import` umbrella chains. Consider interface/implementation separation when heavy implementation blocks many feature modules. Keep test helpers and test-only dependencies out of production targets.

## Pins and scripts

Use Legion's native Rust CLI to parse remote branch requirements & emit text/JSON. A caller may supply read-only `git ls-remote --tags URL` evidence (15s timeout) for tag availability/latest tags; analyzer never invokes git. A tag is a candidate only when observed & measured; do not upgrade pins automatically. If no tags exist, retain a branch when its tracking purpose is intentional, or recommend an observed revision hash for deterministic resolution. Branch pins may force fresh network checks; revisions improve determinism but remove semver range resolution. Verify `xcodebuild -resolvePackageDependencies` through native project execution after any authorized pin.

## Module variants and platform multiplication

Compare macros, language mode, optimization/compilation mode, flags, and configuration-sensitive options across targets importing same module. Align options when safe. Macro-heavy packages can cause trivial edits to cascade; isolate macro use into stable modules when evidence supports it. Check whether `swift-syntax` builds all architectures without a prebuilt binary. A secondary platform (watchOS, Catalyst, macOS) can multiply shared package `SwiftCompile`, `SwiftEmitModule`, and `ScanDependencies` tasks across architecture slices; consider narrower package use or prebuilt binaries only with measured benefit.

Do not assume modular SDK migration reduces build time: more modules add compile, emit, and scan tasks. Benchmark total task count and wall-clock before/after; recommend migration for speed only when unused monolithic portions are actually skipped.

## Report

For each finding include evidence, package/plugin, clean vs incremental impact, CI impact, estimated wall-clock effect, confidence, actionability, risk, and authorization state. High priority: plugin/graph cascades, cycles, umbrella re-exports, macro rebuilds. Medium: duplicate variants, oversized modules, interface split, platform multiplication, universal `swift-syntax`. Low: minor transitive cleanup or checkout cost with no local wait effect.
