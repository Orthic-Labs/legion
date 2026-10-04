# Compilation analysis

Use this lane when timing evidence points to Swift/C/Objective-C compilation. Start from a recent benchmark or raw `-showBuildTimingSummary`; do not infer source bottlenecks from task counts alone.

## Evidence and flags

Inspect `SwiftCompile`, `CompileC`, `SwiftEmitModule`, and `Planning Swift module`, plus per-file compile tasks. The upstream command shape below is retained as a procedure and port contract; Legion ships no Python helper. Run equivalent diagnostics before persistent settings:

```bash
legion apple project.build \
  --project App.xcodeproj --scheme MyApp --configuration Debug \
  --destination "platform=iOS Simulator,name=iPhone 16" \
  --other-swift-flags "-Xfrontend -warn-long-function-bodies=100 -Xfrontend -warn-long-expression-type-checking=100" \
  > .build-benchmark/diagnostics.log 2>&1
legion apple build-analysis --operation compiler.parse \
  --input .build-benchmark/diagnostics.log --threshold-ms 100
```

The Rust port should inject `OTHER_SWIFT_FLAGS` with `-Xfrontend -warn-long-function-bodies=<ms>` and `-Xfrontend -warn-long-expression-type-checking=<ms>`, capture stdout/stderr, parse file:line:column warnings ending `took Nms to type-check`, deduplicate by location/kind, sort by duration, and write JSON plus raw log. `--per-file-timing` adds `-Xfrontend -debug-time-compilation` and parses `N seconds ... compiling FILE`; `--stats-output` adds `-Xfrontend -stats-output-dir` and records JSON-stat directory. Use `-Xfrontend -debug-time-function-bodies` for unfiltered per-function timing, and `-Xswiftc -driver-time-compilation` for driver overhead when supported; preserve exact flags and Xcode version.

## Triage

- If one expression/file dominates, inspect it first.
- If many files share setup cost, inspect module size, public API, explicit modules, and target options.
- If `SwiftEmitModule` dominates after a one-line edit (source reports 60s+ in large modules), consider public-surface narrowing or module split.
- If `Planning Swift module` dominates (source reports up to 30s/module), inspect unexpected input modification, macro invalidation, and script timestamps; escalate to project analysis.
- If category totals are ≥2× wall-clock median, label source findings “reduces compiler workload (parallel)” unless critical-path evidence shows wait-time impact.

## Source checks

Look for explicit local/property types around complex initializers, intermediate bindings for long chains, simple steps instead of nested ternaries/overloaded generic chains, explicit closure parameter/return types, named delegate protocols instead of `AnyObject`, narrow Objective-C bridging headers and prefix headers, framework-qualified/module imports, `final` only after searching for subclasses, narrow `private`/`fileprivate`/`internal` visibility, and value types where identity/reference semantics are unnecessary. Use type aliases or `some Protocol` to reduce deeply nested generic constraints only when semantics remain clear.

For SwiftUI, extract monolithic (roughly 50+ line) `body` result builders into separate `View` structs; avoid deeply nested stacks/groups and prefer typed helpers. Treat each as a candidate tied to measured diagnostics, not a blanket style rule.

## Reporting

Record evidence, file/module, diagnostic flag and threshold, clean vs incremental scope, expected wall-clock impact, confidence, risk, and whether change is authorized. Recommend ad hoc flags before persistent build-setting edits. Hand project-setting, script, module-planning, or target-structure findings to [project analysis](project-analysis.md).
