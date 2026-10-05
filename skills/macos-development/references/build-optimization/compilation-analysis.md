# Compilation analysis

Use this lane when timing evidence points to Swift/C/Objective-C compilation. Start from a recent benchmark or raw `-showBuildTimingSummary`; do not infer source bottlenecks from task counts alone.

## Evidence and flags

Inspect `SwiftCompile`, `CompileC`, `SwiftEmitModule`, and `Planning Swift module`, plus per-file compile tasks. Diagnostic flags belong to the selected Xcode invocation; current native `project.build` does not expose `OTHER_SWIFT_FLAGS` or arbitrary diagnostic arguments. Use the repository wrapper if it owns builds, otherwise this system-command shape on the authorized host:

```bash
mkdir -p .build-benchmark
xcodebuild -project App.xcodeproj -scheme MyApp -configuration Debug \
  -destination "platform=macOS" \
  'OTHER_SWIFT_FLAGS=$(inherited) -Xfrontend -warn-long-function-bodies=100 -Xfrontend -warn-long-expression-type-checking=100' \
  build -showBuildTimingSummary > .build-benchmark/diagnostics.log 2>&1
# Check build exit status before parsing; stop if build failed.
legion apple build-analysis \
  --input '{"operation":"compiler.parse","input_path":".build-benchmark/diagnostics.log","threshold_ms":100}'
```

Keep existing Swift flags. Add `-Xfrontend -warn-long-function-bodies=<ms>` & `-Xfrontend -warn-long-expression-type-checking=<ms>` for an ad hoc run, capture stdout/stderr, then parse file:line:column warnings ending `took Nms to type-check`, deduplicate by location/kind & sort by duration. The parser reads supplied logs; it does not inject flags or build projects.

For per-file timing add `-Xfrontend -debug-time-compilation`; parse `N seconds ... compiling FILE`. For compiler statistics add `-Xfrontend -stats-output-dir` plus an owned output directory. `--per-file-timing` & `--stats-output` are excluded donor-script options, not Legion CLI flags. Use `-Xfrontend -debug-time-function-bodies` for unfiltered per-function timing. Driver timing uses `-driver-time-compilation` in Xcode's Swift flags, or `-Xswiftc -driver-time-compilation` with SwiftPM when supported. Preserve exact flags, Xcode version, exit status & raw logs; avoid persistent build-setting changes before evidence.

## Triage

- If one expression/file dominates, inspect it first.
- If many files share setup cost, inspect module size, public API, explicit modules, and target options.
- If `SwiftEmitModule` dominates after a one-line edit (source reports 60s+ in large modules), consider public-surface narrowing or module split.
- If `Planning Swift module` dominates (source reports up to 30s/module), inspect unexpected input modification, macro invalidation, and script timestamps; escalate to project analysis.
- If category totals are ≥2× wall-clock median, label source findings “reduces compiler workload (parallel)” unless critical-path evidence shows wait-time impact.

## Source checks

Look for explicit local/property types around complex initializers, intermediate bindings for long chains, simple steps instead of nested ternaries/overloaded generic chains, explicit closure parameter/return types, named delegate protocols instead of `AnyObject`, narrow Objective-C bridging headers and prefix headers, framework-qualified/module imports, `final` only after searching for subclasses, narrow `private`/`fileprivate`/`internal` visibility, and value types where identity/reference semantics are unnecessary. Use type aliases or `some Protocol` to reduce deeply nested generic constraints only when semantics remain clear.

For SwiftUI, extract monolithic (roughly 50+ line) `body` result builders into separate `View` structs; an `@ViewBuilder` helper property can retain one result-builder type-checking scope, while separate `View` types reduce scope per `body`. Avoid deeply nested stacks/groups and prefer typed helpers. Treat each as a candidate tied to measured diagnostics, not a blanket style rule.

## Reporting

Record evidence, file/module, diagnostic flag and threshold, clean vs incremental scope, expected wall-clock impact, confidence, risk, and whether change is authorized. Recommend ad hoc flags before persistent build-setting edits. Hand project-setting, script, module-planning, or target-structure findings to [project analysis](project-analysis.md).
