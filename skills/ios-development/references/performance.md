# Measure before optimizing

Define the user's symptom and one reproducible baseline: target, configuration, device,
dataset, cache condition, toolchain, and metric. Change one explanatory factor and compare
the same workload. A faster clean build is not evidence of faster incremental iteration.

## Build-time workflow

1. Reproduce the slow phase using the existing build command and timing output. Separate
   package resolution, compilation, linking, asset processing, code generation, signing,
   and install/launch overhead.
2. For incremental behavior, measure a no-change rebuild and a representative small source
   edit. Check which dependencies and generated files become dirty and why.
3. Inspect build settings and scripts: configuration mismatches, unnecessary target edges,
   missing input/output declarations, timestamp churn, and broad generated-file rewrites.
4. Use compiler diagnostics to identify costly type checking or generic expressions, then
   simplify a proven hotspot while preserving semantics. Do not make speculative sweeping
   syntax changes or hide warnings/errors with compiler flags.
5. Evaluate target/module splitting, caching, parallelism, and linker changes against the
   measured bottleneck and developer/CI environment. Account for cache correctness and
   cold-start cost. Never disable correctness, script sandboxing, signature verification,
   or macro validation merely to reduce build time.
6. Re-run clean and incremental cases that the change could affect, then relevant tests.
   Record before/after numbers, variance, command, and any tradeoffs or failed hypotheses.

Avoid destructive DerivedData/cache deletion as the first diagnosis. If a targeted clean
is needed, name the owned build directory and preserve unrelated developer state.

## Runtime workflow

- Confirm the launched executable path, PID, revision, build configuration, and symbols;
  an already installed app can be mistaken for the newly built binary.
- Profile the real slow interaction on representative hardware/configuration. Debug and
  release builds differ; a simulator timing is not a device performance budget.
- Separate main-thread/actor work, I/O, rendering/layout, allocations, retention, energy,
  and synchronization. Use Instruments or relevant native diagnostics when available.
- In SwiftUI, examine update frequency, view identity, expensive body work, list behavior,
  and image decoding before adding caches or replacing the UI framework.
- Bound fetches, batching, concurrency, and memory to real workload constraints. Cache only
  with explicit invalidation/ownership and verify stale-data behavior.
- For Rust/Tauri, include IPC crossings, locks, blocking operations, and WebView rendering;
  Swift tuning does not explain time spent in another host layer.
- Validate correctness and responsiveness after optimization, including cancellation,
  interruptions, and error states implicated by the change.

## Diagnostics and privacy

Use local Logger/signposts when they answer a concrete timing or lifecycle question;
keep sensitive values private and remove temporary noisy diagnostics when no longer useful.
Instruments/xctrace, allocation/leak analysis, memgraphs, or ETTrace are selected only if
available and appropriate to the measured problem. Inspect tool/version compatibility
first; no profiler is a required installation. Memory captures may contain personal data
or secrets. Keep them local and share only specifically authorized, appropriately redacted
evidence. Do not add an analytics provider or opt into telemetry as a profiling shortcut.

Primary documentation: https://developer.apple.com/documentation/xcode/improving-the-speed-of-incremental-builds
and https://developer.apple.com/documentation/xcode/improving-your-app-s-performance
