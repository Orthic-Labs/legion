# Benchmarking workflow

Benchmark before recommending a change. Primary metric is elapsed wall-clock time; keep Xcode's aggregated timing categories as diagnostic evidence. Measure clean and incremental builds unless request narrows scope.

## Inputs and repeatability

Resolve workspace/project, scheme, configuration, destination, simulator/device choice, DerivedData path, Xcode/SDK/Swift versions, host, architecture, and environment overrides. Normalize one `xcodebuild` command and keep flags, target, cache state, and warm-up policy constant. Preserve command and exit status for every run. In a worktree, create missing gitignored directories named by a package `exclude:` entry (for example `__Snapshots__`) before package resolution; otherwise `xcodebuild -resolvePackageDependencies` can fail before measurement.

Use native `project.build` for ordinary builds. Its current typed schema does not accept timing-summary or arbitrary compiler flags. For a benchmark requiring those flags, use the project's existing Xcode wrapper or the native system command on its authorized build host, then pass captured logs to Legion's pure analyzer. Replace project, scheme & destination with inspected target values:

```bash
mkdir -p .build-benchmark
xcodebuild -workspace App.xcworkspace -scheme MyApp -configuration Debug \
  -destination "platform=macOS" build -showBuildTimingSummary \
  > .build-benchmark/clean-1.log 2>&1
# Check build exit status before parsing; stop if build failed.
legion apple build-analysis \
  --input '{"operation":"timing.parse","input_path":".build-benchmark/clean-1.log"}'
legion apple build-analysis \
  --input '{"operation":"benchmark.stats","input":".build-benchmark/runs.json"}'
```

Use `-project App.xcodeproj` for a project. Add `-derivedDataPath` only for an owned path. `runs.json` must contain a `runs` array with measured `duration_seconds` & `success` per run; stdout alone does not supply wall-clock duration. CLI `--input` is a JSON object, while `--input-file` reads that object from a file. Analyzer input paths belong inside JSON.

## Run contract

1. Run zero or one warm-up validation build; exclude it from statistics.
2. Run three clean builds, clearing build products between runs with the project's approved clean operation.
3. If resolved settings contain `COMPILATION_CACHE_ENABLE_CACHING = YES`, warm compilation cache once, remove only owned DerivedData between runs, and run three cached-clean builds. Skip cached-clean only when it is outside requested measurement; `--no-cached-clean` belongs to the excluded donor script, not Legion CLI.
4. Run three no-edit builds immediately after a successful build. Label these zero-change timings: they expose dependency computation, project-description transfer, build-description creation, script phases, signing, and validation overhead.
5. For incremental runs, make one controlled representative source edit before each run & restore it afterward; record edit strategy. A timestamp-only touch measures invalidation, not a content edit. `--touch-file` belongs to the excluded donor script, not Legion CLI.
6. Stop on failed runs rather than mixing failed and successful results.

Native `project.settings` plans `-showBuildSettings`; native `project.build` plans an ordinary build. Timing capture above remains with the selected system command or repository wrapper; `build-analysis` parses category lines ending in `seconds`, `second`, or `sec`, accepts pipe or whitespace separators, extracts `(N tasks)`, aggregates duplicate category names, and computes statistics from supplied runs. It never claims execution itself.

## Cache and variance interpretation

Cold clean, cached clean, and incremental answer different questions. Compilation cache persists outside DerivedData: warm cache first, remove DerivedData only, then measure cache-hit clean builds. Observed source evidence reports 5–14% faster clean builds across tested projects with 87–1,991 Swift files; treat this as context, then measure current project. Cacheable work excludes common asset/storyboard/XIB, script, data-model, PNG-copy, dSYM, and linker tasks; do not expect cache to remove all build time.

First measured clean can remain 20–40% slower from OS/dynamic-linker caches. Use median, retain min/max/range, and flag high variance when `(max - min) > 0.20 × median`; run at least five additional repetitions before claiming a conclusion. After a change, call improvement only when post-change median falls outside baseline min–max range or evidence otherwise supports it.

## Artifact requirements

Write `.build-benchmark/<UTC timestamp>-<scheme>.json` plus adjacent raw logs. Include schema version, UTC creation time, project context, host/Xcode/macOS details, normalized command, run arrays, per-run durations, success/exit code, raw-log paths, parsed categories, summary statistics, cache mode, and notes. Never replace raw output with formatter output. See [artifacts](artifacts.md).

## Next route

Use timing categories to choose compilation, project, or SPM analysis. Sum category seconds against wall-clock median: totals near 2× or more imply substantial parallelism, so source hotspot fixes may reduce compiler workload without reducing wait. Empty parsed categories require re-parsing raw logs or manual inspection before analysis.
