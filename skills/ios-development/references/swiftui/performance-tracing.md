# SwiftUI performance & Instruments

## Source-aligned detail

For invalidation, lazy/diffing diagnostics, trace windows, and cause-graph interpretation, read [performance patterns](donor-lee-performance-patterns.md),
[trace analysis](donor-lee-trace-analysis.md), and [trace recording](donor-lee-trace-recording.md).

## Evidence-first workflow

Measure before changing structure. Look for broad invalidation sources, redundant state writes,
objects created in `body`, heavy transforms in rows, eager stacks, deep geometry/preference
chains, closure-based containers, and tasks that outlive their view. Pass narrow Equatable
inputs, use lazy containers, cache only with explicit invalidation, and move CPU/file/network
work off UI isolation without violating Sendable rules. Treat optimizations as hypotheses and
compare identical data/interactions before and after.

## Trace helper contract

For a `.trace`, first resolve requested time scope using logs or signposts, then run a full or
windowed analysis. Record `main_running_coverage_pct`: low coverage suggests blocking/waiting;
high coverage suggests CPU-bound work. Use SwiftUI cause graphs and fan-in to find the source
that invalidates an expensive view (wide environment/defaults observers often dominate). Match
symbols to source and report evidence, impact, and smallest fix. Do not claim a screenshot or
preview proves runtime performance.

Trace capture chooses `SwiftUI` template on a real device/host Mac and `Time Profiler` on iOS
 Simulator, after listing devices. Attach/launch/record scope must be explicit. Use stop-file
recording only when operator controls the end; wait for finalization before analysis. Upstream
Python helpers are source evidence only; port required trace capture/parser behavior to Rust
under root-owned tooling.

Rust port must preserve these helper boundaries: target/template selection and device listing;
safe `xctrace` command construction with explicit run/window/stop-file handling; trace TOC and
schema export; XML column/row resolution, typed value conversion, process/thread/backtrace
extraction, symbol selection, time-window predicates, and interval overlap; independent lanes
for Time Profiler, hangs, animation hitches, SwiftUI updates, signposts, and cause/fan-in
analysis; correlation of hitch/signpost intervals with hot symbols and SwiftUI overlaps; and
stable text/JSON summaries that identify skipped lanes, evidence counts, units, and truncation.
Reject malformed or unavailable schemas with a diagnostic that names the lane and trace path;
never turn missing evidence into a zero measurement.
