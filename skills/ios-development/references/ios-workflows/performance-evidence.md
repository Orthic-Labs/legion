# SwiftUI & ETTrace performance evidence

## Code-first triage

Classify symptom (slow render, janky scroll, CPU, memory, hang, or broad updates),
collect exact interaction/device/OS/build mode, then inspect code before tracing. Look
for broad observation reads, unstable IDs, filtering/sorting/formatting in `body`,
main-thread image decode, geometry/layout churn, and over-broad animation. Triage in
that order: invalidation fan-out, identity churn, main-thread work, image cost, then
layout/animation. `_printChanges()` is debug-only evidence; avoid changing production
behavior for diagnosis.

Use `@Observable` with narrow reads, stable domain IDs, precomputed transforms, cached
formatters, background image downsampling, and small extracted views. `@State` is for
view-owned lifecycle state, not arbitrary cache. Apply `equatable()` only where cheap
value equality replaces more expensive subtree work. Keep environment free of fast-
changing values such as timers or geometry.

## SwiftUI Instruments

Record the exact interaction in Release when possible using SwiftUI template plus Time
Profiler and Hangs/Hitches. Inspect long body/platform/other updates, set inspection
range, correlate call tree/flame graph, and use Cause & Effect to find update triggers.
Re-record after fix with comparable setup; report update counts, hitch frequency, CPU,
frame drops, and memory only when measured. Hangs are usually long main-run-loop work;
keep event handlers short and move expensive work out of main actor where safe.

## Focused ETTrace

Choose one visible flow with explicit start/stop, build the exact simulator app,
temporarily link simulator-compatible ETTrace into app target, and remove wiring after
capture. Use one app trace at a time. Capture a matching dSYM set for app executable
and app-owned embedded dynamic frameworks after final build; verify UUIDs. A missing
first-party symbol fails meaningful attribution. System/ETTrace noise may remain.

Capture launch only for startup/first-render; otherwise start from stable screen,
perform one flow, wait for visible completion, stop runner, and preserve fresh processed
`output_<thread>.json` before next run. Do not analyze viewer `output.json` or raw
`emerge-output` data. Use a repository-approved native helper for UUID collection and
strict JSON summaries when available. Report flow, app build, simulator model/runtime, run count, artifact paths,
top active self/inclusive first-party frames, symbol completeness, and comparable
before/after deltas only. A dSYM collector or flamegraph summarizer should be a
repository-approved native helper; preserve raw commands and output paths when no helper
is available.
