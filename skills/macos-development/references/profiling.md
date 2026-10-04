# Native profiling router

Use [capture](profiling/capture.md) as entrypoint for operational capture & analysis:

- [capture](profiling/capture.md) — reproducible workload, correct process, Time Profiler templates, device/simulator selection & privacy.
- [export & symbols](profiling/export.md) — xctrace XML export, matching binaries, ASLR/load addresses & symbolication.
- [hotspots & diagnosis](profiling/hotspots.md) — app-frame ranking, thread/actor/I/O/rendering separation, validation & reporting.

Measure a named symptom against one repeatable baseline: target, revision, configuration, device, dataset, cache state, toolchain, duration & metric. Change one explanatory factor at a time. A clean build time does not establish incremental performance; simulator timing does not establish a device budget.

Keep traces, memory captures, logs & exported XML private; redact before sharing. Select an installed compatible profiler when available. Do not add telemetry or install a profiler as a shortcut.
