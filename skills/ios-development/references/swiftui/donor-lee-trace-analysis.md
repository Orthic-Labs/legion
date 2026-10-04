# Instruments Trace Analysis

Use this reference whenever the user references an Xcode Instruments `.trace`
file. A target SwiftUI source file is **optional** — if provided, you can
cite specific lines; without one, the trace still surfaces view names,
hot symbols, and high-severity events that tell the user where to look.

Native `swiftui-trace` reads five lanes for SwiftUI responsiveness (Time
Profiler, Hangs, Animation Hitches, SwiftUI updates, and the SwiftUI
cause graph) from bounded exported XML. It exposes typed operations
`list-logs`, `list-signposts`, `fanin-for`, and `analyze` with `windowMs`.

## When to invoke

Any of these signals:

- Message contains a path ending in `.trace`.
- User mentions "hangs", "hitches", "jank", "slow view", or performance
  issues alongside an Instruments recording.
- User asks to focus analysis "after / before / between / during" a log
  message or signpost.

Triggering does **not** require a SwiftUI source file. If one is present
you'll ground recommendations in specific lines; if not, base them on the
view names and symbols the trace reveals.

## Native operations

Export first with `legion apple profile.export`, then pass XML to
`legion apple swiftui-trace`. Input stays JSON; this route uses bounded native
Rust parsing without an unbounded trace wrapper.

### 1. Full analysis (default)

```bash
legion apple swiftui-trace --input-file analysis.json
```

`analysis.json`:

```json
{"operation":"analyze","xml":"<exported-trace-xml>","top":10,"windowMs":{"start":10400,"end":11700}}
```

- `top` caps evidence per lane; `windowMs` restricts every lane and
  correlation to one time slice.
- Use `operation:"list-runs"` before selecting a run when exported XML
  contains multiple sessions; absent run metadata is reported explicitly.

### 2. `list-logs` — find os_log timestamps

```json
{"operation":"list-logs","xml":"<exported-trace-xml>","subsystem":"com.myapp.net","category":"Network","messageContains":"loaded feed","top":10}
```

Returns bounded entries with `subsystem`, `category`, `process`, event type,
message, and time fields. Filters are AND-combined; no matches return
`status:"no_evidence"`.

### 3. `list-signposts` — find signpost intervals

```json
{"operation":"list-signposts","xml":"<exported-trace-xml>","nameContains":"ImageDecode","subsystem":"com.myapp.feed","category":"Rendering"}
```

Returns bounded interval/point entries with name, subsystem, category,
process, event type, and time fields. Unpaired points remain evidence;
no matches return `status:"no_evidence"`.

### 4. `fanin-for` — who keeps invalidating this view?

```json
{"operation":"fanin-for","xml":"<exported-trace-xml>","destinationContains":"TextStyleModifier","top":10}
```

Returns JSON with destination and ranked source nodes. Each match names a destination node
whose fmt string contains the substring (case-insensitive) and lists its
top incoming source nodes ranked by edge count. Use this after the
`swiftui` lane names an expensive view and you want to know *why it keeps
being invalidated*. For the example above, the top source is
`closure #1 in UserDefaultObserver.Target.GraphAttribute.send()` — the
canonical signature of an `@AppStorage` / `UserDefaults` feedback storm.

## Composition pattern — scoping to a slice

When the user says something like "focus on X", "between A and B", or
"during signpost Y", compose the three modes:

1. **Discover** — call `list-logs` or `list-signposts` with filters
   that match the user's description. Pick the right entries.
2. **Build the window** — take time fields from logs or intervals and form
   `windowMs:{start,end}`.
3. **Analyse** — call `analyze` with `windowMs`.

Examples:

- *"Focus on the section after the log saying 'loaded feed'."*
  → `list-logs` with `messageContains:"loaded feed"`, take entry's
  `startNs`, set `windowMs` to `[that_ms, end_of_trace_ms]` (or use trace
  `duration_s × 1000`).
- *"Between the 'begin-sync' log and the 'done-sync' log."*
  → Two `list-logs` calls (or one with a broader filter), pick two
  timestamps, set window = `[first, second]`.
- *"During the signpost 'ImageDecode'."*
  → `list-signposts` with `nameContains:"ImageDecode"`, pick the
  interval, set window = `[start_ms, end_ms]`.

## JSON shape

```json
{
  "trace": "...",
  "xctrace_version": "26.4 (...)",
  "template": "SwiftUI",
  "duration_s": 14.83,
  "schemas_available": [...],
  "lanes": [
    { "lane": "time-profiler", "available": true, "schema_used": "time-profile",
      "metrics": { "total_samples": N, "total_weight_ms": ms, "processes": [...] },
      "top_offenders": [ { "symbol", "weight_ms", "percent", "samples", "thread" } ] },
    { "lane": "hangs", "available": true, "schema_used": "potential-hangs",
      "metrics": { "count", "total_duration_ms", "worst_duration_ms",
                   "severity_buckets": {"lt_250ms","250ms_1s","gt_1s"} },
      "top_offenders": [ { "start_ms", "duration_ms", "hang_type", "thread" } ] },
    { "lane": "hitches", "available": true, "schema_used": "hitches",
      "metrics": { "count", "total_hitch_ms", "worst_hitch_ms",
                   "narrative_breakdown": {...}, "system_hitches", "app_hitches" },
      "top_offenders": [ { "start_ms", "hitch_duration_ms", "narrative", "is_system" } ] },
    { "lane": "swiftui", "available": true, "schemas_used": [...],
      "metrics": { "total_events", "unique_views", "total_duration_ms",
                   "severity_breakdown": {"Very Low":N,"Moderate":N,"High":N},
                   "update_type_breakdown": {"View Body Updates":N, ...} },
      "top_offenders": [ { "view", "total_ms", "count", "avg_ms" } ],
      "high_severity_events": [ { "view", "severity", "duration_ms", "category",
                                   "update_type", "description" } ] },
    { "lane": "swiftui-causes", "available": true, "schema_used": "swiftui-causes",
      "metrics": { "total_edges", "unique_sources", "unique_destinations",
                   "top_labels": {...} },
      "top_sources":      [ { "source", "edges", "top_destinations": [...] } ],
      "top_destinations": [ { "destination", "edges", "top_sources":      [...] } ] }
  ],
  "correlations": [
    {
      "trigger": { "lane": "hangs"|"hitches", "start_ms", "end_ms", "duration_ms",
                   "hang_type"|"frame_duration_ms" },
      "time_profiler_main_thread": {
        "samples_in_window": N, "samples_on_main": M,
        "main_running_coverage_pct": 0–100,
        "hot_symbols": [ { "symbol", "samples", "weight_ms", "percent_of_main" } ]
      },
      "swiftui_overlapping_updates": [ { "view", "duration_ms", "start_ms" } ]
    }
  ]
}
```

## Interpretation guide

### `main_running_coverage_pct` is the key diagnostic

Time Profiler samples the main thread every ~1ms. For a correlation window
of `N` ms, you'd expect ~`N` main-thread running samples if main were fully
CPU-bound. Coverage is the ratio of observed main-thread samples to that
expectation.

- **< 25% coverage** → main thread was **blocked** (I/O, lock, sync XPC,
  `Task.sleep`, waiting on an actor-isolated call). The `hot_symbols` you
  do see are the moments main *was* executing — look there for the code
  that *initiates* the blocking work, not the work itself. Common fix:
  move to a background executor / `nonisolated` / `Task.detached`.
- **≥ 75% coverage** → main was **CPU-bound** the whole time. `hot_symbols`
  point directly at the expensive work. Common fixes: hoist computation
  out of view bodies, cache derived values, avoid per-frame allocation,
  debounce `onChange`.
- **25–75%** → mix. Usually computation plus intermittent I/O; show both
  hot symbols and note that main was partially blocked.

### High-severity SwiftUI events → reference routing

When `swiftui.high_severity_events[].description` is one of:

| description      | Likely cause              | Route to                            |
|------------------|---------------------------|-------------------------------------|
| `onChange`       | Expensive `.onChange` body | `donor-lee-performance-patterns.md`, `donor-lee-state-management.md` |
| `Gesture`        | Heavy gesture handler     | `donor-lee-performance-patterns.md` |
| `Action Callback`| Button/tap handler work   | `donor-lee-performance-patterns.md` |
| `Update`         | View body recomputation   | `donor-lee-view-structure.md`, `donor-lee-performance-patterns.md` |
| `Creation`       | View init cost            | `donor-lee-view-structure.md`      |
| `Layout`         | GeometryReader churn      | `donor-lee-layout-best-practices.md` |

### Mapping trace findings to source code

If the user gave you a specific file, use it to confirm/cite. If they didn't, the trace itself tells you which views and symbols to look up.

1. **From `swiftui.top_offenders` and `high_severity_events`**, use the
   `view` string as your search key. If a target file is open, grep it;
   if not, recommend the user grep their project for that type or the
   module name. A partial match (prefix / generic stripping) means it's
   probably a subview.
2. **From `correlations[].time_profiler_main_thread.hot_symbols`**, treat
   symbols starting with the user's module name (or in Swift free-function
   form) as candidates. System frames (`swift_`, `dyld`, `objc_`, `CA*`,
   `CF*`, `NS*`, `__open`, `pthread*`) identify *what* the code was doing
   but the user-code caller one frame up is typically what to fix — say
   so and, if you can, suggest searching the project for callers of the
   equivalent Swift API (e.g. `__open` → `FileHandle` / `Data(contentsOf:)` /
   `JSONDecoder.decode(from: Data)` sites).
3. **From `hitches[].narrative`**, Apple pre-attributes each hitch. The
   string `"Potentially expensive app update(s)"` means SwiftUI blamed the
   app (so user code is in scope); absence of narrative usually means it
   was a system hitch or below the threshold.
4. **Correlating hitches with SwiftUI updates**: the
   `swiftui_overlapping_updates` list on each hitch names the views that
   were actively rendering when the frame dropped. Prioritise those.

### Cause graph: finding *why* updates keep happening

The `swiftui` lane tells you *what* is expensive; the `swiftui-causes`
lane tells you *why* it keeps being triggered. Each edge is "source node
propagated to destination node" in SwiftUI's attribute graph.

Signatures to watch for in `top_sources`:

- **`closure #1 in UserDefaultObserver.Target.GraphAttribute.send()`** —
  an `@AppStorage` / `UserDefaults` write is fanning out to every reader.
  If the destination list contains multiple `@AppStorage <Type>.<prop>`
  entries with thousands of edges each, you have a feedback storm. Fix
  by reading each key once at a high level and passing values down, or
  wrapping settings in a single `@Observable` so only genuine readers
  invalidate. Route to `donor-lee-state-management.md` and
  `donor-lee-performance-patterns.md`.
- **`EnvironmentWriter: …`** with thousands of edges — a modifier (often
  `.hoverEffect`, custom environment keys) is applied too widely and
  being re-installed during every layout pass. Route to
  `donor-lee-view-structure.md`.
- **`View Creation / Reuse`** as the #1 source — the hierarchy is
  replacing children rather than mutating in place. Look for ID
  instability (missing/unstable `.id(…)` on ForEach, type-erased
  `AnyView` wrappers, conditional structure swaps). Route to
  `donor-lee-list-patterns.md` and `donor-lee-view-structure.md`.

When a specific view in `swiftui.high_severity_events` keeps showing up,
run `fanin-for` with `destinationContains:"<view name>"` to see ranked sources
invalidating it.

### Picking targets from a full-trace analysis

Prioritise from most actionable to least:

1. **Any `hangs` with `main_running_coverage_pct < 25%`** — these are
   blocking-I/O smells; nearly always fixable by moving work off-main.
2. **Any `hangs` with `main_running_coverage_pct ≥ 75%`** — CPU-bound
   main-thread work; fix the top `hot_symbols`.
3. **`swiftui-causes.top_sources` with > ~1k edges** — structural
   invalidation bugs (feedback storms, over-applied modifiers). These
   are often cheaper to fix than per-view optimisations and collapse
   many downstream high-severity updates at once.
4. **`hitches` with `narrative == "Potentially expensive app update(s)"`**
   and overlapping `swiftui_overlapping_updates` — specific views to
   restructure.
5. **`swiftui.high_severity_events`** — `onChange`, `Gesture`, or `Action
   Callback` with `duration_ms > ~16` are frame-dropping handlers. For
   any that keep firing, run `fanin-for` to find source.
6. **`swiftui.top_offenders`** — heaviest views by total body time, even
   without triggering hitches; candidates for view extraction or
   memoisation (`equatable`, `@ViewBuilder` extraction).

## Recommended output format for the user

After running the parser, structure your response as:

1. **One-line summary** — "Found N hangs, worst Wms; K hitches; J high-severity SwiftUI updates."
2. **Root-cause findings** — per prioritised target (see above), one paragraph with the trace evidence (coverage %, hot symbol, overlapping view) and a citation from the donor topic refs for the fix pattern.
3. **Plan** — numbered, file-specific edits. Cite line numbers in the user's Swift file when you know them. Don't edit the file unless the user asked for edits.
