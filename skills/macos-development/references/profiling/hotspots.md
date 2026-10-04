# Hotspots & diagnosis

Aggregate call-stack sample addresses, filter to the app's `__TEXT` range, symbolize and rank counts. Report address, sample count, symbol, thread/queue and workload phase. A top frame is a lead, not root cause; correlate with signposts, logs, allocation/energy/launch diagnostics and source.

Separate main-thread/actor isolation, I/O, rendering/layout, allocations/retention, synchronization, launch work and WebView/IPC or Rust/Tauri host work. In SwiftUI inspect update frequency, identity, body cost, list behavior and image decoding before changing framework or adding a cache. Bound fetches, batching, concurrency and memory to measured workload; document invalidation/ownership for every cache.

Validate one hypothesis at a time on same workload. Capture baseline and after-change traces, compare sample counts and wall time with variance, and rerun correctness, cancellation, interruption and error-state checks. Release/debug and simulator/device traces answer different questions.

## Report shape

Record trace path/hash, binary/dSYM identity, command/template, device/OS, load address, duration, workload steps, top app frames and interpretation. Name unsymbolicated/empty traces as evidence gaps. Keep private raw data separate from concise redacted report.
