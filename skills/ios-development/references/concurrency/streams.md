# AsyncSequence and AsyncStream

Use a regular async method for one value, `AsyncSequence` for reusable iteration, and
`AsyncStream`/`AsyncThrowingStream` to bridge callbacks, delegates, notifications or
progress. `AsyncStream.makeStream(of:bufferingPolicy:)` (when available) returns stream and
continuation together and avoids fragile closure capture; use initializer form for older
SDKs. A stream is usually single-consumer; values shared by multiple consumers split rather
than broadcast. Build one stream per consumer or use an appropriate channel/package.

End each stream from every terminal producer path (success, failure, early return and teardown); `finish()` is terminal and repeated calls are tolerated, while a checked continuation's `resume` remains exactly-once. A missing finish can hang `for await`; yields after finish are dropped. `onTermination` is the cleanup boundary: remove observers, stop delegate/source, cancel producer and release handles. Make callback, cancellation and timeout paths race-safe so continuation is not resumed twice.

```swift
let (stream, continuation) = AsyncThrowingStream<Event, Error>.makeStream(
    bufferingPolicy: .bufferingNewest(32)
)
continuation.onTermination = { @Sendable _ in monitor.stop() }
monitor.onEvent = { continuation.yield($0) }
monitor.onError = { continuation.finish(throwing: $0) }
```

Default `.unbounded` buffering can grow memory without limit. Choose `.bufferingNewest(n)`
for latest-state signals, `.bufferingOldest(n)` for first-N work, or zero when stale values
must be dropped. Treat `YieldResult` as evidence of dropped/terminated values when producer
needs to react. Consumers should have an intentional stop condition; cancellation exits a
loop, but code after loop still performs cleanup.

For delegates, retain the delegate while stream is active and stop it from `onTermination`.
For `NotificationCenter` streams, cancellation removes observation through framework. For
observation changes, use `Observations` only when active SDK supports it; otherwise re-register
`withObservationTracking` through a cancellable stream and finish on owner teardown.

AsyncAlgorithms adds debounce/throttle/timer/merge/combineLatest/zip/channel primitives
when dependency is already in scope. It is not a reason to add a dependency: use standard
stream/async APIs for simple bridges. A channel is point-to-point/backpressure, not a
Combine-style broadcast. Cancellation and buffering semantics must be documented per stream.
