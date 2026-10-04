# Swift Testing async work

Prefer native `async`/`await` tests and structured concurrency. Keep non-UI tests off a global
actor unless required by code under test. Inspect target default actor isolation before assuming
where tests execute; `@MainActor` may be applied to a test or suite, and `confirmation`/
`withKnownIssue` can receive an actor isolation for one closure.

## Confirmations and callbacks

Use `await confirmation(expectedCount:)` for event delivery/count semantics that are not naturally
awaitable. The code must finish before the confirmation closure returns: `confirmation` does not
wait for a detached completion callback or an internal `Task`. Prefer making production APIs async;
if that is not possible, return the `Task` and `await task.value` before calling `confirm()`.
`expectedCount: 0` verifies an event never occurs. Swift 6.1+ supports `5...10` and `5...` lower-
bounded ranges; open upper-only ranges such as `...10` are disallowed.

For older completion-handler code, do not modernize production code implicitly. Bridge only in the
test with `withCheckedContinuation` or `withCheckedThrowingContinuation`; resume in the completion
handler and assert after resumption. For repeated callbacks, use an actor, `AsyncSequence`, or
other isolation-safe counter rather than an unprotected mutable closure variable. Verify count and
ordering when those are part of behavior.

```swift
@Test func callbackValue() async throws {
    let value = try await withCheckedThrowingContinuation { continuation in
        legacyLoad { continuation.resume(with: $0) }
    }
    #expect(value == 42)
}
```

If production code must return a `Task`, await it before confirming the event:

```swift
await confirmation(expectedCount: 3) { confirm in
    for _ in 0..<3 {
        let task = worker.run { /* callback work */ }
        await task.value
        confirm()
    }
}
```

## Time limits and serialization

Use `.timeLimit(.minutes(1))` on `@Test` or a suite for bounded hangs. The shorter applicable
limit wins; a suite limit applies to each contained test. Swift Testing’s time-limit spelling is
`.minutes(...)`; do not substitute `.seconds(...)` from unrelated APIs.

`.serialized` has two distinct uses: on a parameterized test, it serializes that test’s cases;
on a suite, it serializes tests and sub-suites. It has no effect on an ordinary non-parameterized
test. First remove shared-state coupling; serialization is a narrow transition or explicit shared
resource requirement, not a blanket flakiness fix.

## Networking boundaries

Avoid arbitrary sleeps. Await deterministic completion/cancellation points instead. Unit tests
should not perform live networking. Inject a small protocol around the URLSession methods used,
provide a mock that returns fixture `Data` or throws a configured error, and assert through that
boundary. This keeps tests fast and prevents network availability from changing results.

```swift
protocol URLSessionProtocol {
    func data(from url: URL) async throws -> (Data, URLResponse)
}
extension URLSession: URLSessionProtocol {}

final class URLSessionMock: URLSessionProtocol {
    var testData = Data()
    var testError: (any Error)?
    func data(from url: URL) async throws -> (Data, URLResponse) {
        if let testError { throw testError }
        return (testData, URLResponse())
    }
}
```
