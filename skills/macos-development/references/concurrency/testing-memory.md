# Testing, cancellation and memory mechanics

Prefer async Swift Testing functions (`@Test`, `#expect`) and await production APIs directly.
Actor access in tests uses `await`; mark a test/suite `@MainActor` only when API requires it.
Use `confirmation` for callbacks/notifications and ensure all work, including returned task
handles, completes before confirmation scope exits. `.serialized` controls parameterized
cases/suite behavior only as documented by active Swift Testing; it does not repair a
production race.

Never use fixed sleeps as synchronization. Use a signal, continuation, stream, task handle,
or deterministic executor support. `Task.yield()` is scheduling help, not cancellation and
not an ordering guarantee. Test cancellation by cancelling while production code is
suspended, then assert production observes cancellation. Test bounded groups for max
parallelism, partial-result/error policy, sibling cancellation and input-order guarantees.

Enable Thread Sanitizer for race-sensitive suites, especially lock-based or unchecked code;
enable Core Data concurrency debugging for context violations. Static compile checks and
TSan do not prove business ordering or lifetime cleanup, so add semantic assertions.

Tasks capture references like closures. If owner stores task and task strongly captures owner,
an infinite loop/stream creates a retain cycle. Store and cancel long-lived tasks, use weak
capture or a separate owner when lifetime should end, and finish stream continuations in
teardown. `isolated deinit` only runs after deallocation; it cannot break a cycle that keeps
deinit from running. Short-lived strong capture may be acceptable when lifetime extension is
intentional and bounded.

For leak checks, hold weak reference, start work, cancel/finish it, await task completion,
then assert owner deallocated. Use Xcode Memory Graph/Instruments Leaks to inspect cycles.
Do not “fix” leaks by arbitrary sleeps or by weakening all captures; identify producer,
consumer and owner edges.
