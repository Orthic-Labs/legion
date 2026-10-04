# Swift Testing isolation and performance

Swift Testing runs sync and async tests in parallel, in nondeterministic order. This improves
feedback and exposes ordering bugs, so isolate mutable state per invocation. Avoid shared mutable
globals, singleton mutation, shared databases/files, implicit fixtures, and external accounts.
Fresh suite instances help; deterministic clocks, random sources, and test data help more.

For shared resources, prefer a fresh backing store per test, in-memory fakes for fast unit paths,
or a dedicated serial integration plan when real state is the behavior under test. Serialized suites
can still run beside unrelated suites in parallel; document why serialization remains and remove it
after isolation work.

Keep purely synchronous tests synchronous; do not add `async` or sleeps for synchronous logic.
Use `@MainActor` only for UI/main-thread-sensitive behavior. Build expensive fixtures only when
needed, keep readonly suite setup immutable and cheap, and reserve network/filesystem setup for
tests that explicitly exercise those boundaries. Parameterized tests reduce duplicated setup and
provide argument-level failures.

Flakiness checklist:

- no execution-order assumptions or arbitrary sleeps;
- no unreset shared globals/singletons;
- no hidden external dependency in a unit test;
- deterministic fixtures plus controllable clock/randomness;
- narrow `withKnownIssue` wrappers for temporary, tracked failures.

