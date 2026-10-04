# Swift concurrency and migration

This page routes to task-specific guidance. Read the smallest matching page, then inspect
the target's compiler/SDK, Swift language mode, strict-concurrency level, default actor
isolation, and upcoming features before applying version-sensitive advice.

- Detailed topic index, including task lifetime and memory guidance: [concurrency/_index.md](concurrency/_index.md)

- Fundamentals, callback bridges, `async let`: [concurrency/async-await-basics.md](concurrency/async-await-basics.md) and [concurrency/foundations.md](concurrency/foundations.md)
- Actors, reentrancy, global actors, executors and `Mutex`: [concurrency/actors.md](concurrency/actors.md)
- `Sendable`, regions, `sending`, closures and unsafe escape hatches: [concurrency/sendable.md](concurrency/sendable.md)
- Tasks, groups, bounded fan-out, timeout and cancellation: [concurrency/tasks.md](concurrency/tasks.md)
- `AsyncSequence`, `AsyncStream`, buffering and teardown: [concurrency/async-sequences.md](concurrency/async-sequences.md) and [concurrency/streams.md](concurrency/streams.md)
- Swift 6.x execution/isolation behavior and GCD migration: [concurrency/threading.md](concurrency/threading.md)
- Diagnostics, staged migration, Core Data, observation and algorithms: [concurrency/migration.md](concurrency/migration.md), [concurrency/core-data.md](concurrency/core-data.md), [concurrency/observation.md](concurrency/observation.md), [concurrency/async-algorithms.md](concurrency/async-algorithms.md)
- Swift Testing, deterministic cancellation and memory/lifetime checks: [concurrency/testing.md](concurrency/testing.md) and [concurrency/testing-memory.md](concurrency/testing-memory.md)
- Performance, linting and terminology: [concurrency/performance.md](concurrency/performance.md), [concurrency/linting.md](concurrency/linting.md), [concurrency/glossary.md](concurrency/glossary.md)

Always prefer the smallest behavior-preserving ownership fix. `@MainActor` describes UI
ownership, `actor` describes mutable state ownership, and `@concurrent` is conditional
offloading; none is a blanket diagnostic suppressor. Structured children inherit lifetime
and cancellation. Unstructured tasks require a named owner and cleanup path. `await` may
reenter an actor, so state must be revalidated after every suspension.

Primary references: Swift Book Concurrency and Swift 6 migration guide.
