# Swift concurrency and migration

## Inspect the actual compilation context

Record compiler/SDK, language mode, strict-concurrency checking, default actor isolation,
and relevant feature flags. Swift language version and compiler version are distinct;
new defaults and annotations are not safe assumptions for every target.

## Isolation and ownership

- Find which actor or synchronization mechanism owns each mutable value. Diagnose the
  crossing before adding annotations. @MainActor is a UI/ownership decision, not a blanket
  fix for every compiler error; avoid moving expensive work there accidentally.
- Sendable describes safe transfer across isolation boundaries. Prefer immutable values
  or isolation-safe ownership. Do not suppress genuine races with @unchecked Sendable,
  nonisolated(unsafe), broad preconcurrency imports, or unchecked shared state.
- Actor isolation prevents simultaneous access to isolated state, but an await permits
  interleaving. Revalidate assumptions after suspension and avoid check-then-act races.
- A Task can inherit actor context; detached work changes context and lifetime semantics.
  Do not use detached tasks as a universal performance or Sendable workaround.
- Bound concurrency to workload and resource limits. Parallelize independent I/O only
  after identifying ordering, rate limits, and shared-state constraints.

## Lifetimes, errors, and cancellation

- Prefer structured child tasks for work whose lifetime belongs to the caller. For an
  unstructured task, name its owner and cancellation/cleanup path; avoid fire-and-forget
  work when success is required for the user's result.
- Cancellation is cooperative. Check it before costly work and mutation, propagate it
  where appropriate, and terminate streams/subscriptions and underlying operations.
- Standard throwing task groups expose child errors when results are consumed. A child
  throwing is not by itself a promise of immediate sibling cancellation. If an error
  escapes the group body, remaining children are cancelled and then awaited.
- Throwing discarding groups have different error behavior: a child failure cancels the
  group automatically. Choose deliberately; verify availability and error requirements.
- All structured group scopes await their children. Racing a sleep against an operation
  is not a hard timeout if the losing operation ignores cancellation. Prefer the
  operation's own timeout/cancellation support and report a non-cooperative blocker.
- Resume a checked continuation exactly once on every completion/cancellation path.
  Test the race between callback, cancellation, timeout, and teardown.
- Consume AsyncSequence with a defined stop condition. A never-ending producer or a
  captured owner can keep tasks, listeners, or resources alive indefinitely.

## Migration workflow

1. Reproduce diagnostics in the affected target and language mode.
2. Fix ownership and boundary types, then isolate UI or service state where justified.
3. Migrate one boundary at a time; retain behavior and public API compatibility.
4. Exercise cancellation, reentrancy, ordering, and repeated/concurrent calls. Compile
   checks prove static enforcement; they do not prove correct business ordering.

Primary documentation: https://docs.swift.org/swift-book/documentation/the-swift-programming-language/concurrency/
and https://www.swift.org/migration/documentation/swift-6-concurrency-migration-guide/
