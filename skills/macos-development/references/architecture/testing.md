# Behavior-focused architecture tests

## Design tests around outcomes

Start with the behavior contract, then choose the smallest test boundary that proves it.
A test should have one primary reason to fail and a concise failure message. If one action
produces several independent outcomes, split tests by outcome while sharing only safe setup.
This keeps tests useful during refactors and makes regressions local.

Assert state or effects that are part of the contract. Do not copy every internal transition,
private helper, incidental effect, or event order unless ordering is externally observable.
Exhaustive assertions are useful when a protocol explicitly requires no unhandled action;
focused assertions are better when implementation details change frequently. Choose per test,
not as a blanket rule.

## Determinism

Inject clock, UUID/randomness, filesystem, network, persistence, schedulers, and feature flags.
Use fixed inputs and explicit initial state. Advance virtual time for delayed work. Wait on a
known completion signal rather than sleeping. Assert cancellation and cleanup for long-lived
tasks. Keep unit tests fast enough for repeated agent/build loops; reserve simulator/device
checks for native behavior unit tests cannot prove.

Construct dependency-reading initial state after overrides are prepared, including nested
fixtures. See [initial-state construction timing](dependency-injection.md#initial-state-construction-timing)
for factory order; supplying explicit state alone does not make an earlier UUID/clock read
deterministic.

## Effects & clients

Use client structs or the project’s established dependency system to override only endpoints
used by a scenario. Unused endpoints should report a named failure; a typed placeholder is
valid when return value is needed to complete a test. Avoid fatal errors that terminate the
whole suite. Assert received effect actions only when they represent observable behavior or a
specific integration contract.

## Red → green → refactor

For new behavior, express the smallest failing contract, implement minimum behavior, then
refactor without changing contract assertions. A test that must change after every private
refactor is coupled too deeply. When converting a long test, identify each behavior, split
into focused tests, remove unrelated assertions, and retain one integration test for wiring.

## Test review

- Does test name state trigger, condition, and observable result?
- Is failure diagnostic without reading unrelated assertions?
- Are time, randomness, I/O, and persistence controlled?
- Does test cover cancellation, empty/invalid input, and recovery when relevant?
- Does test prove public behavior rather than a chosen implementation?
- Is simulator/device evidence required beyond unit coverage?
