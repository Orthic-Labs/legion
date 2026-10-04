# Errors & recovery

## Model failures at boundaries

Use typed errors for decisions callers can make. Keep low-level details in an underlying
cause while exposing a stable domain category and recovery action. Distinguish invalid input,
unavailable capability, transport failure, decoding/schema failure, cancellation, and an
unexpected defect. Do not turn cancellation into a user-facing failure.

```swift
enum ImportError: Error, Equatable {
    case invalidInput(field: String)
    case unavailable
    case transport(reason: String)
    case malformedData
    case cancelled
}
```

Map errors once at each boundary. A URL or persistence error may become `transport` or
`malformedData` for domain code; UI code then maps the domain case to message, retry, sign-in,
or recovery flow. Preserve a safe diagnostic identifier for logs without exposing tokens,
paths, account data, or response bodies.

## Recovery decisions

For each thrown/returned failure, decide explicitly:

1. Can caller retry safely? Require idempotence or a request identifier before retrying.
2. Can caller correct input? Point to field or action, not a generic failure.
3. Can caller continue with stale/partial data? State freshness and persistence rules.
4. Must operation stop? Surface unavailable capability, authorization, migration, or data-loss
   conditions before mutating state.

Do not silently swallow errors, retry forever, force unwrap, force try, or use a fallback that
changes account, store, or security meaning. Log once at the boundary that has enough context;
avoid duplicate logs in every layer.

## Async cancellation

Propagate cancellation through async work. Check cancellation before expensive phases and
after awaited boundaries where partial results would otherwise mutate state. Cleanup belongs
to the owner of the task. Tests should cover cancellation when work is long-lived or tied to
view/module lifetime.

## Persistence & migration

Treat persisted schema changes as compatibility work. Add migration/version evidence and a
rollback or recovery story before writing new data. Test old fixture → migration → current
fixture, including corrupt/partial input. Never discard user data to make a migration pass.
