# Dependency injection

## Ownership rule

Inject collaborators at the boundary that owns their lifetime. The composition root selects
production implementations; features receive only capabilities they use. Previews, tests,
and local tools provide deterministic values explicitly. A global singleton must not choose
accounts, stores, clocks, or network services by accident.

Use the smallest useful seam. A concrete value is enough when there is no alternate behavior.
Use a protocol or client struct when a test double, platform adapter, or second implementation
needs to exist. Keep dependencies grouped by capability instead of passing a service locator.

```swift
struct ClockClient {
    var now: () -> Date
}

struct ReportModel {
    var clock: ClockClient

    mutating func refresh() {
        // deterministic in tests, system clock in composition root
        lastRefresh = clock.now()
    }

    private(set) var lastRefresh: Date?
}
```

## Composition

Construct production clients once at app/module composition. Pass feature dependencies
through initializers or the project’s established dependency mechanism. Keep defaults only
when they are harmless and deterministic; do not hide production I/O in a default argument.

For each dependency, document:

- owner and lifetime;
- allowed execution/isolation boundary;
- failure shape;
- test replacement;
- whether preview/local behavior is intentionally different.

If a feature reaches directly into UserDefaults, a database singleton, URLSession, current
date, UUID, process environment, or a global notification center, first check whether the
existing project already has a seam. Add one narrow seam only when the behavior must be
controlled or observed.

## Initial-state construction timing

Install test/preview dependency overrides before constructing state whose initializers read
UUIDs, clocks or other dynamic values. Passing an already-created state into a later override
scope cannot retroactively replace values captured by its initializer. With an ambient
dependency library, evaluate the state factory inside its prepared override scope; verify
the pinned framework's eager/lazy initializer semantics instead of copying an older API.

An independent factory makes construction order explicit without requiring a framework:

```swift
import Foundation

struct DraftState {
    let id: UUID
}

func makeInitialDraft(makeID: () -> UUID) -> DraftState {
    DraftState(id: makeID())
}

let fixedID = UUID(uuidString: "00000000-0000-0000-0000-000000000001")!
let initialState = makeInitialDraft(makeID: { fixedID })
```

The selected generator runs during state construction. Keep that order when adding nested
state factories; a preconstructed child can capture production values before the parent
enters its test scope. Assert the initial IDs/timestamps as well as later effect results.

## Test doubles

Override only collaborators relevant to behavior under test. Unused endpoints should fail
with an actionable test failure or use an explicit harmless placeholder when a return value
is required. A fatal process abort hides later failures and makes diagnosis harder.

Keep fixtures at the boundary: inject a repository client rather than replacing every model
method. Assert calls that are part of user-visible behavior; avoid asserting incidental call
ordering or private helper structure.

## Review checklist

- Is dependency ownership visible from construction?
- Can a test control time, randomness, I/O, and persistence without process globals?
- Does each feature receive only capabilities it uses?
- Are actor/sendability requirements explicit at the seam?
- Does preview/local composition avoid credentials, accounts, or destructive stores?
- Is any new abstraction justified by a second implementation, test seam, or public boundary?
