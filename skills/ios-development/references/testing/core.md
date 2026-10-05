# Swift Testing core

## Scope and framework choice

Import `Testing` only in test targets. Use Swift Testing for new unit and integration tests when
target/toolchain supports it; keep XCTest for UI automation (`XCUIApplication`), performance
metrics (`XCTMetric`), Objective-C-only tests, and any existing suite not requested for migration.
Swift Testing does not provide UI-test APIs. Treat installed Xcode/Swift and platform deployment
targets as authoritative, because APIs evolve across Swift releases.

## Suites and test declarations

Use `@Test` on global functions or type methods. Prefer `struct` suites for value semantics and
to prevent accidental state sharing; `actor` or `class` suites remain valid when isolation,
deinitialization, or inheritance requires them. A type containing `@Test` methods is already a
suite; add `@Suite` only for a display name or suite-level traits such as `@Suite(.tags(.networking))`.
Nested suites may mirror feature behavior. Do not add `test` prefixes.

Every instance suite must have a callable zero-argument initializer path (implicit or explicit,
sync/async, throwing or non-throwing). Give stored properties defaults or initialize them in
`init`; use `deinit` only where class/actor teardown is needed. Prefer `init`/`deinit` or scoped
traits over XCTest `setUp`/`tearDown`. A suite with no reached `#expect` or `#require` is treated
as passing, so each test must visibly verify behavior.

If an instance suite cannot satisfy its zero-argument initialization path, move its tests to
global or supported static test functions, or refactor fixture state so the suite can initialize
without caller-supplied arguments. Keep fixture construction explicit rather than forcing a
parameterized suite initializer into test discovery.

```swift
import Testing

struct PlayerTests {
    let sut: Player

    init() { sut = Player(name: "Natsuki Subaru") }

    @Test func nameIsCorrect() {
        #expect(sut.name == "Natsuki Subaru")
    }
}
```

Use descriptive display names where they improve reports. Keep each test focused on one behavior,
though multiple expectations are fine when they jointly verify that behavior. Organize new tests
by feature and production layout; preserve existing organization unless a reorganization is asked.
Keep fixtures in dedicated files or nearby feature fixture folders.

## Execution, availability, and tags

Swift Testing runs synchronous and asynchronous tests in parallel with nondeterministic order.
Tests must be independent and safe at any time. Parameterized cases are independent by default;
see [parameterized](parameterized.md) for collection semantics. Put `@available` on each test
function whose behavior needs a newer OS; never put it on a suite or containing type. Use
`@MainActor` only when code under test actually requires it.

Declare tags once and apply them at test or suite scope:

```swift
extension Tag { @Tag static var networking: Self }

@Test(.tags(.networking))
func fetchProfile() async throws { /* ... */ }
```

Tags are cross-cutting metadata for navigator/test-plan filtering, not a replacement for suites.
Use meaningful labels such as `networking`, `slow`, `edgeCase`, `smoke`, and `regression`.

Use `withKnownIssue` for a bounded known bug: it expects an issue and fails if none is recorded.
With `isIntermittent: true`, a clean run passes while a recorded issue remains an expected
failure, which is useful while diagnosing flaky behavior. Keep scope narrow and remove wrapper
after fix. Avoid `!` inside `#expect`/`#require`; write `value == false` so macro diagnostics
retain the tested expression.

## Test hygiene and boundaries

Aim for FIRST properties: fast, isolated, repeatable, self-verifying, and timely. Cover happy,
boundary, invalid-input, and relevant concurrency paths. Test SwiftUI view models or observable
state rather than views driven by `@State`; extracting production logic is a suggestion, not an
automatic refactor. Avoid hidden `URLSession`, `UserDefaults`, clock, randomness, singleton, disk,
or cloud dependencies: inject a default that preserves production call sites, then pass a mock or
fresh test instance (for example, a unique `UserDefaults(suiteName:)` domain cleaned with
`removePersistentDomain`). Unit tests must not use live networking; integration tests should make
their boundary explicit.

For reusable verification helpers, accept `sourceLocation: SourceLocation = #_sourceLocation` and
pass it to every `#expect`/`#require`, so failures point to the calling test. In test targets,
`CustomTestStringConvertible` can improve complex failure output; do not add test-only conformances
to production code.
