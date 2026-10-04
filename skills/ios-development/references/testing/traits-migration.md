# Swift Testing traits and XCTest migration

Traits express behavior/metadata: display names, `.bug`, `.tags`, `.enabled(if:)`, `.disabled`,
`.timeLimit`, and `.serialized`. Apply a trait at suite scope only when every contained test
should inherit it; otherwise keep it on the smallest test. Disabled tests need an actionable reason
and preferably a bug link. Use tags for stable test-plan and navigator filters rather than names.
Use `@available` on each OS-gated test function, never a suite declaration.

## Coexistence

Swift Testing and XCTest can coexist in one target or source file (`import XCTest` plus
`import Testing`). Keep existing XCTest and migrate incrementally; Swift Testing does not replace
UI automation, `XCTMetric` performance tests, or Objective-C-only tests. Do not perform a wholesale
migration unless requested.

Recommended order:

1. Convert assertions to `#expect` and `#require` while preserving broad structure.
2. Replace `test...` methods with `@Test` declarations and remove `XCTestCase` where appropriate.
3. Move setup to suite `init` and teardown to `deinit` only when needed.
4. Collapse repeated methods into parameterized cases.
5. Add traits/tags for conditions, limits, known issues, and test-plan filtering.

Common mappings:

| XCTest | Swift Testing |
| --- | --- |
| `XCTAssertEqual(a, b)` | `#expect(a == b)` |
| `XCTAssertLessThan(a, b)` | `#expect(a < b)` |
| `XCTAssertThrowsError` | `#expect(throws:)` |
| `XCTUnwrap(value)` | `try #require(value)` |
| `XCTFail("message")` | `Issue.record("message")` |
| `XCTAssertIdentical(a, b)` | `#expect(a === b)` |
| `continueAfterFailure = false` | targeted `try #require(...)` |
| `XCTestExpectation` event wait | `confirmation` when event is not awaitable |

Swift Testing has no built-in floating-point tolerance equivalent to XCTest. If Swift Numerics is
already a project dependency, use `isApproximatelyEqual(to:absoluteTolerance:)`; do not add a new
dependency or install tooling as part of migration without explicit scope. Preserve app target,
deployment, simulator, and existing CI proof surfaces.
