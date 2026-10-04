# Swift Testing assertions and diagnostics

## Expectations

Use `#expect` for conditions under test and pass natural Swift expressions (`==`, `>`, `.contains`,
`.isEmpty`). Swift Testing captures subexpressions for diagnostics; do not use XCTest assertion
families in Swift Testing tests. Add a user-facing message when it adds useful context.

Use `try #require` for a prerequisite whose failure makes later results meaningless. It records
failure, throws, and stops the test; its return value safely unwraps optionals. The test must be
`throws` when using it.

```swift
@Test func parsedURLHasHTTPS() throws {
    let url = try #require(URL(string: "https://example.com"), "URL should parse")
    #expect(url.scheme == "https")
}
```

## Errors and failures

For expected errors, use `#expect(throws:)` with the narrowest error type or case. Use
`Never.self` when success must not throw. Use explicit `do`/`catch` plus `Issue.record` when custom
branching or several error cases need separate messages; if no error is thrown, record the failure.
Use `Issue.record("message")` for a direct failure (`XCTFail` equivalent).

```swift
#expect(throws: GameError.notInstalled) { try game.play() }
#expect(throws: Never.self) { try game.play() }
```

```swift
do {
    try game.play()
    Issue.record("Expected an error to be thrown")
} catch GameError.notPurchased {
    // expected case
} catch {
    Issue.record("Wrong error: \\(error)")
}
```

Avoid broad `Error.self` when a concrete case is part of the contract. Use `.bug(id:)` or
`.bug(URL)` on regression tests to retain issue context.

`CustomTestStringConvertible` in the test target gives domain values readable `testDescription`
without changing production `CustomStringConvertible`. Verification helpers should preserve caller
locations:

```swift
func verify(_ value: Result, sourceLocation: SourceLocation = #_sourceLocation) {
    #expect(value.isValid, sourceLocation: sourceLocation)
}
```

## Known issues

Wrap only the failing region in `withKnownIssue("reason") { ... }`. It keeps a temporary defect
visible and fails if expected failure disappears unexpectedly. Use `isIntermittent: true` for a
flaky defect being investigated; do not disable tests without a reason and tracking link.
