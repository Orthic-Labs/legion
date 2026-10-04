# Swift Testing newer features

Use newer APIs only when installed Swift/Xcode and deployment support them; gate by availability
and retain a compatible form when target requires it.

## Swift 6.1+

- `confirmation(expectedCount: 5...10)` checks an inclusive count range; `5...` means at least five.
  Upper-only `...10` is intentionally invalid.
- Test-scoping traits conform to `TestTrait` and `TestScoping`, implement `provideScope(for:testCase:performing:)`,
  and can wrap `@TaskLocal` values with `withValue`. Expose a `Trait` extension, apply scopes in
  listed order, and remember later scopes can overwrite earlier values. Scopes complement suite
  `init`/`deinit` for per-test configuration.
- `#expect(throws:)` and `#require(throws:)` return the checked error. Prefer binding it then
  validating its case. Migrate away from deprecated trailing `throws:` validation closures.

```swift
let error = #expect(throws: GameError.self) { try playGame(at: 22) }
#expect(error == .disallowedTime)
```

```swift
struct DefaultPlayerTrait: TestTrait, TestScoping {
    func provideScope(for test: Test, testCase: Test.Case?, performing function: () async throws -> Void) async throws {
        try await Player.$current.withValue(Player(name: "Natsuki Subaru")) {
            try await function()
        }
    }
}
extension Trait where Self == DefaultPlayerTrait {
    static var defaultPlayer: Self { Self() }
}
```

## Swift 6.2+

- Raw identifiers allow ``@Test func `Readable test name`()`` and parameterized raw names. Suggest
  them when useful; do not introduce this style unexpectedly into a project using conventional names.
  Operators may appear only when not the entire identifier.
- `await #expect(processExitsWith: .failure) { ... }` verifies `precondition`/`fatalError`-style
  process termination in a dedicated process. Keep `await`; it suspends until child evaluation.
- `Attachable` plus `Attachment.record(value, named:)` can attach `String`, `Data`, or `Encodable`
  diagnostics to failures. Swift Testing attachments have no XCTest lifetime controls. Image
  attachment support is toolchain-dependent; do not assume it before Swift 6.3.
- `ConditionTrait.evaluate()` lets non-test code evaluate the same condition trait used by tests;
  it is async/throwing as required by the condition.

```swift
let trait = ConditionTrait.disabled(if: TestManager.inSmokeTestMode)
if try await trait.evaluate() { print("Smoke mode") }
```
