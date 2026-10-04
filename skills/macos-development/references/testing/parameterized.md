# Swift Testing parameterized tests

Use `@Test(arguments:)` when test logic is identical and only inputs vary. It gives each argument
an independent case, diagnostic, and rerun target; replace copy-pasted methods and in-test `for`
loops where that improves coverage and reporting. Keep one behavior per parameterized test and
keep argument data inline unless genuinely reused.

Swift Testing accepts one or two sendable argument collections directly. Two collections form a
Cartesian product, not pairwise zip, so reduce collections or split concerns when combinations
could grow too large. For aligned pairs, `zip(collection1, collection2)` is valid, but it silently
truncates to the shorter collection and pairing `CaseIterable.allCases` can break when enum order
changes. Prefer an explicit array of tuples or dictionary for input/expected mappings:

```swift
@Test(arguments: [Region.eu, .us], [Plan.free, .pro])
func vatAccess(region: Region, plan: Plan) {
    #expect(canUseVATInvoice(region: region, plan: plan) ==
            (region == .eu && plan == .pro))
}
```

```swift
@Test(arguments: [
    (Status.active, "Active"),
    (.inactive, "Inactive")
])
func statusLabel(_ status: Status, expected: String) {
    #expect(label(for: status) == expected)
}
```

When separate collections are genuinely needed, `zip` passes one tuple per aligned pair:

```swift
@Test(arguments: zip([Tier.basic, .premium], [3, 10]))
func freeTryLimits(_ tier: Tier, expected: Int) {
    #expect(freeTries(for: tier) == expected)
}
```

Use `allCases` for universal property tests where expected output is derived from the property,
not for case-specific expected values. Keep expectations concrete; deriving both sides from same
input can let identical bugs pass. Avoid `if`/`switch` that mirrors production branching inside
the test; split special cases into separate tests. Use readable parameter labels/display names,
and keep sets small enough for CI.

For Swift 6.2+, a custom `InlineArray` plus same-length generic `zip` can enforce pair lengths at
compile time, but it is a project helper rather than a standard-library overload. Use it only when
the project already accepts that helper; tuple arrays remain simplest.
