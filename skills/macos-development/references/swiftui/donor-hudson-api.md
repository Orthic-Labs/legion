# Using modern SwiftUI API

Apply these replacements only when the project's SDK and deployment target support them. Keep
conditional fallbacks and preserve working soft-deprecated APIs outside the edited scope.

- Prefer `foregroundStyle()` over `foregroundColor()` when the minimum target exposes it; keep a guarded legacy branch otherwise.
- Prefer `clipShape(.rect(cornerRadius:))` over `cornerRadius()` when the shape shorthand is available.
- Prefer the `Tab` API over `tabItem()` on targets that expose typed tabs; retain `tabItem()` below that availability.
- Prefer zero- or two-parameter `onChange` overloads when available; use the one-parameter form only in older supported branches.
- Do not use `GeometryReader` if a newer alternative works: `containerRelativeFrame()`, `visualEffect()`, or the `Layout` protocol. Flag `GeometryReader` usage and suggest the modern alternative.
- When designing haptic effects, prefer using `sensoryFeedback()` over older UIKit APIs such as `UIImpactFeedbackGenerator`.
- Use the `@Entry` macro to define custom `EnvironmentValues`, `FocusValues`, `Transaction`, and `ContainerValues` keys. This replaces the legacy pattern of manually creating a type conforming to (for example) `EnvironmentKey` with a `defaultValue`, then extending `EnvironmentValues` with a computed property.
- Strongly prefer `overlay(alignment:content:)` over the deprecated `overlay(_:alignment:)`. For example, use `.overlay { Text("Hello, world!") }` rather than `.overlay(Text("Hello, world!"))`.
- `.navigationBarLeading` and `.navigationBarTrailing` are deprecated on newer SDKs; use `.topBarLeading` and `.topBarTrailing` in a version-appropriate branch.
- Prefer to rely on automatic grammar agreement when dealing with English, French, German, Portuguese, Spanish, and Italian. For example, use `Text("^[\(people) person](inflect: true)")` to show a number of people.
- You can fill and stroke a shape with two chained modifiers; you do *not* need an overlay for the stroke. The overlay was required previously, but this is fixed in iOS 17 and later.
- When referencing images from an asset catalog, prefer the generated symbol asset API when the project is configured to use them: `Image(.avatar)` rather than `Image("avatar")`.
- On macOS 26 and later, use native `WebView` when the installed SDK exposes it, gated with `#available(macOS 26, *)`; keep existing deployment targets. For earlier macOS targets, wrap `WKWebView` with `NSViewRepresentable` (`makeNSView`/`updateNSView`) as the fallback. The iOS `UIViewRepresentable` guidance does not apply to macOS.
- For `ForEach` over `enumerated()`, use the direct form only when compiler, target stdlib, and platform SDK expose `EnumeratedSequence`'s collection conformance (Swift stdlib 6.2; do not infer it from iOS 17/macOS 14): `ForEach(items.enumerated(), id: \.element.id)`. On older iOS/macOS toolchains, retain `ForEach(Array(items.enumerated()), id: \.element.id)`; use `ForEach(items)` when index is unnecessary.
- When hiding scroll indicators, use `.scrollIndicators(.hidden)` rather than `showsIndicators: false` in the initializer.
- Avoid `Text` concatenation with `+`; interpolation or a composed `Text` value preserves localization and styling.

For example, the usage of `+` here is bad and deprecated:

```swift
Text("Hello").foregroundStyle(.red)
+
Text("World").foregroundStyle(.blue)
```

Instead, use text interpolation like this:

```swift
let red = Text("Hello").foregroundStyle(.red)
let blue = Text("World").foregroundStyle(.blue)
Text("\(red)\(blue)")
```


## Using ObservableObject

If legacy `ObservableObject` remains necessary, for example for a Combine publisher debouncer, add
`import Combine` explicitly; do not assume SwiftUI re-exports it on every SDK.
