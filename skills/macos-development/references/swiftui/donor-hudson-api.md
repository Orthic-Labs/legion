# Using modern SwiftUI API

Apply these replacements only when the project's SDK and deployment target support them. Keep
conditional fallbacks and preserve working soft-deprecated APIs outside the edited scope.

- Prefer `foregroundStyle()` over `foregroundColor()` when the minimum target exposes it; keep a guarded legacy branch otherwise.
- Prefer `clipShape(.rect(cornerRadius:))` over `cornerRadius()` when the shape shorthand is available.
- Prefer the `Tab` API over `tabItem()` on targets that expose typed tabs; retain `tabItem()` below that availability.
- Prefer zero- or two-parameter `onChange` overloads when available; use the one-parameter form only in older supported branches.
- Do not use `GeometryReader` if a newer alternative works: `containerRelativeFrame()`, `visualEffect()`, or the `Layout` protocol. Flag `GeometryReader` usage and suggest the modern alternative.
- On macOS, use SwiftUI `sensoryFeedback()` only where the installed SDK and product behavior
  support it; do not import or recommend UIKit haptic generators. For tactile Mac interaction,
  prefer semantic control feedback and AppKit-native behavior.
- Use the `@Entry` macro to define custom `EnvironmentValues`, `FocusValues`, `Transaction`, and `ContainerValues` keys when the project SDK/compiler provides it. Retain manual key fallbacks for older SDK/compiler baselines.
- Strongly prefer `overlay(alignment:content:)` over the deprecated `overlay(_:alignment:)`. For example, use `.overlay { Text("Hello, world!") }` rather than `.overlay(Text("Hello, world!"))`.
- `.topBarLeading`/`.topBarTrailing` and `.navigationBarLeading`/`.navigationBarTrailing` are unavailable on macOS. Use native placements such as `.navigation`, `.primaryAction`, `.secondaryAction`, or `.accessoryBar(id:)` for Mac toolbars.
- Prefer to rely on automatic grammar agreement when dealing with English, French, German, Portuguese, Spanish, and Italian. For example, use `Text("^[\(people) person](inflect: true)")` to show a number of people.
- You can fill and stroke a shape with two chained modifiers; you do *not* need an overlay for the stroke. This is supported on macOS targets that expose the modifier.
- When referencing images from an asset catalog, prefer the generated symbol asset API when the project is configured to use them: `Image(.avatar)` rather than `Image("avatar")`.
- WebKit SwiftUI integration exposes native `WebView`/`WebPage` on macOS 26+; use an explicit
  `import WebKit` and gate use with `#available(macOS 26, *)`. The installed SDK’s
  `_WebKit_SwiftUI` interface re-exports `WebKit` and declares this SwiftUI surface. For older
  macOS targets, wrap `WKWebView` with `NSViewRepresentable` (`makeNSView`/`updateNSView`); the
  iOS `UIViewRepresentable` guidance does not apply to macOS.
- For `ForEach` over `enumerated()`, use the direct form only when Swift 6.2 compiler support
  and target stdlib/deployment expose `EnumeratedSequence`'s Collection conformance (SDK
  declaration: any Apple OS 26+): `ForEach(items.enumerated(), id: \.element.id)`. On older
  toolchains or deployment targets, retain `ForEach(Array(items.enumerated()), id: \.element.id)`;
  use `ForEach(items)` when index is unnecessary.
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
