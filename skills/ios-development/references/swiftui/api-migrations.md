# SwiftUI API migrations

## Source-aligned detail

For concrete replacements and soft-deprecation scope, read [API lookup](donor-lee-latest-apis.md), [soft deprecation](donor-lee-soft-deprecation.md),
[Hudson API rules](donor-hudson-api.md), and [Swift hygiene](donor-hudson-swift.md).

## Version-aware replacements

Use only APIs available for project's SDK/deployment target. Replace hard deprecations in code
being changed, preserve soft-deprecated APIs in untouched scope, and avoid unrelated migration
churn. Typical conditional replacements include `foregroundStyle` for `foregroundColor`,
`clipShape(.rect(cornerRadius:))` for `cornerRadius`, `NavigationStack`/`NavigationSplitView`
for `NavigationView`, `navigationDestination(for:)` for eager destinations, `Tab` for
`tabItem`, `onChange(of:initial:)` for one-parameter handlers, `sensoryFeedback` for UIKit
haptics, `MagnifyGesture`/`RotateGesture` for renamed gestures, and `@Entry` for custom keys.
`GeometryReader` remains valid when layout needs measurement; use `containerRelativeFrame`/
`visualEffect` only when they express the need better.

| Older API/pattern | Replacement | Availability gate |
| --- | --- | --- |
| `foregroundColor(_:)` | `foregroundStyle(_:)` | iOS 15+ / matching SDK |
| `cornerRadius(_:)` | `clipShape(.rect(cornerRadius:))` | target must expose shape shorthand |
| `NavigationView` | `NavigationStack` or `NavigationSplitView` | iOS 16+; fallback below |
| eager `NavigationLink(destination:)` | value link + `navigationDestination(for:)` | iOS 16+ |
| one-parameter `onChange` | zero- or two-parameter `onChange(of:initial:)` | iOS 17+ |
| new `ObservableObject` model | `@Observable` + `@State` | iOS 17+; preserve legacy integration |
| `tabItem(_:)` | `Tab` | iOS 18+; retain legacy branch below |
| UIKit haptic generators | `sensoryFeedback` | iOS 17+ |
| `GeometryReader` for simple sizing | `containerRelativeFrame`/`visualEffect` | iOS 17+ where semantics fit |

Use `#available` around structurally different branches. Keep older behavior equivalent and
verify minimum deployment target before changing call sites.

Use `topBarLeading`/`topBarTrailing`, `toolbarVisibility`, `scrollIndicators`, `tint`,
`autocorrectionDisabled`, `focused`, and `safeArea` APIs according to availability. iOS 26+
adds Liquid Glass, `WebView`, rich text, scroll-edge/background effects, typed drag/drop, and
`@Animatable`; iOS 27/27.1 adds toolbar/sidebar/arrangement/reserved-region families. Every
new family needs `#available`, fallback, and a rationale. Do not assume a future SDK is the
project's target or force a specific architecture.

## Maintenance disposition

The donor updater's external documentation scan is maintenance guidance only and proposes
branch/PR changes. This package records API topics and disposition; a future maintainer may
refresh them through normal repository process.
