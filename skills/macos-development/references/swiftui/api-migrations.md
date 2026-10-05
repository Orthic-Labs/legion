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
| `foregroundColor(_:)` | `foregroundStyle(_:)` | macOS 12+ / matching SDK |
| `cornerRadius(_:)` | `clipShape(.rect(cornerRadius:))` | target must expose shape shorthand |
| `NavigationView` | `NavigationStack` or `NavigationSplitView` | macOS 13+; fallback below |
| eager `NavigationLink(destination:)` | value link + `navigationDestination(for:)` | macOS 13+ |
| one-parameter `onChange` | zero- or two-parameter `onChange(of:initial:)` | macOS 14+ |
| new `ObservableObject` model | `@Observable` + `@State` | macOS 14+; preserve legacy integration |
| `tabItem(_:)` | `Tab` | macOS 15.4+; retain legacy branch below |
| AppKit haptic generators | `sensoryFeedback` where supported | check SDK availability |
| `GeometryReader` for simple sizing | `containerRelativeFrame`/`visualEffect` | macOS 14+ where semantics fit |

Use `#available` around structurally different branches. Keep older behavior equivalent and
verify minimum deployment target before changing call sites.

Use macOS toolbar placements such as `.automatic`, `.navigation`, `.primaryAction`,
`.secondaryAction`, and `.accessoryBar(id:)`; `topBarLeading`/`topBarTrailing` are unavailable
on macOS. Also use `toolbarVisibility`, `scrollIndicators`, `tint`,
`autocorrectionDisabled`, `focused`, and platform safe-area APIs according to availability.
macOS 26+ adds Liquid Glass, WebKit SwiftUI `WebView`/`WebPage`, rich text, scroll-edge/background
effects, typed drag/drop, and the SDK/compiler-provided `@Animatable` macro (its generated
conformance can back-deploy to macOS 10.15). Future 27/27.1 donor families such as arrangement
and reserved-region APIs require matching SDK verification; the installed macOS 27.0 SDK has no
Mac declarations for those two families. Every
new family needs `#available`, fallback, and a rationale. Do not assume a future SDK is the
project's target or force a specific architecture.

## Maintenance disposition

The donor updater's external documentation scan is maintenance guidance only and proposes
branch/PR changes. This package records API topics and disposition; a future maintainer may
refresh them through normal repository process.
