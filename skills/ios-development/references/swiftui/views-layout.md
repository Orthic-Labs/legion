# SwiftUI views & layout

## Source-aligned detail

For detailed composition, adaptive layout, and bridge examples, read [view structure](donor-lee-view-structure.md),
[layout](donor-lee-layout-best-practices.md), [large-display guidance](donor-lee-iphone-duo.md), and [Hudson views](donor-hudson-views.md).

## Composition and identity

Keep `body` and initializers cheap, pure, and constant-time. Move filtering, sorting, mapping,
formatters, decoding, I/O, and business rules into models/services; `init` runs repeatedly in
lists and parent reevaluation. A separate `View` type creates a narrower invalidation boundary;
computed `some View` properties and `@ViewBuilder` helpers only reorganize the parent's body.
Use helpers for small static fragments, but extract stateful, reusable, or expensive sections
into types with narrow inputs. Keep action methods outside layout closures. A custom container
owns static containers; callers own lazy/repeatable containers. Store built `@ViewBuilder` content
instead of escaping closures when a generic container can do so.

Use `Group` for branches/multiple children; remove a single-child `Group`. Use `ZStack` for peer
layers that jointly define size, and `overlay`/`background` for decoration anchored to a primary
view. Composite layered content before clipping to avoid antialiasing fringes. Prefer
`ViewModifier`/`ButtonStyle` for repeatable styling and `AnyShapeStyle` only when style types
truly differ. Avoid `AnyView` unless type erasure is required.

```swift
struct ProductDetail: View {
    let product: Product
    var body: some View {
        ScrollView {
            ProductHeader(name: product.name)
            ProductGallery(images: product.images)
            ProductDescription(text: product.description)
        }
    }
}
```

For large collections use `LazyVStack`, `LazyHStack`, `LazyVGrid`, or `LazyHGrid`. `List` rows
should produce one semantic root view per element; do not vary child count across branches.

## Proposed-size layout

Avoid using `UIScreen.main.bounds` or device-sized frames for layout. Prefer proposed size,
`containerRelativeFrame`, `visualEffect`, `ViewThatFits`, `AnyLayout`, and local size classes.
Read size classes in the nearest consuming view, not an app/model cache. Use `GeometryReader`
when layout genuinely depends on measured geometry; use `onGeometryChange` for an effect/state
reaction. Gate frequent geometry/preference updates by meaningful thresholds. Use leading/trailing
for RTL. Cap readable long-form text width on broad windows.

Safe-area rules are semantic: `safeAreaBar(edge:)` for bars on supported SDKs with
`safeAreaInset` fallback; `safeAreaInset` for controls/content occupying an inset; fixed
`safeAreaPadding` only for a deliberate inward margin; scoped `ignoresSafeArea` for true
full-bleed visual layers. Do not read and reapply `GeometryProxy.safeAreaInsets`, which
double-counts reserved space.

For large/foldable displays, select a technique by screen structure. Reflow cards with a custom
`LayoutValueKey`/`Layout` only when width permits; preserve reading/VoiceOver order and keep
Dynamic Type content in one column. `ArrangementView` and `reservedRegions` are iOS 27.1+
conditional tools for custom two-region/fold layouts; prefer system navigation/safe-area
containers, filter inactive regions, preserve RTL mirroring, and provide an earlier-OS fallback.
Avoid unsupported nesting with `NavigationSplitView`, `List`, or `ScrollView`, and keep state
above branches when a layout switch could recreate stateful children.

## Representables and diagnostics

Use UIKit/AppKit representables only at a necessary bridge, pass SwiftUI environment through
`Context`, and keep `make`/`update` idempotent. For compiler type-check failures, split complex
expressions into subviews or local values. Previews are not lifecycle or device evidence.
