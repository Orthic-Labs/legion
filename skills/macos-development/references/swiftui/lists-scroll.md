# SwiftUI lists & scrolling

## Source-aligned detail

For identity, tables, reorder, and scroll geometry examples, read [list patterns](donor-lee-list-patterns.md),
[scroll patterns](donor-lee-scroll-patterns.md), and [Hudson performance rules](donor-hudson-performance.md).

## Identity and rows

Every `ForEach` element needs a stable, unique, cheap identity that outlives a view update.
Prefer `Identifiable` models; never use indices/offsets for mutable collections, freshly made
UUIDs, duplicate IDs, or IDs derived from mutable display content. Use
`ForEach(items.enumerated(), id: \.element.id)` only when Swift 6.2 compiler support and the
target stdlib/deployment expose `EnumeratedSequence`'s Collection conformance (SDK declaration:
any Apple OS 26+). Otherwise use `ForEach(Array(items.enumerated()), id: \.element.id)`; never
use the offset as identity.
Keep row structure unary and move transforms out of `List`/`ForEach` initializers. Constant row
shape preserves state and diffing.

For drag reorder, use stable transfer representations and validate dropped IDs; update source
of truth once. On SDKs providing reorderable drag/drop or modern `dropDestination`, gate those
APIs and keep a legacy fallback. Swipe actions outside `List` need an explicit gesture/control
model with accessibility and keyboard semantics; do not assume List-only behavior.

## Empty, refresh, tables

Use `ContentUnavailableView` for empty data and its search variant for no search results. Add
`.refreshable` around async refresh state and handle cancellation/error visibly. Hide indicators
with `.scrollIndicators(.hidden)`, not the older initializer flag. `Table` needs stable IDs,
typed columns, and a selection model; sort in model/service state. On compact width provide a
meaningful alternative when a multi-column table cannot remain legible.

## Scroll position and effects

Use `ScrollViewReader` for event-driven `scrollTo` and keep IDs stable; use `scrollPosition(id:)`
for state restoration/programmatic binding on supported targets. `scrollTargetBehavior` and
`scrollTargetLayout` express paging/snapping. Use `onScrollGeometryChange`/scroll transitions
for effects, but gate updates at thresholds and avoid writing state on every pixel. Put bars
covering content in `safeAreaBar`; keep full-bleed artwork as overlay/background. Large data
sets require lazy containers.

```swift
ScrollView {
    LazyVStack {
        ForEach(items) { item in ItemRow(item: item).id(item.id) }
    }
    .scrollTargetLayout()
}
.scrollTargetBehavior(.viewAligned)
.scrollIndicators(.hidden)
```
