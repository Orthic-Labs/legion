# SwiftUI navigation & presentation

## Source-aligned detail

For item-driven sheets, split views, inspectors, and restoration examples, read [navigation patterns](donor-lee-sheet-navigation-patterns.md)
and [Hudson navigation rules](donor-hudson-navigation.md).

Use `NavigationStack` or `NavigationSplitView` by screen structure and proposed width. Keep
navigation state in a typed `Hashable` path/selection model when restoration or deep links
matter. Register each `navigationDestination(for:)` once per type in a hierarchy; do not mix
typed destinations with eager `NavigationLink(destination:)` in that hierarchy. Preserve
existing navigation/restoration architecture during local fixes.

```swift
NavigationStack(path: $path) {
    List(model.items) { item in
        NavigationLink(value: item) { Text(item.name) }
    }
    .navigationDestination(for: Item.self) { ItemDetail(item: $0) }
}
```

Use split views for sidebar/detail/inspector relationships, nested stack for deeper pushes, and
column visibility/selection that remains valid across compact/regular transitions. Avoid swapping
container identity merely on size class when system containers adapt themselves. For iOS 27+
`TabView` `.sidebarAdaptable` may morph from tab bar/sidebar; gate default placement and provide
an earlier fallback, keeping nested content reachable when no sidebar exists.

Prefer `sheet(item:)` for optional model presentation; use an enum `Identifiable` item for
multiple sheet kinds. Sheets own dismiss/save actions and use environment `dismiss`; do not pass
callbacks solely to dismiss. Use item-bound alert/confirmation APIs where available. Attach
`confirmationDialog` to its triggering control so source animation is correct. Use `.alert`
actions for meaningful choices; an empty action builder is enough for dismiss-only alerts.
Inspectors are trailing supplementary panels and adapt to sheets in compact contexts; width
constraints are conditional. Popovers may need `.presentationCompactAdaptation(.popover)` when
that behavior is required. Use full-screen cover only for a true full-screen task.

Availability examples:

```swift
if #available(iOS 27, *) {
    TabView { Tab("Home", systemImage: "house") { HomeView() } }
        .tabViewStyle(.sidebarAdaptable)
} else {
    TabView { HomeView().tabItem { Label("Home", systemImage: "house") } }
}
```
