# SwiftUI desktop scenes

Choose scene type from behavior. Use `WindowGroup` for independent or multi-instance
windows, `Window` for a singleton utility or on-demand surface, `DocumentGroup` for a
document-first app, `Settings` for preferences, and `MenuBarExtra` for a menu-bar-first
utility. If a menu-bar app also promises a main window at launch, give it a stable
`WindowGroup(..., id:)`; reserve `Window` for auxiliary windows and verify launch policy.
Keep app, scene, window, and view state at their narrow ownership levels.

Expose important desktop actions through scene-level `commands`, `CommandMenu`, and
`CommandGroup`; use focused values or scene state for the active document/window.
Pair critical commands with toolbar/content affordances and avoid duplicate shortcuts.
Preserve responder-chain and standard Edit/Undo behavior unless the task requires an
AppKit boundary. Menu validation must read the same state as the action and work with
zero, one, or several active windows.

Put settings in a dedicated `Settings` scene with simple sections/tabs, durable
preferences in `@AppStorage`, and `SettingsLink` or `OpenSettingsAction` entry points.
Do not turn settings into a pushed content destination. Use `@SceneStorage` for
window-local restoration only when its state is genuinely ephemeral.

For sidebar/detail workflows, prefer explicit stable selection with
`NavigationSplitView`; use `inspector(isPresented:)` for supplementary selection-aware
controls. Keep sidebar rows light (one icon, one strong title, optional secondary line),
and move rich metadata into detail/inspector panes. Keep native source-list and window
materials instead of opaque root fills. A manual split is justified by unusual sizing or
column behavior, not by preference alone.

For a menu-bar extra, keep labels concise (derive a short display title for long content),
provide settings and quit paths, and open a dedicated window for deeper workflows. A
regular Dock app can install an `NSApplicationDelegate` with
`@NSApplicationDelegateAdaptor`, set `.regular`, and activate on launch; preserve
accessory/no-Dock behavior when that is the intentional product contract.

Use semantic controls, keyboard focus, localization, contrast, reduced motion/transparency,
and larger text. Keep newer scene APIs behind availability checks. A preview or screenshot
does not prove multiwindow state, menu routing, restoration, accessibility, or persistence.

For selection-driven content, keep selection in the scene/window owner and pass a binding
into stable columns:

```swift
struct LibraryRoot: View {
    @Binding var selection: UUID?
    let items: [LibraryItem]

    var body: some View {
        NavigationSplitView {
            List(items, selection: $selection) { item in
                Text(item.title).tag(Optional(item.id))
            }
        } detail: {
            DetailView(itemID: selection)
        }
    }
}
```

The list and detail remain mounted while selection changes. Replace `LibraryItem` and
`DetailView` with project types; the contract is stable identity plus one owner.
