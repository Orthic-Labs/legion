# SwiftUI documents & macOS surfaces

## Source-aligned detail

For document readers/writers, scene choice, windows, file operations, and AppKit bridges, read [document apps](donor-lee-document-apps.md),
[macOS scenes](donor-lee-macos-scenes.md), [macOS views](donor-lee-macos-views.md), and [window styling](donor-lee-macos-window-styling.md).

## Documents

For SDK 27+ document APIs, choose flat `Document`/`DocumentReader` or package documents from
the data model. Keep read/write serialization separate from view state, register undo before
autosave, report progress with `Subprogress`, and coordinate direct URL access. Use
`DocumentGroup`/scene declarations for document lifecycle; preserve `FileDocument` on older
targets with a conditional adapter. Declare UTTypes/content types and export/import behavior
explicitly. Never perform file I/O in `body` or preview.

## macOS scenes and windows

Use `WindowGroup` for repeatable windows, `Window` for a singleton, `DocumentGroup` for
documents, `Settings` for preferences, `MenuBarExtra` for menu-bar utilities, and `UtilityWindow`
for auxiliary panels where availability permits. Give windows sensible default/ideal sizes,
resizability, position, toolbar style, and restoration; do not treat a macOS window as an iOS
full-screen surface. `NavigationSplitView`, inspectors, `HSplitView`/`VSplitView`, and `Table`
should reflect broad-window behavior.

Use commands, `CommandGroup`, `CommandMenu`, keyboard shortcuts, focused values, and menu-bar
items for macOS actions. Keep command state synchronized with focused document/selection.
`fileImporter`/`fileExporter`, `PasteButton`/`CopyButton`, `Transferable`, and drop destinations
provide permission-aware file/paste flows. Gate SDK-specific overloads and retain established
NSItemProvider fallback when needed.

Use `NSViewRepresentable`/`NSViewControllerRepresentable` only at AppKit boundaries. Keep
Coordinator delegates bounded and update methods idempotent; pass environment/selection into
the bridge instead of reading global app state. `NSHostingView`/`NSHostingController` are the
reverse bridge for embedding SwiftUI in AppKit.
