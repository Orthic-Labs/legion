# SwiftUI that runs on Windows (SwiftRight)

Use when SwiftUI must render on Windows through SwiftRight, the pipeline that runs SwiftUI
outside Apple platforms (for example RightKitHub and RightKitEngine in RightKitSwift).
Skip for Apple-only targets. `references/macos-workflows/windows.md` covers macOS app
windows, not this.

## Rules

1. Write views as pure SwiftUI. No AppKit/UIKit bridges (`NSViewRepresentable`,
   `UIViewRepresentable`, `NSHostingView` inside views), no `Canvas`, no Swift Charts, no
   `#if canImport(AppKit)` inside a view body.
2. Put Mac-only code (status items, hotkeys, permissions, login items, `NSWorkspace`) behind a
   small service protocol. Inject it; views never call it.
3. Reach the Rust core through one narrow engine interface (a protocol the views depend on).
   Views never import FFI types.
4. Use only SwiftRight-proven controls and modifiers. Check the status doc before using one;
   probe an unlisted control on Windows before building on it.

## Project overlay: where the proven list lives

The SwiftRight proven-controls list is the only source of truth for what renders on Windows.
In the RightKit workspace it is `swiftright/docs/proven-controls.json`: use `apis.fromManifest`
as the exact list (`apis.fromCaseSources` is only a lexical scan). SwiftRight regenerates it with its
proven-controls generator, whose `--check` mode exits 1 on drift;
`swiftright/docs/sr1-status.md` holds the narrative and caveats. Read them each time; do not copy
the list into code comments or skills. When the overlay is absent, assume nothing is proven: keep
views to stacks, text, images, shapes and buttons, and report the portability claim as unverified.

Snapshot as of 2026-10-14, superseded by the proven-controls list: text, images, shapes, stacks,
scroll-view, toggle, button, disabled, binding, textfield, list, alert, color-scheme (also
measured: focus-state, animation, opacity-transition, padding/frame, preference-key,
custom-layout). Caveats: no Windows focus ring on text fields; IME deferred to hardware;
toggle label widths differ (Segoe vs SF); `ImageRenderer` renders a `ScrollView` blank on the
Mac side.

## Third-party Swift packages

A package needs both checks before it enters a shared-SwiftUI target:

- SwiftRight check: pure SwiftUI, and every control it draws is SwiftRight-proven.
- Ownership check: `rustright owns <capability>` (project overlay; absent, ask the project
  owner instead of adding the package).

Known rejects:

| Package | Reason |
|---|---|
| SwiftUIX, swiftui-introspect | Wrap AppKit/UIKit. |
| KeyboardShortcuts | `rightkit-hotkeys` owns hotkeys. |
| sindresorhus/Settings | RightKitHub's settings kit and `rightkit-app-settings` own settings. |
| LaunchAtLogin | A platform service owns login items. |
| Sparkle | `@rightkit/app-update` owns updates. |
| PopupView | RightKitHub owns toasts. |
| TCA | Surface too large; prefer `@Observable` once it is proven (below). |
| MarkdownUI 2.4.1 | Fails on Windows (`swiftright/docs/probes/markdownui-windows.md`). |

Compile on Windows but not yet proven, so do not build on them until the list includes them:
`@Observable`, `.task` with `AsyncStream`, `Spacer`, `Divider`
(`swiftright/docs/probes/hub-base-gap-check.md`).

## Reading-only references

Read for design; never add as dependencies:

- jordanbaird/Ice: status items and permissions.
- Dimillian/IceCubesApp: multiplatform package split.
