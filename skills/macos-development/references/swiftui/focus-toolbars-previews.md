# SwiftUI focus, toolbars & previews

## Source-aligned detail

For focused values, default focus, toolbar customization, and preview diagnostics, read [focus](donor-lee-focus-patterns.md),
[toolbars](donor-lee-toolbar-patterns.md), and [previews](donor-lee-previews.md).

Keep `@FocusState` private; use Bool for one field or an optional Hashable enum for several.
Give each focus target a distinct enum case. Prefer `.defaultFocus` to `onAppear` writes.
`.focusable(interactions:)`, `.focusSection`, `.focusScope`, `focusedValue`, and search focus
support keyboard/command flows; do not redundantly write focus from tap gestures on focusable
views. Use focus effect suppression only with a replacement visual.

Use modern toolbar placements and let overflow/minimization adapt. iOS/macOS 26+ customizable
toolbars and iOS 27+ overflow/pinned/status-bar families require availability gates; preserve
older `ToolbarItem` layouts. Toolbar bars that cover scrolling content belong in safe-area bars.

Use `#Preview` with self-contained mock data, explicit environment values, and meaningful
default/empty/loading/error/long-content states. `@Previewable` is iOS 18+/Xcode 16+; use a
wrapper view below that target. Never make previews depend on network, disk, live services, or
missing injected environment. A rendered preview does not prove lifecycle, permissions,
persistence, accessibility, or device behavior.
