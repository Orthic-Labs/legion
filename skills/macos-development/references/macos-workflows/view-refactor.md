# Stable SwiftUI view refactors

Map scene roots, window ownership, selection, commands, persistence, services, and AppKit
edges before moving code. Preserve behavior and local conventions. A useful non-trivial
shape keeps `App/<Name>App.swift` for `@main`/delegate, `Views/` for composition and
feature views, `Models/` for value types/identifiers, `Stores/` for persistence,
`Services/` for process/network/platform clients, and `Support/` for small helpers.
Tiny throwaway snippets are the exception.

Within a view, keep environment/dependencies, stored state, computed non-view properties,
initializer, body, view builders, then helper/async functions. Prefer dedicated subview
types for sidebar rows, detail panels, inspectors, and toolbar content. Pass explicit
inputs/bindings/actions rather than a whole scene model. Keep body focused on composition;
move command/action logic out when it obscures ownership.

Keep one stable split/window layout while selection changes; let state drive content inside
it rather than swapping radically different roots. Avoid singleton state for per-window
selection/drafts, duplicate source-of-truth models, arbitrary line-count extraction, and
AppKit references spreading through SwiftUI. Build after major splits in normal work and
exercise multiwindow, settings, command, restoration, and selection paths when affected.
