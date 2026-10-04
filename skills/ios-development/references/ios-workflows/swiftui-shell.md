# SwiftUI app shell & interaction patterns

## Root shell

Define one `AppTab` identity model and one selected-tab source. Give each tab its own
`NavigationStack` and router path, inject router via environment, and map lightweight
`Hashable` route values centrally. Keep sheet destination as an `Identifiable` enum on
router and use one `sheet(item:)` modifier. Reset tab paths on account/logout context
change. Special compose tabs intercept selection to present composer without changing
selection.

Install truly shared services, theme, clients, model container, push/stream watchers,
and intent service at app root. Use explicit initializers for feature-local models;
use legacy environment objects only when project already requires them. Lifecycle
`.task(id:)` may rewire account/client-dependent services and must stop unauthenticated
streams. Keep dependency modifier slim. One model container at root avoids duplicate
stores across tabs/sheets.

## Async state & forms

Use `.task` for view-lifetime loading, `.task(id:)` for changing query/selection, and
treat cancellation as normal. Debounce search, clear empty query, and expose explicit
idle/loading/loaded/failed states. Move cross-screen work, retry/cache/offline policy,
and business logic into services/models. Sheets own save/cancel actions and call
`dismiss()`; use `.sheet(item:)` instead of optional unwrap in sheet body.

Use Form + Section for settings/input, focus enum with `@FocusState` for field chains,
`safeAreaInset(edge: .bottom)` for chat input, and `searchable` with scopes for native
search. Use List for feed/settings semantics, ScrollView + Lazy stacks for custom feeds,
Lazy grids for galleries. Keep stable row IDs, avoid same-axis nested scrollers, and
use ContentUnavailableView or redacted fixed placeholders instead of spinner stacks.

Centralize URL parsing in router with OpenURL fallback. Keep media viewer state single,
load resized previews in rows, and present full viewer from one sheet/window entry. Use
semantic theme tokens and Dynamic Type. Haptics belong near user action, are preference-
gated, and should not fire for every tiny event. macOS Settings/menu-specific references
remain conditional for native Mac targets.
