# SwiftUI state & environment

## Source-aligned detail

For concrete wrapper diagnostics and examples, continue with [Hudson data rules](donor-hudson-data.md),
[SwiftUI observation/state](donor-lee-state-management.md), and [environment patterns](donor-lee-environment-patterns.md).

## Ownership

Treat each `View` as an invalidation boundary. `@State` owns view-local, transient value
state and should be `private`; `@Binding` is an explicit write capability for state owned by
an ancestor. A changing parent input must remain a `let`/`var` input, not be copied into
`@State`, unless a documented one-time seed is intended. Preserve an existing observation
scheme when a migration is outside request scope.

For iOS 17+, new observable reference models normally use `@Observable` and `@State` for
ownership, `@Environment(Type.self)` for shared injection, and `@Bindable` for an injected
model that needs bindings. Mark models `@MainActor` unless project-wide default isolation is
already Main Actor. Use `ObservableObject`/`@StateObject`/`@ObservedObject`/`@EnvironmentObject`
for legacy or integration code where changing ownership would risk behavior. Do not nest
observable objects or recreate reference models in `body`.

```swift
@Observable @MainActor
final class EditorModel {
    var title = ""
    var isSaving = false
}

struct EditorView: View {
    @State private var model = EditorModel()
    var body: some View {
        @Bindable var model = model
        TextField("Title", text: $model.title)
            .task { await saveIfNeeded() }
    }
}
```

`@State` storage persists by view identity; it does not mean a parent-owned model is copied.
If a model's identity must be seeded from an initializer, initialize the wrapper explicitly
and document that later input changes do not replace it. Bindings should be key-path bindings
from state/model. Avoid `Binding(get:set:)` in `body`; use `onChange(of:initial:)` for effects.
Numeric fields bind to numeric values with `format:`; keyboard modifiers alone do not parse.

Never put `@AppStorage` in an `@Observable` model: defaults changes do not reliably invalidate
that model. Keep `@AppStorage` at view boundary or bridge tested changes explicitly. `@Query`
belongs to a SwiftUI view; services use explicit fetch descriptors/context/isolation. For a
count-only SwiftData need, `fetchCount` avoids materialization but is not live by itself. With
CloudKit, avoid `@Attribute(.unique)`, give fields defaults or make them optional, and make
relationships optional.

## Environment and focused values

Read environment values near the view consuming them; do not cache size class, display scale,
locale, or safe-area values in app/model state. Custom environment/focused/container keys use
`@Entry` where deployment target supports it. Defaults must be stable constants: never create
`Model()`, `Date()`, `UUID()`, or other fresh reference/value in a default. Never store a
closure in a custom key because it obscures dependencies and invalidates poorly; publish an
action object or value instead. Remove unused reads and avoid high-frequency environment
values at broad ancestors.

```swift
extension EnvironmentValues {
    @Entry var editorMode: EditorMode = .normal
}
extension FocusedValues {
    @Entry var selectedDocument: Binding<Document>?
}
```

Use `.focusedValue`/`.focusedSceneValue` for command state from the focused document, and
`@FocusedBinding`/`@FocusedValue` in commands. Focused defaults are optional and nil when no
view publishes them.

## Effects, tasks, and dependencies

Put business rules in testable services/models; view closures orchestrate state. `.task(id:)`
is preferred to `onAppear` for async work because disappearance cancels it. Key tasks by real
request identity. Handle loading, empty, failure, cancellation, and success explicitly, and
prevent stale responses from overwriting newer intent. `async` does not itself leave Main
Actor; choose actors/isolation for expensive work and protect mutable shared state.

Pass only fields a child reads; a wide model/environment dependency invalidates unrelated UI.
Separate side-effect-only dependencies from rendering inputs. Make model projections Equatable
when it enables a meaningful update gate, but do not add `EquatableView` blindly.
