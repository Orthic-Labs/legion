# AppKit interop

Name the SwiftUI capability gap first: a specific view/text system, controller lifecycle,
window/panel behavior, responder/menu validation, pasteboard type, or drag/drop delegate.
Prefer SwiftUI scenes, commands, focused values, panels, and controls when they express
the behavior. Choose the smallest bridge:

- `NSViewRepresentable` for one AppKit view/control;
- `NSViewControllerRepresentable` for controller lifecycle, delegation, or presentation;
- a small `NSWindow`/`NSPanel` or app delegate hook for window/responder/app-level needs.

Keep SwiftUI as source of truth for bindings, selection, and observable models. Let AppKit
objects live inside the wrapper/coordinator or a narrowly owned bridge service. Expose
bindings for editable state and small callbacks for events; do not leak `NSView` or
`NSWindow` through unrelated view layers or make a coordinator a second architecture.

Representables may be recreated. Put delegate and target/action glue in `Coordinator`,
set up the view/controller once in `make*`, and reconcile external state in `update*`.
Push values only when they changed to avoid feedback loops; guard callbacks against
reentrant updates. Tear down observers, monitors, delegates, panels, and tasks with the
same owner that created them.

This compact bridge keeps binding ownership in SwiftUI, delegate glue in the coordinator,
and cleanup explicit:

```swift
struct NoteEditor: NSViewRepresentable {
    @Binding var text: String

    func makeCoordinator() -> Coordinator { Coordinator(text: $text) }

    func makeNSView(context: Context) -> NSTextView {
        let view = NSTextView()
        view.delegate = context.coordinator
        view.isRichText = false
        view.string = text
        return view
    }

    func updateNSView(_ view: NSTextView, context: Context) {
        guard view.string != text else { return }
        view.string = text
    }

    static func dismantleNSView(_ view: NSTextView, coordinator: Coordinator) {
        view.delegate = nil
    }

    final class Coordinator: NSObject, NSTextViewDelegate {
        @Binding var text: String
        init(text: Binding<String>) { _text = text }
        func textDidChange(_ note: Notification) {
            guard let view = note.object as? NSTextView else { return }
            text = view.string
        }
    }
}
```

For a controller wrapper, use the same split: `makeNSViewController` constructs once,
`updateNSViewController` applies changed inputs, `Coordinator` owns delegates, and
`dismantleNSViewController` unregisters observers or callbacks. If a callback can arrive
after teardown, make the coordinator's stopped state explicit before releasing it.

For menus, start with `commands`, `FocusedValue`, and focused scene state. Use responder
chain selectors and `validateMenuItem` only where active first responder or legacy AppKit
behavior is material, and keep enablement beside its source state. For file panels, keep a
small main-actor helper around `NSOpenPanel`/`NSSavePanel`; preserve sandbox security-scoped
access and cleanup at every completion path.

This focused command keeps menu routing tied to active editor state:

```swift
struct EditorActions { let rename: () -> Void }
struct EditorActionsKey: FocusedValueKey { typealias Value = EditorActions }
extension FocusedValues {
    var editorActions: EditorActions? {
        get { self[EditorActionsKey.self] }
        set { self[EditorActionsKey.self] = newValue }
    }
}

struct EditorView: View {
    let rename: () -> Void
    var body: some View {
        Text("Editor")
            .focusedValue(\.editorActions, EditorActions(rename: rename))
    }
}

struct EditorCommands: Commands {
    @FocusedValue(\.editorActions) private var actions
    var body: some Commands {
        CommandMenu("Document") {
            Button("Rename") { actions?.rename() }
                .keyboardShortcut("r", modifiers: [.command, .shift])
                .disabled(actions == nil)
        }
    }
}
```

Use `validateMenuItem` or responder selectors only when this focused-value route cannot
represent the required first-responder contract.

Use SwiftUI drag/drop first. Cross the boundary for custom `NSPasteboard` types, rich
previews, legacy delegates, or AppKit validation; convert file URLs/data at that boundary,
validate declared types, and avoid moving a full list/canvas to AppKit for one drop target.
