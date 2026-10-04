# App Intents & system surfaces

## Pick a small surface

Start with one to three useful verbs: compose, open, find, filter, continue, or start.
Choose entities only when the system must identify an app object. Expose a compact
identifier/display representation, query by stable IDs, provide suggestions only when
useful, and provide a default only when it is genuinely helpful. Do not mirror app
navigation or persistence graphs.

Decide per intent whether work completes inline or opens the app. Inline actions keep
`openAppWhenRun` false, call an existing domain service, validate auth/access, handle
cancellation/errors, and return dialog/snippet feedback. Open actions set
`openAppWhenRun` true, carry lightweight input, and publish one handled payload to a
central router. The scene translates it once into tab, route, sheet, or editor state.
If both manual review and automation matter, expose paired intents sharing parameter
names and domain service.

Use `AppEnum` for small fixed choices (tabs, modes, visibility). Use `AppEntity` plus
`EntityQuery` for accounts, projects, lists, drafts, destinations, or media. For a
dependent picker, use `@IntentParameterDependency` and scope child queries to parent
ID. Reuse entity/parameter models for WidgetKit configurations, controls, Spotlight,
Siri, Live Activities, and Shortcuts where semantics match.

## Concrete implementation shape

Keep intent types thin and place business logic in services. Typical shapes are:

```swift
struct OpenEditorIntent: AppIntent {
  static let title: LocalizedStringResource = "Open editor"
  static let openAppWhenRun = true
  @Parameter(title: "Draft") var draftID: String?

  func perform() async throws -> some IntentResult {
    await MainActor.run { IntentHandoff.shared.enqueue(.editor(draftID)) }
    return .result()
  }
}

struct CreateRecordIntent: AppIntent {
  static let title: LocalizedStringResource = "Create record"
  static let openAppWhenRun = false
  @Parameter(title: "Name") var name: String

  func perform() async throws -> some IntentResult & ProvidesDialog {
    do {
      try await RecordService.shared.create(name: name)
      return .result(dialog: "Created \(name).")
    } catch is CancellationError {
      throw CancellationError()
    } catch {
      return .result(dialog: "Could not create that record.")
    }
  }
}
```

An entity should expose `id`, `typeDisplayRepresentation`, `displayRepresentation`,
and `defaultQuery`; query methods resolve IDs against current storage and tolerate stale
or inaccessible records. File parameters must handle security-scoped URLs with balanced
access calls and should reject empty input. A shortcut provider should use one or two
short, verb-led phrases, precise titles, and a meaningful system symbol.

## Validate system behavior

Build the app/extension target, then invoke through requested Shortcuts/Siri/Spotlight/
widget/control surface. Check stale entity, denied access, cancellation, repeated run,
locked/background, and open-app route cases promised by feature. Keep auth and
destructive safeguards at domain boundary. Record OS, target, invocation path, result,
and any surface unavailable in current simulator. Unit tests or an in-app button alone
do not prove system integration.
