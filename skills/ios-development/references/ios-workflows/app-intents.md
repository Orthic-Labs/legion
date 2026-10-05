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
central router. Keep existing qualified intent target/module ownership. The scene
translates each payload once into tab, route, sheet, or editor state, then consumes it
by its stable payload ID & clears queued value. This prevents restoration or SwiftUI
re-render from replaying same handoff. If both manual review & automation matter,
expose paired intents sharing parameter
names and domain service.

Use `AppEnum` for small fixed choices (tabs, modes, visibility). Use `AppEntity` plus
`EntityQuery` for accounts, projects, lists, drafts, destinations, or media. For a
dependent picker, use `@IntentParameterDependency` and scope child queries to parent
ID. Reuse entity/parameter models for WidgetKit configurations, controls, Spotlight,
Siri, Live Activities, and Shortcuts where semantics match.

## Shortcut chaining

When parameter should accept prior intent's result in Shortcuts chain, opt in
explicitly with `inputConnectionBehavior: .connectToPreviousIntentResult`:

```swift
@Parameter(
  title: "Prefilled text",
  inputConnectionBehavior: .connectToPreviousIntentResult
)
var text: String?
```

This is input contract for parameter; keep validation & conversion in
intent or its domain service. See Apple's
[`InputConnectionBehavior`](https://developer.apple.com/documentation/appintents/inputconnectionbehavior).

## Widget configuration & dependent queries

Widget configuration intents can reuse app entities. Child query can depend on parent
parameter & scope suggestions plus identifier resolution to that parent:

```swift
struct ProjectSelectionIntent: WidgetConfigurationIntent {
  static let title: LocalizedStringResource = "Project widget configuration"

  @Parameter(title: "Workspace")
  var workspace: WorkspaceEntity?

  @Parameter(title: "Project")
  var project: ProjectEntity?
}

struct ProjectQuery: EntityQuery {
  @IntentParameterDependency<ProjectSelectionIntent>(\.$workspace)
  var intentDependency

  func entities(for identifiers: [ProjectEntity.ID]) async throws -> [ProjectEntity] {
    try await fetchProjects()
      .filter { identifiers.contains($0.id) }
      .map(ProjectEntity.init)
  }

  func suggestedEntities() async throws -> [ProjectEntity] {
    try await fetchProjects().map(ProjectEntity.init)
  }

  func defaultResult() async -> ProjectEntity? {
    try? await fetchProjects().first.map(ProjectEntity.init)
  }

  private func fetchProjects() async throws -> [Project] {
    guard let intentDependency else { return [] }
    let workspaceID = intentDependency.workspace.id
    return try await ProjectStore.shared.projects(in: workspaceID)
  }
}
```

For a widget-specific configuration, keep parameters on a
`WidgetConfigurationIntent` and reuse entity queries where semantics match:

```swift
struct ActivityWidgetConfiguration: WidgetConfigurationIntent {
  static let title: LocalizedStringResource = "Activity widget configuration"
  static let description = IntentDescription("Choose workspace and filter")

  @Parameter(title: "Workspace")
  var workspace: WorkspaceEntity?

  @Parameter(title: "Filter")
  var filter: ActivityFilterEntity?
}
```

Use `WidgetConfigurationIntent` for widget settings &
[`IntentParameterDependency`](https://developer.apple.com/documentation/appintents/intentparameterdependency)
for dependent pickers. Preserve stable entity IDs & tolerate stale selections.

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

For scene delivery, observe payload ID & consume by matching ID before routing:

```swift
func consumeIntent(id: UUID) -> HandledIntent? {
  guard let payload = handledIntent, payload.id == id else { return nil }
  handledIntent = nil
  return payload
}
```

Route returned payload immediately; do not read queue again from destination
view bodies.

## Validate system behavior

Build the app/extension target, then invoke through requested Shortcuts/Siri/Spotlight/
widget/control surface. Check stale entity, denied access, cancellation, repeated run,
locked/background, and open-app route cases promised by feature. Keep auth and
destructive safeguards at domain boundary. Record OS, target, invocation path, result,
and any surface unavailable in current simulator. Unit tests or an in-app button alone
do not prove system integration.
