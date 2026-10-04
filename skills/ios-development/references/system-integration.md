# App Intents and system-facing features

For concrete iOS recipes, use [iOS workflows: App Intents](ios-workflows/app-intents.md).

Use this reference when the requested feature participates in Shortcuts, Siri, Spotlight,
widgets, sharing, or another system surface. Inspect existing extensions/integrations and
the supported SDK/deployment targets before choosing an API or adding a target.

## Define the real action

- Reuse the app's domain operation rather than maintaining separate business logic for
  the system entrypoint. Define inputs, validation, success, cancellation, and error results.
- Use stable entity identifiers and explicit lookup behavior; tolerate records being
  deleted, inaccessible, offline, or changed since a suggestion was created.
- Expose only parameters that make sense outside the foreground screen. Do not assume
  a selected document/window, unlocked device, logged-in account, or active UI exists.
- Preserve authorization and authentication checks at the actual operation boundary.
  Invocation by a shortcut or assistant must not bypass destructive-action safeguards.
- Check the supported execution context and lifetime. Do not assume an intent can run
  unrestricted background work, present any UI, or access resources held by the app.
- Keep titles, parameter descriptions, localization, and returned errors meaningful for
  the system surface. Avoid leaking private data into suggestions, logs, or public results.

Start with one to three user-valued verbs such as compose, open, find, filter, continue,
or start. Keep `AppEntity` smaller than persistence models: stable ID, display
representation, and only fields needed for lookup/disambiguation. Use `AppEnum` for a
small fixed set such as tabs or visibility. Add `suggestedEntities()` only when picker
UX benefits, and `defaultResult()` only when a real default exists.

Choose inline completion (`openAppWhenRun = false`) for quick create/update/archive/
toggle work and return a dialog or snippet. Choose open-app handoff for editors,
navigation, auth, or richer UI; enqueue one payload in a central router and translate
it in the main scene. If both modes matter, pair intents with aligned parameters and a
shared domain service. A dependent picker uses `@IntentParameterDependency` to scope
child query results to parent ID. Reuse these types for widgets and controls where
semantics match.

## Integrate proportionately

Identify whether the work belongs in the app target, an existing extension, or a justified
new target. Preserve dependency and storage ownership; shared containers, entitlements,
URL handlers, and keychain access groups are security/data decisions, not boilerplate.
Keep availability fallbacks and existing behavior on older supported systems.

For widgets or other extensions, verify the data-transfer/update mechanism and relevant
resource/lifecycle constraints. A successful app action does not prove extension behavior.

## Validate the actual surface

Build the relevant targets, exercise parameter/entity resolution and the domain action,
then invoke through the requested supported system surface. Test invalid/stale entities,
denied access, cancellation, repeated invocation, and foreground/background cases that
the feature promises. Record the OS, target, and observed result.

Without a suitable simulator/device or Mac, return code and source-level checks with the
system-surface verification explicitly unrun. Do not claim Siri/Shortcuts/Spotlight works
because unit tests or an in-app button passed.

For file parameters, balance security-scoped resource access around each URL and handle
empty or inaccessible input. For every query, tolerate stale/deleted records and
current authorization. Test open-app routing, inline result, stale entity, denied
access, cancellation, repeated invocation, locked/background context, and destructive
action safeguards at the service boundary.

Primary documentation: https://developer.apple.com/documentation/appintents
and https://developer.apple.com/documentation/widgetkit
