# App Intents and system-facing features

For concrete iOS recipes in a multiplatform target, select `ios-development` & its App Intents workflow through this bundle's [iOS workflow boundary](ios-workflows.md).

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

Start with a small set of user-valued verbs. Keep system-facing entities narrower than
Mac persistence models, use `AppEnum` for fixed choices, and scope dependent queries
with `@IntentParameterDependency`. Inline intents should complete through shared domain
services and return useful dialog/snippet feedback; open-app intents should enqueue one
central handoff payload for the native scene. Reuse parameter/entity models for widgets,
controls, Spotlight, Siri, and Shortcuts when behavior matches.

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

Validate stale entities, denied access, cancellation, repeated invocation, locked or
background execution, open-app routing, and destructive-action safeguards. File intent
parameters must balance security-scoped URL access. Validate iOS and Mac targets
separately; Mac success does not prove iOS behavior.

Primary documentation: https://developer.apple.com/documentation/appintents
and https://developer.apple.com/documentation/widgetkit
