# Inject in an existing development integration

Use this page when an approved project already uses Inject, or the requested change
includes that integration. Match the resolved Inject version, injection application,
Xcode version, platform & target before applying settings. This is an optional iteration
path; retain a normal build/test path & existing application architecture.

## Debug prerequisites

The pinned Inject source describes `-Xlinker -interposable` in Other Linker Flags for
participating Debug targets, qualified to the simulator SDK for that iOS setup. It also
describes `EMIT_FRONTEND_COMMAND_LINES = YES` for newer Xcode Debug configurations.
Treat these as version-dependent prerequisites: inspect the resolved tool's instructions
& effective settings for the selected destination. Do not apply simulator settings to a
macOS target or broaden them to device/Release configurations by inference.

Confirm which Xcode the build & injection application use. The pinned setup assumes
`/Applications/Xcode.app`; a custom Xcode location needs support from the matched injection
tool. Open the intended workspace in the existing InjectionIII/InjectionForXcode app,
launch the selected Debug app & inspect connection/watched-source output before diagnosing
view integration. A running developer app alone does not prove connection to this build.

Keep dependency additions, machine-app installation & target-setting changes within the
user's requested scope. Verify distribution settings independently; a library's advertised
production no-op is not proof that project linker flags or developer tooling are absent.

## SwiftUI integration

For versions exposing these APIs, put `@ObserveInjection` on the view being iterated on
& attach `.enableInjection()` to its body result. Keep imports local to participating files.

```swift
import SwiftUI
import Inject

struct StatusBadge: View {
    @ObserveInjection var injection

    var body: some View {
        Text("Connected")
            .padding(6)
            .enableInjection()
    }
}
```

Change one visible detail, confirm it appears after injection, then verify a normal build.
Do not use reload success to infer persistence correctness, startup behavior or test success.

## UIKit & AppKit host lifecycle

Use `Inject.ViewHost` or `Inject.ViewControllerHost` at the parent construction callsite,
where ownership & replacement already belong. The host must receive an initializer
expression that creates a fresh instance on every reload:

```swift
let hostedPanel = Inject.ViewHost(InspectorPanel(model: model))
let hostedController = Inject.ViewControllerHost(InspectorController(model: model))
```

These arguments use `@autoclosure`. Passing an already-created `panel` or `controller`
variable captures that same instance, preventing reconstruction. Preserve dependencies in
the constructor expression & keep required state at its existing owner. An initializer API
change still requires updating callsites & rebuilding. Confirm old hosted instances release
their observers/tasks when replaced; do not attach duplicate subscriptions during reload.

When an existing UIKit integration must rebind a presenter after replacement, use the
version-matched `onInjectionHook`. Bind the controller passed to that callback, rather than
capturing the original instance. Release old bindings & avoid owner/closure retain cycles;
ordinary initial construction still needs its normal wiring path.

Avoid global exported imports & bulk scripts that rewrite every Swift file. Apply the
smallest participating seam, then verify Debug behavior & a normal non-injection build.

Source: Inject README at `67e3ee9a2b7e40d6af72d07cf1b0d5c04399e809`;
see [source manifest](../../config/source-manifest.json) for rights & provenance.
