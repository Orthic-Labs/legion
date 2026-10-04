# Shared macOS workflow boundary

Use this short boundary when an iOS or multiplatform task touches a Mac target. Keep
shared SwiftUI, state, identity, observation, concurrency, persistence, and test rules
in this skill's existing references. Route native Mac behavior to
[macOS workflow references](../../macos-development/references/macos-workflows.md).

Before changing a shared target, separate platform conditions: deployment minimum,
SDK, scene model, window/document ownership, menu and keyboard routing, sandbox/TCC,
AppKit bridges, signing, and distribution artifact. Preserve target-specific behavior;
an iOS pattern does not establish a Mac window or menu contract, and a Mac API does not
automatically apply to Catalyst or another platform.

For multiplatform code, put availability checks and platform branches at the boundary,
keep domain operations shared, and verify each affected target. Use Mac references for
SwiftPM GUI bundle staging, `NSWindow`/`NSPanel`, responder chains, menu-bar extras,
Liquid Glass, macOS window placement, codesign/notarization, and unified logging.
Do not infer a simulator, device, or Mac runtime pass from source checks on another
platform.
