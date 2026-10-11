# iOS workflow boundary

Use this boundary when a multiplatform or Catalyst task includes an iOS target. Keep
Mac-specific windows, menus, sandbox, signing, & release checks in `macos-development`
references. Select `ios-development` capability for iOS workflow topics, applying every
recipe to selected iOS target and deployment minimum.

| Need | Load from `ios-development` (topic) |
| --- | --- |
| Build, launch, inspect UI, logs | simulator-debugging |
| Browser mirror or package preview hot reload | preview-browser |
| App Intents & system surfaces | app-intents |
| Performance or memory evidence | performance-evidence, memory-evidence |
| SwiftUI shell & quality patterns | swiftui-shell, swiftui-quality |

The iOS topic files ship only in the standalone `ios-development` bundle; this bundle does not
contain them and its reference closure cannot link to them. Select that capability by name.

Use existing project tooling and preserve target boundaries. A successful Mac build
does not prove iOS behavior; record target, SDK/runtime, simulator UDID, scheme,
configuration, bundle ID, artifacts, and unrun device checks.
