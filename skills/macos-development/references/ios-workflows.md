# iOS workflow boundary

Use this boundary when a multiplatform or Catalyst task includes an iOS target. Keep
Mac-specific windows, menus, sandbox, signing, & release checks in `macos-development`
references. Select `ios-development` capability for iOS workflow topics, applying every
recipe to selected iOS target and deployment minimum.

| Need | Read |
| --- | --- |
| Build, launch, inspect UI, logs | `ios-workflows/simulator-debugging` |
| Browser mirror or package preview hot reload | `ios-workflows/preview-browser` |
| App Intents & system surfaces | `ios-workflows/app-intents` |
| Performance or memory evidence | `ios-workflows/performance-evidence`, `ios-workflows/memory-evidence` |
| SwiftUI shell & quality patterns | `ios-workflows/swiftui-shell`, `ios-workflows/swiftui-quality` |

Use existing project tooling and preserve target boundaries. A successful Mac build
does not prove iOS behavior; record target, SDK/runtime, simulator UDID, scheme,
configuration, bundle ID, artifacts, and unrun device checks.
