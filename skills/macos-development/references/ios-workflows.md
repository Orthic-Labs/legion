# iOS workflows

Use this router when a multiplatform or Catalyst task includes an iOS target. Keep
Mac-specific windows, menus, sandbox, signing, & release checks in macOS references;
apply every recipe to the selected iOS target and deployment minimum.

| Need | Read |
| --- | --- |
| Build, launch, inspect UI, logs | [simulator-debugging.md](../../ios-development/references/ios-workflows/simulator-debugging.md) |
| Browser mirror or package preview hot reload | [preview-browser.md](../../ios-development/references/ios-workflows/preview-browser.md) |
| App Intents & system surfaces | [app-intents.md](../../ios-development/references/ios-workflows/app-intents.md) |
| Performance or memory evidence | [performance-evidence.md](../../ios-development/references/ios-workflows/performance-evidence.md), [memory-evidence.md](../../ios-development/references/ios-workflows/memory-evidence.md) |
| SwiftUI shell & quality patterns | [swiftui-shell.md](../../ios-development/references/ios-workflows/swiftui-shell.md), [swiftui-quality.md](../../ios-development/references/ios-workflows/swiftui-quality.md) |

Use existing project tooling and preserve target boundaries. A successful Mac build
does not prove iOS behavior; record target, SDK/runtime, simulator UDID, scheme,
configuration, bundle ID, artifacts, and unrun device checks.
