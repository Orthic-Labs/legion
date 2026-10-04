# macOS workflow router

Use this router for native Mac work while preserving an existing SwiftUI, AppKit,
SwiftPM, Xcode, Rust/Tauri, or hybrid shape. First identify target, SDK, minimum OS,
product type, scheme/package product, and current build/test/release path. Load only
the focused reference needed:

- [Build, run, and debug](macos-workflows/build-run-debug.md) for project discovery,
  repeatable shell loops, SwiftPM app staging, launch failures, and debugger/log modes.
- [SwiftPM](macos-workflows/swiftpm.md) for products, resources, GUI-vs-CLI launch,
  package tests, and package graph diagnosis.
- [SwiftUI desktop scenes](macos-workflows/swiftui-scenes.md) for windows, documents,
  commands, menus, settings, menu-bar extras, split views, and inspectors.
- [Window management](macos-workflows/windows.md) for titlebars, drag regions, placement,
  restoration, minimize policy, borderless style, and concrete availability checks.
- [Conditional Liquid Glass](macos-workflows/liquid-glass.md) for system materials,
  toolbar/search/control adoption, custom glass, and older-system fallbacks.
- [AppKit interop](macos-workflows/appkit-interop.md) for representables, coordinators,
  panels, responder routing, pasteboards, and drag/drop.
- [Signing and packaging](macos-workflows/signing-packaging.md) for codesign,
  entitlements, hardened runtime, Gatekeeper, archives, notarization, and installers.
- [Telemetry](macos-workflows/telemetry.md) for Logger, signposts, Console, and
  `log stream` evidence without sensitive payloads.
- [Stable view refactors](macos-workflows/view-refactor.md) for scene ownership,
  file boundaries, selection stability, and narrow AppKit edges.
- [Test triage](macos-workflows/testing-triage.md) for focused Xcode/SwiftPM tests,
  failure classification, and native runtime evidence.

Keep generic SwiftUI state, identity, concurrency, persistence, and testing advice in
their existing references. These workflows add Mac-specific detail and do not mandate
host setup, a new architecture, a new dependency, security relaxation, or a particular
agent/orchestration surface. Every version-specific API needs an active SDK and minimum
OS check with a useful fallback where support requires it.
