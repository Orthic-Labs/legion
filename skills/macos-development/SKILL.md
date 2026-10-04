---
name: macos-development
description: "Build, change, debug, test, or optimize macOS apps and Apple-native components. Use for SwiftUI/AppKit, windows and menus, Swift concurrency, persistence, Xcode/SwiftPM, native permissions, and release preparation; preserve existing Rust/Tauri/Cargo hosts."
kind: capability
capabilityClass: domain
discoverability: public
domain: engineering
operations:
  - analyze
  - diagnose
  - decide
  - produce
  - evaluate
  - execute
effects:
  - source-read
  - repository-write
  - artifact-write
  - process-exec
  - network-request
hostRequirements: []
---

# macOS Development

Deliver the requested Mac change with evidence from the affected application or component.
This adds platform expertise to Legion; it does not replace its runtime or authority roles.

1. Identify the app's host architecture, native boundary, Xcode project/workspace or Swift
   package, schemes, deployment minimum, Swift mode, architectures, UI and storage stacks.
   Read repository instructions and existing build/test/release commands first.
2. Preserve SwiftUI/AppKit, Rust/Tauri/Cargo, web UI, XCTest, and current persistence choices.
   A Mac feature is not a mandate to rewrite the app in Swift. Choose APIs against the
   actual SDK/deployment target rather than a blanket newest-version assumption.
3. For execution or tool-dependent work, run the mandatory [tool setup lifecycle](references/tool-setup.md):
   detect → select → reuse → authorized setup only when missing → verify → continue.
   The agent owns finding and proposing the needed tools; the user should not hunt for them.
   Then load only the relevant references:
   - Windows, menus, documents, focus, keyboard, sandbox/TCC: [macOS platform](references/macos-platform.md)
   - App Intents, Shortcuts, Spotlight, widgets: [System integration](references/system-integration.md)
   - View identity, state ownership, SwiftUI performance: [SwiftUI](references/swiftui.md)
   - Actors, Sendable, isolation, cancellation, Swift migration: [Concurrency](references/concurrency.md)
   - SwiftData/Core Data models, migrations, fetches, isolation: [Persistence](references/persistence.md)
   - Unit/UI tests and native runtime debugging: [Testing](references/testing.md)
   - Module boundaries, dependency injection, code generation: [Architecture](references/architecture.md)
   - Xcode/SwiftPM and optional development tools: [Toolchain](references/toolchain.md)
   - Measured build, launch, rendering, memory improvements: [Performance](references/performance.md)
   - Signing, sandbox, notarization, distribution preparation: [Release](references/release.md)
   - Cross-language implementation and host preservation: [Rust/Tauri interop](references/tauri-rust-interop.md)
4. Implement the bounded change and verify at its actual layer. Swift unit tests, Cargo
   tests, browser tests, native app behavior, and signed distribution each prove different
   things. Use the project's existing checks; exercise native behavior when implicated.
5. Report exact checks and tool/target context, outcomes, unrun coverage, and remaining
   risks. A Linux-only review cannot establish a macOS UI or release pass.

## Boundaries

- Read-only advice and review remain available without Apple tooling. Host dependencies
  are scoped in [route resources](references/route-resources.json), not mandatory installs.
- Discover the connected tools and their versions. No model, paid app, account, credential,
  persistent integration, upload, signing, notarization, or publication is authorized by
  this skill. Follow the user's actual scope and Legion's effect controls.
- Compose with existing Architect, Debugger, QA, and Designer capabilities as appropriate;
  do not duplicate their general workflow or infer authority from platform effects.
- Use ios-development for iOS/iPadOS targets; share only the changes the task genuinely
  requires. Catalyst and multiplatform apps need explicit target-by-target validation.

[Source manifest](config/source-manifest.json) records reviewed sources and reuse limits.
[Third-party notices](references/third-party-notices.md) travel with this standalone bundle.
