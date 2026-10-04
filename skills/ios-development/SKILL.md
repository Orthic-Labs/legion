---
name: ios-development
description: "Build, change, debug, test, or optimize iOS and iPadOS apps and their Apple-native components. Use for SwiftUI/UIKit, Swift concurrency, SwiftData/Core Data, Xcode builds, simulator/device behavior, and release preparation; preserve an existing cross-platform host."
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

# iOS Development

Deliver the requested iOS/iPadOS change with evidence from the affected target. This is
platform expertise within Legion, not a new authority, agent harness, or permission grant.

1. Identify the actual target, workspace/project/package, scheme, deployment minimum,
   Swift language mode, UI framework, persistence stack, and existing build/test commands.
   Inspect repository instructions and current code before selecting a pattern.
2. Keep the app's architecture and dependencies unless the request requires a change.
   Preserve UIKit, XCTest, Core Data, Tauri/Rust, and other existing choices; modern APIs
   are conditional on the target's SDK and deployment availability.
3. Read only the references needed for the request:
   - iOS lifecycle, navigation, adaptation, permissions, native UI: [iOS platform](references/ios-platform.md)
   - App Intents, Shortcuts, Siri, Spotlight, widgets: [System integration](references/system-integration.md)
   - View identity, state ownership, SwiftUI performance: [SwiftUI](references/swiftui.md)
   - Actors, Sendable, isolation, cancellation, Swift migration: [Concurrency](references/concurrency.md)
   - SwiftData/Core Data models, migrations, fetches, isolation: [Persistence](references/persistence.md)
   - Unit/UI tests, simulator/device evidence, debugging: [Testing](references/testing.md)
   - Module boundaries, dependency injection, code generation: [Architecture](references/architecture.md)
   - Xcode selection, tools, simulator workflows: [Toolchain](references/toolchain.md)
   - Measured build, launch, rendering, memory improvements: [Performance](references/performance.md)
   - Signing, archive/export, TestFlight/App Store preparation: [Release](references/release.md)
   - A cross-platform shell or native bridge: [Rust/Tauri interop](references/tauri-rust-interop.md)
4. Make the smallest coherent change, then run the existing focused checks and the actual
   platform build/runtime checks required by the changed behavior. Fix observed failures
   within scope; distinguish simulator success from device or distribution validation.
5. Report the change, commands/target/tool versions, observed results, unrun checks, and
   material remaining risks. Missing tools or SDKs mean unverified coverage, never a pass.

## Boundaries

- Read-only advice and code review work without Xcode. Execution requirements bind only
  to selected routes in [route resources](references/route-resources.json).
- Discover actual tool capabilities before use. No automatic installation, paid-service
  requirement, model choice, credential setup, account access, upload, or release follows
  from loading this skill. Preserve Legion's live authorization and effect controls.
- Compose with Architect for architecture-significant decisions, Debugger for systematic
  diagnosis, QA for verification method, and Designer for qualitative UI work when needed.
  Those capabilities keep their existing ownership; Audit remains user-invoked.
- Use macos-development for Mac-specific targets. A multiplatform change may use both;
  shared Swift changes do not justify unrelated platform rewrites or duplicate work.

[Source manifest](config/source-manifest.json) records reviewed sources and reuse limits.
[Third-party notices](references/third-party-notices.md) travel with this standalone bundle.
