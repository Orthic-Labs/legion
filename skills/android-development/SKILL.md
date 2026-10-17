---
name: android-development
description: "Build, change, debug, test, or optimize native Android apps & components. Use for Kotlin/Jetpack Compose or Views, Android SDK APIs, lifecycle, permissions, background work, audio, storage, Gradle/AGP, adb/emulator testing, Rust JNI/UniFFI integration & Play release preparation; preserve existing cross-platform hosts."
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

# Android development

Deliver requested Android behavior with evidence from affected app, variant & runtime.
This supplies platform expertise within Legion's existing authority & effect controls.

1. Identify app/module, UI stack, application ID, variants, min/target/compile SDK,
   Gradle wrapper, AGP/Kotlin/JDK pins, native ABIs & existing build/test commands.
   Read repository instructions before choosing APIs or tools.
2. Preserve Compose, Views/Fragments, Java, Kotlin, Rust/Tauri & current persistence or
   dependency injection choices. Compare device API availability separately from
   target-SDK behavior changes. Load only references needed for current change:
   - State, lifecycle, effects, accessibility & adaptive UI: [Compose & Kotlin](references/compose-kotlin.md).
   - Permissions, services, WorkManager, recording, Keystore & storage: [Platform APIs](references/platform-apis.md).
   - Wrapper/toolchain selection, adb, emulator/device tests & Play preparation: [Build, testing & release](references/toolchain-testing-release.md).
   - Rust boundaries, native packaging & RightKit ownership: [Rust interoperability](references/rust-interop.md).
3. For execution or tool-dependent work, use [route resources](references/route-resources.json)
   to bind host dependencies only to selected routes. Detect → select → reuse → authorized
   setup when missing → verify → continue. Read-only advice needs no SDK.
   Respect repository build admission before commands that configure, compile, test or
   package. Discover actual commands before using task-name examples. Missing tooling
   leaves affected coverage unverified; do useful source work meanwhile.
4. Implement smallest coherent change. Verify affected UI/platform/FFI boundary at
   its actual layer. Exercise denial, cancellation, process recreation, backgrounding
   or hardware behavior where implicated; reuse existing tests & fixtures.
5. Report source revision, artifact/variant, toolchain, device/API/ABI, commands &
   observed outcomes. Distinguish source review, JVM tests, emulator evidence,
   physical-device behavior & signed distribution evidence.

## Boundaries

- Loading this skill grants no account, credential, device-reset, upload, publication,
  persistent integration or unrelated dependency changes. Existing user authorization
  still governs setup & execution; avoid repeated approval for authorized work.
- Reuse shared RightKit owners where applicable. Inspect actual source & integration
  evidence: package declaration, README or dependency resolution alone proves no
  working Android bridge.
- Compose with Architect for significant architecture choices, Debugger for systematic
  diagnosis, QA for test method & Designer for visual work. Those capabilities retain
  ownership; full-repository Audit stays user-invoked.
- Preserve other platforms; an Android request does not authorize an app rewrite or
  migration to Compose Multiplatform, Navigation 3 or newest AGP.

[Source manifest](config/source-manifest.json) records dated sources & reuse limits.
