# Apple boundaries in Rust and Tauri apps

Use this reference when an iOS or macOS feature touches a Rust/Tauri consumer.
These skills provide engineering guidance; they install nothing and grant no access.

## Architecture is a constraint

- Inspect Cargo workspace, Rust toolchain, Tauri version, frontend, and lockfiles.
- Read existing commands, plugins, capabilities, configuration, and build scripts.
- Preserve the consuming app's Rust services, state ownership, and IPC contracts.
- Preserve its web UI framework, routing, styling, accessibility, and test setup.
- Keep database, serialization, migration, and persistence choices unchanged by default.
- An Apple-platform task is not authorization for a Swift or SwiftUI rewrite.
- Do not generate a second application shell or parallel business-logic layer.
- Follow the installed Tauri major version; do not apply v2 recipes to v1 blindly.
- Keep supported targets, feature flags, and deployment minima intact.

## Decide the smallest boundary

- First check whether the existing Tauri API or maintained project plugin fits.
- Keep portable logic and policy in Rust; keep web presentation in the frontend.
- Add native Apple code only for a genuine platform integration boundary.
- A native framework, delegate callback, or native view may justify a small bridge.
- Prefer the project's established Rust Apple bindings where they already solve it.
- For iOS plugins, follow the matching Tauri Swift-package/mobile-plugin mechanism.
- Do not assume the iOS plugin layout is the macOS integration mechanism.
- Document why the bridge exists, its owner, inputs, outputs, and lifetime.
- Avoid adding a new bridge generator, dependency, or runtime without need.
- Keep platform-specific code gated so non-Apple builds remain viable.

## IPC and FFI contracts

- Keep command names, payloads, event names, and error shapes compatible.
- Validate frontend inputs again at the trusted native/Rust boundary.
- Constrain paths, identifiers, URLs, payload sizes, and requested operations.
- Return structured errors for denial, unavailable hardware, cancellation, and failure.
- Keep privileged effects out of arbitrary frontend-evaluated strings.
- Scope Tauri permissions to the required operation, platform, and windows/webviews.
- Check capability overlap; permissions from multiple capabilities can accumulate.
- Audit application-command exposure separately from plugin permission declarations.
- Do not enable remote content access or broad shell/filesystem commands incidentally.
- For FFI, specify ABI, layout, encoding, nullability, ownership, and freeing rules.
- Keep unsafe operations small with documented preconditions and safe wrappers.
- Prevent panics/exceptions from crossing an incompatible ABI boundary.
- Unregister callbacks before their referenced state is destroyed.
- Marshal callbacks onto the proper executor before touching UI or isolated state.
- Define cancellation and completion ownership to avoid double responses or leaks.

## Build and packaging implications

- Trace Cargo, frontend, native bridge, and app-bundle builds as distinct stages.
- Preserve checked-in lockfiles and repository-managed generation workflows.
- Determine whether generated Xcode files are disposable before editing them.
- Keep minimum OS settings aligned across Tauri, Cargo/native code, and Xcode.
- Check requested architectures, link settings, embedded resources, and native libraries.
- A new native dependency can affect bundle contents, signing, and distribution.
- Review required usage strings, privacy manifests, entitlements, and provisioning.
- Tauri capabilities do not replace Apple sandbox entitlements or runtime consent.
- Do not add blanket entitlements or disable Hardened Runtime to hide a failure.
- Distinguish local debug signing, release signing, and notarization evidence.
- Avoid handling signing secrets; use the approved credential workflow if needed.

## Evidence by layer

- Run the project's formatter, static checks, Rust tests, and frontend tests as relevant.
- Add contract tests for changed payloads, error mapping, and permission boundaries.
- Use browser tests for rendering, DOM interaction, routing, and mocked IPC behavior.
- Label mocked IPC explicitly; mocks cannot prove native commands work.
- Build and launch the actual Tauri app for shell, plugin, native UI, and IPC checks.
- On macOS, verify native menus, windows, focus, file dialogs, and relevant TCC behavior.
- On iOS, verify the target simulator flow and use devices for hardware-specific claims.
- Exercise denied permission, cancelled operation, repeated invocation, and relaunch.
- Record target, toolchain, command, artifact, and observed outcome for each claim.
- Cross-platform unit tests do not establish Apple linking or native runtime success.
- Missing macOS/Xcode/device access means native validation is unverified, not passed.
- Finish with what changed, what passed, what failed, and exactly what remains untested.

## Least-authorized execution

- Read and propose before changing credentials, permissions, distribution, or host setup.
- Follow the user's task scope and applicable approval rules for consequential actions.
- A skill does not authorize installing Xcode, plugins, certificates, or dependencies.
- Do not reset TCC, grant broad Accessibility access, or weaken security for convenience.
- Do not upload, notarize, publish, or release merely because a build succeeded.
- Never substitute a browser demo for a native deliverable without stating the gap.

## Primary references

- Tauri mobile plugins: https://v2.tauri.app/develop/plugins/develop-mobile/
- Tauri capabilities: https://v2.tauri.app/security/capabilities/
- Tauri tests: https://v2.tauri.app/develop/tests/
- Tauri macOS signing: https://v2.tauri.app/distribute/sign/macos/
- Rust FFI: https://doc.rust-lang.org/nomicon/ffi.html
- Apple sandbox: https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox
- Apple protected resources: https://developer.apple.com/documentation/bundleresources/protected-resources
