# macOS platform decisions

Use this reference for native Mac behavior, including hybrid desktop applications.
It is guidance, not installed tooling or permission to operate the host Mac.

## Preserve the app's structure

- Identify deployment target, SDK, app type, distribution channel, and build commands.
- Keep the existing SwiftUI, AppKit, Rust/Tauri, or hybrid architecture in place.
- Preserve persistence, document format, dependency injection, and test systems.
- Apply modern APIs only after checking the consuming app's supported versions.
- Treat a SwiftUI/AppKit migration or deployment-target bump as a separate decision.
- In Tauri apps, retain Rust and web UI ownership; use the interop reference.
- Identify whether state belongs to the process, document, window, or view.

## Windows and lifecycle

- Extend existing scenes/window controllers rather than adding competing owners.
- Select WindowGroup, Window, DocumentGroup, or AppKit controllers by actual behavior.
- Keep per-window selection, navigation, focus, and transient state independent.
- Avoid global state that makes the wrong window react to a command.
- Test new window, reopen, close, minimize, full screen, and restoration paths.
- Distinguish closing a window from quitting the app; preserve existing policy.
- Handle activation, deactivation, reopening, sleep/wake, and termination as needed.
- Keep costly work out of UI callbacks and update native UI on the main thread.
- Cancel window-owned work when its owner closes; preserve genuinely shared work.
- Review delegate, observer, timer, and event-monitor lifetimes for leaks.
- Persist important edits before termination and recover gracefully from stale state.

## Menus, focus, and keyboard

- Keep standard app, File, Edit, View, Window, and Help behavior where applicable.
- Route menu actions to the focused document/window through the existing command model.
- Validate enabled state and checkmarks against that same source of truth.
- Preserve standard shortcuts, text editing, Undo/Redo, and responder-chain behavior.
- Avoid global key interception when a local command or responder action is enough.
- Check first responder, initial focus, tab order, default action, and Escape behavior.
- Test keyboard-only navigation and conflicts between shortcuts and text fields.
- Update menus on the main thread; do not mutate them from background callbacks.
- Ensure toolbar and menu versions of an action remain behaviorally consistent.
- Test commands with no open window and with several different windows active.

## Documents and menu-bar apps

- Preserve the established DocumentGroup/FileDocument or NSDocument model.
- Keep file type declarations, serialization, migrations, and compatibility intact.
- Exercise open, save, save-as/export, revert, autosave, and unsaved-close handling.
- Preserve undo grouping, edited state, and coordination for external file changes.
- Handle missing, moved, locked, unsupported, and malformed files without data loss.
- Use MenuBarExtra or NSStatusItem consistently with the existing app and target.
- Keep a menu-bar item's lifecycle owned outside transient views.
- Check menu/popover dismissal, activation, keyboard access, and multiple displays.
- Make settings and quit reachable; do not accidentally change Dock visibility.
- Treat launch-at-login behavior or background persistence as separately scoped work.

## Sandbox, privacy, and accessibility

- Inspect current entitlements and distribution requirements before proposing changes.
- App Sandbox, Hardened Runtime, and TCC privacy consent are distinct mechanisms.
- Prefer the narrowest file/network/device access needed by the requested feature.
- Use system file pickers and security-scoped access where the sandbox requires it.
- Balance successful security-scoped access with cleanup on every completion path.
- Handle stale bookmarks and lost access; do not silently broaden filesystem access.
- Supply accurate protected-resource usage descriptions and test denial/revocation.
- Do not bypass TCC, disable protection, or reset host privacy settings to pass tests.
- Avoid requesting Accessibility or Automation access unless the feature needs it.
- Prefer native semantic controls; expose custom control roles, names, and values.
- Validate VoiceOver, focus movement, keyboard operation, and visible focus indicators.
- Check contrast, Reduce Motion, resizing, localization, and increased text sizes.

## Native validation and release boundaries

- Discover the available macOS/Xcode toolchain and repository scripts before execution.
- Run affected unit/integration tests, then build and launch the actual app bundle.
- Exercise native windows, menus, keyboard, dialogs, and permissions on macOS.
- Browser tests cover web content; they do not prove AppKit or Tauri-shell behavior.
- Check the oldest supported OS and CPU architectures relevant to the change.
- Test sandboxed and packaged behavior when the change depends on either.
- Distinguish a debug launch from a signed, notarized distribution artifact.
- Inspect signing and entitlements without exposing credentials or altering identities.
- Keep certificate, provisioning, notarization, upload, and release actions explicit.
- Report the exact build/test evidence, failing checks, and manual steps still needed.
- Without macOS/Xcode or native access, mark native checks unverified, never passing.

## Primary references

- SwiftUI windows: https://developer.apple.com/documentation/swiftui/windows
- AppKit windows: https://developer.apple.com/documentation/appkit/app-windows
- Menus: https://developer.apple.com/documentation/appkit/menus
- Documents: https://developer.apple.com/documentation/swiftui/documentgroup
- Menu-bar scenes: https://developer.apple.com/documentation/swiftui/menubarextra
- App Sandbox: https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox
- File access: https://developer.apple.com/documentation/security/accessing-files-from-the-macos-app-sandbox
- Protected resources: https://developer.apple.com/documentation/bundleresources/protected-resources
- Accessibility: https://developer.apple.com/documentation/appkit/accessibility-for-appkit
