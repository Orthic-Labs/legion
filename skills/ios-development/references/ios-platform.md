# iOS platform decisions

Use this reference for iPhone and iPad implementation, review, and validation.
It is guidance, not an installed SDK, simulator, tool, or grant of permission.

## Establish the existing contract

- Identify the app target, schemes, supported devices, deployment target, and SDK.
- Read the repository's build instructions, CI, dependencies, and test conventions.
- Preserve SwiftUI, UIKit, hybrid, or web-backed ownership already used by the app.
- Keep persistence, networking, dependency injection, and navigation conventions.
- Do not introduce SwiftData, a new router, or a framework migration incidentally.
- Separate the requested behavior change from optional modernization proposals.
- For Rust/Tauri consumers, read the interoperability reference before changing layers.

## State and UI ownership

- Give each mutable value one authoritative owner with a clear lifetime.
- Keep transient presentation state local; pass bindings when children edit it.
- Use the project's Observation or ObservableObject pattern consistently.
- Check availability before adopting Observation; do not raise the target silently.
- Own reference models at an appropriate app, scene, or view boundary.
- Do not recreate long-lived services during view-body evaluation.
- Keep UI mutations on the required main actor or main thread.
- Tie asynchronous work to the intended lifetime; cancel or ignore obsolete results.
- Model loading, empty, success, error, and cancellation states explicitly.
- With UIKit bridges, define coordinator, delegate, and controller ownership.
- Avoid duplicate subscriptions, retained delegate cycles, and update feedback loops.
- Preserve containment and appearance forwarding when embedding view controllers.

## Navigation and presentation

- Extend the existing router; avoid a second source of navigation truth.
- Use NavigationStack or NavigationSplitView only where the target supports them.
- Keep route identity stable across refreshes and restoration.
- Validate incoming URLs and restored identifiers before opening their destinations.
- Handle back navigation, interactive dismissal, repeated links, and cold launch.
- Distinguish push navigation from sheets and genuinely blocking presentations.
- Test compact and regular widths, keyboard appearance, and resizing on iPad.
- Keep navigation and selection isolated per scene where multiple scenes are supported.
- Do not make phone-only assumptions about available width or window count.

## Lifecycle and restoration

- Respect the existing SwiftUI App or UIKit scene/app-delegate lifecycle.
- Handle foreground, inactive, background, and reconnect paths without duplicate work.
- Persist important edits incrementally; termination is not a reliable save hook.
- Keep durable application data in the established persistence layer.
- Use scene restoration for UI continuity, not as a database or secret store.
- Store minimal stable IDs and selections; tolerate deleted or inaccessible records.
- Scope SceneStorage keys deliberately; its persistence timing is system-controlled.
- Restore only after required model data is available; handle failed restoration safely.
- Test restoration separately from fresh launch and deliberate force-quit behavior.
- Use background execution only for an actual supported requirement and budget.

## Permissions and accessible interaction

- Identify the exact protected resource and required usage-description key.
- Explain the feature-specific purpose and request access at the relevant action.
- Handle denied, restricted, limited, unavailable, and revoked access where applicable.
- Keep useful functionality available when an optional permission is refused.
- Treat entitlements, privacy declarations, and runtime consent as separate checks.
- Prefer semantic system controls; give custom controls names, roles, and values.
- Verify VoiceOver order, focus after navigation, and meaningful status announcements.
- Check Dynamic Type, sufficient contrast, Reduce Motion, and non-color cues.
- Test long/localized text, right-to-left layout where supported, and touch targets.
- Provide keyboard access for relevant iPad workflows without disrupting text entry.

## Validation and completion evidence

- Discover available Xcode, SDKs, schemes, destinations, and project scripts first.
- Run the repository's relevant unit, integration, and UI tests without replacing them.
- Build the affected app target; a package-only build does not validate app wiring.
- Exercise the changed flow in the actual iOS app on a named simulator/runtime.
- Cover the minimum supported OS when available and the intended current SDK path.
- Use physical devices for hardware-dependent behavior and meaningful performance checks.
- Test interruption, offline/retry, permission denial, and relaunch when relevant.
- Browser previews and static screenshots are not evidence of native lifecycle behavior.
- Report commands, destinations, outcomes, and remaining gaps separately.
- If Xcode, a simulator, signing, or a device is unavailable, mark that check unverified.
- Never report unavailable native testing as passing or imply a device run occurred.
- Do not install tools, alter signing, reset permissions, or release builds implicitly.

## Primary references

- Model ownership: https://developer.apple.com/documentation/swiftui/managing-model-data-in-your-app
- Navigation: https://developer.apple.com/documentation/swiftui/navigation
- UIKit lifecycle: https://developer.apple.com/documentation/uikit/app-and-environment
- Restoration: https://developer.apple.com/documentation/swiftui/restoring-your-app-s-state-with-swiftui
- Protected resources: https://developer.apple.com/documentation/bundleresources/protected-resources
- Native validation: https://developer.apple.com/documentation/xcode/running-your-app-on-simulated-or-physical-devices
