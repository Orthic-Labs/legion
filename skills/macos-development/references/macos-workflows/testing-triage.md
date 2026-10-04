# macOS test triage

Find existing schemes, test plans, XCTest/Swift Testing targets, fixtures, and CI commands.
Use `xcodebuild test` for Xcode projects and `swift test` for SwiftPM packages, selecting
the named target/filter and smallest meaningful scope first. Keep raw exit status and
result bundles when available; format output only after preserving the original evidence.

Classify failures as compile/module, assertion/contract, crash/signal, async timing/flake,
fixture/environment, missing SDK/toolchain, host-app/entitlement, or distribution state.
Focused reruns should answer a hypothesis; repeated full-suite runs without new evidence
add little. A compiled test target is not an executed pass.

For native UI, record app mode, active window/focus, menu/keyboard route, OS, target,
architecture, sandbox/permission state, and whether proof came from a Mac runtime. Browser
or simulator evidence does not establish AppKit/window behavior, keychain, permission,
performance, background, or distribution behavior. Prefer semantic accessibility IDs and
meaningful interruption/re-entry paths over coordinates. Isolate test files, accounts,
keychains, and cloud containers from production data.

For async tests, await real signals rather than fixed sleeps; test cancellation and
re-entry where relevant. For a crash, capture exact diagnostic, revision/configuration,
reproduction, and redacted logs, then choose the smallest separating check. Missing native
runner/device/permission is explicitly unrun, never a clean result.
