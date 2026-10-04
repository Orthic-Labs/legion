# Tests and debugging

## Reuse the project's proof surface

Find existing test targets, schemes, plans, fixtures, snapshot conventions, and CI commands.
Retain XCTest and UI tests where used; adopt Swift Testing only when it fits the target and
request. Framework coexistence is preferable to an unrelated wholesale test migration.

## Swift Testing and XCTest

- Test observable contracts, transitions, error handling, and regressions rather than
  private implementation shapes. Use table/parameter-driven cases where they clarify
  boundaries; avoid giant fixtures that obscure the failing input.
- Swift Testing tests can execute in parallel. Isolate mutable state, disk locations,
  clocks, network responses, and singletons; serial execution is a deliberate exception.
- Use expectations/assertions that distinguish required setup from the condition under
  test. Await real events with bounded waits instead of arbitrary sleeps.
- For async code, test cancellation, actor reentrancy, repeated requests, and failure
  propagation where those are relevant. Use controllable dependencies at real boundaries.
- Run focused tests first, then the project's broader applicable checks. Report the actual
  configuration and failures; a compiled test target is not an executed test pass.

### Swift Testing reference router

- [core](testing/core.md): suite structure, test hygiene, dependency injection, tags, and availability.
- [assertions](testing/assertions.md): `#expect`, `#require`, throw checks, known issues, and diagnostics.
- [parameterized](testing/parameterized.md): argument collections, Cartesian products, `zip`, and coverage traps.
- [async](testing/async.md): `confirmation`, continuations, actor isolation, time limits, and network mocks.
- [isolation-performance](testing/isolation-performance.md): parallel safety, serialization, speed, and deterministic fixtures.
- [traits-migration](testing/traits-migration.md): traits, test plans, XCTest coexistence, and incremental migration.
- [new-features](testing/new-features.md): Swift 6.1/6.2 APIs with explicit availability conditions.
- [xcode-workflows](testing/xcode-workflows.md): navigator, test-plan, report, and evidence workflows.

Load only topic references needed for current work. Swift Testing guidance supplements this file;
it does not require replacing existing XCTest or UI tests.

### Review output

For code review, report findings by file with relevant lines, violated rule, and brief before/after
fix; omit files without issues and finish with prioritized impact. When writing tests, apply fixes
directly while preserving project conventions.

## Runtime and UI evidence

- Select the precise app target and destination. Record device/simulator model and OS;
  never silently choose the first connected physical device or unrelated simulator.
- Prefer accessibility identifiers and native UI semantics over brittle coordinates.
  Exercise both the intended action and meaningful interruption/re-entry paths.
- Simulators do not establish every hardware, permission, performance, keychain, push,
  background execution, or distribution behavior. Name the missing device checks.
- For macOS, reproduce app mode, active window/focus, menu/keyboard routing, sandbox and
  permission state. A browser rendering cannot prove native AppKit or Tauri window behavior.
- Use screenshots as supporting evidence. Successful clicks or screenshots alone do not
  prove a data write, accessibility contract, persistence, or correct runtime state.
- Keep test data out of production app-data, accounts, keychains, and cloud containers.
  If a test could touch runtime state, inspect its paths and verify isolation first.

## Diagnose from evidence

Capture the crash/diagnostic, reproduction, target/build configuration, and relevant logs.
Form a falsifiable hypothesis; take the smallest check that separates likely causes.
LLDB, Instruments, sanitizers, and native logs are optional techniques selected for the
failure. Do not enable mutually incompatible diagnostics or change release settings blindly.

Preserve raw build/test exit status and result bundles even when formatting logs. Redact
secrets and unrelated personal data before sharing evidence. A missing test runner, SDK,
simulator, device, or permission is an explicit unrun check, not a clean result.

Primary documentation: https://developer.apple.com/documentation/testing
and https://developer.apple.com/documentation/xctest
