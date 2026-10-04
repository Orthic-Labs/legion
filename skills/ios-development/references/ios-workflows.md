# iOS workflows

Use this router for iOS/iPadOS work that needs simulator lifecycle, preview/browser
feedback, App Intents, memory or performance evidence, or SwiftUI composition. Read
only sections relevant to request; preserve existing project targets, deployment
minimum, architecture, & tool setup.

## Choose a workflow

| Need | Read |
| --- | --- |
| Build, launch, inspect UI, logs | [simulator-debugging.md](ios-workflows/simulator-debugging.md) |
| Browser mirror or package preview hot reload | [preview-browser.md](ios-workflows/preview-browser.md) |
| Shortcuts, Siri, Spotlight, widgets, controls | [app-intents.md](ios-workflows/app-intents.md) |
| ETTrace, dSYMs, flamegraphs | [performance-evidence.md](ios-workflows/performance-evidence.md) |
| Memgraph, leaks, retain cycles | [memory-evidence.md](ios-workflows/memory-evidence.md) |
| App shell, routing, sheets, async state, UI patterns | [swiftui-shell.md](ios-workflows/swiftui-shell.md) |
| SwiftUI rendering, glass, refactoring | [swiftui-quality.md](ios-workflows/swiftui-quality.md) |

Every execution workflow starts by identifying workspace/project/package, scheme,
target, deployment minimum, Swift mode, simulator UDID, & bundle identifier. Use
existing setup and tools; optional CLIs are capability references, not automatic
install or enable instructions. Keep raw logs and exact artifact paths.

## Evidence discipline

Source review can identify hypotheses. Build output proves compilation only; a launched
process plus UI description or screenshot proves the visible state; a system-surface
invocation proves App Intent routing; symbolicated ETTrace proves only captured flow;
memgraph comparison proves a leak claim only when same flow, simulator, & app-owned
type or ownership path are compared. Record OS/runtime, configuration, target, and
what was not exercised.

## Availability & boundaries

Gate APIs by actual deployment target. Liquid Glass, newer tab placement, scroll
geometry, matched transitions, and safe-area bars need availability branches. Keep
older fallback behavior. Do not change entitlements, signing, shared containers,
permissions, dependencies, or simulator state as incidental workflow setup. Do not
edit an app project to support previews when a disposable host is sufficient.

## Shared SwiftUI ownership

Core router and composition principles remain in the shared SwiftUI references. This
router adds iOS execution recipes and points at focused iOS patterns. macOS bundle may
reuse this index for multiplatform source, but validate each native target separately.
