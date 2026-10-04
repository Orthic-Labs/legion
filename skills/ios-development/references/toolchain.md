# Toolchain and task-selected adapters

Native route first: use `legion apple catalog --input '{}'` to discover operations,
`legion apple preflight --input '{"list":true}'` for read-only PATH inventory, or MCP
`legion_apple` with `operation`, `arguments` and optional `policyContext`. Plans do not
execute until `execute: true` is requested within existing authorization. Native routes
cover `project.*`, `swiftpm.*`, `simulator.*`, `device.*`, `debug.batch`, `profile.record`,
`build-analysis`, `flamegraph`, `memgraph`, `build-log` & `app-store`. Compatibility
adapters below remain optional fallbacks.

Profile recording accepts `template` & `output`, with optional `bundle_id` or
`device_id`; project build/test accepts project or workspace, scheme & optional
destination. Keep these JSON arguments intact across CLI & MCP.

Read [tool setup](tool-setup.md) before execution. It contains official acquisition recipes,
reusable client configuration and verification. Optional means task-selected, not undiscoverable.

## Preflight the selected project

Read the repository's commands/configuration and discover the installed OS, selected
developer directory, Xcode/SDK, Swift compiler, language mode/default isolation, project
or workspace, shared scheme/test plan, deployment minimum, destination, and architectures.
Keep those choices in the result. Do not upgrade targets or replace project scripts with
a generic command copied from a donor skill.

For an Xcode build, resolve the intended workspace/project and scheme before building.
For a Swift package, inspect Package.swift and the package's supported platforms. A pure
Swift package may have cross-platform checks; an Apple app still needs its Apple SDK and
runtime for platform claims. Preserve the project's Cargo/Tauri build path when present.

## Capability/version matrix

| Route or tool | Use when | Check first | When unavailable |
|---|---|---|---|
| Xcode command-line tools | Native build/test/archive is required | Developer directory, xcodebuild version, SDKs, schemes, destination, build settings | Continue source review; mark Apple build/test unrun |
| SwiftPM | Existing Swift package needs build/test | Installed Swift version, manifest/tools version, target platform, project command | Mark package checks unrun; do not substitute app validation |
| Legion Apple CLI/MCP | Native typed Apple operation is available | Legion binary or MCP registration, catalog/schema, host authorization | Use selected project CLI or existing adapter; report missing native host capability |
| XcodeBuildMCP / MobileBuildMCP | An existing configured server exposes the needed Apple operation | Actual server version, tool listing and schemas, repository pin, session/default target | Use Legion Apple or approved project CLI if available; otherwise report blocked operation |
| AXe | The available version supports the required simulator UI action | Executable/version/help, simulator identity, accessibility output, permission state | Use existing XCTest/UI tooling or report unrun UI evidence |
| DocSetQuery | Local Apple documentation is available through it | Version, selected Xcode/docsets, SDK availability | Use official Apple/Swift documentation; distinguish online docs from installed SDK |
| xcbeautify | Existing build logs need formatting | Version, pipeline failure semantics, raw output retention | Keep raw output; formatter absence never blocks a build |
| Inject / Sourcery | Existing project hot reload or generation is relevant | Project pin, supported compiler/targets, debug-only or deterministic-generation boundaries | Use normal build/manual implementation; do not add a dependency automatically |
| RocketSim | An approved installed app materially helps simulator inspection | App/version, allowed feature, target simulator | Use simulator/XCTest; no paid feature is required |
| AppStoreConnectCLI | Authorized account/release operation needs the existing CLI | Version/help, authentication mechanism, exact app/team/action | Return local release preparation and the missing capability |
| CodexMonitor / agent-scripts | The user's existing development workflow explicitly uses them | Repository setup and exact approved operation | Keep the current agent/terminal workflow; no new orchestration dependency |

This matrix selects capabilities; [tool setup](tool-setup.md) supplies native-first setup
& optional adapter paths.
Only selected workflows/adapters bind host capabilities in [route resources](route-resources.json).
Never infer that a tool is installed or connected; detect and reuse before proposing setup.

## Version-safe MCP use

Historical XcodeBuildMCP examples can refer to removed/renamed tools. Inspect the server's
current capability listing and input schema; bind the intended operation to the tool that
actually exists. If the project pins a version, use that compatible interface. Record the
version and mapping when needed for reproducibility; do not silently update or install a
different server to make an old example work. MobileBuildMCP is the current upstream name;
the inspected source pin is recorded in the source manifest, not a universal version pin.
Inspect telemetry, macro-validation, and stateful per-workspace daemon behavior before
invocation; don't enable unapproved telemetry, daemons, or validation bypasses. A skill
does not authorize telemetry or persistent access.

## Build/run loop

1. Establish the intended target and smallest observable acceptance condition.
2. Use the repository's build/test wrapper or discovered compatible adapter; keep exit
   status, raw logs and result-bundle paths. Formatting must not convert failure to success.
3. Start only the app/simulator and processes needed for the task. Track what this run owns;
   do not kill unrelated apps, reset devices, erase simulators, or delete caches broadly.
4. Reproduce the changed behavior and relevant failure/interruption cases, then clean up
   only run-owned temporary processes/artifacts as permitted by the task.
5. Distinguish source checks, compilation, tests, launch, UI behavior, and distribution.

Do not bypass macro/plugin validation or trust prompts with convenience flags. Respect
code execution, permission, account, and publishing boundaries at the relevant action.

Primary documentation: https://developer.apple.com/documentation/xcode
and https://www.swift.org/documentation/package-manager/
Pinned third-party discovery and licensing: [source manifest](../config/source-manifest.json)
