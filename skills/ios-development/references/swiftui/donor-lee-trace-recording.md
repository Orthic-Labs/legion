# Recording an Instruments Trace

Use this reference when the user asks to record a new trace — either to
attach to a running app, launch one fresh, or capture a specific session
of actions they'll perform interactively.

Native Legion `profile` operation plans `xcrun xctrace record` with:

- The **SwiftUI** template by default (override by passing a JSON `template` field in the `profile` operation's input).
- Manual stop via host transport or `--time-limit`.
- JSON discovery for devices and templates.
- Typed argv, host policy gating, bounded output, and explicit execution.
- App/target-scoped capture; system-wide capture is outside current `profile` scope.

## Privacy and consent

Prefer app/target-scoped capture with typed `profile` fields. Native catalog
support must add typed system-wide fields before that capture scope is available.

Values passed through `--env KEY=VALUE` are forwarded to `xctrace`, but the
wrapper redacts each value from its displayed command. Avoid placing secrets on
command lines when a safer launch configuration is available, because other
local process-inspection tools may still expose process arguments.

## Typical flows

### A) Attach to a running app on a connected device

```bash
legion apple profile --input '{"template":"SwiftUI","output":"artifacts/helm-session.trace","device_id":"DEVICE-UDID","bundle_id":"Helm"}'
```

Leave it running while the user exercises the app. Stop with **Ctrl+C**.

### B) Launch an app and record from the first frame

```bash
legion apple profile --input '{"template":"SwiftUI","output":"artifacts/launch.trace","device_id":"DEVICE-UDID","bundle_id":"com.example.App"}'
```

Useful for diagnosing cold-start hitches and view-creation cost.

### C) Agent-driven: bounded timeout

For bounded native execution, pass explicit template/output/device/bundle fields
to `profile`; timeout and cleanup remain owned by host process transport:

```bash
# Start recording (background)
legion apple profile --input '{"template":"SwiftUI","output":"artifacts/session.trace","device_id":"DEVICE-UDID","bundle_id":"com.example.App","timeout_ms":30000}'
```

Native transport uses typed argv and bounded timeout/cleanup; inspect returned
status before reading an output trace.

### D) Time-boxed recording

```bash
legion apple profile --input '{"template":"Time Profiler","output":"artifacts/30s.trace","device_id":"DEVICE-UDID","bundle_id":"com.example.App","timeout_ms":30000}'
```

xctrace stops itself at the limit.

## Discovery helpers

```bash
# List simulators and connected physical devices before choosing a target.
legion apple simulator.list --input '{}' --execute
legion apple device.list --input '{}' --execute

# Choose a template supported by host Xcode; profile plan keeps template typed.
legion apple profile --input '{"template":"Time Profiler","output":"artifacts/profile.trace","bundle_id":"com.example.App"}'
```

`--input` may be omitted; it defaults to `{}`. Without `--execute` each list operation only
returns its plan. With it, the result carries the tool's raw output in `stdout`; read the target's
entry from there as reported by the tool. A target found by `simulator.list` is a simulator; one
found by `device.list` is a physical device. If the tool reports a device as unavailable or
offline, plug it in or unlock it before recording.

## Picking a template

> **Hard rule: the `SwiftUI` template only populates the SwiftUI lane on a
> real device — a physical iOS/iPadOS device or the host Mac. On the iOS
> Simulator it records but the SwiftUI lane comes back empty.** If the
> target is listed by `simulator.list` (a simulator),
> switch to `Time Profiler`. It still gives you Time Profiler + Hangs +
> Animation Hitches, which native `swiftui-trace` analysis can correlate
> normally; only the `swiftui` lane will report `available: false`.

Decision flow:

| Target                                       | Template to pass     |
|----------------------------------------------|----------------------|
| Physical iOS/iPadOS device (connected)       | `SwiftUI` (default)  |
| Host Mac (macOS app, target-scoped)         | `SwiftUI` (default)  |
| iOS / iPadOS / watchOS / tvOS Simulator      | `Time Profiler`      |

Confirm the target kind before starting a recording: a target from `simulator.list` is a
simulator and uses Time Profiler; a target from `device.list` is a physical device and supports
the SwiftUI template. If the target is in neither list, or the tool reports it unavailable,
report the unavailable target and retry after it becomes available.

For ad-hoc hang hunting on any target, `Time Profiler` or
`Animation Hitches` alone may be enough.

System-wide recording is outside current bounded `profile` operation scope;
use app/target-scoped capture until native operation catalog adds explicit
system-wide acknowledgement fields.

## Chaining into analysis

Pass returned trace path into native `profile.export`, then into
`swiftui-trace` pure analysis:

```bash
legion apple profile.export --input '{"trace_path":"artifacts/session.trace","output_path":"artifacts/session.xml"}'
legion apple swiftui-trace --input-file artifacts/analysis-request.json
```

For a specific scope, set `operation` to `list-logs`, `list-signposts`, or
`analyze` with `windowMs` in analysis-request.json.

## Failure modes to handle

- **Device offline** — `device.list` reports unavailable target state.
  Report device unavailable; retry after device is connected and unlocked.
- **Output path exists** — choose a new output path or remove existing artifact
  through an explicitly authorized file operation.
- **App target unavailable** — use a launch-capable bundle path/identifier or
  start target before selecting an attach flow.
- **Signing / trust on device** — iOS requires a development build
  signed with the user's team. If xctrace returns a signing error, point
  the user to trust the developer profile on the device.
