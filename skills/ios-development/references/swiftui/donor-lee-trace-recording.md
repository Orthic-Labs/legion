# Recording an Instruments Trace

Use this reference when the user asks to record a new trace — either to
attach to a running app, launch one fresh, or capture a specific session
of actions they'll perform interactively.

Native Legion `profile` operation plans `xcrun xctrace record` with:

- The **SwiftUI** template by default (override with `--template`).
- **Manual stop** via Ctrl+C, a stop-file, or `--time-limit`.
- JSON discovery for devices and templates.
- Typed argv, host policy gating, bounded output, and explicit execution.
- An explicit acknowledgement gate for system-wide recordings.

## Privacy and consent

Prefer `--attach` or `--launch`, which limits collection to the app being
diagnosed. A system-wide recording can capture activity and metadata from
unrelated applications. Before using `--all-processes`, explain that scope to
the user and obtain their explicit approval. Then pass
`--allow-system-wide-recording` to record that acknowledgement in the command.

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

### C) Agent-driven: start in background, stop via stop-file

For bounded native execution, pass explicit template/output/device/bundle fields
to `profile`; stop/timeout behavior remains owned by host process transport:

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
# List devices through mobile catalog/operation before choosing device_id.
legion apple device.list --input '{}'

# Choose a template supported by host Xcode; profile plan keeps template typed.
legion apple profile --input '{"template":"Time Profiler","output":"artifacts/profile.trace","bundle_id":"com.example.App"}'
```

Device entries have `kind` (`devices`, `devices offline`, `simulators`),
`name`, `os`, `udid`. Offline devices are known but unplugged / unpaired —
plug them in before recording.

## Picking a template

> **Hard rule: the `SwiftUI` template only populates the SwiftUI lane on a
> real device — a physical iOS/iPadOS device or the host Mac. On the iOS
> Simulator it records but the SwiftUI lane comes back empty.** If the
> chosen UDID falls under the `simulators` kind from `--list-devices`,
> switch to `Time Profiler`. It still gives you Time Profiler + Hangs +
> Animation Hitches, which native `swiftui-trace` analysis can correlate
> normally; only the `swiftui` lane will report `available: false`.

Decision flow:

| Target                                       | Template to pass     |
|----------------------------------------------|----------------------|
| Physical iOS/iPadOS device (connected)       | `SwiftUI` (default)  |
| Host Mac (macOS app, `--all-processes`, etc.)| `SwiftUI` (default)  |
| iOS / iPadOS / watchOS / tvOS Simulator      | `Time Profiler`      |

Confirm target kind with `--list-devices` before starting a recording: entries under
`simulators` use Time Profiler; entries under `devices` (connected devices and host Mac)
support the SwiftUI template. For `devices offline`, report the unavailable target and retry
after it becomes available.

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
