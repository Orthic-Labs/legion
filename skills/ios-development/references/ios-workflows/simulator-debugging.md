# Simulator build, run, & debug

## Select a simulator

Resolve an explicit UDID from available devices and use one booted simulator for a
session. Reuse an already booted device; do not erase or boot a device as an implicit
side effect. If no device is booted, report that prerequisite. Confirm selected model,
iOS runtime, architecture, scheme, configuration, and bundle ID before build.

Set session defaults in whichever supported build adapter is already configured:
project/workspace, scheme, simulator UDID, and Debug configuration. Optional build
adapters may expose list, build/run, launch, UI description, tap, type, gesture,
screenshot, start/stop log capture, app-path, and bundle-ID operations; inspect live
tool schemas before calling them. Do not assume names or install an MCP client.

## Build and launch

Build/run only when requested. A failed build ends the run path: read compiler output,
fix an in-scope cause, or report it before attempting UI actions. After success, prove
launch with UI description or screenshot. If only launch was requested, resolve the
installed app path and bundle ID first, then launch that exact app.

Use a raw build log alongside any formatter output. A formatter is optional and must
not hide exit status or diagnostics. Keep project changes out of simulator helpers.

## Inspect & interact

Describe UI before tapping, typing, or swiping. Prefer accessibility identifier/label;
use coordinates only when no semantic target exists. Focus a text field before typing.
After layout or navigation changes, describe UI again. Capture a screenshot after a
state transition when visual proof matters. For console evidence, enable console
capture before relaunch when required; stop capture and preserve relevant lines.

## Failure decisions

- Wrong app: verify scheme, installed path, bundle ID, and simulator UDID.
- No process: inspect simulator launch services and confirm bundle ID.
- Build failure: keep UI actions paused until build is fixed or explicitly unverified.
- Element not hittable: refresh UI description after state/layout settles.
- Log noise: isolate app-owned lines and retain raw capture for auditability.

Report exact flow, target, runtime, build result, launch proof, interaction evidence,
and any device-only or distribution checks that remain unrun.
