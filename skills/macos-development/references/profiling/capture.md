# Capture a reproducible trace

## Baseline

Write symptom, workload steps, target path, PID, revision/build, configuration, device/OS, dataset, cache state, duration & metric before capture. Launch exactly intended binary; an installed `/Applications` copy can silently replace local build when LaunchServices resolves a bundle. Prefer direct executable path for `--launch`, or attach to a PID whose command/path is verified with `ps`.

## xctrace

Check available templates with `xcrun xctrace list templates`; inspect flags with `xcrun xctrace help record` and `... help export` (`xctrace --help` is not a valid subcommand). Time Profiler examples:

```sh
# launch a known executable
xcrun xctrace record --template 'Time Profiler' --time-limit 90s \
  --output /tmp/App.trace --launch -- /path/App.app/Contents/MacOS/App

# attach to already verified process
xcrun xctrace record --template 'Time Profiler' --time-limit 90s \
  --output /tmp/App.trace --attach PID
```

For iOS, list devices with `xcrun xctrace list devices`, pass `--device UDID` when required, launch/attach through approved device workflow and ensure matching dSYM. Trigger slow path during recording; idle or a short-lived process produces empty evidence. Use longer duration or repeat workload when sample count is too low.

## Permissions & privacy

Developer Tools permission may be required for Terminal/Xcode. Request it through normal system settings; do not disable protections. Traces, memory captures and diagnostics may contain user data, tokens or document names. Store privately, redact before sharing and remove temporary noisy signposts after diagnosis. Do not install telemetry or analytics to measure performance.

## Capture checklist

- process path/PID equals intended build;
- trace output is new and writable;
- target interaction starts during recording;
- build has symbols or matching dSYM;
- device, OS, revision and configuration are recorded;
- no credentials or private rows are copied into report.

Reusable native helper requirement: a future Rust wrapper should accept exactly one of `--attach PID` or `--launch BINARY`, require explicit `--trace`, validate duration and preserve xctrace's exit status. Upstream shell remains source evidence and is not shipped.
