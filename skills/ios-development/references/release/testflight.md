# TestFlight, processing & release diagnostics

Examples below use raw external `asc` CLI path. Read [asc tool setup](../tool-setup.md#asc).
Before any `asc` call, export telemetry opt-outs, run known-version check, then
inspect `asc --help` plus each leaf command's `--help`:

```sh
export ASC_TELEMETRY_DISABLED=1 DO_NOT_TRACK=1
asc version
```

Legion-native surfaces may differ & must not be claimed to support these
options without observed help output.

## Upload and process

Resolve app, version, build & group IDs deterministically. Upload IPA/PKG through selected adapter, then poll build processing with bounded interval/timeout. Check structured state, error messages, version/build match, platform, symbols and export compliance before attaching to groups. A successful transport or upload ID is not a processed build.

Use `asc publish testflight` for an end-to-end authorized lane or `asc builds upload` when later steps are separately controlled. Existing groups/testers are state; do not create duplicates. Attach a build only after processing is complete and validation allows it. Keep internal/external tester assignment & review as distinct effects.

Export current TestFlight state before changes, including builds/testers only
when requested:

```bash
asc testflight config export --app "APP_ID" --output "./testflight.yaml"
asc testflight config export --app "APP_ID" --output "./testflight.yaml" --include-builds --include-testers
```

Upload-only requires new IPA or local Xcode build. It cannot combine with an
existing `--build-id`, groups, tester notifications, TestFlight notes or
beta-review submission. `--build-number` may annotate upload metadata but
cannot be only build input. Read processing state after upload before any
distribution effect.

## What to Test notes

Create/update notes per locale, then read back exact localized value:

```bash
asc builds test-notes create --build-id "BUILD_ID" --locale "en-US" --whats-new "Test instructions"
asc builds test-notes update --build-id "BUILD_ID" --locale "en-US" --whats-new "Updated instructions"
asc builds test-notes list --build-id "BUILD_ID"
asc builds test-notes view --build-id "BUILD_ID" --locale "en-US"
```

Use leaf help when CLI version differs; a successful write response alone is
not readback evidence.

## Terminal checks

For every wait, classify `processing`, `valid`, `invalid`, `failed`, timeout and unknown states. On timeout, read current state before retry; never assume upload failed or repeat a possibly completed remote write. For resumable workflows, reuse run ID only after durable evidence revalidation. Report exact current state and next independent action.

## Crash, feedback & diagnostics

Use App Store Connect crash/feedback/performance diagnostic reads for a named build. Paginate when collecting all records; filter by build/device/OS/type. Summarize counts, top signatures, affected builds, device/OS breakdown & timeline while keeping raw reports/private URLs out of public output. Data can lag 24–48 hours. Deeper performance profiling routes to [profiling](../profiling.md).

Resolve one exact build before diagnostics, then keep filters bounded:

```bash
asc builds info --app "APP_ID" --latest --platform IOS
asc testflight crashes list --app "APP_ID" --build-id "BUILD_ID" --sort -createdDate --limit 10
asc testflight feedback list --app "APP_ID" --build-id "BUILD_ID" --sort -createdDate --limit 10
asc performance diagnostics list --build-id "BUILD_ID" --diagnostic-type "HANGS"
asc performance diagnostics list --build-id "BUILD_ID" --diagnostic-type "DISK_WRITES"
asc performance diagnostics list --build-id "BUILD_ID" --diagnostic-type "LAUNCHES"
```

Use `--device-model`, `--os-version`, & `--paginate` only when requested or
needed for complete bounded collection. Map diagnostic type to hangs, disk
writes, & launches; never combine records from different builds without
stating each build ID.

Optional local Instruments review may apply Call Tree filters — Hide System
Libraries, Invert Call Tree, Separate by Thread, focus hot frames/call counts —
when an actual profiling trace is available. Keep capture, symbolication & analysis
with the [profiling procedure](../profiling.md); record observed trace evidence.

Never treat a crash summary as proof of release acceptance. Resolve fix/retry decisions through submission-health owner when a review submission is blocked or stuck.
