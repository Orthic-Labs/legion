# TestFlight, processing & release diagnostics

## Upload and process

Resolve app, version, build & group IDs deterministically. Upload IPA/PKG through selected adapter, then poll build processing with bounded interval/timeout. Check structured state, error messages, version/build match, platform, symbols and export compliance before attaching to groups. A successful transport or upload ID is not a processed build.

Use `asc publish testflight` for an end-to-end authorized lane or `asc builds upload` when later steps are separately controlled. Existing groups/testers are state; do not create duplicates. Attach a build only after processing is complete and validation allows it. Keep internal/external tester assignment & review as distinct effects.

## Terminal checks

For every wait, classify `processing`, `valid`, `invalid`, `failed`, timeout and unknown states. On timeout, read current state before retry; never assume upload failed or repeat a possibly completed remote write. For resumable workflows, reuse run ID only after durable evidence revalidation. Report exact current state and next independent action.

## Crash, feedback & diagnostics

Use App Store Connect crash/feedback/performance diagnostic reads for a named build. Paginate when collecting all records; filter by build/device/OS/type. Summarize counts, top signatures, affected builds, device/OS breakdown & timeline while keeping raw reports/private URLs out of public output. Data can lag 24–48 hours. Deeper performance profiling routes to [profiling](../profiling.md).

Never treat a crash summary as proof of release acceptance. Resolve fix/retry decisions through submission-health owner when a review submission is blocked or stuck.
