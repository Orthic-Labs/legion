# Memgraph & leak evidence

Drive exact release flow on same simulator and app build where possible. Resolve UDID
and bundle ID, locate exactly one running process through simulator launch services,
then capture `.memgraph`, raw `leaks` output, and metadata into a run-specific folder.
Never infer PID from an unrelated app or use broad simulator cleanup.

If process is not found, first confirm expected bundle ID, then inspect running labels
with `xcrun simctl spawn <sim> launchctl list`; match app bundle ID to its running label
before retrying capture. Missing label is prerequisite failure, not permission to select
another process.

Summarize an existing graph with grouped counts/types/images, then inspect each
app-owned candidate. Use `leaks --traceTree=<address>` for a retaining path and
`leaks --groupByType` when trace reports no roots, which can indicate unreachable or
self-retaining cycle. Identify first app-owned type, intended lifetime (process,
session, account, view, request, task), and retaining edge. Lazy allocation is scope
reduction only when eager allocation violated intended lifetime; it is not proof of a
fix. Prefer deleting retaining edge over broad cleanup.

After a patch, recapture same flow on same simulator where practical. Report before /
after count, disappeared root type or path, remaining leaks, graph/summary paths,
build/test context, and framework-only noise separately. Smaller total graph alone is
not proof of leak repair.
