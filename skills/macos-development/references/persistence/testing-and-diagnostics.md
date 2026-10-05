# Persistence testing and diagnostics

## Test matrix

Use an in-memory container for fast unit tests, but include a temporary on-disk SQLite/SwiftData store for reopen, save failure, migration, relationship, and sidecar behavior. Never point tests at production app-data paths. Use one shared `NSManagedObjectModel` in Core Data tests to avoid duplicate entity descriptions. Generate deterministic fixtures with empty, duplicate, relationship, large, malformed, and old-version data.

Cover:

- insert, update, delete rules, inverse relationships, uniqueness/constraint conflicts, validation, rollback, and save errors;
- fetch predicates, sort stability, limits, pagination/batches, counts/IDs, prefetching, and SwiftData predicate runtime failures;
- background context/actor ownership, ID handoff, merge visibility, batch object-ID merges, and history token resume/purge;
- opening each supported old store, migration invariants, interrupted/failing migration recovery, relaunch, and downgrade behavior;
- CloudKit only in separately authorized integration tests with controlled accounts, offline/delayed sync, conflict, setup/import/export events, and production-schema readiness.

```swift
func makeTemporaryCoreDataContainer(model: NSManagedObjectModel) throws -> NSPersistentContainer {
    let container = NSPersistentContainer(name: "Test", managedObjectModel: model)
    let description = NSPersistentStoreDescription(
        url: FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
            .appendingPathExtension("sqlite")
    )
    description.type = NSSQLiteStoreType
    container.persistentStoreDescriptions = [description]
    let lock = DispatchSemaphore(value: 0)
    var loadError: Error?
    container.loadPersistentStores { _, error in loadError = error; lock.signal() }
    lock.wait()
    if let loadError { throw loadError }
    return container
}
```

For SwiftData, construct a unique temporary URL/configuration, insert fixtures through a context, save, release the container, reopen with the same schema, then fetch and assert values/relationships. For Core Data, await or gate `loadPersistentStores`, run context work on its queue, and assert store load/migration errors instead of using `try?`.

## Diagnostics

Use `-com.apple.CoreData.ConcurrencyDebug 1` for reproducible queue violations, `-com.apple.CoreData.SQLDebug 1` to inspect SQL/query count, and migration logging for model/store mismatches. Add `-com.apple.CoreData.MigrationDebug 1` to a debug/test launch only when reproducing migration behavior; remove it after diagnosis and never make it a permanent production setting. Use Instruments Time Profiler and Allocations with realistic data. Measure before adding indexes, prefetches, batch sizes, context resets, or partial property fetches. `context.reset()` invalidates registered objects; use only when callers no longer hold them. `refresh(_:mergeChanges:)`/`refreshAllObjects()` can discard pending values, so make that choice explicit.

For SwiftData predicate failures, isolate each expression against a real temporary store; a successful macro expansion does not prove store execution. Inspect model/container schema, stored-vs-computed property use, availability, and CloudKit mode before changing query syntax.

For Core Data with CloudKit, qualify logs by platform, app process, and container. Use these predicates on the target log source. Plain macOS `log stream` reads Mac logs; it does not stream a connected physical device. Select the device in Console for device capture, use an explicitly targeted simulator log command, or query an exported target log archive:

```bash
# Replace YourApp and iCloud.com.example.container with actual identifiers.
log stream --info --debug --predicate 'process = "YourApp" and (subsystem = "com.apple.coredata" or subsystem = "com.apple.cloudkit")'
log stream --info --debug --predicate 'process = "cloudd" and message contains[cd] "iCloud.com.example.container"'
log stream --info --debug --predicate 'process = "apsd" and message contains[cd] "YourApp"'
log stream --info --debug --predicate 'process = "dasd" and message contains[cd] "com.apple.coredata.cloudkit.activity"'
```

Start only predicates supported by target platform/runtime; daemon visibility and message content differ between macOS, iOS/iPadOS, simulator, and device. Reproduce one bounded sync case, stop capture, then collect a sysdiagnose: on a physical iOS/iPadOS device, follow Apple’s model-specific sysdiagnose button procedure (brief simultaneous Volume Up, Volume Down & Side press where supported), wait for the archive & retrieve it through device diagnostics; on macOS use `Shift-Control-Option-Command-Period`. For an archive, use `log show --info --debug` with a narrow time range and the same predicates against its `system_logs.logarchive`. System logs and sysdiagnose can contain account, device, container, timing, and payload metadata; restrict access, keep process/container filters narrow, and redact before sharing.

## Triage decisions

- Stale Core Data UI: inspect context ownership, automatic merging, persistent history notification, token/filter/author, and batch merge before adding refresh calls.
- Cross-thread crash or Sendable warning: replace managed-object/context transfer with `NSManagedObjectID`/`PersistentIdentifier` or a value snapshot, and run work on owning queue/actor.
- Memory growth: bound fetches, use count/ID requests, prefetch only measured relationships, save in chunks, and reset a disposable background context after releasing objects.
- Duplicate entity description: reuse one model instance and ensure container/model versions match entity module/class names.
- Migration hash/error: retain source model, verify current-version marker and renaming identifiers, infer/test mapping, then use staged/manual migration for data-dependent work.
- Batch changes invisible: request IDs/counts, merge/refetch affected contexts, and enable/process history when changes cross contexts or processes.
- Cloud sync issue: inspect entitlements/container/model restrictions, account/network, event errors, remote notifications, eventual consistency, and deployed schema; do not delete the local store as first response.
