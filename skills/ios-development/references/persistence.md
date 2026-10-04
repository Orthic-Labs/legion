# Persistence routing

Use this reference when a request touches SwiftData, Core Data, model schemas, stores, migrations, or sync. Start by inspecting shipped models, store/container configuration, supported OS versions, threading/isolation boundaries, and existing user data. Preserve the project’s persistence technology and store location; a rewrite, store reset, or CloudKit enablement requires an explicit product requirement.

## Route

- [SwiftData](persistence/swiftdata.md): `@Model`, `ModelContainer`, `ModelContext`, `@Query`, predicates, relationships, indexes, inheritance, and SwiftData CloudKit constraints.
- [Core Data](persistence/core-data.md): stack setup, contexts, fetch/save/batch behavior, context transfer, persistent history, model configuration, and CloudKit mirroring.
- [Schema, migration, and cloud](persistence/migration-and-cloud.md): version inventories, lightweight/staged migration, recovery, SwiftData schemas, and CloudKit gates.
- [Testing and diagnostics](persistence/testing-and-diagnostics.md): temporary stores, migration fixtures, concurrency/history checks, profiling, and failure triage.

## Triage

1. Record iOS deployment target and SDK, framework, store URLs/configurations, model versions, and whether CloudKit/history is enabled.
2. Identify the owning context/actor for every read/write. Transfer IDs or value snapshots across isolation boundaries; never pass mutable persisted objects casually.
3. Keep predicates, sorting, limits, batching, relationship prefetching, and indexes at the data boundary.
4. For schema changes, enumerate every supported starting model and test representative copies in temporary locations before changing production handling.
5. Treat cloud sync as eventual and separately qualified. Do not add entitlements, access personal records, upload fixtures, or reset a user store as a local fix.

## Evidence bar

Claim a persistence change only after reading back resulting model/container behavior and relevant tests or fixtures. A successful local save does not prove migration, multi-context merge, or CloudKit behavior.

Primary references: [SwiftData](https://developer.apple.com/documentation/swiftdata), [Core Data](https://developer.apple.com/documentation/coredata), [Core Data migration](https://developer.apple.com/documentation/coredata/migrating-your-data-model-automatically), and [Core Data persistent history](https://developer.apple.com/documentation/coredata/persistent-history).
