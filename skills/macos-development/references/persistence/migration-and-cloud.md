# Schema, migration, and cloud

## Inventory before changing schema

Record current model versions, current-version marker, entity/attribute/relationship names, optionality/cardinality/ordering, constraints, renaming identifiers, store URLs/configurations, and whether stores mirror CloudKit. Keep every shipped model version in the bundle. Identify supported starting stores, target result, invariants, backup/recovery plan, and downgrade limitations; a newer binary may migrate a store that an older binary cannot open or downgrade.

Preserve existing storage. Never delete/reset a user store to make a migration pass. Use copies of representative fixtures in temporary paths, including empty, populated, large, relationship-heavy, and previously interrupted cases.

## Core Data migration choice

First ask whether a change is lightweight-compatible, then prove it with `NSMappingModel.inferredMappingModel` or an actual fixture migration. Typical lightweight changes include adding/removing entities, attributes, or relationships; optionality changes where values/defaults are valid; compatible cardinality/ordering changes; and renames with the old `renamingIdentifier`. Keep old versions and chain renames correctly. Do not assume optional-to-required, arbitrary transforms, entity merges, or data-dependent normalization are inferred.

For lightweight stores, configure automatic/inferred migration before loading:

```swift
let description = NSPersistentStoreDescription(url: storeURL)
description.shouldMigrateStoreAutomatically = true
description.shouldInferMappingModelAutomatically = true
container.persistentStoreDescriptions = [description]
```

For complex changes, use a distinct staged migration for each model version on OS releases that provide `NSStagedMigrationManager`, with lightweight and custom stages as needed. Make custom stages restartable and idempotent; stage data preparation before making a property required. Manual mapping models remain appropriate when staged migration is unavailable or insufficient. Deferred lightweight migration can postpone expensive cleanup, but it adds pending-work handling and recovery states; do not add it without measured benefit and tests for `finishDeferredLightweightMigration()`.

Composite attributes (Core Data iOS 17+/macOS 14+) can model structured fields without a transformable, but they still belong in the model-version inventory and migration fixtures. A staged plan should name every model reference/checksum in order; do not collapse multiple model transitions into one opaque custom step. Deferred migration is useful only when the store can serve current-schema reads while cleanup waits for a controlled background opportunity.

After migration, verify every invariant, relationship, derived/transformable value, index/constraint, and next-launch reopen. If migration fails, preserve original fixture, capture error/model/store metadata, and use a recoverable backup or user-facing recovery path. Do not claim rollback by merely installing an older app.

## SwiftData schema evolution

Use explicit `VersionedSchema`/`SchemaMigrationPlan` when a SwiftData store has supported releases. Enumerate source and destination schemas, stage additive/lightweight changes, and write custom migration stages only for transformations that cannot be inferred. Keep migration code deterministic and test each supported starting schema in a copied store. Never swap in a new container/store URL to avoid a migration unless product explicitly accepts data loss or a fresh store.

For each SwiftData plan, test model rename/relationship/delete-rule changes, uniqueness/index changes, optionality/default changes, and custom transforms separately. Open the migrated store again with the shipping container and verify that persistent IDs, relationships, and query predicates still behave after relaunch.

## Core Data CloudKit

Use `NSPersistentCloudKitContainer` only when entitlements, model configuration, account behavior, and sync are in scope. Configure each store description’s `cloudKitContainerOptions` before loading; local-only and CloudKit-backed stores can coexist with explicit configurations. CloudKit imposes schema restrictions, including no uniqueness constraints for mirrored entities, optional relationships with inverses, and no deny delete rule. Production schema changes are constrained by deployed CloudKit schema; test in Development, deploy intentionally, and plan additive/cross-version compatibility before release.

Observe `NSPersistentCloudKitContainer.eventChangedNotification` for setup/import/export failures, but do not treat an event as proof all records are synchronized. Test signed-out/offline/delayed import/conflict/retry states on real qualified accounts. Never enable CloudKit or upload local fixtures as a local validation shortcut.

## SwiftData CloudKit

Apply CloudKit restrictions only to CloudKit-backed configurations. SwiftData CloudKit models need defaults or optional properties, optional relationships, valid inverse modeling, and no local uniqueness constraints (`@Attribute(.unique)`/`#Unique`). Design UI and writes for eventual consistency and delayed remote data. Indexes, inheritance, and newer schema features require both their OS availability and CloudKit schema support; verify against current Apple documentation before adoption.

## Recovery checklist

1. Stop writes to affected store while diagnosing.
2. Preserve store plus sidecars and exact model versions.
3. Reproduce against a copy with migration logging and representative fixtures.
4. Determine whether failure is model discovery, mapping, validation, disk, history-token, or cloud schema/sync.
5. Repair migration/model/configuration in a new build, reopen migrated copy, then qualify upgrade and relaunch paths.

## Upgrade fixture sequence

1. Create a copy of a store with its old model and representative rows.
2. Close/remove the old coordinator/container cleanly, preserving SQLite sidecars.
3. Open the copy with the new model and intended migration options/plan.
4. Assert values, relationship cardinality, delete rules, constraints, indexes, derived/transformable fields, history state, and next-launch reopen.
5. Keep failed copy, logs, and exact model versions for diagnosis; never mutate source fixture in place.
