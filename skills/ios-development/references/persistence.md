# Persistence without an accidental migration

## Choose from the existing project

Inspect the current models, store/container, schema versions, threading model, and shipped
data. Preserve SwiftData, Core Data, GRDB, SQLite, files, or another established layer unless
a requested requirement justifies a migration. Do not infer a global user preference.

## SwiftData

- Verify SDK/deployment support for each used feature. Identify container ownership,
  configurations, store URL, model relationships, delete rules, and uniqueness assumptions.
- Keep @Query in SwiftUI views. For background or service-layer fetching, use explicit
  model contexts and the project's actor boundary; do not pass mutable persisted models
  or contexts across actors casually. Transfer stable identifiers or value snapshots.
- Define fetch predicates, sorting, limits, and pagination at the data boundary; avoid
  loading an entire store to filter or sort repeatedly in a view.
- Test insertion, update, relationship deletion, save failure, and reopening a real
  temporary store. In-memory tests can miss persistence and migration failures.

## Core Data

- Respect context queue confinement. Use context perform APIs and transfer object IDs
  or value data across queues; do not share managed objects as ordinary thread-safe values.
- Inspect merge policies, background saves, history/notification handling, and faulting
  before repairing stale UI. A main-context refresh is not a substitute for an ownership fix.
- Measure fetch counts and faults; use bounded fetches, indexes, batching, and relationship
  prefetching only where the actual workload benefits.
- Retain existing model versions and mapping policies. Establish whether an intended
  schema change supports lightweight migration rather than assuming it does.

## Schema and store changes

1. Identify every supported starting schema and the desired result; use representative
   prior-version fixtures without real user data.
2. Test opening/migrating each relevant old store, data invariants, relationships, and
   interrupted/failed migration recovery. Check the platform/cloud-sync constraints.
3. Define backup/recovery and rollback limitations before a destructive transformation.
   Downgrading an app binary does not necessarily downgrade an already migrated store.
4. Isolate all tests to temporary app-data/store paths. Never reset, delete, or seed the
   user's production store to make tests green without explicit authorization.

## Cloud and privacy

CloudKit/iCloud behavior needs account, entitlement, conflict, offline, and synchronization
evidence beyond local persistence tests. Do not enable cloud capabilities, access personal
records, or upload fixtures merely to validate a local change. Record untested coverage.

Primary documentation: https://developer.apple.com/documentation/swiftdata
and https://developer.apple.com/documentation/coredata
