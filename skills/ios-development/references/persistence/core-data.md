# Core Data

Use Core Data when project models/stores already use it, when interoperability is required, or when a requirement needs a Core Data capability. Audit `NSManagedObjectModel` versions, `NSPersistentContainer`/`NSPersistentCloudKitContainer`, store descriptions/configurations, view/background contexts, merge policy, history options, transaction authors, and generated class isolation before changing code.

## Stack and store loading

Keep stack ownership in an injectable type. Configure store descriptions before `loadPersistentStores`; gate reads/writes until its completion succeeds. Store loading is asynchronous. A standard completion handler is sufficient; bridge it to async/await only when project concurrency style benefits. Use an in-memory store only for isolated tests, and a stable SQLite URL for production.

```swift
final class DataController {
    let container: NSPersistentContainer

    init(modelName: String, inMemory: Bool = false) {
        container = NSPersistentContainer(name: modelName)
        if inMemory {
            let description = NSPersistentStoreDescription()
            description.type = NSInMemoryStoreType
            container.persistentStoreDescriptions = [description]
        }
        container.viewContext.name = "ViewContext"
        container.viewContext.automaticallyMergesChangesFromParent = true
        container.viewContext.mergePolicy = NSMergeByPropertyStoreTrumpMergePolicy
        container.loadPersistentStores { _, error in
            // Surface failure to app startup/recovery; never silently continue.
            precondition(error == nil, "Store load failed: \(String(describing: error))")
        }
    }

    func newBackgroundContext(author: String) -> NSManagedObjectContext {
        let context = container.newBackgroundContext()
        context.name = "Background.\(author)"
        context.transactionAuthor = author
        context.mergePolicy = NSMergeByPropertyStoreTrumpMergePolicy
        return context
    }
}
```

Choose merge policy from conflict semantics; no policy is universal. Store-trump is useful with uniqueness constraints, object-trump for intentional user edits, rollback to discard conflicts, and `NSErrorMergePolicy` when callers must resolve conflicts explicitly. Configure `automaticallyMergesChangesFromParent` only when the view context should consume background saves; it does not replace persistent history for batch or cross-process changes.

## Context ownership and transfer

Every `NSManagedObjectContext` is confined to its queue. View contexts serve UI and stay on main actor/queue; private contexts perform imports, exports, and heavy writes. Run all context and managed-object work inside `perform`/`performAndWait`; prefer async `perform` and never block main with heavy `performAndWait`.

```swift
func renameArticle(id: NSManagedObjectID, in container: NSPersistentContainer) async throws {
    let context = container.newBackgroundContext()
    try await context.perform {
        guard let article = try context.existingObject(with: id) as? Article else { return }
        article.name = "Updated"
        try context.save()
    }
}
```

`NSManagedObjectID` is the cross-context handle. Pass it, or a Sendable value snapshot/DAO, then refetch in destination context. Never pass `NSManagedObject`, `NSManagedObjectContext`, or relationship graphs as ordinary Sendable values. Child contexts add complexity: a child save pushes into its parent, then parent must save to reach disk. Use them only when edit isolation/discard semantics justify two saves.

Swift concurrency does not remove Core Data confinement. Use `@MainActor` for view-context APIs, context `perform` for private work, and `NSManagedObjectID` for task handoff. Do not silence warnings with `@unchecked Sendable`. For default-main-actor projects, inspect generated class isolation; manual code generation/nonisolated declarations may be needed, but preserve generated-model conventions and validate on the project’s Swift version.

## Fetching and presentation

Use typed `NSFetchRequest` with a predicate, stable sort descriptors, `fetchLimit`, and `fetchBatchSize` appropriate to the workload. Use `count(for:)` or object-ID result types for counts/existence. Set `propertiesToFetch` only where dictionary/partial fetch semantics are supported by the existing model and caller. Prefetch relationships when profiling shows N+1 faults; avoid prefetching everything.

```swift
let request: NSFetchRequest<Article> = Article.fetchRequest()
request.predicate = NSPredicate(format: "views > %d AND category.name == %@", 100, "Swift")
request.sortDescriptors = [NSSortDescriptor(key: #keyPath(Article.creationDate), ascending: false)]
request.fetchLimit = 50
request.fetchBatchSize = 20
request.relationshipKeyPathsForPrefetching = [#keyPath(Article.category)]
let articles = try context.fetch(request)
```

Use `NSFetchedResultsController` for UIKit table/collection updates, or a diffable data source keyed by `NSManagedObjectID`. Keep UI updates on main context/queue. Aggregates can use `count(for:)` and dictionary result requests with `NSExpression`, but verify supported store/model expressions; do not fetch all objects just to count or sum.

For a list whose cells access related values, prefetch only those relationships. For a count or existence check, use `count(for:)`; for a handoff or batch merge, fetch object IDs:

```swift
let count = try context.count(for: request)
let idsRequest = request.copy() as! NSFetchRequest<NSFetchRequestResult>
idsRequest.resultType = .managedObjectIDResultType
let ids = try context.fetch(idsRequest) as? [NSManagedObjectID] ?? []
```

Use `NSAsynchronousFetchRequest` for a large read whose result is not needed synchronously, and return IDs/value snapshots before leaving its context. Use dictionary-result aggregate requests for grouped sums/counts only after confirming the store supports each expression; a normal object fetch is clearer for small data.

## Saving and batch operations

Save at transaction boundaries: after a user action, at app background/termination hooks where appropriate, and in bounded import chunks. Check persistent changes when a helper is intended to avoid no-op saves, but always handle `save()` errors. `hasChanges` can include transient changes; a project-specific helper may inspect inserted/deleted objects and `hasPersistentChangedValues`. Never use `try?` where losing a save error can lose user data; surface validation, constraint, disk, and migration errors with recovery guidance.

`NSBatchInsertRequest`, `NSBatchDeleteRequest`, and `NSBatchUpdateRequest` availability varies by OS release (check the project’s deployment target; batch insert is available from iOS 13/macOS 10.15). These requests operate below the object graph: they avoid object materialization but bypass normal validation, lifecycle callbacks, and in-memory context state; batch inserts cannot establish relationships. Execute them on a private context, request object IDs/counts when needed, then merge changes or refetch affected contexts. Persistent history and remote-change notifications are required for a durable cross-context/cross-process merge design, but history is not a blanket requirement for every local batch caller.

```swift
try context.performAndWait {
    let request: NSFetchRequest<NSFetchRequestResult> = Article.fetchRequest()
    request.predicate = NSPredicate(format: "creationDate < %@", cutoff as NSDate)
    let delete = NSBatchDeleteRequest(fetchRequest: request)
    delete.resultType = .resultTypeObjectIDs
    let result = try context.execute(delete) as? NSBatchDeleteResult
    let ids = result?.result as? [NSManagedObjectID] ?? []
    let userInfo: [AnyHashable: Any] = [NSDeletedObjectsKey: ids]
    NSManagedObjectContext.mergeChanges(fromRemoteContextSave: userInfo, into: [container.viewContext])
}
```

Use object-graph inserts when relationships, validation, or lifecycle behavior matter. Batch APIs are a measured optimization for large changes, not a fixed “10–20x” promise; qualify with representative data.

Batch insert can use a dictionary array or a row-producing closure. Batch delete/update can request `.resultTypeObjectIDs`, `.resultTypeCount`, or updated IDs. None runs normal validation, `awakeFromInsert`, `willSave`, or relationship maintenance. Fetch and repair relationships in a separate object-graph step, or use ordinary inserts when those semantics are required. A batch request executed against a view context can block UI; keep heavy work private.

When a batch or another process changes the store, merge its object-ID notification into each affected context on that context’s queue, or let a persistent-history consumer do so. Do not assume a successful SQL operation updated already-registered objects.

## Model configuration

Use model constraints for true uniqueness, and select a merge policy that defines duplicate behavior. Derived attributes are read-only and update on save/refresh; do not manually assign them. Transformables require an explicit secure, versionable transformer and should be tested for decode failure. Model validation (`validateForInsert`, `validateForUpdate`, `validateForDelete`, property validators) must return actionable errors. Lifecycle hooks have distinct timing: use `awakeFromInsert` for primitive defaults, `willSave` for pre-save normalization, `didSave` for post-save notifications, `prepareForDeletion` for cancellation only. Do not call `save()` from `willSave`, or perform irreversible file deletion in `prepareForDeletion` because deletion can roll back.

For a transformable attribute, register a named `ValueTransformer` before loading stores, use secure coding, and treat decode errors as data-recovery events. For derived attributes, remember that in-memory relationship changes are not reflected until save/refresh. For a uniqueness constraint, test duplicate inserts under the selected merge policy and assert which object survives; never rely on a default conflict choice.

## Persistent history

Enable `NSPersistentHistoryTrackingKey` on every relevant store before loading it. Add `NSPersistentStoreRemoteChangeNotificationPostOptionKey` when other contexts/processes need notification. Give app targets distinct `transactionAuthor` values. Process history on a private context with a persisted `NSPersistentHistoryToken`: observe remote changes, fetch after token, filter own authors where appropriate, merge transaction object-ID notifications into the view context on its queue, atomically persist the new token, and purge only before the oldest token still needed by all targets. Handle gaps, token decode failure, store replacement, and interrupted processing by refetching from a safe boundary.

History tracks context saves and batch operations; it does not itself resolve conflicts. `automaticallyMergesChangesFromParent` and history merge address visibility, while merge policy and domain logic address conflict choice.

## Minimal history consumer

Persist one token per consumer/target. On remote notification, serialize processing on a private history context, fetch transactions after that token, filter authors that the current target already observes, merge each transaction’s object-ID notification into the view context, save the new token only after merge succeeds, and purge before the oldest token required by any still-running target. If token unarchiving fails or history was purged, discard only that consumer’s token and rebuild its view from the store.
