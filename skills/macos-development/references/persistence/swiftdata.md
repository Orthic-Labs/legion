# SwiftData

Use SwiftData only when project already uses it or requirement selects it. Determine deployment target before using APIs: SwiftData is iOS 17+/macOS 14+, `#Index` and `#Unique` are iOS 18+/macOS 15+, and model inheritance is iOS 26+/macOS 26+. Keep availability checks with feature use; do not raise a project’s minimum OS for convenience.

## Audit model/container first

Find every `@Model`, `Schema`, `ModelConfiguration`, `ModelContainer`, store URL, migration plan, and `.modelContainer`/`.modelContext` injection. Confirm one owner for each container and which configuration each model uses. A model context attached to SwiftUI is main-actor bound; an unconfigured environment context is in-memory/schema-less and cannot persist the app’s models.

```swift
@main
struct CatalogApp: App {
    private let container: ModelContainer?
    private let startupError: Error?

    init() {
        do {
            let schema = Schema([Book.self, Author.self])
            let configuration = ModelConfiguration(
                "Catalog",
                schema: schema,
                isStoredInMemoryOnly: false
            )
            container = try ModelContainer(for: schema, configurations: configuration)
            startupError = nil
        } catch {
            container = nil
            startupError = error
        }
    }

    var body: some Scene {
        WindowGroup {
            if let container {
                BookList()
                    .modelContainer(container)
            } else {
                ContentUnavailableView(
                    "Catalog unavailable",
                    systemImage: "externaldrive.badge.xmark",
                    description: Text(startupError?.localizedDescription ?? "The persistent store could not be opened.")
                )
            }
        }
    }
}
```

`App` initialization is nonthrowing, so this example renders an explicit startup error when the configured store cannot open. It does not delete the store or silently fall back to memory; a production app can route this state to recovery/support UI after preserving the original error.

Preserve existing configuration, URL, schema versions, and shipped data. Do not silently replace a store with an in-memory configuration, move its URL, delete it, or change local storage to CloudKit.

## Models, relationships, and saves

Give persisted properties stable defaults or intentional optionality, and give relationships an explicit inverse and delete rule when the ownership is known. `.nullify` is the default; it can leave orphans or violate a nonoptional relationship. Use `.cascade`, `.deny`, or `.noAction` only when domain semantics require it. Build a related object graph then insert its root; the context can register related new models.

```swift
@Model
final class Author {
    var name: String
    @Relationship(deleteRule: .cascade, inverse: \Book.author)
    var books: [Book] = []

    init(name: String) { self.name = name }
}

@Model
final class Book {
    var title: String
    var publishedAt: Date?
    var author: Author?

    init(title: String, author: Author? = nil) {
        self.title = title
        self.author = author
    }
}

@MainActor
func addBook(_ book: Book, to context: ModelContext) throws {
    context.insert(book)
    try context.save() // use explicit save where correctness matters
}
```

Autosave timing is context configuration and lifecycle behavior, not a transaction boundary. Explicitly save after a meaningful unit, handle errors, and use `rollback()` when discarding pending changes. A newly inserted model’s persistent identifier is temporary until its first successful save; do not publish that ID as a durable key earlier.

`@Transient` values are not stored and must have a default; they reset after fetch. Prefer computed properties for cheap derivations. `@Attribute(.externalStorage)` is a storage hint for `Data`, not a guarantee. Persisted enums must be `Codable`. Avoid a stored property named `description`, and do not rely on property observers in `@Model` classes; use explicit mutation or context notifications.

For each bidirectional relationship pair, put `@Relationship(inverse:)` on one side to avoid circular macro expansion, leaving the other side as the corresponding stored relationship property. This is a per-pair pattern, not a blanket prohibition on models that contain multiple `@Relationship` declarations.

## Queries and predicates

Keep `@Query` in a SwiftUI view. Services use an explicit `ModelContext` and `FetchDescriptor`; put filtering, sorting, limits, offsets/batching, and counts at that boundary.

```swift
struct RecentBooks: View {
    @Query(
        filter: #Predicate<Book> { book in
            book.title.localizedStandardContains("swift")
        },
        sort: [SortDescriptor(\Book.publishedAt, order: .reverse)]
    ) private var books: [Book]

    var body: some View { List(books) { Text($0.title) } }
}

func recentBooks(in context: ModelContext) throws -> [Book] {
    var descriptor = FetchDescriptor<Book>(
        predicate: #Predicate { $0.publishedAt != nil },
        sortBy: [SortDescriptor(\Book.publishedAt, order: .reverse)]
    )
    descriptor.fetchLimit = 50
    return try context.fetch(descriptor)
}
```

`localizedStandardContains` is the supported string-search shape. `hasPrefix`/`hasSuffix`, `lowercased`, `map`, `reduce`, `count(where:)`, `Collection.first`, custom operators, regular expressions, computed/`@Transient` values, and custom `Codable` struct fields can fail to compile or crash at runtime depending on SDK/store path. Keep predicate expressions over stored model properties and verify each predicate with a real store. For counts use `fetchCount`; for IDs use `fetchIdentifiers`; neither live-updates like `@Query`.

One toolchain-qualified runtime trap is `$0.cast.isEmpty == false` in a predicate. Use `!$0.cast.isEmpty`; the former has been observed to trap on affected SDK/store paths, so do not generalize that regression to every current SDK.

## Concurrency and identity

`ModelContext` and model instances belong to their actor/context. Do not move them between actors or contexts. Pass `PersistentIdentifier` or immutable value snapshots, then fetch again in destination context. A container and persistent identifiers are the stable handles; a context is not a general-purpose Sendable service.

```swift
func renameBook(id: PersistentIdentifier, in container: ModelContainer) async throws {
    let context = ModelContext(container)
    guard let book = context.model(for: id) as? Book else { return }
    book.title = "Updated"
    try context.save()
}
```

Use the project’s actor boundary for background contexts. If a background task returns models, convert them to Sendable value data before crossing back. Avoid “fixing” warnings with unchecked Sendable.

## Uniqueness, indexes, and inheritance

Use `#Unique` only for local stores when uniqueness is a real invariant; one macro can contain multiple key-path groups. Resolve conflicts at save and test duplicate insert/update behavior. `#Index` improves reads at write/storage cost; add it only for measured, frequent predicates/sorts, including compound groups used together.

```swift
@Model
final class Event {
    #Unique<Event>([\.externalID])
    #Index<Event>([\.accountID, \.createdAt])

    var accountID: String
    var externalID: String
    var createdAt: Date
    init(accountID: String, externalID: String, createdAt: Date) {
        self.accountID = accountID; self.externalID = externalID; self.createdAt = createdAt
    }
}
```

For iOS 26/macOS 26 inheritance, annotate parent and child with `@Model`, mark each child `@available`, and list parent plus every child in `Schema`/container creation; SwiftData does not infer the hierarchy there. A relationship typed as the parent can contain parent and child instances. Query a child for only that type, query the parent for all descendants, or filter with `is` and cast the resulting parent values. Prefer a protocol when inheritance adds no persisted-model benefit; deep hierarchies increase migration complexity.

## SwiftData with CloudKit

These constraints apply only when the project is already configured for SwiftData CloudKit. Do not enable the capability as a repair. CloudKit stores do not support local uniqueness constraints (`#Unique`/`.unique`), require model properties to have defaults or be optional, and require optional relationships with valid inverses where the schema calls for them. Treat remote data as eventually consistent: missing records, delayed imports, conflicts, offline operation, and duplicate-looking local work are expected states to handle. Indexes and inheritance still require the OS release that introduced them plus a CloudKit-compatible schema; qualify them against current Apple docs.
