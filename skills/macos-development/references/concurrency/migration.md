# Migration to Swift 6 and Strict Concurrency

Use this when:

- You are moving an existing codebase toward Swift 6 or stricter concurrency checking.
- Compiler diagnostics depend on language mode, default isolation, or upcoming features.
- You need the smallest safe migration sequence instead of a full architectural rewrite.

Skip this file if:

- You already know the exact diagnostic and only need a local fix. Start from `actors.md`, `sendable.md`, or `threading.md`.
- You are looking for debounce, stream composition, or FRP operator replacements. Use `async-algorithms.md`.

Jump to:

- Project Settings
- Six Migration Habits
- Step-by-Step Migration
- Migration Tooling
- Rewriting Closures to Async/Await
- Migrating from Combine/RxSwift
- Concurrency-Safe Notifications (iOS 26+)
- Anti-Patterns

---

## Why Migrate to Swift 6?

Swift 6 doesn't fundamentally change how Swift Concurrency works—it **enforces existing rules more strictly**:

- **Compile-time safety**: Catches data races and threading issues at compile time instead of runtime
- **Warnings become errors**: Many Swift 5 warnings become hard errors in Swift 6 language mode
- **Compatibility**: New concurrency features build on these isolation and transfer rules
- **Better maintainability**: Code becomes safer and easier to reason about

> **Important**: You can adopt strict concurrency checking gradually while still compiling under Swift 5. You don't need to flip the Swift 6 switch immediately.


---

## Project Settings That Change Concurrency Behavior

Before interpreting diagnostics or choosing a fix, confirm the target/module settings. These settings can materially change how code executes and what the compiler enforces.

### Quick matrix

| Setting / feature | Where to check | Why it matters |
|---|---|---|
| Swift language mode (Swift 5.x vs Swift 6) | Xcode build settings (`SWIFT_VERSION`) / SwiftPM `swiftLanguageModes: [.v6]` or target `.swiftLanguageMode(.v6)` | Swift 6 turns many warnings into errors and enables stricter defaults. |
| Strict concurrency checking | Xcode: Strict Concurrency Checking (`SWIFT_STRICT_CONCURRENCY`) / SwiftPM: strict concurrency flags | Controls how aggressively Sendable + isolation rules are enforced. |
| Default actor isolation | Xcode: Default Actor Isolation (`SWIFT_DEFAULT_ACTOR_ISOLATION`) / SwiftPM: `.defaultIsolation(MainActor.self)` | Changes the default isolation of declarations; can reduce migration noise but changes behavior and requirements. |
| `NonisolatedNonsendingByDefault` | Xcode upcoming feature / SwiftPM `.enableUpcomingFeature("NonisolatedNonsendingByDefault")` | Changes how nonisolated async functions execute (can inherit the caller’s actor unless explicitly marked `@concurrent`). |
| Approachable Concurrency | Xcode build setting / SwiftPM enables the underlying upcoming features | Bundles multiple upcoming features; recommended to migrate feature-by-feature first. |

## The Concurrency Rabbit Hole

A common migration experience:

1. Enable strict concurrency checking
2. See 50+ errors and warnings
3. Fix a bunch of them
4. Rebuild and see 80+ new errors appear

**Why this happens**: Fixing isolation in one place often exposes issues elsewhere. This is normal and manageable with the right strategy.


---

## Migration guardrails

### 1. Iterate in small batches

Break migration into small, reviewable chunks and keep each diagnostic change attributable:

```swift
// Enable the strictness level selected for this target, then address one diagnostic category.
// Recheck the target before moving to the next module.
```


### 2. Separate unrelated refactors

**Focus solely on concurrency changes**. Don't combine migration with:
- Architecture refactors
- API modernization
- Code style improvements

Keep unrelated architecture or style changes outside this diagnostic pass so each behavior change remains attributable.

### 3. Keep each change small

- Migrate one class or module at a time
- Recheck diagnostics after each isolated change
- Avoid combining unrelated modules in one migration step

### 4. Choose isolation from ownership

Don't blindly add `@MainActor` to fix warnings. Consider:
- Should this actually run on the main actor?
- Would a custom actor be more appropriate?
- Is `nonisolated` the right choice?

Confirm target ownership before enabling default `@MainActor` isolation; app and framework targets can need different defaults.


---

## Step-by-Step Migration Process

### 1. Find an Isolated Piece of Code

Start with:
- Standalone packages with minimal dependencies
- Individual Swift files within a package
- Code that's not heavily used throughout the project

**Why**: Fewer dependencies = less risk of falling into the concurrency rabbit hole.

### 2. Update Related Dependencies

Before enabling strict concurrency:

```swift
// Confirm required dependency versions support target's active concurrency mode.
// Upgrade only when needed for the migration; do not assume latest is compatible.
```

Apply these updates in a separate PR before proceeding with concurrency changes.

### 3. Add Async Alternatives

Provide async/await wrappers for existing closure-based APIs:

```swift
// Original closure-based API
@available(*, deprecated, renamed: "fetchImage(urlRequest:)", 
           message: "Consider using the async/await alternative.")
func fetchImage(urlRequest: URLRequest, 
                completion: @escaping @Sendable (Result<UIImage, Error>) -> Void) {
    // ... existing implementation
}

// New async wrapper
func fetchImage(urlRequest: URLRequest) async throws -> UIImage {
    return try await withCheckedThrowingContinuation { continuation in
        fetchImage(urlRequest: urlRequest) { result in
            continuation.resume(with: result)
        }
    }
}
```

**Benefits**:
- Colleagues can start using async/await immediately
- You can migrate callers before rewriting implementation
- Tests can be updated to async/await first

**Tip**: Use Xcode's **Refactor → Add Async Wrapper** to generate these automatically.

### 4. Change Default Actor Isolation (when supported)

For a UI-owned app target, consider default isolation `@MainActor` only after measuring
the target and checking module/deployment compatibility:

**Xcode Build Settings**:
```
Swift Concurrency → Default Actor Isolation = MainActor
```

**Swift Package Manager**:
```swift
.target(
    name: "MyTarget",
    swiftSettings: [
        .defaultIsolation(MainActor.self)
    ]
)
```

This drastically reduces warnings in app code where most types need main thread access.

### 5. Enable Strict Concurrency Checking

**Xcode Build Settings**: Search for "Strict Concurrency Checking"

Three levels available:

- **Minimal**: Only checks code that explicitly adopts concurrency (`@Sendable`, `@MainActor`)
- **Targeted**: Checks all code that adopts concurrency, including `Sendable` conformances
- **Complete**: Checks entire codebase (matches Swift 6 behavior)

**Swift Package Manager**:
```swift
.target(
    name: "MyTarget",
    swiftSettings: [
        .enableExperimentalFeature("StrictConcurrency=targeted")
    ]
)
```

**Strategy**: Start with Minimal → Targeted → Complete, fixing errors at each level.

### 6. Add Sendable Conformances

Even if the compiler doesn't complain, add `Sendable` to types that will cross isolation domains:

```swift
// Preferred: Prepare for future use
struct Configuration: Sendable {
    let apiKey: String
    let timeout: TimeInterval
}
```

This prevents warnings when the type is used in concurrent contexts later.

### 7. Enable Approachable Concurrency (Swift 6.2+)

**Xcode Build Settings**: Search for "Approachable Concurrency"

Enables multiple upcoming features at once:
- `DisableOutwardActorInference`
- `GlobalActorIsolatedTypesUsability`
- `InferIsolatedConformances`
- `InferSendableFromCaptures`
- `NonisolatedNonsendingByDefault`

**Warning: Warning**: Don't just flip this switch for existing projects. Use migration tooling (see below) to migrate to each feature individually first.


### 8. Enable Upcoming Features

**Xcode Build Settings**: Search for "Upcoming Feature"

Enable features individually:

**Swift Package Manager**:
```swift
.target(
    name: "MyTarget",
    swiftSettings: [
        .enableUpcomingFeature("ExistentialAny"),
        .enableUpcomingFeature("InferIsolatedConformances")
    ]
)
```

Find feature keys in Swift Evolution proposals (e.g., SE-335 for `ExistentialAny`).

### 9. Change to Swift 6 Language Mode

**Xcode Build Settings**:
```
Swift Language Version = Swift 6
```

**Swift Package Manager**:
```swift
// swift-tools-version: 6.0
// Minimum tools + manifest API; default mode if no explicit mode is set.
import PackageDescription

let package = Package(
    name: "MyPackage",
    targets: [
        .target(name: "MyTarget")
    ],
    swiftLanguageModes: [.v6]
)

```

`// swift-tools-version` selects the minimum tools and PackageDescription manifest API, and supplies a default language mode when no explicit mode is configured. Set `swiftLanguageModes` or target `.swiftLanguageMode(.v6)` when source mode must be explicit.

Target-level alternative (replace the target entry above):

```swift
.target(
    name: "MyTarget",
    swiftSettings: [
        .swiftLanguageMode(.v6)
    ]
)
```

If you've completed all previous steps, you should have minimal new errors.


---

## Migration Tooling for Upcoming Features

Swift 6.2+ includes **semi-automatic migration** for upcoming features.

### Xcode Migration

1. Go to Build Settings → Find the upcoming feature (e.g., "Require Existential any")
2. Set to **Migrate** (temporary setting)
3. Build the project
4. Warnings appear with **Apply** buttons
5. Click Apply for each warning

**Example warning**:
```swift
protocol DataProvider {
    func fetchData() throws -> Data
}

func fetchData(using provider: DataProvider) throws -> Data  // Before
func fetchData(using provider: any DataProvider) throws -> Data  // After applying fix
```

### Package Migration

Use the `swift package migrate` command:

```bash
# Migrate all targets
swift package migrate --to-feature ExistentialAny

# Migrate specific target
swift package migrate --target MyTarget --to-feature ExistentialAny
```

**Output**:
```
> Applied 24 fix-its in 11 files (0.016s)
> Updating manifest
```

The tool automatically:
- Applies all fix-its
- Updates `Package.swift` to enable the feature

**Available migrations** (as of Swift 6.2):
- `ExistentialAny` (SE-335)
- `InferIsolatedConformances` (SE-470)
- More features will add migration support over time


**Additional resource**: [Migration Tooling Video](https://youtu.be/FK9XFxSWZPg?si=2z_ybn1t1YCJow5k)

---

## Rewriting Closures to Async/Await

### Using Xcode Refactoring

Three refactoring options available:

1. **Add Async Wrapper**: Wrap an existing closure-based method when callers need async composition; this is one possible first step
2. **Add Async Alternative**: Rewrites method as async, keeps original
3. **Convert Function to Async**: Replaces method entirely

**Warning: Known Issue**: Refactoring can be unstable in Xcode. If you get "Connection interrupted" errors:
- Clean build folder
- Clear derived data
- Restart Xcode
- Simplify complex methods (shorthand if statements can cause failures)

### Manual Rewriting Example

**Before** (closure-based):
```swift
func fetchImage(urlRequest: URLRequest, 
                completion: @escaping @Sendable (Result<UIImage, Error>) -> Void) {
    URLSession.shared.dataTask(with: urlRequest) { data, _, error in
        do {
            if let error = error { throw error }
            guard let data = data, let image = UIImage(data: data) else {
                throw ImageError.conversionFailed
            }
            completion(.success(image))
        } catch {
            completion(.failure(error))
        }
    }.resume()
}
```

**After** (async/await):
```swift
func fetchImage(urlRequest: URLRequest) async throws -> UIImage {
    let (data, _) = try await URLSession.shared.data(for: urlRequest)
    guard let image = UIImage(data: data) else {
        throw ImageError.conversionFailed
    }
    return image
}
```

**Benefits**:
- Less code to maintain
- Easier to reason about
- No nested closures
- Automatic error propagation


---

## Using @preconcurrency

Suppresses `Sendable` warnings from modules you don't control.

### When to Use

```swift
// Warning: Third-party library doesn't support Swift Concurrency yet
@preconcurrency import SomeThirdPartyLibrary

actor DataProcessor {
    func process(_ data: LibraryType) {  // No Sendable warning
        // ...
    }
}
```

### Risks

- **No compile-time safety**: You're responsible for ensuring thread safety
- **Hides real issues**: Library might not be thread-safe at all
- **Technical debt**: Easy to forget to revisit later

### Best Practices

1. **Don't use by default**: Only add when compiler suggests it
2. **Check for updates first**: Library might have a newer version with concurrency support
3. **Document why**: Add a comment explaining why it's needed
4. **Revisit regularly**: Set reminders to check if library has been updated

```swift
// TODO: Remove @preconcurrency when SomeLibrary adds Sendable support
// Last checked: 2026-01-07 (version 2.3.0)
@preconcurrency import SomeLibrary
```

The compiler will warn if `@preconcurrency` is unused:
```
'@preconcurrency' attribute on module 'SomeModule' is unused
```


---

## Migrating from Combine/RxSwift

### Observation Alternative

Swift 6 will include **Transactional Observation** (SE-475):

```swift
// Future API (not yet implemented)
let names = Observations { person.name }

Task.detached {
    for await name in names {
        print("Name updated to: \(name)")
    }
}
```

**Current alternatives**:
- Use `@Observable` macro for SwiftUI
- Use `AsyncStream` for custom observation
- Consider [AsyncExtensions](https://github.com/sideeffect-io/AsyncExtensions) package

### Debouncing Example

**Combine**:
```swift
$searchQuery
    .debounce(for: .milliseconds(500), scheduler: DispatchQueue.main)
    .sink { [weak self] query in
        self?.performSearch(query)
    }
    .store(in: &cancellables)
```

**Swift Concurrency**:
```swift
func search(_ query: String) {
    currentSearchTask?.cancel()
    
    currentSearchTask = Task {
        do {
            try await Task.sleep(for: .milliseconds(500))
            performSearch(query)
        } catch {
            // Search was cancelled
        }
    }
}
```

**SwiftUI Integration**:
```swift
struct SearchView: View {
    @State private var searchQuery = ""
    @State private var searcher = ArticleSearcher()
    
    var body: some View {
        List(searcher.results) { result in
            Text(result.title)
        }
        .searchable(text: $searchQuery)
        .onChange(of: searchQuery) { _, newValue in
            searcher.search(newValue)
        }
    }
}
```

### Mindset Shift

**Don't think in Combine pipelines**. Many problems are simpler without FRP:

```swift
// Avoid: Looking for AsyncSequence equivalent of complex Combine pipeline
somePublisher
    .debounce(for: .seconds(0.5))
    .removeDuplicates()
    .flatMap { ... }
    .sink { ... }

// Preferred: Rethink the problem with Swift Concurrency
Task {
    var lastValue: String?
    for await value in stream {
        guard value != lastValue else { continue }
        lastValue = value
        try await Task.sleep(for: .seconds(0.5))
        await process(value)
    }
}
```

**For complex operators**: Check [Swift Async Algorithms](https://github.com/apple/swift-async-algorithms) package.

### Warning: Critical: Actor Isolation with Combine

**Problem**: `sink` closures don't respect actor isolation at compile time.

```swift
@MainActor
final class NotificationObserver {
    private var cancellables: [AnyCancellable] = []
    
    init() {
        NotificationCenter.default.publisher(for: .someNotification)
            .sink { [weak self] _ in
                self?.handleNotification()  // Warning: May crash if posted from background
            }
            .store(in: &cancellables)
    }
    
    private func handleNotification() {
        // Expects to run on main actor
    }
}
```

**Why it crashes**: Notification observers run on the same thread as the poster. If posted from a background thread, the `@MainActor` method is called off the main actor.

**Solutions**:

1. **Migrate to Swift Concurrency** (recommended):
```swift
Task { [weak self] in
    for await _ in NotificationCenter.default.notifications(named: .someNotification) {
        await self?.handleNotification()  // Preferred: Compile-time safe
    }
}
```

2. **Use Task wrapper** (temporary):
```swift
.sink { [weak self] _ in
    Task { @MainActor in
        self?.handleNotification()
    }
}
```


---

## When to Use AsyncAlgorithms

When migrating from Combine or RxSwift, you have multiple options for handling asynchronous patterns:

### Use AsyncAlgorithms for:

- **Time-based operations**: debounce, throttle, timers
- **Combining multiple async sequences**: merge, combineLatest, zip
- **Multi-consumer scenarios**: AsyncChannel for backpressure
- **Complex operator chains**: FRP-like patterns in Swift Concurrency
- **Specific operators**: removeDuplicates, chunks, adjacentPairs, compacted

### Use Standard Library for:

- **Bridging callbacks**: AsyncStream is sufficient
- **Simple iteration**: for await in sequence
- **Single-value operations**: async/await
- **Basic transformations**: map, filter, contains

### Use SwiftUI for:

- **UI observation**: @Observable macro
- **State management**: @State, @Published properties
- **User interactions**: onChange, onReceive modifiers

> **See**: [async-algorithms.md](async-algorithms.md) for detailed AsyncAlgorithms usage examples.

---

## Real-World Migration Examples

### Example: ArticleSearcher with AsyncAlgorithms

**Before: Manual Debouncing**

```swift
final class ArticleSearcher {
    @MainActor private(set) var results: [Article] = []
    private var currentSearchTask: Task<Void, Never>?

    func search(_ query: String) {
        currentSearchTask?.cancel()

        currentSearchTask = Task {
            do {
                try await Task.sleep(for: .milliseconds(500))
                await MainActor.run {
                    self.results = []
                }
                self.results = await APIClient.searchArticles(query)
            } catch {
                // Search was cancelled
            }
        }
    }
}

// SwiftUI integration
struct SearchView: View {
    @State private var searchQuery = ""
    @State private var searcher = ArticleSearcher()

    var body: some View {
        List(searcher.results) { result in
            Text(result.title)
        }
        .searchable(text: $searchQuery)
        .onChange(of: searchQuery) { _, newValue in
            searcher.search(newValue)
        }
    }
}
```

**After: AsyncAlgorithms Debounce**

```swift
import AsyncAlgorithms

@Observable
final class ArticleSearcher {
    @MainActor private(set) var results: [Article] = []
    private var searchQueryContinuation: AsyncStream<String>.Continuation?

    private lazy var searchQueryStream: AsyncStream<String> = {
        AsyncStream { continuation in
            searchQueryContinuation = continuation
        }
    }()

    func search(_ query: String) {
        searchQueryContinuation?.yield(query)
    }

    func startDebouncedSearch() {
        Task { @MainActor in
            for await query in searchQueryStream.debounce(for: .milliseconds(500)) {
                self.results = []
                self.results = await APIClient.searchArticles(query)
            }
        }
    }
}

// SwiftUI integration
struct SearchView: View {
    @State private var searchQuery = ""
    @State private var searcher = ArticleSearcher()

    var body: some View {
        List(searcher.results) { result in
            Text(result.title)
        }
        .searchable(text: $searchQuery)
        .onChange(of: searchQuery) { _, newValue in
            searcher.search(newValue)
        }
        .onAppear {
            searcher.startDebouncedSearch()
        }
    }
}
```

**Benefits of using AsyncAlgorithms**:
- Automatic cancellation when new values arrive
- Backpressure handling (producer respects consumer pace)
- Cleaner code than manual Task.sleep management
- No need to track and cancel tasks manually

### Example: Notification Stream Migration

**Before: Combine Publisher**

```swift
import Combine

final class NotificationObserver: ObservableObject {
    @Published private(set) var notifications: [AppNotification] = []
    private var cancellables = Set<AnyCancellable>()

    init() {
        NotificationCenter.default.publisher(for: UIApplication.didBecomeActiveNotification)
            .compactMap { notification in
                notification.object as? AppNotification
            }
            .receive(on: DispatchQueue.main)
            .assign(to: &$notifications)
    }
}
```

**After: Standard Library Notifications**

```swift
@Observable
final class NotificationObserver {
    @MainActor private(set) var notifications: [AppNotification] = []

    func startObserving() {
        Task {
            for await notification in NotificationCenter.default.notifications(named: UIApplication.didBecomeActiveNotification) {
                if let appNotification = notification.object as? AppNotification {
                    notifications.append(appNotification)
                }
            }
        }
    }
}
```

**When to use each approach**:
- Use `notifications(named:)` for standard system notifications
- Use `AsyncChannel` for custom multi-consumer notification scenarios
- Use `@Observable` + SwiftUI for UI state updates

### Example: Multi-Source Data Loading

**Before: Combine Merge**

```swift
import Combine

final class MultiSourceLoader: ObservableObject {
    @Published private(set) var items: [Item] = []
    private var cancellables = Set<AnyCancellable>()

    func loadFromAllSources() {
        let source1 = APIClient.fetchItems(from: .source1)
        let source2 = APIClient.fetchItems(from: .source2)
        let source3 = APIClient.fetchItems(from: .source3)

        Publishers.Merge3(source1, source2, source3)
            .flatMap { items in
                Just(items)
                    .delay(for: .seconds(0.1), scheduler: DispatchQueue.main)
            }
            .scan([]) { accumulated, new in
                accumulated + new
            }
            .receive(on: DispatchQueue.main)
            .assign(to: &$items)
            .store(in: &cancellables)
    }
}
```

**After: AsyncAlgorithms Merge + TaskGroup**

```swift
import AsyncAlgorithms

@Observable
final class MultiSourceLoader {
    @MainActor private(set) var items: [Item] = []

    func loadFromAllSources() async {
        let sources = [
            APIClient.fetchItems(from: .source1),
            APIClient.fetchItems(from: .source2),
            APIClient.fetchItems(from: .source3)
        ]

        Task { @MainActor in
            for await stream in sources.map { $0.values }.merge() {
                for await newItems in stream {
                    self.items.append(contentsOf: newItems)
                }
            }
        }
    }

    // Alternative: Using TaskGroup for parallel execution
    func loadFromAllSourcesParallel() async {
        await withTaskGroup(of: [Item].self) { group in
            group.addTask {
                await APIClient.fetchItems(from: .source1)
            }
            group.addTask {
                await APIClient.fetchItems(from: .source2)
            }
            group.addTask {
                await APIClient.fetchItems(from: .source3)
            }

            for await newItems in group {
                await MainActor.run {
                    self.items.append(contentsOf: newItems)
                }
            }
        }
    }
}
```

**Key differences**:
- Combine `merge()` combines publishers; AsyncAlgorithms `merge()` combines sequences
- For parallel execution, use `TaskGroup` instead of `flatMap`
- State updates can use `@MainActor` instead of `.receive(on:)`

---

## Anti-Patterns to Avoid

### Avoid: Don't Use Task.sleep for Debouncing

```swift
// Avoid: Bad: Manual debouncing without backpressure
func search(_ query: String) {
    Task {
        try? await Task.sleep(for: .milliseconds(500))
        await performSearch(query)
    }
}
```

**Problem**: Every keystroke spawns a new task. If user types fast, multiple tasks execute simultaneously after 500ms, causing out-of-order results and wasted API calls.

**Solution**: Use `debounce()` from AsyncAlgorithms for automatic backpressure and cancellation.

### Avoid: Don't Manually Combine Values

```swift
// Avoid: Bad: Manual combination without operator
actor FormValidator {
    private var currentUsername: String = ""
    private var currentEmail: String = ""
    private var currentPassword: String = ""

    func updateUsername(_ username: String) {
        currentUsername = username
        checkForm()
    }

    func updateEmail(_ email: String) {
        currentEmail = email
        checkForm()
    }

    func updatePassword(_ password: String) {
        currentPassword = password
        checkForm()
    }

    private func checkForm() {
        let state = validate(
            username: currentUsername,
            email: currentEmail,
            password: currentPassword
        )
        // Update UI or emit validation state
    }
}
```

**Problems**:
- More state management
- Boilerplate code for each field
- Harder to add new fields
- No stream composition benefits

**Solution**: Use `combineLatest()` for cleaner, composable validation.

### Avoid: Don't Share Streams Without AsyncChannel

```swift
// Avoid: Bad: Multiple consumers sharing same stream
let stream = AsyncStream<Int> { continuation in
    for i in 1...10 {
        continuation.yield(i)
    }
    continuation.finish()
}

Task {
    for await value in stream {
        print("Consumer 1: \(value)")
    }
}

Task {
    for await value in stream {
        print("Consumer 2: \(value)")
    }
}
```

**Problem**: Values are split between consumers unpredictably. Each value goes to only one consumer.

**Solution**: Use `AsyncChannel` for true multi-consumer scenarios with backpressure.

---

---

## Concurrency-Safe Notifications (iOS 26+)

Swift 6.2 introduces **typed, thread-safe notifications**.

### MainActorMessage

For notifications that should be delivered on the main actor:

```swift
// Old way
NotificationCenter.default.addObserver(
    forName: UIApplication.didBecomeActiveNotification,
    object: nil,
    queue: .main
) { [weak self] _ in
    self?.handleDidBecomeActive()  // Warning: Concurrency warning
}

// New way (iOS 26+)
token = NotificationCenter.default.addObserver(
    of: UIApplication.self,
    for: .didBecomeActive
) { [weak self] message in
    self?.handleDidBecomeActive()  // Preferred: No warning, guaranteed main actor
}
```

**Key difference**: Observer closure is guaranteed to run on `@MainActor`.

### AsyncMessage

For notifications delivered asynchronously on arbitrary isolation:

```swift
struct RecentBuildsChangedMessage: NotificationCenter.AsyncMessage {
    typealias Subject = [RecentBuild]
    let recentBuilds: Subject
}

// Enable static member lookup
extension NotificationCenter.MessageIdentifier 
where Self == NotificationCenter.BaseMessageIdentifier<RecentBuildsChangedMessage> {
    static var recentBuildsChanged: NotificationCenter.BaseMessageIdentifier<RecentBuildsChangedMessage> {
        .init()
    }
}
```

**Posting**:
```swift
let builds = [RecentBuild(appName: "Stock Analyzer")]
let message = RecentBuildsChangedMessage(recentBuilds: builds)
NotificationCenter.default.post(message)
```

**Observing**:
```swift
// Old way: Unsafe casting
NotificationCenter.default.addObserver(forName: .recentBuildsChanged, object: nil, queue: nil) { notification in
    guard let builds = notification.object as? [RecentBuild] else { return }
    handleBuilds(builds)
}

// New way: Strongly typed, thread-safe
token = NotificationCenter.default.addObserver(
    of: [RecentBuild].self,
    for: .recentBuildsChanged
) { message in
    handleBuilds(message.recentBuilds)  // Preferred: Direct access, no casting
}
```

**Benefits**:
- Strongly typed (no `Any` casting)
- Compile-time thread safety
- Clear isolation guarantees


---

## Common Mistakes Agents Make

- **Blanket `@MainActor`**: Do not slap `@MainActor` on everything to silence errors. Ask whether the code truly needs main-actor isolation.
- **Mixing migration with unrelated refactors**: Focus solely on concurrency changes. Architectural improvements belong in separate PRs.
- **Using `@unchecked Sendable` as a first response**: Prefer immutable value types or actors. Reserve escape hatches for documented, temporary exceptions.
- **Giving pre-Swift 6.2 execution advice without checking the active feature set**: `nonisolated async` behavior depends on whether `NonisolatedNonsendingByDefault` is enabled.
- **Using Approachable Concurrency without migrating feature-by-feature first**: Enable individual upcoming features before the full bundle to understand each change's impact.

## Legion review corrections

Examples labelled Xcode 26, iOS 26, macOS 26, Swift 6.2, typed notifications or
`Observations` are conditional examples, never baseline requirements. Verify compiler,
SDK, deployment target and feature flags per target before adopting them; retain a
continuation/`AsyncStream` or ordinary NotificationCenter fallback where unavailable.
`@preconcurrency` is a temporary boundary with a documented dependency/version and
removal condition, not a general warning switch. `defaultIsolation(MainActor.self)` is
per module and changes inferred isolation; it does not prove neighboring modules match.
