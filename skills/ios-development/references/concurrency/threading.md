# Threading

Execution advice is target-specific. Record Swift language mode, strict-concurrency level,
default actor isolation, `NonisolatedNonsendingByDefault`, deployment target and compiler
availability before applying Swift 6.x examples. A plain async function does not promise a
background thread; `@concurrent` is conditional opt-in and requires Sendable-safe captures.

Use this when:

- You need to understand the relationship between tasks and threads.
- You are debugging suspension points, actor reentrancy, or unexpected execution contexts.
- You need Swift 6.2 behavior guidance (`nonisolated async`, `@concurrent`, `nonisolated(nonsending)`).

Skip this file if:

- You mainly need to protect mutable state. Use `actors.md`.
- You need to make types safe to transfer. Use `sendable.md`.

Jump to:

- Core Concepts (Tasks vs Threads)
- Cooperative Thread Pool
- Suspension Points and Actor Reentrancy
- Swift 6.2 Changes (SE-461, SE-466)
- Default Isolation Domain
- Debugging Thread Execution
- Common Misconceptions
- Migration Strategy

## Core Concepts

### What is a Thread?

System-level resource that runs instructions. High overhead for creation and switching. Swift Concurrency abstracts thread management away.

### Tasks vs Threads

**Tasks** are units of async work, not tied to specific threads. Swift dynamically schedules tasks on available threads from a cooperative pool.

**Key insight**: No direct relationship between one task and one thread.


**Important (Swift 6+)**: Avoid using `Thread.current` inside async contexts. In Swift 6 language mode, `Thread.current` is unavailable from asynchronous contexts and will fail to compile. Prefer reasoning in terms of isolation domains; use Instruments and the debugger to observe execution when needed.

## Cooperative Thread Pool

Swift creates only as many threads as CPU cores. Tasks share these threads efficiently.

### How it works

1. **Limited threads**: Number matches CPU cores
2. **Task scheduling**: Tasks scheduled onto available threads
3. **Suspension**: At `await`, task suspends, thread freed for other work
4. **Resumption**: Task resumes on any available thread (not necessarily the same one)

```swift
func example() async {
    print("Started on: \(Thread.current)")
    
    try await Task.sleep(for: .seconds(1))
    
    print("Resumed on: \(Thread.current)") // Likely different thread
}
```

### Benefits over GCD

**Prevents thread explosion**:
- No excessive thread creation
- No high memory overhead from idle threads
- No excessive context switching
- No priority inversion

**Better performance**:
- Fewer threads = less context switching
- Continuations instead of blocking
- CPU cores stay busy efficiently

## Threading Mindset → Isolation Mindset

### Old way (GCD)

```swift
// Thinking about threads
DispatchQueue.main.async {
    // Update UI on main thread
}

DispatchQueue.global(qos: .background).async {
    // Heavy work on background thread
}
```

### New way (Swift Concurrency)

```swift
// Thinking about isolation domains
@MainActor
func updateUI() {
    // Runs on main actor (usually main thread)
}

func heavyWork() async {
    // Runs on any available thread in pool
}
```

### Think in isolation domains

**Don't ask**: "What thread should this run on?"

**Ask**: "What isolation domain should own this work?"

- `@MainActor` for UI updates
- Custom actors for specific state
- Nonisolated for general async work

### Provide hints, not commands

```swift
Task(priority: .userInitiated) {
    await doWork()
}
```

You're describing the nature of work, not assigning threads. Swift optimizes execution.


## Suspension Points

### What is a suspension point?

Moment where task **may** pause to allow other work. Marked by `await`.

```swift
let data = await fetchData() // Potential suspension
```

**Critical**: `await` marks *possible* suspension, not guaranteed. If operation completes synchronously, no suspension occurs.

### Why suspension points matter

1. **Code may pause unexpectedly** - resumes later, possibly different thread
2. **State can change** - mutable state may be modified during suspension
3. **Actor reentrancy** - other tasks can access actor during suspension

The same entry-isolation rule applies to any unstructured task: choose startup isolation by what the synchronous prefix needs. If nothing before the first `await` needs the main actor—whether that first operation is `Task.sleep`, an actor hop, a `print`, or a Sendable computation—consider `Task { @concurrent in ... }` only when active compiler/SDK supports it and measured work or an executor requirement needs caller isolation left; otherwise keep inherited/structured isolation, hopping to `MainActor` only for UI mutation. If the synchronous prefix already needs main actor for one statement, keep nearby cheap lines on main with it instead of splitting them out.

### Actor reentrancy example

```swift
actor BankAccount {
    private var balance: Int = 0
    
    func deposit(amount: Int) async {
        balance += amount
        print("Balance: \(balance)")
        
        await logTransaction(amount) // Warning: Suspension point
        
        balance += 10 // Bonus
        print("After bonus: \(balance)")
    }
    
    func logTransaction(_ amount: Int) async {
        try? await Task.sleep(for: .seconds(1))
    }
}

// Two concurrent deposits
async let _ = account.deposit(amount: 100)
async let _ = account.deposit(amount: 100)

// Unexpected: 100 → 200 → 210 → 220
// Expected:   100 → 110 → 210 → 220
```

**Why**: During `logTransaction`, second deposit runs, modifying balance before first completes.

### Avoiding reentrancy bugs

**Complete actor work before suspending**:

```swift
func deposit(amount: Int) async {
    balance += amount
    balance += 10 // Bonus applied first
    print("Final balance: \(balance)")
    
    await logTransaction(amount) // Suspend after state changes
}
```

**Rule**: Don't mutate actor state after suspension points.



## Choosing Task entry isolation

For unstructured `Task { ... }`, choose entry isolation based on the synchronous prefix (everything before the first `await`), not on where the task was created.

Two common reasons a bare `Task { ... }` starts on `@MainActor`:
- The task is spawned from a `@MainActor` context.
- The module enables default main-actor isolation (for example, `defaultIsolation(MainActor.self)`).

Rule:
- If the synchronous prefix contains any main-actor work, keep inherited main-actor entry.
- If the synchronous prefix contains no main-actor work, consider `Task { @concurrent in ... }` only when active compiler/SDK supports it and measured work needs offloading; otherwise use structured or inherited isolation, hopping to `MainActor` only when needed.

```swift
// Avoid: Synchronous prefix is empty; first work hops away
Task {
    await hopToOtherIsolationDomain()
}

// Avoid: Synchronous prefix is only `print` (trivial, non-main); first await hops away
Task {
    print("Also not main-thread-bound")
    await hopToOtherIsolationDomain()
}

// Preferred: Start off the main actor, hop back only for UI work
Task { @concurrent in
    await hopToOtherIsolationDomain()
    await MainActor.run { updateUI() }
}

// Preferred: Synchronous prefix DOES contain main-actor work — keep inheritance
Task {
    print("debug")              // trivial, non-main — rides along
    self.isLoading = true       // needs @MainActor, before any await
    await fetchData()
}
```

The delayed-retry `Task.sleep` pattern (see `performance.md` "Match Task entry isolation to its synchronous prefix") is a specialization of this same rule: the wait is usually not UI-owned, while the final mutation is.

Note that `Task { @concurrent in ... }` changes the closure's isolation, so any capture of non-Sendable state from the enclosing actor must move inside the `MainActor.run { ... }` hop, or be captured weakly (e.g., `[weak self]` plus a `guard let self`) before being used there. The examples above stay safe by keeping `self` use inside `MainActor.run`. If the body needs to touch non-Sendable state directly, see `sendable.md` before reaching for `@concurrent`.

## Thread Execution Patterns

### Default: Background threads

Tasks run on cooperative thread pool (background threads):

```swift
Task {
    print(Thread.current) // Background thread
}
```

### Main thread execution

Use `@MainActor` for main thread:

```swift
@MainActor
func updateUI() {
    Task {
        print(Thread.current) // Main thread
    }
}
```

### Inheritance example

```swift
@MainActor
func updateUI() {
    print("Main thread: \(Thread.current)")
    
    await backgroundTask() // Switches to background
    
    print("Back on main: \(Thread.current)") // Returns to main
}

func backgroundTask() async {
    print("Background: \(Thread.current)")
}
```

## Swift 6.2 Changes

### Nonisolated async functions (SE-461)

With the `NonisolatedNonsendingByDefault` behavior enabled, a nonisolated async function
whose values are not sent can inherit caller isolation; without that feature, active
compiler semantics differ. Do not infer either behavior from a Swift marketing/version
label alone.

When that feature is enabled, nonisolated nonsending async work can inherit caller
isolation. The exact behavior must come from this target's active feature set.

```swift
class NotSendable {
    func performAsync() async {
        // Work executes according to active isolation; do not infer a thread.
    }
}

@MainActor
func caller() async {
    let obj = NotSendable()
    await obj.performAsync()
    // Check isolation and Sendable diagnostics for this target.
}
```

### Enabling new behavior

In Xcode 16+:

```swift
// Build setting or swift-settings
.enableUpcomingFeature("NonisolatedNonsendingByDefault")
```

### Opting out with @concurrent

Opt into concurrent-pool execution when supported and when leaving caller isolation is
required by measured CPU work:

```swift
@concurrent
func performAsync() async {
    // Runs on the concurrent pool under supported compiler semantics.
}
```

### nonisolated(nonsending)

Prevent sending non-Sendable values across isolation:

```swift
nonisolated(nonsending) func storeTouch(...) async {
    // Runs on caller's isolation, no value sending
}
```


**Use when**: Method doesn't need to switch isolation, avoiding Sendable requirements.

## Default Isolation Domain (SE-466)

### Configuring default isolation

**Build setting** (Xcode 16+):
- Default Actor Isolation: `MainActor` or `None`

**Swift Package**:

```swift
.target(
    name: "MyTarget",
    swiftSettings: [
        .defaultIsolation(MainActor.self)
    ]
)
```

### Why change default?

Most app code runs on main thread. Setting `@MainActor` as default:
- Reduces false warnings
- Avoids "concurrency rabbit hole"
- Makes migration easier

### Inference with @MainActor default

```swift
// With @MainActor as default:

func f() {} // Inferred: @MainActor

class C {
    init() {} // Inferred: @MainActor
    static var value = 10 // Inferred: @MainActor
}

@MyActor
struct S {
    func f() {} // Inferred: @MyActor (explicit override)
}

```

### Per-module setting

Must opt in for each module/package. Not global across dependencies.

### Backward compatibility

Opt-in only. Default remains `nonisolated` if not specified.

## Debugging Thread Execution

### Print current thread

**Warning: Important**: `Thread.current` is unavailable in Swift 6 language mode from async contexts. The compiler error states: "Class property 'current' is unavailable from asynchronous contexts; Thread.current cannot be used from async contexts."

**Workaround** (Swift 6+ mode only):

```swift
extension Thread {
    public static var currentThread: Thread {
        Thread.current
    }
}

print("Thread: \(Thread.currentThread)")
```

### Debug navigator

1. Set breakpoint in task
2. Debug → Pause
3. Check Debug Navigator for thread info

### Verify main thread

```swift
assert(Thread.isMainThread)
```

## Common Misconceptions

### Avoid: Each Task runs on new thread

**Wrong**. Tasks share limited thread pool, reuse threads.

### Avoid: await blocks the thread

**Wrong**. `await` suspends task without blocking thread. Other tasks can use the thread.

### Avoid: Task execution order is guaranteed

**Wrong**. Tasks execute based on system scheduling. Use `await` to enforce order.

### Avoid: Same task = same thread

**Wrong**. Task can resume on different thread after suspension.

## Why Sendable Matters

Since tasks move between threads unpredictably:

```swift
func example() async {
    print("Thread 1: \(Thread.current)")
    
    await someWork()
    
    print("Thread 2: \(Thread.current)") // Different thread
}
```

Values crossing suspension points may cross threads. **Sendable** ensures safety.

## Best Practices

1. **Stop thinking about threads** - think isolation domains
2. **Trust the system** - Swift optimizes thread usage
3. **Use @MainActor for UI** - clear, explicit main thread execution
4. **Minimize suspension points in actors** - avoid reentrancy bugs
5. **Complete state changes before suspending** - prevent inconsistent state
6. **Use priorities as hints** - not guarantees
7. **Make types Sendable** - safe across thread boundaries
8. **Enable supported upcoming features selectively** - record each target setting
9. **Set default isolation only when target ownership fits** - verify module boundaries
10. **Don't force thread switching** - let Swift optimize

## Migration Strategy

### For targets adopting newer isolation features

1. Confirm whether default isolation should be `@MainActor` for this target
2. Enable `NonisolatedNonsendingByDefault` only after reviewing its effect
3. Use `@concurrent` only for measured offloading when target supports it

### For existing projects

1. Gradually enable Swift 6 language mode
2. Consider default isolation change
3. Use supported `@concurrent` only where old executor behavior is required and verified
4. Migrate module by module

## Decision Tree

```
Need to control execution?
├─ UI updates? → @MainActor
├─ Specific state isolation? → Custom actor
├─ Background work? → Regular async (trust Swift)
└─ Need measured offload and supported feature? → @concurrent; otherwise keep structured/inherited isolation

Seeing Sendable warnings?
├─ Can make type Sendable? → Add conformance
├─ Same isolation OK? → nonisolated(nonsending)
└─ Need different isolation? → Make Sendable or refactor
```

## GCD to Isolation Domain Migration

Instead of asking "what thread should this run on?" ask "what isolation domain should own this work?"

- `DispatchQueue.main.async { }` → `@MainActor func updateUI()`
- `DispatchQueue.global().async { }` → `func work() async` (or `@concurrent` if it must leave caller isolation)
- `DispatchQueue(label:).sync { }` → `actor` or `Mutex` for protecting state
- Serial queue for ordering → `actor` (guarantees serial access)

## Decision Rules

- UI state → usually `@MainActor`
- Mutable shared state → usually an `actor`
- Plain async work with no isolated state → `async` API with explicit ownership
- Work that must hop away from caller isolation under Swift 6.2-era behavior → consider `@concurrent`

## Common Mistakes Agents Make

- Recommending GCD queue hopping when actor isolation already expresses the ownership model.
- Debugging correctness by thread ID instead of by isolation and ordering.
- Treating `await` as a blocking call — it suspends the task, freeing the thread.
- Mapping each `Task` to a conceptual thread.
- Picking task entry isolation by the enclosing context instead of by the task's synchronous prefix. A `Task { ... }` from `@MainActor` whose first `await` immediately hops away can remain inherited; use `Task { @concurrent in ... }` only when active compiler support and measured offloading need are established.

## Performance Insights

### Why fewer threads = better performance

- **Less context switching**: CPU spends more time on actual work
- **Better cache utilization**: Threads stay on same cores longer
- **No thread explosion**: Predictable resource usage
- **Forward progress**: Threads never block, always productive

### Cooperative pool advantages

- Matches hardware (one thread per core)
- Prevents oversubscription
- Efficient task scheduling
- Automatic load balancing

## Legion review corrections

Examples that print `Thread.current` describe legacy observation only; do not copy them
into Swift 6 async code where the API is unavailable. Thread identity is never proof of
actor isolation. Record `SWIFT_VERSION`, strict-concurrency level, default actor isolation,
and `NonisolatedNonsendingByDefault`/related feature flags per target before deciding
whether plain `nonisolated async` inherits caller isolation or `@concurrent` is available.
Deployment availability and compiler language mode are independent checks.
