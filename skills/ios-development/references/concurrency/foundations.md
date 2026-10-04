# Foundations: async/await and bridges

Use `async` for operations that can suspend, `throws` for failure, and `await` at each
potential suspension. Sequential awaits preserve dependency order. Use `async let` only
for a fixed set of independent values; declarations start child work immediately, errors
are observed at the await point, and children are cancelled/awaited when scope exits.
Use a task group for a dynamic collection, with the rules in `tasks.md`.

```swift
async let profile = fetchProfile()
async let settings = fetchSettings()
let result = try await (profile, settings)
```

From synchronous code, `Task {}` is a bridge that inherits actor, priority and task-local
context. Prefer making the caller async when possible. Handle errors inside a task or
return its handle; an ignored throwing task silently loses its failure. `.task` in SwiftUI
binds lifetime to a view and cancels on disappearance.

For callback APIs, add an async overload beside old API, then migrate callers. Use checked
continuations by default and resume exactly once on every success, failure, early-return,
timeout and cancellation path. If cancellation must stop underlying work, install a
cancellation handler and arrange callback/cancel races through one serialized gate.

```swift
func load() async throws -> Data {
    try await withCheckedThrowingContinuation { continuation in
        legacyLoad { result in continuation.resume(with: result) }
    }
}
```

Use `AsyncStream` for repeated callback/delegate values; use a regular async method for
one result. See `streams.md` for continuation lifecycle and buffering. Prefer URLSession's
async APIs: validate HTTP status, decode typed values, and let thrown errors propagate.

Typed throws, availability of APIs, and syntax depend on active Swift/SDK; confirm before
recommending them. Do not add fake `await` solely to satisfy lint.
