# Rubric pack: Swift (`**/*.swift`)

Loaded by `correctness`, `security`, `resilience`, and `platform-parity` when scoped files match.
Every finding needs a real `file:line`.

## Correctness
- Force unwraps (`!`), `try!`, `as!`, and `fatalError` on values that come from disk, network,
  `UserDefaults`, a decoder, or a user. Outlets and compile-time constants are the usual exceptions.
- UI state touched off the main actor: missing `@MainActor` on view models, completion handlers that
  mutate `@State` / `@Published` from a background queue.
- Swift concurrency: a `Task {}` that captures `self` strongly and is never cancelled; `Task.detached`
  dropping actor isolation by accident; actor reentrancy assumptions across an `await`; ignored
  `CancellationError`.
- Retain cycles: closures stored on `self` capturing `self` without `[weak self]` / `[unowned self]`
  where the owner outlives the call; delegates declared without `weak`.
- `Codable` types that fail the whole payload because one optional key is missing or a new enum case
  appears; no default case on enums that cross a version boundary.
- Date, number, and unit formatting built with fixed formats and no locale, calendar, or time zone.
- `@StateObject` vs `@ObservedObject` mix-ups that recreate model objects on every view update.

## Security
- Tokens, passwords, and keys stored in `UserDefaults`, plist, or files instead of the Keychain; Keychain
  items with a permissive accessibility class.
- `NSAllowsArbitraryLoads`, disabled certificate validation, or `URLSession` delegates that accept any
  trust.
- `WKWebView` loading remote or user content with JavaScript bridges exposed; unvalidated custom URL
  scheme or universal-link parameters.
- Sensitive data in `print`, `os_log` without privacy annotations, pasteboard, or screenshots of the
  app switcher.
- Entitlements or `Info.plist` usage strings broader than the code needs.

## Resilience and platform parity
- File and database writes that are not atomic; no recovery for a corrupt or newer-schema store.
- Work that must survive suspension (uploads, saves) running without a background task or session.
- API availability: `#available` / deployment-target mismatches; iOS-only APIs reachable from
  macOS or visionOS targets, and the reverse (`UIKit` vs `AppKit` behind `#if os(...)` with a stub arm).
- Accessibility: custom controls without labels, traits, or Dynamic Type support.

## Not findings
- Force unwraps in previews, tests, and `@IBOutlet`s.
- Style preferences already covered by SwiftLint configuration.
