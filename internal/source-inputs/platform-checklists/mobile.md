# Mobile app pre-release audit framework

A serious mobile audit should evaluate the **entire delivered system**, not merely the iOS or Android codebase. That includes the mobile client, backend APIs, authentication infrastructure, databases, third-party SDKs, build pipeline, store configuration, operational controls, privacy declarations, and post-release monitoring.

For security, use OWASP MASVS and MASTG as the control baseline. For platform quality, use Apple’s App Review, accessibility, and performance guidance together with Android’s core and adaptive app-quality requirements. ([mas.owasp.org][1])

## Top-line audit domains

| Domain                                      | Principal audit question                                                              |
| ------------------------------------------- | ------------------------------------------------------------------------------------- |
| 1. Scope and risk                           | Do we know exactly what is being released, what can fail, and what matters most?      |
| 2. Product readiness                        | Does the app reliably deliver its intended user value?                                |
| 3. Architecture                             | Is the system understandable, maintainable, testable, and resilient?                  |
| 4. Technology stack                         | Is the chosen stack supported, appropriate, and sustainable?                          |
| 5. Dependencies and supply chain            | Do we know and trust everything included in the binary?                               |
| 6. Code quality                             | Is the implementation correct, safe, readable, and testable?                          |
| 7. Security                                 | Can users, data, APIs, and business logic resist realistic attacks?                   |
| 8. Privacy                                  | Is data collection necessary, disclosed, controlled, and legally defensible?          |
| 9. Authentication and authorization         | Are identity, sessions, and permissions enforced correctly?                           |
| 10. Backend and API                         | Can the server remain correct under failure, abuse, and version mismatch?             |
| 11. Data, storage, and synchronization      | Can data be stored, migrated, synchronized, and recovered safely?                     |
| 12. Performance                             | Is the app responsive without excessive memory, battery, network, or storage use?     |
| 13. Reliability and lifecycle               | Does it survive process death, backgrounding, interruptions, and degraded conditions? |
| 14. UX and accessibility                    | Can intended users successfully complete every important task?                        |
| 15. Device and OS compatibility             | Does it behave correctly across supported devices, displays, and OS versions?         |
| 16. Testing                                 | Is there enough evidence that the release works and remains working?                  |
| 17. Build and release engineering           | Is the exact tested artifact reproducible, signed, and safely deployable?             |
| 18. Observability and operations            | Will the team know when production fails and be able to respond?                      |
| 19. Store, legal, and commercial compliance | Will it pass review and operate lawfully in each market?                              |
| 20. Documentation and ownership             | Can another engineer operate, debug, and extend the system?                           |

---

# Granular audit checklist

## 0. Audit scope and risk model

Before inspecting code, establish the audit boundary.

* Identify every release target:

  * iOS application.
  * Android application.
  * Tablet or foldable variants.
  * Widgets, extensions, watch apps, App Clips, instant apps, share extensions, notification extensions, or companion applications.
  * Development, staging, production, enterprise, white-label, and regional variants.
* Record the exact release candidate:

  * Git commit.
  * Build number.
  * Version number.
  * Toolchain version.
  * Dependency lockfiles.
  * Build configuration.
  * Backend environment.
  * Artifact hashes.
* Identify the app’s critical user journeys:

  * Installation and first launch.
  * Registration and authentication.
  * Primary product action.
  * Purchase or subscription.
  * Data creation and recovery.
  * Logout and account deletion.
* Identify “crown-jewel” assets:

  * Credentials.
  * Personal data.
  * Payment entitlements.
  * User-created content.
  * Proprietary models or algorithms.
  * Administrative functionality.
* Classify data:

  * Public.
  * Internal.
  * Confidential.
  * Highly sensitive.
  * Regulated.
* Define severity before auditing:

  * **P0:** active security exposure, data loss, legal breach, or total product failure.
  * **P1:** critical journey unavailable or materially unsafe.
  * **P2:** significant degradation with a workaround.
  * **P3:** minor defect or maintainability issue.
* Require evidence for every result:

  * Pass.
  * Fail.
  * Partial.
  * Not applicable, with rationale.
  * Unknown.

For release decisions, **unknown should be treated as failed**, not as implicitly acceptable.

---

## 1. Product and release readiness

### Product definition

* Is the target user clearly defined?
* Is the problem solved by the app obvious during first use?
* Can a new user understand the primary value proposition without external explanation?
* Does the product provide useful value before demanding registration, payment, or excessive permissions?
* Are core features complete rather than technically present but operationally unusable?
* Are experimental features clearly separated from stable features?
* Are deprecated or abandoned flows still visible?

### Critical journeys

Audit every important journey from beginning to end:

* Fresh installation.
* First launch.
* Onboarding.
* Registration.
* Login.
* Password or credential recovery.
* Primary workflow.
* Save and resume.
* Sharing or exporting.
* Purchase.
* Subscription restoration.
* Logout.
* Account deletion.
* Reinstallation and data recovery.

For each journey, test:

* Happy path.
* Invalid input.
* Empty state.
* Slow response.
* Server error.
* Network loss.
* Permission denial.
* User cancellation.
* Duplicate submission.
* App backgrounding.
* Process termination.
* Expired session.

### Release scope

* Is the release scope frozen?
* Are uncompleted features disabled rather than merely hidden visually?
* Are feature flags configured correctly in production?
* Are remote-config defaults safe if the configuration service is unavailable?
* Can risky features be disabled remotely?
* Are backend changes backward-compatible with the previous mobile version?
* Is there a rollback strategy?
* Are known limitations documented?
* Has customer support been given the release notes and known-issue list?
* Is there a clear operational owner for release day?

---

## 2. Architecture and system design

A good audit does not require a particular pattern such as MVVM, MVI, Redux, Clean Architecture, or VIPER. It requires that the chosen architecture have clear ownership, boundaries, and failure behavior.

### Architecture visibility

* Is there an up-to-date architecture diagram?
* Does it show:

  * UI layers.
  * State management.
  * Domain or business logic.
  * Data access.
  * Local storage.
  * Network clients.
  * Background workers.
  * Native platform integrations.
  * External services.
* Is the runtime data flow understandable?
* Are trust boundaries documented?
* Are sensitive-data flows documented?
* Are major design decisions recorded as ADRs or equivalent?

### Module boundaries

* Are modules based on clear responsibilities?
* Is dependency direction intentional?
* Can feature modules be changed without touching unrelated functionality?
* Is shared code truly shared, or has it become an unstructured utility layer?
* Are domain rules independent of UI frameworks where practical?
* Are persistence details leaking into presentation code?
* Are networking models used directly as UI models?
* Is one feature able to mutate another feature’s state unexpectedly?
* Are cyclic dependencies prevented?

### State ownership

* Is there a clear source of truth for each state?
* Can multiple parts of the app write conflicting values?
* Is transient UI state separated from persisted business state?
* Is state restored correctly after process death?
* Are stale server responses able to overwrite newer state?
* Are asynchronous operations cancelled when screens disappear?
* Are duplicate requests or duplicate UI events possible?
* Are navigation events idempotent?

### Concurrency

* Is work assigned to appropriate threads or executors?
* Can blocking I/O occur on the main thread?
* Are concurrency primitives used consistently?
* Are mutable shared objects protected?
* Are race conditions possible during:

  * Authentication refresh.
  * Database writes.
  * File operations.
  * Sync.
  * Purchases.
  * Navigation.
* Can cancelled operations still commit state?
* Are deadlocks or lock inversions possible?
* Is structured concurrency used where supported?
* Are background jobs bounded and observable?

### Lifecycle design

* Does the architecture assume the application process remains alive?
* Can a screen be reconstructed from durable state?
* Are background tasks designed around OS scheduling constraints?
* Can operations continue safely after the UI disappears?
* Are long operations resumable?
* Are lifecycle callbacks used as business-logic containers?
* Are observers, subscriptions, delegates, and listeners removed correctly?
* Are resources closed deterministically?

### Cross-platform architecture

For Flutter, React Native, Kotlin Multiplatform, .NET MAUI, Capacitor, Ionic, or other cross-platform stacks:

* Is the framework version actively supported?
* Is the native bridge boundary documented?
* Are high-frequency bridge calls causing latency?
* Are native plugins maintained and compatible with current platforms?
* Is native functionality abstracted without hiding important platform differences?
* Is there a controlled native escape hatch?
* Are iOS and Android behaviors tested independently?
* Can the app upgrade framework versions without a full rewrite?
* Are generated native projects treated as disposable or hand-maintained? Is that policy explicit?
* Does the team understand the native crash, signing, packaging, and lifecycle layers beneath the framework?

---

## 3. Technology stack

### Platform stack

Document and assess:

* iOS:

  * Swift and Objective-C versions.
  * SwiftUI versus UIKit.
  * Swift concurrency adoption.
  * Minimum deployment target.
  * Xcode and SDK version.
* Android:

  * Kotlin and Java versions.
  * Compose versus Views.
  * Coroutines and Flow usage.
  * Gradle and Android Gradle Plugin versions.
  * Minimum and target SDK.
* Cross-platform:

  * Flutter/Dart.
  * React Native/JavaScript/TypeScript.
  * Kotlin Multiplatform.
  * .NET MAUI.
  * Ionic/Capacitor.
  * Unity or game engines.

### Stack fitness

* Is the stack appropriate for the app’s latency, hardware, graphics, security, and offline requirements?
* Are unsupported or end-of-life components present?
* Is the team dependent on one engineer who understands a critical layer?
* Is the stack overly complex for the product?
* Is there unnecessary duplication between native and shared implementations?
* Does the stack support required accessibility functionality?
* Can platform APIs be adopted promptly?
* Are build times and developer feedback loops acceptable?
* Are debugging and profiling tools adequate?
* Is the architecture constrained by framework limitations that the product is already exceeding?
* Is the application locked to a vendor with no practical migration path?

---

## 4. Dependencies and software supply chain

### Inventory

* Generate a complete dependency inventory.
* Include:

  * Direct dependencies.
  * Transitive dependencies.
  * Native frameworks.
  * Build plugins.
  * Code generators.
  * JavaScript packages.
  * CocoaPods, Swift Packages, Gradle modules, Maven artifacts, Flutter packages, and native binaries.
* Generate an SBOM for the release artifact.
* Confirm that lockfiles are committed.
* Confirm that dependency versions are pinned appropriately.

### Dependency health

For every significant dependency:

* Is it actively maintained?
* When was the last security update?
* Does it support the current platform SDK?
* Is it maintained by a credible owner?
* Is there a documented vulnerability history?
* Is it replaceable?
* Does it increase startup time, binary size, memory, or permissions?
* Does it add native code?
* Does it open sockets, start services, or schedule background work?
* Does it collect telemetry?
* Does it execute before user consent?
* Does it use reflection or dynamic code loading?
* Does it introduce duplicated functionality already present elsewhere?

### Supply-chain controls

* Run software-composition analysis.
* Run known-vulnerability scans.
* Scan build scripts and CI actions, not only runtime packages.
* Verify package provenance where possible.
* Reject dependencies fetched from untrusted repositories.
* Prevent dependency confusion.
* Restrict arbitrary post-install scripts.
* Verify binary frameworks and checksums.
* Review maintainer changes for critical packages.
* Restrict CI dependency-update automation from auto-merging sensitive changes.
* Ensure emergency dependency patches can be released quickly.

### Licensing

* Identify each open-source license.
* Check attribution obligations.
* Check source-distribution obligations.
* Check copyleft implications.
* Check whether model weights, fonts, media, icons, and datasets have separate licenses.
* Include required notices in the application or distribution package.
* Confirm commercial use is permitted.

---

## 5. Code quality and maintainability

### Static quality

* Run platform-native linting.
* Run language-level static analysis.
* Treat relevant compiler warnings as failures.
* Scan for:

  * Force unwraps.
  * Unsafe casts.
  * Nullability violations.
  * Unchecked return values.
  * Unreachable code.
  * Unhandled promises or futures.
  * Deprecated APIs.
  * Thread-safety warnings.
* Enforce formatting and import rules.
* Identify excessive complexity.
* Identify oversized classes, screens, reducers, view models, or services.
* Identify duplicate business logic.

### Error handling

* Does every external operation have an explicit failure path?
* Are errors typed or categorised?
* Are technical errors translated into useful user-facing messages?
* Are retryable and non-retryable errors distinguished?
* Are cancellations treated differently from failures?
* Are errors swallowed silently?
* Are catch-all exception handlers hiding defects?
* Can partial operations leave data inconsistent?
* Are error messages exposing backend details or sensitive information?
* Are fatal assertions or development-only traps reachable in production?

### Resource management

* Are file handles closed?
* Are database cursors or transactions closed?
* Are streams and sockets closed?
* Are media resources released?
* Are camera, microphone, location, and Bluetooth sessions ended correctly?
* Are observers and listeners removed?
* Are timers invalidated?
* Can background jobs outlive their owner?
* Are retain cycles or leaked contexts present?
* Are large buffers retained unnecessarily?

### Production cleanliness

* No development endpoints.
* No staging credentials.
* No mock data.
* No hidden administrative screen unintentionally enabled.
* No verbose network logging.
* No debug overlays.
* No test certificates.
* No bypass authentication flag.
* No hardcoded premium entitlement.
* No unresolved release-critical `TODO`, `FIXME`, or temporary workaround.
* No debug menu accessible through a predictable gesture or URL unless intentionally secured.

### Maintainability

* Is code ownership defined?
* Are high-risk components reviewed by more than one engineer?
* Can business logic be tested without launching the full app?
* Are platform-specific workarounds documented?
* Are workarounds tied to issue numbers and removal conditions?
* Is naming consistent?
* Are public APIs minimal?
* Is configuration centralised?
* Is dead code removed rather than indefinitely retained?

---

## 6. Security

OWASP MASVS divides mobile security into storage, cryptography, authentication, network communication, platform interaction, code quality, resilience, and privacy. The remote API must also be assessed; a secure client cannot compensate for broken server authorization. ([mas.owasp.org][2])

### Threat model

* Identify attackers:

  * Anonymous remote attacker.
  * Malicious authenticated user.
  * Compromised device.
  * Malicious application on the same device.
  * Network attacker.
  * Rogue employee.
  * Compromised third-party SDK.
* Identify attack surfaces:

  * API endpoints.
  * Deep links.
  * Custom URL schemes.
  * WebViews.
  * Exported Android components.
  * App extensions.
  * Shared storage.
  * Push notifications.
  * Clipboard.
  * Local databases.
  * Cached files.
  * Backup data.
  * Inter-process communication.
* Document abuse cases, not only software defects:

  * Account farming.
  * Scraping.
  * Subscription fraud.
  * Referral abuse.
  * Automated content generation.
  * Resource exhaustion.
  * Brute force.
  * Spam.

### Secrets and configuration

* No private API secret should be trusted merely because it is embedded in the app.
* Inspect the compiled binary, resources, strings, JavaScript bundles, source maps, and configuration files.
* Check for:

  * API keys.
  * Service credentials.
  * Private certificates.
  * Encryption keys.
  * Admin URLs.
  * Database credentials.
  * Analytics secrets.
* Public client identifiers should be restricted by:

  * Bundle ID or package name.
  * Signing certificate.
  * Allowed API.
  * Rate limits.
  * Environment.
* Secrets used by CI must reside in a proper secret store.
* Production and staging credentials must be isolated.
* Secrets must be rotatable without publishing a new app where possible.

### Authentication

* Test registration, login, logout, recovery, SSO, passkeys, MFA, and biometric flows.
* Prevent account enumeration.
* Rate-limit authentication attempts.
* Enforce secure password and recovery policies where passwords are used.
* Validate OAuth:

  * State.
  * Nonce.
  * PKCE.
  * Redirect URI.
  * Issuer.
  * Audience.
* Do not use embedded client secrets as proof of app identity.
* Ensure account linking cannot merge the wrong identities.
* Require reauthentication for highly sensitive actions.
* Treat biometrics as a local authorization mechanism, not automatic proof that the backend user remains valid.
* Define behavior when biometric enrolment changes.

### Session management

* Store tokens in Keychain or Android Keystore-backed storage as appropriate.
* Use short-lived access tokens.
* Rotate refresh tokens where supported.
* Detect refresh-token reuse.
* Enforce token expiration.
* Support server-side revocation.
* Invalidate or appropriately expire sessions on logout.
* Handle “logout all devices.”
* Prevent parallel refresh races.
* Do not expose tokens in URLs, logs, analytics, crash reports, or notifications.
* Clear sensitive in-memory and persistent state on logout.
* Test:

  * Expired token.
  * Revoked token.
  * Deleted account.
  * Disabled account.
  * Password change.
  * Device clock error.
  * Multiple devices.
  * Offline launch with expired credentials.

### Authorization

Authorization must be enforced by the server.

* Test object-level authorization.
* Test role-level authorization.
* Test tenant separation.
* Change IDs in requests and verify another user’s data cannot be accessed.
* Verify administrative APIs independently.
* Ensure UI hiding is not treated as authorization.
* Verify ownership on:

  * Reads.
  * Writes.
  * Deletes.
  * Exports.
  * Shares.
  * Attachments.
* Check batch endpoints and search endpoints.
* Check indirect references such as file URLs.
* Check push-notification actions.
* Check offline queues that execute after the user’s authorization changes.

### Local storage

Inspect:

* Databases.
* Preferences.
* Files.
* Caches.
* Logs.
* Cookies.
* Web storage.
* Backups.
* Screenshots.
* Temporary files.
* Shared containers.
* External storage.

Verify:

* Sensitive data is minimised.
* Platform-secure storage is used for credentials and keys.
* Sensitive files use appropriate file protection.
* Android backup rules exclude sensitive data.
* iCloud and device backups do not capture prohibited data.
* Cached content is cleared at appropriate times.
* Logout clears user-specific state.
* One user cannot see another user’s residual data after account switching.
* Notification content does not expose sensitive information.
* Sensitive data is not left in clipboard history unnecessarily.
* App-switcher snapshots are handled appropriately for highly sensitive screens.
* Local databases are not assumed secure merely because they are in the application sandbox.

### Network security

* HTTPS only.
* No “trust all certificates” logic.
* No hostname-verification bypass.
* No cleartext fallback.
* No expired or self-signed production certificates.
* TLS errors must fail closed.
* Sensitive data must not appear in query parameters.
* Redirects must be validated.
* Request signing or device attestation should be used only where justified by the threat model.
* Certificate pinning, when used:

  * Must have backup pins or a rotation strategy.
  * Must not create an unrecoverable outage.
  * Must be tested against certificate renewal.
* Test through:

  * Intercepting proxy.
  * VPN.
  * Captive portal.
  * Invalid certificate.
  * Hostname mismatch.
  * Slow TLS negotiation.

### Deep links and platform surfaces

* Use verified Universal Links or Android App Links where possible.
* Validate all deep-link parameters.
* Require authentication and authorization after navigation.
* Prevent links from invoking unintended internal screens.
* Prevent open redirects.
* Prevent arbitrary file access.
* Prevent JavaScript injection.
* Ensure custom schemes cannot be hijacked for sensitive callbacks.
* Audit Android exported activities, services, receivers, and providers.
* Audit iOS URL handlers, extensions, associated domains, and shared containers.
* Validate incoming intents and IPC messages.
* Test deep links from:

  * Logged-out state.
  * Expired-session state.
  * Background.
  * Terminated process.
  * Malicious parameters.
  * Duplicate invocation.

### WebViews

* Avoid WebViews for authentication when a secure system browser flow is available.
* Disable unnecessary JavaScript.
* Restrict navigation to allowed origins.
* Validate redirects.
* Do not expose dangerous JavaScript bridges.
* Disable unnecessary file access.
* Treat downloaded files as untrusted.
* Prevent mixed content.
* Prevent arbitrary URL loading.
* Clear sensitive cookies and web storage at logout.
* Verify external links do not inherit privileged session state.
* Test XSS and malicious HTML where content is user-controlled.

### Cryptography

* Do not invent cryptographic algorithms.
* Use platform and established library primitives.
* Use authenticated encryption where confidentiality and integrity are required.
* Generate cryptographically secure random values.
* Do not reuse nonces or initialization vectors.
* Do not hardcode encryption keys.
* Separate keys by purpose and environment.
* Define key rotation.
* Define what happens when keys are lost or invalidated.
* Ensure encryption keys are not backed up alongside encrypted data.
* Verify cryptography is not being used to conceal an insecure architecture.

### Device integrity and resilience

For high-risk applications:

* Consider Play Integrity or Apple attestation mechanisms.
* Treat jailbreak or root detection as a risk signal, not an absolute security boundary.
* Test instrumentation, hooking, repackaging, and tampering risks.
* Consider anti-debugging or obfuscation proportionate to risk.
* Ensure resilience controls do not lock out legitimate users unpredictably.
* Keep critical authorization and entitlement logic server-side.
* Assume a determined attacker can inspect and modify client-side code.

### Logging and telemetry

* No passwords.
* No access or refresh tokens.
* No full payment details.
* No private message contents unless strictly necessary.
* No raw health or location data without a justified need.
* No sensitive request or response bodies.
* No session identifiers that permit replay.
* Production logs should be bounded and redact sensitive fields.
* Crash-report attachments should be reviewed for private data.
* Analytics properties should be allowlisted rather than accepting arbitrary objects.

---

## 7. Privacy and data governance

Apple requires privacy disclosures and privacy policies to match the app’s actual collection and sharing behavior. Apple privacy manifests must account for required-reason APIs and relevant third-party SDKs. Android similarly expects permissions to be requested in context, explained, and handled gracefully when denied. ([Apple Developer][3])

### Data inventory

For every data element, record:

* What is collected?
* Why is it collected?
* Where is it collected?
* Is it required or optional?
* Where is it stored?
* How long is it retained?
* Who receives it?
* Which SDK receives it?
* Is it linked to identity?
* Can the user delete it?
* Is it used for advertising, profiling, training, or attribution?

Include:

* Account information.
* Contact information.
* Device identifiers.
* Advertising identifiers.
* IP addresses.
* Precise and approximate location.
* Contacts.
* Photos and media.
* Camera and microphone data.
* Health data.
* Financial data.
* Browsing or search history.
* Diagnostics.
* Crash logs.
* Analytics events.
* Push tokens.
* Clipboard content.
* AI prompts and outputs.

### Data minimisation

* Is every collected field necessary?
* Can collection happen on-device instead?
* Can precise location be replaced with approximate location?
* Can raw content be replaced with a derived value?
* Can identifiers be rotated or pseudonymised?
* Is data being retained “just in case”?
* Does a third-party SDK collect more than the product requires?
* Is analytics capturing complete objects instead of approved fields?

### Permissions

* Request permissions only when the related feature is invoked.
* Explain why the permission is needed before the system prompt where appropriate.
* Avoid requesting every permission during onboarding.
* Test:

  * Denied.
  * Denied permanently.
  * Later granted.
  * Revoked in Settings.
  * Restricted by parental or device controls.
  * Limited photo-library access.
  * Approximate rather than precise location.
* Provide graceful degradation.
* Avoid blocking unrelated features.
* Ensure permission descriptions match actual use.

### Consent

* Consent must be specific and comprehensible.
* Preselected consent should be avoided where legally inappropriate.
* Separate necessary processing from optional analytics or marketing.
* Record consent version and timestamp where required.
* Support consent withdrawal.
* Stop future processing after withdrawal.
* Ensure SDKs do not initialize before required consent.
* Ensure server behavior respects mobile consent state.
* Ensure privacy choices survive reinstall or account use on another device where appropriate.

### Retention, export, and deletion

* Publish a retention schedule.
* Implement automatic expiration where required.
* Support account deletion.
* Delete or anonymise related backend data.
* Handle backups and delayed-deletion systems.
* Revoke tokens and sessions after deletion.
* Prevent a deleted account from continuing to receive notifications.
* Define legal holds.
* Support data export where required.
* Verify deletion through an end-to-end test.
* Avoid claiming immediate deletion if backups retain data for a defined period.

### Privacy declarations

Verify consistency among:

* Actual runtime collection.
* iOS privacy labels.
* Apple privacy manifest.
* Required-reason API declarations.
* Third-party SDK manifests.
* Google Play Data safety form.
* Privacy policy.
* In-app consent text.
* SDK documentation.
* Backend logs.
* Analytics schemas.

A declaration mismatch is a release blocker even when the underlying collection is otherwise legitimate.

---

## 8. Authentication, account, and identity flows

Beyond the security mechanics, evaluate the complete user lifecycle.

* Registration succeeds under normal and poor network conditions.
* Duplicate email or phone behavior is understandable.
* Verification links and codes expire appropriately.
* Verification codes cannot be reused.
* Email and phone changes require appropriate verification.
* Account recovery does not expose whether an account exists.
* Social-login cancellation returns the user to a valid state.
* SSO account linking cannot create duplicate or hijacked accounts.
* Passkey registration and login work across supported devices.
* MFA recovery is documented.
* Lost-device recovery is possible without undermining security.
* Disabled and suspended account states are handled.
* Logout removes local personal data.
* Switching accounts does not leak prior account data.
* Account deletion is discoverable.
* Deletion warnings explain consequences.
* Re-registration after deletion has defined behavior.
* Administrative impersonation, when supported, is strongly controlled and audited.

---

## 9. Backend, API, and cloud services

### API contract

* Is the API documented?
* Are request and response schemas versioned?
* Are unknown fields tolerated?
* Are missing fields handled safely?
* Can old mobile versions continue working after a server deployment?
* Are server-side defaults safe?
* Are error codes stable and machine-readable?
* Is pagination deterministic?
* Are sorting and filtering rules documented?
* Are upload and download limits enforced?

### Resilience

* Every request has an appropriate timeout.
* Retries are limited.
* Exponential backoff and jitter are used where appropriate.
* Non-idempotent operations are not blindly retried.
* Idempotency keys protect purchases and create operations.
* Circuit breakers or load shedding exist where needed.
* Partial failures are surfaced accurately.
* Queued operations have expiry and retry policies.
* The app distinguishes:

  * Offline.
  * Timeout.
  * Server unavailable.
  * Authentication failure.
  * Authorization failure.
  * Validation failure.
  * Rate limit.
* The API handles client clock skew.
* Client and server agree on time zones and date formats.

### Backend security

* Authorization is enforced for every endpoint.
* Rate limits exist by account, device, IP, or operation as appropriate.
* Abuse controls exist for expensive operations.
* Administrative APIs are isolated.
* Debug endpoints are disabled in production.
* Internal error details are not returned to clients.
* File uploads are validated by type, size, and content.
* Uploaded files are scanned where relevant.
* Signed URLs are short-lived and scoped.
* Webhooks are signed and replay-protected.
* Push-notification payloads are authenticated by server state, not trusted as authority.

### Purchases and entitlements

* Receipts or transactions are verified securely.
* Entitlements are determined server-side where practical.
* Pending purchases are handled.
* Refunds and revocations are handled.
* Subscription expiry and grace periods are handled.
* Restore purchases works.
* Entitlements synchronize across devices.
* Duplicate callbacks are idempotent.
* Offline entitlement behavior is explicitly defined.
* Clock manipulation does not grant access indefinitely.

### Operational resilience

* Backups exist.
* Restore has been tested.
* Database migrations are reversible or recoverable.
* Recovery time and recovery point objectives are defined.
* Third-party outages have fallbacks or clear degraded behavior.
* Credentials and signing keys can be rotated.
* Production access is role-controlled and audited.
* No single developer account is the sole operational dependency.

---

## 10. Data storage, cache, and synchronisation

### Schema and migration

* Test migration from every supported released version.
* Test users who skipped multiple versions.
* Test migration with:

  * Large datasets.
  * Empty datasets.
  * Partially corrupted data.
  * Interrupted migration.
  * Low disk space.
  * Low memory.
* Use transactions or atomic migration mechanisms.
* Do not destroy user data merely because migration fails.
* Record schema versions.
* Define downgrade behavior.
* Ensure backend schema changes remain compatible during staged rollout.

### Data integrity

* Writes are atomic where necessary.
* Multi-step updates cannot leave invalid intermediate state.
* Duplicate submissions are handled.
* Database constraints reflect business invariants.
* File and database state cannot diverge silently.
* Corruption is detected.
* Recovery behavior is user-safe.
* Caches are not mistaken for authoritative data.
* Cache invalidation is defined.
* Sensitive cached material expires.

### Offline and sync

* Define which operations work offline.
* Queue offline mutations durably.
* Preserve ordering where necessary.
* Prevent duplicate replay.
* Handle server rejection after an optimistic local update.
* Define conflict resolution:

  * Server wins.
  * Client wins.
  * Latest timestamp.
  * Field-level merge.
  * User resolution.
* Test two devices editing the same record.
* Test device clock differences.
* Test deletion conflicts.
* Test account logout with queued operations.
* Test app uninstall before sync completes.
* Surface unsynced state to the user when material.

### Storage pressure

* Test full disk.
* Bound cache growth.
* Remove orphan files.
* Avoid retaining multiple copies of large media.
* Stream large files where practical.
* Clean failed downloads and uploads.
* Respect platform storage-cleanup behavior.
* Avoid repeatedly redownloading unchanged content.

---

## 11. Performance and resource efficiency

Performance must be measured on release builds and representative physical devices. Apple provides launch, hang, hitch, memory, and termination diagnostics through Xcode and Organizer; Android emphasizes startup latency, rendering jank, memory, battery, and Android vitals. ([Apple Developer][4])

### Establish budgets

Define measurable budgets for:

* Cold startup.
* Warm startup.
* Time to first meaningful content.
* Time to interactive.
* Screen transition latency.
* Search response.
* Save operation.
* Upload and download.
* Memory under normal and heavy use.
* Binary and installed size.
* Network transfer per common session.
* Battery consumption during representative use.

Measure p50, p95, and worst credible cases rather than relying only on an average.

### Startup

* Measure cold, warm, and resumed launch.
* Test logged-in and logged-out states.
* Remove unnecessary SDK initialization.
* Defer analytics, advertising, update checks, and noncritical database work.
* Avoid synchronous network requests.
* Avoid blocking secure-storage reads where possible.
* Avoid loading full datasets before first render.
* Verify splash screens do not conceal excessive startup.
* Ensure first content is useful rather than an empty shell.
* Test after fresh install and after upgrade.
* Test on low-end and older devices.

On Android, evaluate Baseline Profiles and startup profiling for important journeys. ([Android Developers][5])

### UI responsiveness

* No network, disk, database, decompression, or heavy parsing on the main thread.
* Profile scrolling.
* Profile navigation transitions.
* Profile animations.
* Profile long lists.
* Profile image-heavy screens.
* Test rapid repeated taps.
* Prevent accidental duplicate actions.
* Avoid unnecessary recomposition or rerendering.
* Avoid excessive layout passes.
* Avoid loading full-resolution images into small views.
* Cancel work for invisible content.
* Ensure loading indicators themselves remain responsive.

### Memory

* Measure baseline and peak memory.
* Look for continual growth across repeated navigation.
* Detect:

  * Retain cycles.
  * Leaked activities, fragments, contexts, views, and controllers.
  * Large image retention.
  * Unbounded caches.
  * Unclosed streams.
  * WebView leaks.
  * Native-memory leaks.
* Test memory warnings and low-memory callbacks.
* Test large content.
* Test long-running sessions.
* Test switching between multiple accounts or workspaces.
* Test repeated camera, audio, or video use.
* Verify the app can recover after OS memory pressure.

### CPU, battery, and thermal behavior

* Profile idle CPU usage.
* Confirm timers are not waking the app unnecessarily.
* Bound location update frequency.
* Bound Bluetooth and sensor polling.
* Avoid continuous background execution.
* Batch network operations where appropriate.
* Test Low Power Mode and battery saver.
* Test thermal throttling during media, AI, mapping, or graphics workloads.
* Ensure background work stops when no longer necessary.
* Ensure retries cannot create a battery-draining loop.

### Network

* Measure request count.
* Measure payload size.
* Compress appropriate content.
* Avoid repeated downloads.
* Use caching correctly.
* Paginate large collections.
* Support resumable transfers for large files.
* Cancel obsolete requests.
* Prevent polling when push or server events are available.
* Test:

  * High latency.
  * Packet loss.
  * Low bandwidth.
  * Network handoff.
  * Captive portal.
  * Offline.
  * IPv6-only environments where relevant.

### Binary and installation size

* Inspect architecture slices.
* Remove unused resources.
* Remove duplicate libraries.
* Strip debug symbols from shipped binaries while retaining symbols separately.
* Review bundled fonts, videos, models, and localization assets.
* Use app thinning, dynamic delivery, or equivalent where appropriate.
* Check download size and final installed size.
* Check size after several months of cached data.
* Ensure updates do not unnecessarily redownload large assets.

---

## 12. Reliability and application lifecycle

### Stability

* No reproducible crash in any critical journey.
* No ANR or significant hang.
* No crash loop after launch.
* No repeated crash caused by corrupt local state.
* No crash due to malformed server data.
* No crash due to missing optional hardware.
* No crash when permissions are denied or revoked.
* No crash when an activity or view controller is recreated.
* No crash on notification or deep-link entry into a cold process.

### Lifecycle events

Test during every major operation:

* Background app.
* Foreground app.
* Lock device.
* Unlock device.
* Rotate device.
* Fold or unfold device.
* Enter split screen.
* Resize window.
* Receive phone call.
* Receive alarm or system interruption.
* Connect or disconnect headphones.
* Change audio route.
* Terminate process.
* Force stop.
* Reboot device.
* Upgrade OS.
* Upgrade application.

### Environmental changes

* Wi-Fi to cellular.
* Cellular to Wi-Fi.
* Airplane mode.
* VPN enabled or disabled.
* Proxy or captive portal.
* Time zone change.
* Daylight saving transition.
* Manual clock change.
* Locale change.
* Calendar-system change.
* Dark-mode change.
* Text-size change.
* Permission revocation.
* Biometric enrolment change.
* Low disk.
* Low memory.
* Battery saver.
* Data saver.

### Failure recovery

* Server unavailable.
* Authentication provider unavailable.
* Analytics unavailable.
* Feature-flag service unavailable.
* Push service unavailable.
* Payment service unavailable.
* CDN unavailable.
* One API succeeds and the next fails.
* Upload interrupted at 99%.
* Download returns corrupt content.
* Database becomes unavailable.
* Background worker is killed.
* Retry queue survives process death.
* App does not create duplicate records after recovery.
* User receives an accurate status rather than a false success.

---

## 13. User experience

### First-use experience

* App launches into a meaningful state.
* Onboarding is proportional to complexity.
* Users can skip nonessential education.
* Permission prompts are contextual.
* Users know what to do next.
* Loading is not mistaken for failure.
* Registration requirements are justified.
* The first successful outcome occurs quickly.

### Navigation

* Back behavior is predictable.
* Tab state is preserved appropriately.
* Deep links land in the correct context.
* Modal screens can be dismissed.
* Navigation does not create duplicate screens.
* Login redirects return to the originally requested destination.
* Destructive actions do not happen through accidental gestures.
* Navigation survives state restoration.
* External browser or system-settings trips return cleanly.

### Screen states

Every data-driven screen should have deliberate states for:

* Initial loading.
* Refreshing.
* Empty.
* Filtered empty.
* Offline.
* Error.
* Partial data.
* Stale data.
* Permission denied.
* Account restricted.
* Content deleted.
* Rate limited.
* Maintenance.

### Forms and input

* Correct keyboard appears.
* Autofill works appropriately.
* Password managers and passkeys work.
* Validation is specific.
* Errors appear next to the relevant field.
* User input is preserved after recoverable failure.
* Submit buttons prevent duplicate submission.
* Long content can be entered and reviewed.
* Pasted Unicode and emoji are handled.
* Keyboard does not cover fields or actions.
* Hardware keyboard navigation works where relevant.
* Date, number, currency, and phone inputs are locale-aware.

### User control

* Destructive actions require appropriate confirmation.
* Undo is offered where feasible.
* Cancellation works.
* Long operations display progress.
* Users can retry.
* Users can distinguish local, pending, and synchronized state.
* Settings are discoverable.
* Notification preferences are controllable.
* Privacy controls are discoverable.
* Account deletion is not hidden.
* Help and support paths work.

### Visual quality

* Safe areas and cutouts are respected.
* No clipped text.
* No overlapping controls.
* No low-resolution assets.
* Dark mode is complete.
* Loading states do not cause excessive layout shifts.
* Animations reinforce rather than obstruct.
* Screens remain coherent at large text sizes.
* Tablet screens do not simply stretch narrow phone layouts without consideration.
* Empty space and density remain intentional across device sizes.

---

## 14. Accessibility

Accessibility requires automated audits and manual use with assistive technologies. Apple specifically recommends accessibility audits together with practical testing using technologies such as VoiceOver and Dynamic Type. ([Apple Developer][6])

### Screen readers

* Test VoiceOver.
* Test TalkBack.
* Every actionable control has an accessible name.
* Role, value, state, and hint are accurate.
* Decorative content is hidden from the accessibility tree.
* Grouping is logical.
* Focus order follows visual and task order.
* Focus moves appropriately after navigation, dialogs, and errors.
* Dynamic updates are announced.
* Custom controls expose equivalent semantics.
* Swipe actions have accessible alternatives.
* Charts and visualisations have meaningful descriptions.
* No critical content is conveyed only through an image.

### Text and visual accessibility

* Dynamic Type or font scaling works.
* Content reflows at accessibility sizes.
* Text is not clipped.
* Controls do not overlap.
* Contrast is sufficient.
* Information is not conveyed by colour alone.
* Links are distinguishable.
* Selected, disabled, and error states remain perceivable.
* Bold text and increased contrast settings are respected where applicable.
* Light and dark themes both meet accessibility requirements.

### Motor and interaction accessibility

* Touch targets are adequately sized.
* Controls are not placed excessively close together.
* Drag-only interactions have alternatives.
* Multi-finger or complex gestures have alternatives.
* Time-limited tasks can be extended where appropriate.
* Switch Control and equivalent navigation work.
* External keyboard navigation works where expected.
* Voice Control labels are meaningful.
* Orientation is not unnecessarily restricted.

### Motion, audio, and media

* Reduce Motion is respected.
* Essential functionality does not depend on animation.
* Flashing content is avoided.
* Audio has captions or transcripts where required.
* Information conveyed through sound has a visual alternative.
* Information conveyed through haptics has another alternative.
* Media controls are accessible.
* Background audio does not interfere with assistive speech unnecessarily.

### Accessibility automation

* Add accessibility audits to automated UI tests.
* Detect missing labels.
* Detect duplicate identifiers.
* Detect clipped content.
* Detect insufficient contrast where tooling supports it.
* Run tests at multiple text sizes.
* Include accessibility regressions in release gating.

---

## 15. Localization and internationalisation

* All user-visible strings are externalised.
* No string concatenation that breaks grammar.
* Plural rules are locale-aware.
* Gender and grammatical variations are supported where necessary.
* Dates, times, numbers, and currencies use locale-aware formatting.
* Server timestamps have explicit time zones.
* Right-to-left layouts work.
* Icons that imply direction mirror appropriately.
* Phone numbers and addresses are not assumed to use one national format.
* Text fields support Unicode.
* Search and sorting handle locale rules.
* Long translated strings do not clip.
* Buttons accommodate text expansion.
* Screens are tested in a pseudo-localized locale.
* Screenshots and store metadata are localized where promised.
* Legal and pricing language is correct for each market.
* Content unavailable in a region is handled intentionally.
* User-selected language and system language behavior are defined.
* Notifications are localized.
* Backend-generated errors are not exposed as untranslated technical text.

---

## 16. Device, display, and OS compatibility

Android’s current quality guidance explicitly covers phones, tablets, foldables, desktops, multi-window operation, multiple displays, and changing device postures. ([Android Developers][7])

### Device matrix

Test at minimum:

* Oldest supported OS.
* Most common supported OS.
* Latest stable OS.
* Low-end device.
* Mid-range device.
* High-end device.
* Small screen.
* Large phone.
* Tablet.
* Foldable where Android is supported.
* Devices with display cutouts.
* High-refresh-rate device where animations matter.

### Display configurations

* Portrait.
* Landscape.
* Split screen.
* Resizable window.
* Folded and unfolded postures.
* External display where supported.
* Different aspect ratios.
* Large text.
* Display zoom.
* Dark mode.
* High contrast.
* Reduced motion.
* Right-to-left layout.

### Hardware capabilities

Test hardware present, absent, denied, unavailable, and interrupted:

* Camera.
* Microphone.
* GPS.
* Biometrics.
* Bluetooth.
* NFC.
* Accelerometer.
* Gyroscope.
* Proximity sensor.
* External keyboard.
* Headphones.
* Multiple cameras.
* Limited-storage devices.

### Android ecosystem variation

* Test more than a single emulator and Pixel device.
* Include major OEM variations where the user base warrants it.
* Test manufacturer battery restrictions.
* Test notification delivery under aggressive background management.
* Test custom permission-management behavior.
* Test devices without Google Play Services if those markets are supported.
* Test app links and browsers across OEM configurations.

---

## 17. Platform-specific audit

## iOS and iPadOS

### Project and signing

* Bundle identifier correct.
* Marketing version correct.
* Build number unique.
* Correct team and provisioning profile.
* Distribution certificate valid.
* Signing is performed by controlled CI or authorised release personnel.
* Entitlements are minimal.
* Keychain access groups are correct.
* App groups are intentional.
* Associated domains are correct.
* Production APNs environment is used.
* Debug entitlements are absent.

### Privacy and permissions

* Every protected-resource API has an accurate usage description.
* Privacy manifest is present and accurate.
* Required-reason APIs are declared.
* Third-party SDK manifests are included.
* Binary SDK signatures are valid where required.
* Privacy labels match runtime behavior.
* Tracking behavior and consent are correct.
* Background modes are justified.
* Pasteboard and local-network access are justified.

### Platform behavior

* Scene lifecycle works.
* State restoration works.
* Universal Links work.
* Push notifications work from foreground, background, and terminated states.
* Notification actions are authorized server-side.
* Background tasks respect system limits.
* Widgets and extensions handle unavailable shared data.
* Share extensions handle large and malformed input.
* Files and document providers handle security-scoped access.
* Keychain behavior after reinstall is understood.
* iCloud backup behavior is intentional.
* App Transport Security exceptions are minimal and justified.
* StoreKit purchase, restore, pending, refund, and revocation flows work.

### Current Apple submission requirement

As of August 6, 2026, apps uploaded to App Store Connect must be built with Xcode 26 or later using the iOS 26 or corresponding platform SDK. This requirement has applied since April 28, 2026. ([Apple Developer][8])

## Android

### Project and signing

* `applicationId` correct.
* `versionCode` incremented.
* `versionName` correct.
* Release signing is correct.
* Play App Signing configuration is understood.
* Upload key is securely backed up.
* Production signing access is restricted.
* Release build is not debuggable.
* Backup and cleartext-network rules are explicit.
* R8 or equivalent release optimisation is tested.
* Obfuscation mapping files are retained.
* Native debug symbols are uploaded.

### Manifest and components

* Exported activities, services, receivers, and providers are reviewed.
* Intent filters are minimal.
* Permissions are minimal.
* Dangerous permissions are requested contextually.
* Custom permissions use appropriate protection levels.
* Content providers do not expose unintended data.
* FileProvider paths are narrowly scoped.
* Pending intents use correct mutability.
* Foreground services have valid types and user-visible justification.
* Notification channels are configured.
* Background work uses appropriate OS scheduling.
* Android App Links are verified.
* Back navigation is correct.
* Edge-to-edge and system-bar behavior are correct.

### Packaging and runtime

* Android App Bundle is validated.
* Split configurations contain required resources and native libraries.
* ABI coverage is intentional.
* Resource shrinking does not remove dynamically referenced resources.
* Dynamic features install and uninstall safely.
* App update preserves data.
* Downgrade behavior is understood.
* Pre-launch report findings are resolved or accepted explicitly.
* Baseline Profile installation is verified through a supported testing track where used.

### Current Google Play target requirement

As of August 6, 2026, new apps and updates must currently target at least Android 15, API level 35. Starting August 31, 2026, new apps and updates must target Android 16, API level 36 or higher. Existing apps must target at least API level 35 by August 31, 2026 to remain broadly available to users on newer Android versions. ([Google Support][9])

---

## 18. Testing strategy

### Unit tests

* Business rules.
* Validation.
* State reducers.
* View models or presenters.
* Parsing.
* Formatting.
* Authentication state.
* Retry decisions.
* Conflict resolution.
* Entitlement calculations.
* Date and time logic.
* Migration helpers.
* Security-sensitive utility functions.

### Integration tests

* Network client and API.
* Database.
* Secure storage.
* File system.
* Authentication provider.
* Push notification handling.
* Deep links.
* Purchase framework.
* Analytics.
* Feature flags.
* Background workers.
* Native bridge modules.

### Contract tests

* Mobile client and backend schemas.
* Error responses.
* Optional and newly introduced fields.
* Old clients against new servers.
* New clients against old or partially deployed servers where relevant.
* Pagination.
* Idempotency.
* Authentication refresh.
* Webhook or push payload formats.

### UI and end-to-end tests

Automate the most valuable, stable journeys:

* Fresh launch.
* Registration.
* Login.
* Primary task.
* Offline and reconnect.
* Purchase and restore.
* Deep-link entry.
* Notification entry.
* Logout.
* Account deletion.

Do not assess test quality solely by line coverage. Assess whether the highest-risk behavior is exercised.

### Specialised testing

* Static application security testing.
* Software-composition analysis.
* Secret scanning.
* Dynamic security testing.
* API penetration testing.
* Fuzz testing of parsers and deep links.
* Property-based testing of complex state logic.
* Performance benchmarks.
* Memory and leak tests.
* Accessibility tests.
* Screenshot or visual-regression tests.
* Localization tests.
* Database migration tests.
* Install, update, uninstall, and reinstall tests.
* Network degradation tests.
* Battery and background-execution tests.
* Payment sandbox tests.

### Test environment integrity

* The tested release candidate must be built by the production pipeline.
* It must point to production-equivalent services.
* Debug behavior must not invalidate results.
* Test credentials must not be present in the released artifact.
* Test data must represent realistic size and complexity.
* Flaky tests must not simply be rerun until green.
* Quarantined tests must have owners and deadlines.
* Manual test evidence should identify device, OS, build, tester, and date.

---

## 19. Build, CI/CD, and release engineering

### Build reproducibility

* Toolchain versions are pinned.
* Dependencies are locked.
* Clean CI builds succeed.
* Local-only files are not required.
* Generated code is deterministic or controlled.
* Build environment is documented.
* Production builds cannot accidentally use development configuration.
* Environment selection is explicit.
* Artifact hashes are retained.
* Build provenance is retained where practical.

### CI controls

* Pull requests require relevant tests.
* Protected branches are configured.
* Release workflows have restricted permissions.
* CI secrets use least privilege.
* Third-party CI actions and plugins are pinned and reviewed.
* Release approval is separate from ordinary development access where warranted.
* Build logs do not expose secrets.
* Artifacts have defined retention.
* Compromised credentials can be revoked promptly.

### Release configuration

Check the compiled artifact, not merely source configuration:

* Correct API base URL.
* Correct authentication client.
* Correct analytics project.
* Correct crash-reporting project.
* Correct push environment.
* Correct feature-flag environment.
* Correct payment products.
* Correct legal URLs.
* Correct app identifiers.
* Correct certificate pin set, where used.
* No debug flags.
* No staging menus.
* No verbose logging.
* No test entitlement.

### Signing and key management

* Signing keys are backed up securely.
* Access is limited.
* Recovery procedure is documented.
* Rotation procedure is documented.
* No signing key is stored in the repository.
* Departed employees cannot sign releases.
* CI signing credentials are auditable.
* The team understands which keys can and cannot be replaced.
* Certificates and profiles will not expire unexpectedly.

### Symbols and diagnostics

Before release:

* iOS dSYMs are archived and uploaded.
* Android mapping files are archived and uploaded.
* Native symbols are retained.
* JavaScript source maps are uploaded where applicable.
* Build IDs map correctly to symbols.
* A production crash can be symbolicated before launch.
* Debug symbols are not unnecessarily shipped in the public binary.

### Rollout

* Use internal testing first.
* Use TestFlight or an appropriate beta track.
* Use staged or phased rollout.
* Define pause conditions.
* Define rollback or mitigation.
* Confirm backend compatibility with both old and new clients.
* Keep remote defaults safe.
* Identify features that can be disabled independently.
* Avoid coupling an irreversible database migration to an immediate 100% mobile rollout.

### Store submission package

* Store name and subtitle accurate.
* Description matches actual functionality.
* Screenshots match current UI.
* Privacy policy works publicly.
* Support URL works.
* Review notes explain non-obvious behavior.
* Review credentials work.
* Demo data is available where needed.
* Age rating is accurate.
* Encryption/export questions are answered.
* Privacy labels or Data safety form are current.
* In-app products are approved and linked correctly.
* Subscription terms are visible.
* Regional availability is intentional.
* Content rights are documented.

---

## 20. Observability and production operations

### Technical telemetry

Collect enough information to diagnose production problems:

* Crashes.
* Hangs and ANRs.
* Failed launches.
* Out-of-memory termination.
* Startup latency.
* Screen-rendering latency.
* Network failures.
* API latency.
* Background-task failures.
* Database migration failures.
* Push-delivery and handling failures.
* Purchase and entitlement errors.

Telemetry should include:

* App version.
* Build number.
* OS version.
* Device class.
* Release channel.
* Feature-flag state where safe.
* Backend correlation ID.
* Network category.
* Error category.

Do not include unnecessary personal data.

### Business telemetry

Audit whether the team can answer:

* Are users completing onboarding?
* Are users reaching the primary value event?
* Where do critical journeys fail?
* Are purchases completing?
* Are subscriptions restoring?
* Are users stuck in permission or login loops?
* Is a new release changing retention or conversion?
* Are changes caused by one OS, device, region, or app version?

### Alerting

* Alerts exist for significant crash increases.
* Alerts exist for ANR or hang increases.
* Alerts exist for authentication failure spikes.
* Alerts exist for elevated API errors.
* Alerts exist for payment failures.
* Alerts exist for migration failures.
* Alerts are actionable rather than purely informational.
* Alert ownership is defined.
* Escalation paths are defined.
* Thresholds account for normal traffic variation.

### Operational controls

* Feature flags.
* Kill switches.
* Maintenance mode.
* Rate limits.
* Server-side version controls.
* Minimum supported version mechanism.
* Safe forced-update policy.
* Rollback documentation.
* Incident runbooks.
* Vendor contact information.
* Status communication.
* Customer-support scripts.
* Data-correction procedures.

### Post-release review

During staged rollout:

* Compare crash and hang rates with the previous version.
* Compare startup and latency metrics.
* Inspect reviews and support tickets.
* Monitor authentication and payment funnels.
* Check by OS, device, and region.
* Confirm backend capacity.
* Confirm no unexpected data collection.
* Confirm new SDKs are behaving as expected.
* Pause rollout on predefined thresholds rather than relying on intuition.

---

## 21. Monetisation and commercial behavior

### Purchases

* Correct product identifiers.
* Correct pricing and currency display.
* Pending transactions handled.
* User cancellation handled.
* Duplicate transactions handled.
* Interrupted transaction resumes safely.
* Restore purchases works.
* Family or shared entitlements behave as intended.
* Refunds and revocations remove access correctly.
* Entitlements synchronize across devices.
* Server events are idempotent.
* Purchase success is not granted solely from a client callback.

### Subscriptions

* Trial terms are clear.
* Renewal terms are clear.
* Billing period is clear.
* Introductory pricing is clear.
* Upgrade and downgrade behavior is defined.
* Proration is understood.
* Grace period is handled.
* Billing retry is handled.
* Expiry is handled.
* Cancellation instructions are accessible.
* Restore works after reinstall.
* Offline access has a bounded grace policy.
* Subscription state does not depend only on the device clock.

### Advertising

* Consent obtained where required.
* Ads do not initialize before required consent.
* Advertising identifier use is disclosed.
* Child-directed treatment is configured where relevant.
* Ads do not obscure controls.
* Ads do not mimic system messages.
* Rewarded-ad entitlements are fraud-resistant.
* Malicious ad destinations are controlled as far as the SDK permits.
* Ad SDK data collection matches store declarations.

---

## 22. Store, legal, and regulatory compliance

* Privacy policy.
* Terms of service.
* End-user licence terms.
* Open-source notices.
* Copyright ownership.
* Trademark permissions.
* Media and font licences.
* Age rating.
* Regional restrictions.
* Encryption export declarations.
* Tax and trader information.
* Consumer cancellation rights.
* Subscription disclosures.
* Account deletion obligations.
* Data access, correction, and deletion obligations.
* Children’s privacy requirements.
* Health-data rules.
* Financial-service rules.
* Location-data rules.
* Biometric-data rules.
* Workplace or employee-monitoring rules.
* Accessibility obligations.
* Digital Services Act obligations where applicable.
* Sanctions and export restrictions where applicable.

### User-generated content

Where users can publish or communicate:

* Reporting mechanism.
* Blocking mechanism.
* Moderation process.
* Rate limits.
* Spam controls.
* Impersonation controls.
* Harassment and abuse controls.
* Illegal-content escalation.
* Moderator access controls.
* Audit trail.
* Appeals process where appropriate.
* Emergency contact and preservation procedures where legally required.

Store policies change frequently. Re-check the applicable Apple and Google policies against the actual release immediately before submission rather than relying on an old internal checklist.

---

## 23. AI and machine-learning features

Where the app contains generative AI, agents, on-device models, or cloud inference:

### Product behavior

* Clearly identify AI-generated output where appropriate.
* Define which actions require user confirmation.
* Prevent AI output from silently executing high-impact actions.
* Provide cancellation and recovery.
* Define behavior when the model is unavailable.
* Provide a non-AI fallback where the core product requires one.
* Measure latency, failure rate, and cost.

### Security

* Treat user content and retrieved content as untrusted.
* Defend against prompt injection.
* Restrict tools by capability and scope.
* Require authorization independently of model output.
* Do not expose system prompts, credentials, or internal data through tool responses.
* Validate generated URLs, commands, queries, and file paths.
* Rate-limit expensive inference.
* Prevent cross-user context leakage.
* Isolate tenants and conversation state.

### Privacy

* Disclose whether content leaves the device.
* Disclose whether prompts or outputs are retained.
* Disclose whether data is used for training.
* Avoid sending unnecessary device or account data.
* Redact secrets before model calls.
* Ensure analytics do not capture full prompts by default.
* Define deletion behavior for model-provider logs.
* Review model-provider agreements and data residency.

### Quality and safety

* Maintain task-specific evaluation sets.
* Test hallucination and refusal behavior.
* Test adversarial inputs.
* Test multilingual behavior.
* Test model-version changes before rollout.
* Record model and prompt versions in diagnostics where privacy permits.
* Use feature flags for model changes.
* Establish human escalation for high-risk domains.
* Validate model and dataset licences.

---

## 24. Documentation and ownership

Required release documentation should include:

* Architecture diagram.
* Data-flow diagram.
* Threat model.
* API specification.
* Dependency inventory.
* SBOM.
* Privacy data inventory.
* Permission inventory.
* Feature-flag inventory.
* Third-party SDK inventory.
* Database schema and migration history.
* Build and signing procedure.
* Release procedure.
* Rollback procedure.
* Incident runbook.
* Monitoring dashboard links.
* Known-risk register.
* Supported-device matrix.
* Test matrix.
* Store metadata ownership.
* Key and credential ownership.
* Vendor ownership.
* On-call or escalation contacts.
* Customer-support playbook.
* Disaster-recovery procedure.

No critical component should have only one person who knows how to build, sign, deploy, restore, or debug it.

---

# Hard go/no-go release gates

The app should not ship with any of the following unresolved:

1. Authentication or authorization bypass.
2. Exposed production secret capable of privileged access.
3. Sensitive-data disclosure.
4. Privacy declaration that does not match actual behavior.
5. Known data loss or corruption.
6. Untested migration from a supported production version.
7. Reproducible crash, ANR, or major hang in a critical journey.
8. Broken login, purchase, restore, entitlement, or account-deletion flow.
9. Release artifact built differently from the tested candidate.
10. Production configuration not independently verified.
11. Unsymbolicated production crashes with no way to diagnose them.
12. Signing keys or release credentials under uncontrolled access.
13. Store-policy violation likely to cause rejection or removal.
14. Critical workflow unusable with required accessibility technology.
15. No recovery plan for a high-risk backend or remotely activated feature.
16. Previous mobile version incompatible with the new backend during rollout.
17. Third-party SDK collecting undisclosed data.
18. No owner for release monitoring and incident response.

A numerical score must never average away a release blocker. For example, an app that scores 95% overall but has one authorization bypass is not 95% ready; it is not releasable.

---

# Recommended release acceptance criteria

Define app-specific SLOs, but a defensible minimum is:

* Zero open P0 findings.
* Zero unaccepted P1 findings.
* All critical journeys pass on the supported device matrix.
* No known data-loss path.
* All supported-version migrations pass.
* Security and privacy declarations are reconciled with the binary and runtime traffic.
* Performance budgets pass at p95 on the agreed low- and mid-tier devices.
* Beta crash, hang, and ANR metrics remain within the team’s release threshold.
* Purchase and entitlement tests pass in store sandboxes.
* Production crash symbolication has been proven.
* Store validation completes without unresolved warnings.
* Staged rollout, pause criteria, and rollback ownership are approved.
* Support and incident runbooks are available before rollout begins.

---

# Audit tracking format

Use one row per auditable control:

| Field                | Meaning                                                           |
| -------------------- | ----------------------------------------------------------------- |
| ID                   | Stable control identifier                                         |
| Domain               | Security, performance, architecture, etc.                         |
| Requirement          | Exact condition being evaluated                                   |
| Applicable platforms | iOS, Android, backend, all                                        |
| Risk                 | What can happen if it fails                                       |
| Evidence             | Test, trace, screenshot, code reference, configuration, or report |
| Status               | Pass, fail, partial, N/A, unknown                                 |
| Severity             | P0–P3                                                             |
| Release blocker      | Yes or no                                                         |
| Owner                | Person responsible for remediation                                |
| Remediation          | Required change                                                   |
| Retest evidence      | Proof that the fix was verified                                   |
| Accepted risk        | Named approver and rationale                                      |
| Target release       | Release in which it must be resolved                              |

The audit should be evidence-driven. “The code looks fine,” “the SDK should handle that,” and “it worked on my phone” are not sufficient evidence.

# Practical audit sequence

1. Freeze and identify the release candidate.
2. Map architecture, data flows, critical journeys, and threat boundaries.
3. Inspect dependencies, licences, vulnerabilities, secrets, and build configuration.
4. Build the production artifact through CI.
5. Execute critical journeys on the device matrix.
6. Exercise lifecycle, offline, interruption, and failure conditions.
7. Profile startup, responsiveness, memory, battery, network, and size.
8. Perform security testing against both the client and backend.
9. Reconcile privacy declarations with observed runtime behavior.
10. Validate signing, symbols, store metadata, payments, and release controls.
11. Deploy to beta or internal tracks.
12. Review production-like telemetry.
13. Hold a documented go/no-go review.
14. Release gradually and monitor against predefined pause criteria.

[1]: https://mas.owasp.org/MASVS/?utm_source=chatgpt.com "OWASP MASVS - OWASP Mobile Application Security"
[2]: https://mas.owasp.org/?utm_source=chatgpt.com "OWASP Mobile Application Security - OWASP Foundation"
[3]: https://developer.apple.com/documentation/bundleresources/describing-use-of-required-reason-api?utm_source=chatgpt.com "Describing use of required reason API | Apple Developer Documentation"
[4]: https://developer.apple.com/documentation/xcode/diagnosing-performance-issues-early?utm_source=chatgpt.com "Diagnosing performance issues early"
[5]: https://developer.android.com/topic/performance/baselineprofiles/overview?utm_source=chatgpt.com "Baseline Profiles overview | App quality"
[6]: https://developer.apple.com/documentation/accessibility/performing-accessibility-audits-for-your-app?utm_source=chatgpt.com "Performing accessibility audits for your app"
[7]: https://developer.android.com/docs/quality-guidelines/adaptive-app-quality?utm_source=chatgpt.com "Adaptive app quality guidelines"
[8]: https://developer.apple.com/news/upcoming-requirements/?utm_source=chatgpt.com "Upcoming Requirements"
[9]: https://support.google.com/googleplay/android-developer/answer/11926878?hl=en&utm_source=chatgpt.com "Target API level requirements for Google Play apps"
