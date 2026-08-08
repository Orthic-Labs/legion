# Desktop app pre-release audit: master checklist

A desktop release is not just the application executable. The audit must cover the complete shipped system:

* The application and all child processes
* Installer and uninstaller
* Auto-updater
* Local storage and migrations
* Native helpers, sidecars, plugins, services, and IPC
* Remote APIs and authentication
* Build and signing pipeline
* Diagnostics, support, rollback, and incident response

The audit should be performed against a specific, immutable release-candidate build and artifact hash—not merely the current source branch.

## Top-line audit domains

1. **Release scope and requirements** — What exactly is being shipped, to whom, and on which systems?
2. **Functional correctness** — Do all critical workflows work, including failure paths?
3. **Security** — Can untrusted input, local processes, remote content, or update infrastructure compromise the user?
4. **Privacy and compliance** — What data is collected, stored, transmitted, retained, and disclosed?
5. **Architecture** — Are boundaries, process responsibilities, state ownership, and failure domains sound?
6. **Technology stack** — Is the chosen framework supported, appropriate, secure, and maintainable?
7. **Code quality** — Is the implementation understandable, testable, typed, and maintainable?
8. **Performance** — Is startup, responsiveness, memory, CPU, disk, network, and energy usage acceptable?
9. **Reliability and recovery** — Can the application survive crashes, interruptions, corruption, and environmental failures?
10. **Data and storage** — Are writes atomic, migrations safe, permissions correct, and user data recoverable?
11. **Networking and backend dependencies** — Does the application handle offline use, latency, authentication, API changes, and outages?
12. **Operating-system integration** — Does the application behave correctly as a Windows, macOS, or Linux application?
13. **Installation and uninstallation** — Can users cleanly install, repair, upgrade, and remove the application?
14. **Updating and rollback** — Is the update path cryptographically secure, recoverable, and tested?
15. **User experience** — Is the application understandable, consistent, responsive, and resistant to user error?
16. **Accessibility and localization** — Can it be used with keyboards, screen readers, scaling, alternate languages, and accessibility modes?
17. **Compatibility** — Does it work across supported operating systems, architectures, hardware, drivers, and enterprise environments?
18. **Testing and quality engineering** — Is there sufficient automated, manual, security, performance, and compatibility coverage?
19. **Observability and supportability** — Can failures be diagnosed without exposing private information?
20. **Dependencies and supply chain** — Are third-party components trustworthy, licensed, pinned, scanned, and reproducible?
21. **Build and release engineering** — Is the release produced securely and consistently from reviewed source?
22. **Licensing, subscriptions, and entitlements** — Do paid, trial, expired, offline, and account states behave correctly?
23. **Documentation, legal, and support readiness** — Are policies, notices, help materials, and escalation processes ready?
24. **AI and automation safety, where applicable** — Are model actions, file access, shell access, cost, and data disclosure controlled?

---

# Granular checklist

## 1. Release scope and requirements

Establish the release contract before inspecting implementation details.

* Define supported operating systems and minimum versions.
* Define supported architectures: x64, ARM64, Apple Silicon, and any 32-bit exclusions.
* Define supported installation modes: per-user, per-machine, portable, store-distributed, enterprise-managed.
* Define minimum hardware, RAM, disk, GPU, display, and network requirements.
* Identify online-only, offline-capable, and degraded-mode functionality.
* Identify critical user journeys that must work for release.
* Identify explicitly unsupported scenarios.
* Define performance budgets and reliability targets.
* Define compatibility expectations with older application versions.
* Define upgrade and downgrade policy.
* Define data-retention and backup expectations.
* Identify external services whose availability is required.
* Identify permissions the application will request.
* Confirm that release notes and marketing claims match actual behavior.
* Create explicit release-blocker criteria rather than relying on subjective sign-off.

A useful release statement is:

> Build X supports operating systems A–C, architectures D–E, migration from versions F–H, and the critical workflows I–N under defined performance and reliability budgets.

## 2. Functional correctness

Test complete workflows, not isolated buttons.

### Core workflows

* First launch and onboarding
* Account creation, sign-in, sign-out, and account switching
* Password reset, SSO, OAuth, and authentication expiry
* Creating, opening, editing, saving, exporting, and deleting content
* Import and export
* Search, filtering, sorting, navigation, and history
* Undo and redo
* Autosave and unsaved-change handling
* Copy, paste, drag-and-drop, and clipboard handling
* Keyboard shortcuts and application menus
* Multi-window and multi-document behavior
* Background operations
* Printing and print preview, where applicable
* Licensing, purchase restoration, and entitlement refresh
* Offline operation and reconnection
* Upgrade from previous versions

### Edge cases

* Empty data sets
* Zero-byte files
* Extremely large files
* Malformed or unsupported files
* Duplicate names and conflicting paths
* Read-only files and directories
* Files opened from network drives or cloud-synced folders
* Files deleted or modified by another process
* Long paths
* Unicode, emoji, right-to-left text, and unusual filenames
* Invalid user input
* Repeated clicks or commands
* Simultaneous operations
* Cancellation during long-running operations
* Application closure during active work
* Session expiry during an operation
* Server response duplication or reordering
* Clock and timezone changes
* Daylight-saving transitions

### State correctness

* UI state matches persisted state.
* Failed operations do not appear successful.
* Retried operations are idempotent where necessary.
* Back and forward navigation do not corrupt state.
* Closing a window does not silently discard work.
* Restarting restores only valid state.
* Actions cannot be performed against stale selections or deleted objects.
* Optimistic updates are reverted correctly when the backend rejects them.
* Progress indicators represent real progress.
* Cancel buttons actually cancel underlying work.

## 3. Security and threat modelling

Do not begin with a vulnerability scanner. Begin with a threat model.

Document:

* Processes and privilege levels
* Trust boundaries
* Data flows
* Local storage locations
* IPC mechanisms
* Network endpoints
* Privileged helpers
* Update infrastructure
* File parsers
* Plugins and extensions
* Custom protocols and deep links
* Authentication and token storage
* Third-party SDKs

### Privilege and process isolation

* The application runs without administrator or root privileges by default.
* Privileged services or helpers expose the smallest possible API.
* Privileged helpers authenticate callers.
* UI or renderer processes do not directly receive unnecessary native capabilities.
* Child processes inherit only necessary environment variables and handles.
* Sidecars are terminated when the application exits.
* Sidecar binaries are signed or hash-verified.
* Privileged services cannot be repurposed to execute arbitrary commands.
* IPC boundaries are treated as security boundaries.
* IPC senders, message types, arguments, and permissions are validated.
* Named pipes, Unix sockets, shared memory, and localhost services authenticate peers.

### File and path security

Treat every user-controlled file and path as hostile.

* Canonicalize paths before authorization decisions.
* Prevent path traversal.
* Prevent archive extraction outside the destination directory.
* Handle symbolic links, junctions, aliases, and mount points safely.
* Prevent time-of-check/time-of-use races.
* Do not follow untrusted symlinks during privileged writes.
* Create temporary files with secure permissions and unpredictable names.
* Avoid writing secrets to temporary directories.
* Set limits for file size, archive expansion, recursion depth, image dimensions, and document complexity.
* Protect against decompression bombs.
* Fuzz file parsers.
* Disable macros and active content unless explicitly required.
* Prevent HTML, SVG, PDF, or document content from gaining native privileges.
* Validate MIME type and actual file content rather than trusting extensions.
* Do not pass user-controlled filenames directly into shell commands.
* Ensure deletion operations cannot escape intended directories.

### Command execution

* Avoid invoking a shell where direct process execution is possible.
* Separate executable names from arguments.
* Never build command strings through concatenation.
* Validate command-line arguments received from the OS or another process.
* Constrain working directories and environment variables.
* Review use of `eval`, dynamic code loading, reflection, and runtime compilation.
* Validate all plugin and script execution boundaries.
* Block loading executables or libraries from writable directories where possible.
* Review Windows DLL search order and hijacking risks.
* Review macOS dynamic library loading and entitlements.
* Review Linux `PATH`, `LD_LIBRARY_PATH`, and runtime search paths.

### Webview and browser security

For Tauri, Electron, embedded Chromium, WebView2, WKWebView, or similar:

* Disable Node or native integration in untrusted renderer content.
* Enable renderer sandboxing where supported.
* Enable context isolation.
* Expose a minimal preload or bridge API.
* Validate every IPC call in the native process.
* Use a restrictive Content Security Policy.
* Do not load arbitrary remote content into a privileged webview.
* Restrict navigation and new-window creation.
* Validate external URLs before opening them.
* Block dangerous schemes such as `javascript:`, unexpected `file:`, and malformed custom protocols.
* Do not rely on application bundling formats such as ASAR as a security boundary.
* Disable developer tools in production unless there is a justified support mode.
* Prevent drag-and-drop content from bypassing navigation restrictions.
* Review CORS assumptions; desktop applications are not automatically protected like normal web pages.
* Ensure renderer compromise does not lead directly to filesystem or shell compromise.

### Deep links and custom protocols

* Treat every deep-link argument as untrusted.
* Enforce strict parsing and allowlists.
* Prevent command injection through URLs.
* Prevent open redirects.
* Prevent arbitrary file opening.
* Verify OAuth state and PKCE.
* Handle duplicate or replayed callbacks.
* Verify which application owns the protocol.
* Ensure malformed links fail safely.
* Prevent one user account from consuming another account’s callback.

### Authentication and secrets

* Store passwords, refresh tokens, private keys, and sensitive credentials in the OS keychain or credential store.
* Do not store long-lived secrets in plaintext configuration files.
* Do not embed service secrets in client binaries.
* Assume all client-side constants can be extracted.
* Implement token expiry, revocation, and account removal.
* Clear sensitive in-memory and persisted state during sign-out where practical.
* Prevent one local OS user from reading another user’s tokens.
* Use OAuth authorization code flow with PKCE for desktop applications.
* Validate callback state and redirect targets.
* Avoid exposing tokens in URLs, logs, crash reports, or command-line arguments.
* Do not ship development credentials or test accounts.

### Network security

* Validate TLS certificates.
* Do not disable certificate validation to fix development issues.
* Do not silently accept invalid or expired certificates.
* Use certificate pinning only when there is an operationally sound rotation plan.
* Protect local web servers from DNS rebinding and cross-site requests.
* Bind local services to loopback unless external access is intentional.
* Authenticate local service requests.
* Avoid sensitive data in query strings.
* Validate downloaded content before using it.
* Verify signatures independently of HTTPS for updates and executable content.

### Installer and updater security

The updater is one of the highest-risk components in a desktop product.

* Sign application binaries.
* Sign update packages.
* Cryptographically verify update metadata and payloads.
* Prevent downgrade to vulnerable versions unless explicitly controlled.
* Ensure update URLs cannot be redirected by untrusted configuration.
* Prevent local users from replacing staged update files.
* Use secure permissions for updater directories.
* Ensure privileged update services verify the publisher and package.
* Protect signing keys using controlled signing infrastructure.
* Timestamp signatures where applicable.
* Test compromised-manifest and corrupted-package scenarios.
* Ensure failed verification stops installation.
* Ensure updater logs do not expose credentials or signed URLs.

### Logging and diagnostics

* Remove credentials, tokens, document contents, and personal data from logs.
* Review crash dumps for sensitive memory.
* Restrict diagnostic bundle contents.
* Rotate and cap log size.
* Use secure file permissions.
* Do not log raw authentication headers.
* Do not expose internal paths unnecessarily.
* Ensure verbose logging cannot be remotely enabled without authorization.

### Security validation

* Static application security testing
* Dependency vulnerability scanning
* Secret scanning
* Dynamic application security testing
* Fuzzing of parsers and IPC
* Memory sanitizers for native code
* Penetration testing of privileged boundaries
* Manual review of updater and signing paths
* Review of all `unsafe`, native FFI, shell, and dynamic-loading code
* Verification that the production binary has no development backdoors

## 4. Privacy and compliance

Create a data inventory showing what data exists, why it exists, where it goes, and how long it remains.

* List all personal, diagnostic, behavioral, financial, and content data.
* Identify local-only versus remotely transmitted data.
* Verify that the privacy policy matches real application behavior.
* Minimize telemetry.
* Make analytics and crash reporting consent behavior explicit.
* Provide opt-out controls where required or appropriate.
* Do not upload user documents without a clear user action or disclosure.
* Request microphone, camera, screen-recording, contacts, and filesystem permissions only when needed.
* Explain permission requests before the operating-system dialog appears.
* Define retention periods.
* Support account deletion and data deletion.
* Support data export where required.
* Review third-party analytics and crash SDKs.
* Review SDK endpoints and sub-processes, not just documented behavior.
* Redact personal data from logs and support bundles.
* Avoid stable machine identifiers unless necessary.
* Do not use hardware identifiers as casual analytics identifiers.
* Separate essential operational telemetry from optional analytics.
* Cap offline telemetry queues.
* Do not claim secure deletion on SSDs unless the guarantee is technically supportable.
* Confirm compliance obligations for GDPR, CCPA/CPRA, children, healthcare, finance, education, or other regulated data where applicable.

## 5. Architecture

The architecture audit should explain how the application behaves under success, failure, and partial compromise.

### Structure and boundaries

* UI, domain logic, persistence, networking, and OS integration have clear boundaries.
* Business logic is not duplicated across platform-specific UI layers.
* Privileged functionality is isolated.
* Renderer or presentation code does not directly own high-value secrets.
* Native capability exposure is explicit and reviewable.
* Components have clear ownership.
* Dependencies flow in an intentional direction.
* Cross-platform abstractions do not conceal unsafe platform differences.
* Shared libraries do not become uncontrolled dumping grounds.

### Process model

* Document every process, helper, worker, webview, service, and sidecar.
* Define who starts and stops each process.
* Define restart and crash behavior.
* Ensure orphan processes do not remain after exit.
* Ensure child processes cannot outlive security context changes.
* Supervise critical child processes.
* Prevent uncontrolled process spawning.
* Define how processes authenticate each other.

### IPC and API contracts

* IPC messages are typed or schema-validated.
* Inputs are length-limited and validated.
* Contracts are versioned where needed.
* Unknown message types are rejected.
* Privileged operations require explicit authorization.
* Error responses do not expose secrets.
* Callers cannot invoke methods outside their capability set.
* IPC does not depend on UI-visible state for security decisions.

### State and concurrency

* There is a clear source of truth for application state.
* State transitions are explicit.
* Concurrent operations cannot corrupt shared state.
* Locks have defined ownership and ordering.
* Long-running work is cancellable.
* Queues are bounded.
* Backpressure is implemented.
* Work is not silently dropped.
* UI event subscriptions are cleaned up.
* Background tasks stop during shutdown.
* Reentrancy and duplicate event delivery are considered.
* Startup and shutdown ordering are deterministic.

### Error architecture

* Errors are classified: user error, transient infrastructure error, permanent error, programmer error, corruption, and security failure.
* Errors are not swallowed.
* Recoverable failures have recovery paths.
* Fatal failures fail safely.
* Error messages preserve enough context for diagnostics.
* Internal details are separated from user-facing messages.
* Retry policy is centralized rather than improvised.
* Partial success is represented explicitly.

### Evolvability

* Local schemas and IPC contracts are versioned.
* Migrations are testable independently.
* Feature flags have owners and expiry plans.
* Configuration has a schema and safe defaults.
* Plugins or extensions have a documented compatibility model.
* Platform-specific code is isolated.
* Framework replacement would not require rewriting all domain logic.
* Critical dependencies have contingency plans.
* Architecture decisions are documented for non-obvious tradeoffs.

## 6. Technology stack

Assess whether the stack is suitable for the product, not merely whether it builds.

* Framework and runtime versions are supported.
* Security patches can be adopted without extensive rework.
* The framework supports required accessibility features.
* The framework supports target OS versions and architectures.
* Native dependencies have compatible ABIs.
* Cross-compilation and packaging are reliable.
* Framework startup and memory overhead fit the product.
* Embedded browser or webview version behavior is understood.
* GPU, media codec, printing, and filesystem support meet requirements.
* The auto-update mechanism is production-grade.
* Framework licenses and bundled runtime licenses are compatible with distribution.
* The framework has sufficient maintainership and release activity.
* There is a plan for runtime deprecation.
* Platform-specific escape hatches do not undermine architecture.
* A large portion of the application is not dependent on unmaintained plugins.

### Stack-specific high-risk areas

**Tauri**

* Capability and permission configuration is least-privilege.
* Every `invoke` command validates arguments.
* Shell, filesystem, HTTP, dialog, and process permissions are narrowly scoped.
* Sidecars are signed or verified.
* Updater signatures are enforced.
* Asset protocol and filesystem scopes are restricted.
* Rust `unsafe` and FFI code is reviewed.
* CSP is restrictive.
* Frontend input cannot select arbitrary native commands.

**Electron**

* `nodeIntegration` is disabled for untrusted renderers.
* `contextIsolation` and sandboxing are enabled.
* The preload bridge is minimal.
* IPC handlers validate sender and arguments.
* Navigation and window creation are restricted.
* Remote content is isolated.
* Electron is kept current enough for security updates.
* Auto-updates are signed and verified.
* Devtools and debugging ports are disabled in production.
* ASAR is not treated as tamper protection.

**C++/Qt**

* Address, undefined-behavior, and thread sanitizers have been used.
* Ownership and lifetime are explicit.
* Plugin and DLL search paths are restricted.
* QML and web content do not expose arbitrary native execution.
* Third-party codecs and parsers are fuzzed.
* Crash symbols are retained securely.

**.NET/WPF/WinUI**

* P/Invoke and COM boundaries are reviewed.
* Obsolete unsafe serializers are not used.
* DPAPI or Credential Manager is used for sensitive local secrets.
* Runtime packaging and trimming do not break reflection-dependent paths.
* MSIX, ClickOnce, or custom updater behavior is fully tested.
* ACLs and registry writes are correct.

**Swift/AppKit**

* App Sandbox and entitlements are minimal.
* Hardened Runtime is enabled.
* The app is notarized.
* Keychain access groups are correct.
* XPC interfaces validate callers and arguments.
* TCC permissions are requested correctly.
* Helper tools use secure installation and authorization.

**Flutter**

* Platform channels validate all inputs.
* Native plugins are reviewed separately from Dart code.
* Webviews use secure navigation and scripting settings.
* Dynamic libraries and native assets are verified.
* Desktop accessibility behavior is manually tested.

## 7. Code quality and maintainability

* Static analysis passes without suppressed high-risk findings.
* Type checking is strict enough to catch real defects.
* Compiler warnings are treated seriously.
* Error returns are handled.
* Exceptions are not broadly swallowed.
* Resource ownership is clear.
* File handles, sockets, database connections, webviews, threads, and processes are released.
* Thread-safety assumptions are documented.
* Mutable global state is minimized.
* Functions and modules have coherent responsibilities.
* Complexity hotspots are identified.
* Duplication in security-sensitive logic is removed.
* Magic constants are replaced with named configuration.
* Feature flags and dead code are cleaned up.
* Debug-only code is excluded from production.
* Development endpoints and test keys are absent.
* Comments explain rationale, not obvious syntax.
* Public APIs and non-obvious invariants are documented.
* Generated code is reproducible and its source is controlled.
* Native `unsafe` blocks and FFI boundaries have explicit justification.
* Code ownership exists for critical subsystems.
* The project is not dependent on one person’s undocumented knowledge.
* Last-minute release patches receive the same review as normal changes.

## 8. Performance and resource usage

Measure performance on clean, representative hardware. Report percentiles, not only a single developer-machine result.

### Startup

Measure:

* Process launch to first window
* First window to usable UI
* Cold launch
* Warm launch
* Launch while offline
* Launch with large user state
* Launch after an update
* Launch with corrupted cache
* Launch on low-end supported hardware

Check:

* Synchronous work on the UI thread
* Blocking network calls
* Database initialization
* Migration time
* Plugin discovery
* Font and asset loading
* Child-process startup
* Renderer initialization
* Antivirus-sensitive file scanning patterns

### Runtime responsiveness

* Input latency
* Menu and dialog latency
* Search latency
* Save and export latency
* Scrolling and rendering smoothness
* Window resizing
* Switching documents or views
* Cancellation responsiveness
* Responsiveness during background jobs
* Performance with multiple windows
* Large file or large dataset behavior
* UI-thread blocking
* Excessive IPC round trips
* Excessive serialization and copying
* Main-thread filesystem access

### Memory

Measure:

* Idle working set
* Typical working set
* Peak working set
* Per-window or per-document growth
* Child-process memory
* GPU memory
* Memory after closing documents or windows
* Long-duration memory growth

Test:

* Repeated open/close cycles
* Repeated navigation
* Large imports
* Multi-window usage
* Eight-to-twenty-four-hour soak runs
* Low-memory conditions
* Allocation spikes
* Memory fragmentation
* Native and webview leaks

### CPU, GPU, and energy

* Idle CPU should approach zero rather than continuously polling.
* Background watchers should not wake excessively.
* Animations should stop when not visible.
* GPU acceleration and fallback paths should both work.
* Rendering should not consume excessive power.
* Background syncing should be bounded.
* Thermal throttling behavior should be understood.
* Battery impact should be tested on laptops.
* Sleep should suspend unnecessary work.
* Resume should not create duplicate timers or workers.

### Disk and network

* Install size
* Update size
* Cache growth
* Log growth
* Temporary-file cleanup
* Database size and index behavior
* Read/write amplification
* Large file copying
* Network request count
* Payload sizes
* Compression
* Duplicate downloads
* Retry storms
* Cache invalidation
* Offline queue growth

Create explicit budgets for cold startup, warm startup, idle CPU, typical memory, peak memory, interaction latency, package size, and long-duration stability.

## 9. Reliability, resilience, and recovery

Test deliberate failure, not just normal operation.

### Fault injection scenarios

* Kill the application during a save.
* Kill it during a migration.
* Kill it during an update.
* Disconnect the network mid-request.
* Suspend and resume during an operation.
* Fill the disk.
* Make the data directory read-only.
* Revoke permissions while running.
* Corrupt configuration.
* Corrupt cache.
* Corrupt the database.
* Remove a device or mounted volume.
* Change proxy or VPN while running.
* Change system time.
* Return malformed server responses.
* Return old or future API schemas.
* Return rate limits and server overload responses.
* Simulate DNS failure.
* Simulate certificate failure.
* Start multiple instances simultaneously.
* Crash a helper process.
* Refuse child-process startup.
* Lock a required file from another process.
* Force low-memory conditions.
* Shut down the OS during work.

### Recovery behavior

* Writes are atomic.
* Recovery does not overwrite the last valid copy.
* Failed migrations can resume or roll back.
* Crash loops are detected.
* A safe mode exists where justified.
* Corrupted caches can be discarded safely.
* Corrupted settings can be reset without deleting user data.
* The user can export diagnostics even when startup fails.
* Retries use timeouts, limits, and backoff.
* Non-idempotent actions are not blindly retried.
* Partial operations are identified and reconciled.
* Background jobs resume safely.
* The application does not silently abandon incomplete work.
* Shutdown is graceful but bounded.
* The application cannot hang forever waiting for a child process or network call.

## 10. Data, storage, and migrations

### Storage design

* User data, configuration, cache, logs, and temporary files are separated.
* Platform-standard directories are used.
* The application does not write to its installation directory.
* File and directory permissions are appropriate.
* Sensitive data is encrypted where the threat model requires it.
* Encryption keys are stored separately in the OS credential system.
* Cache data can be deleted without damaging user data.
* Log and cache sizes are bounded.
* Multi-user systems isolate each OS user’s data.
* Temporary files are cleaned up after abnormal termination.
* Database indexes support realistic data sizes.
* Database locking and concurrent access are understood.
* File-format compatibility is documented.

### Write safety

* Use atomic replace patterns where possible.
* Use transactions for multi-step database changes.
* Validate data before replacing a valid file.
* Preserve the previous valid version during risky transformations.
* Handle disk-full and quota errors.
* Handle read-only and permission-denied failures.
* Do not report success before durable state is written when durability matters.
* Avoid partial writes that appear valid.
* Detect and report corruption.

### Migrations

Test:

* Clean install to current version
* Every supported prior version to current
* Interrupted migration
* Repeated migration
* Migration with low disk space
* Migration with malformed legacy data
* Migration with very large data
* Migration from beta or preview versions
* Migration after partial manual file restoration
* Attempted downgrade

Requirements:

* Migrations are versioned.
* Migrations are deterministic.
* Migrations are idempotent where practical.
* A backup or recovery strategy exists.
* Migration failure does not destroy the source data.
* The application does not open a partially migrated database as normal.
* Downgrade behavior is explicit.
* Migration duration is visible when lengthy.

### User control

* Import and export are tested.
* Account deletion is tested.
* Local-data deletion is tested.
* Uninstall behavior regarding user data is documented.
* Backup and restore procedures are documented where important.
* Cloud-sync conflict behavior is defined.
* The application does not unexpectedly upload local data.
* User content is not held hostage after subscription expiry.

## 11. Networking and backend services

A desktop application dependent on cloud services cannot be considered release-ready if only the client is audited.

### Client network behavior

* Every request has a timeout.
* Long-running requests support cancellation.
* Retries are bounded.
* Retries use exponential backoff and jitter where appropriate.
* Authentication refresh is race-safe.
* Multiple failed requests do not create a retry storm.
* Offline state is detected and communicated.
* The application does not block startup unnecessarily on telemetry or optional services.
* Proxy and VPN environments are supported or explicitly excluded.
* System proxy settings are respected where expected.
* IPv4 and IPv6 behavior is tested.
* Captive portal behavior is reasonable.
* Metered or limited connections are considered for large downloads.
* Upload and download interruption behavior is defined.
* Large transfers can resume where necessary.
* Rate-limit responses are handled.
* Server clock skew is handled where relevant.
* Sensitive data is not placed in URLs.

### API compatibility

* Client and server versions negotiate capabilities safely.
* Unknown response fields do not break the client.
* Missing expected fields fail safely.
* Deprecated APIs have a migration plan.
* Older desktop versions are considered during server deployment.
* Server changes are backward-compatible for the supported client window.
* Remote feature flags have safe defaults.
* Remote configuration cannot enable arbitrary code or dangerous capabilities.
* API schema validation exists.
* Pagination, duplication, and ordering assumptions are tested.
* Error codes are mapped to meaningful application behavior.

### Backend readiness

* Production endpoints are correct.
* Development and staging endpoints are absent from the release configuration.
* Capacity and rate limits have been tested.
* Authentication and account deletion flows work in production.
* Backups and disaster recovery exist.
* Service monitoring and alerting exist.
* Incident response ownership is defined.
* Rollback of server changes has been tested.
* There is a degraded-mode plan for an outage.
* A desktop release can be disabled or contained without bricking valid offline use, where feasible.

## 12. Operating-system integration

### Common desktop behavior

* Single-instance versus multi-instance behavior is intentional.
* File associations work.
* Deep links work.
* Context-menu integration works.
* Global shortcuts do not unexpectedly conflict.
* Clipboard behavior is correct.
* Drag-and-drop works across privilege boundaries where expected.
* Notifications work and respect OS settings.
* Tray or menu-bar behavior is consistent.
* Autostart is opt-in and removable.
* Application menus follow platform conventions.
* Open and save dialogs use appropriate defaults.
* Window positions and sizes restore correctly.
* Windows are recovered if a previously attached monitor is missing.
* Multi-monitor, mixed-DPI, and display hot-plug are tested.
* Dark mode, light mode, and high-contrast mode are tested.
* Sleep, hibernate, resume, shutdown, and logout are tested.
* OS language and regional settings are respected.
* Input-method editors are tested.
* Non-US keyboard layouts are tested.
* The application handles OS permission revocation.
* The application behaves correctly as a non-administrator user.

### Windows

* Per-monitor DPI awareness is correct.
* Long paths and Unicode paths work.
* Files are stored under appropriate AppData locations.
* Registry changes are minimal and removed appropriately.
* Authenticode signatures validate.
* SmartScreen and Defender behavior are tested.
* DLL search paths are safe.
* UAC prompts occur only when necessary.
* Services and scheduled tasks are securely configured.
* File associations and protocol registrations quote executable paths safely.
* Uninstall registration is correct.
* MSIX/NSIS/WiX behavior is tested on clean systems.
* Remote Desktop and enterprise EDR environments are considered.

### macOS

* Hardened Runtime is enabled.
* The application is notarized.
* Gatekeeper acceptance is tested on a clean machine.
* Entitlements are minimal.
* App Sandbox behavior is correct where used.
* Keychain access is correct.
* TCC permissions are requested and recover gracefully if denied.
* App Translocation behavior is considered.
* Menu-bar and window conventions are respected.
* Apple Silicon and Intel behavior are tested where supported.
* Universal binaries contain the expected architectures.
* Login items and privileged helpers use supported mechanisms.
* Uninstall documentation covers residual data.

### Linux

* XDG directory conventions are followed.
* X11 and Wayland behavior is tested as applicable.
* Required system libraries are declared.
* Packaging dependencies are correct.
* AppImage, Flatpak, Snap, deb, or rpm differences are understood.
* Desktop entries, icons, MIME registration, and protocol handling are correct.
* Polkit usage is reviewed.
* Sandboxing expectations are documented.
* Multiple distributions and desktop environments are tested according to support policy.

## 13. Installer, repair, upgrade, and uninstallation

Test installation on clean machines, not only developer systems.

### Installation

* The installer is signed.
* The publisher identity is correct.
* Installation succeeds without unnecessary elevation.
* Per-user and per-machine behavior is correct.
* Installation paths are safely quoted and permissioned.
* Insufficient disk space is handled.
* Existing running processes are handled.
* Antivirus interference produces useful errors.
* Required runtimes are bundled or installed correctly.
* File associations are optional where appropriate.
* Firewall rules are not added unnecessarily.
* Services, scheduled tasks, and startup entries are justified.
* Silent installation works if enterprise use is supported.
* Repair installation works where advertised.
* The exact production package is tested after signing.

### Upgrade

Test upgrades:

* From every supported prior version
* Across architecture transitions where supported
* With the application running
* With locked files
* With modified configuration
* With large user data
* With insufficient disk space
* With interrupted download
* With interrupted installation
* With antivirus scanning active
* With previous partial installation state

Verify:

* User data remains intact.
* Settings remain valid.
* Old binaries are removed.
* Services and helpers are upgraded.
* File associations remain correct.
* The application launches after upgrade.
* Rollback restores a working version.
* Rollback does not corrupt newer-format data.

### Uninstallation

* Application binaries are removed.
* Services, tasks, startup entries, protocol handlers, and file associations are removed.
* Temporary update files are removed.
* Shared system components are not deleted incorrectly.
* User-data retention behavior is clear.
* Users can choose whether to retain or delete data where appropriate.
* Uninstallation works when the application is damaged.
* Uninstallation works without an internet connection.
* Reinstallation after uninstall behaves like a clean install where expected.

## 14. Auto-update and rollback

* Update metadata is signed.
* Update payloads are signed.
* Signatures are checked before execution.
* Update channels are isolated.
* Stable users cannot accidentally receive development builds.
* Version comparison handles prerelease versions correctly.
* Downgrade policy is explicit.
* Update download supports interruption and resume where appropriate.
* Update staging uses secure permissions.
* The application verifies sufficient disk space.
* Update installation handles locked files.
* Update failures preserve the current working version.
* Rollback is automated or operationally documented.
* A bad release can be paused.
* Staged rollout or canary deployment is supported where the user base justifies it.
* A kill switch cannot be abused to execute arbitrary behavior.
* Update prompts are not coercive.
* Mandatory updates are reserved for justified cases.
* Offline users are not locked out unnecessarily.
* Update logs are available for support.
* The application can recover from an updater crash.
* The updater itself can be updated securely.
* The final signed update artifact is the same artifact that QA tested.

## 15. User experience

### Comprehension and workflow

* A new user can understand the application’s purpose.
* The primary action is apparent.
* First-run setup is not longer than necessary.
* Empty states explain what to do next.
* Loading states are distinguishable from failures.
* Offline state is visible.
* Errors explain what failed, what was preserved, and what action is possible.
* Technical details are available without being forced on normal users.
* Destructive operations are clear.
* Undo is preferred over excessive confirmation dialogs.
* Long-running work displays progress.
* Long-running work can be cancelled.
* Success feedback is explicit where ambiguity would be harmful.
* UI labels use the user’s vocabulary rather than internal implementation terms.
* Core actions do not move unpredictably between releases.

### Window and document behavior

* Closing a modified document prompts or autosaves correctly.
* Closing the main window has platform-appropriate behavior.
* Window restoration does not reopen invalid or sensitive state unexpectedly.
* Modal dialogs do not become hidden behind other windows.
* Focus returns to a logical location.
* Multiple windows do not overwrite each other’s state.
* Minimize-to-tray behavior is explicit.
* The application exits when the user expects it to.
* Keyboard shortcuts are discoverable.
* Shortcut conflicts are handled.
* Context menus match the selected object.

### Error prevention

* Invalid actions are prevented or clearly explained.
* Dangerous defaults are avoided.
* File overwrite behavior is explicit.
* The user can inspect a destination before export.
* Operations affecting many items show scope.
* Account and workspace identity are visible before destructive actions.
* Network retries do not duplicate user actions.
* Subscription or entitlement changes do not delete user data.

## 16. Accessibility, internationalization, and localization

### Keyboard and focus

* Every core workflow can be completed without a mouse.
* Tab order is logical.
* Focus is visible.
* Custom controls expose keyboard behavior.
* Modal dialogs trap focus correctly.
* Focus is restored after dialogs close.
* Escape and Enter behavior are consistent.
* Global shortcuts do not override assistive-technology shortcuts.

### Screen readers and semantics

* Controls have accessible names and roles.
* Status changes are announced where appropriate.
* Errors are programmatically associated with fields.
* Custom canvases or editors provide meaningful accessibility.
* Icons are not the only labels for critical actions.
* Tables, trees, menus, and tabs expose correct semantics.
* Installer and updater dialogs are accessible.

### Visual accessibility

* Text and controls remain usable at increased scaling.
* The application works at 125%, 150%, 200%, and higher scaling where supported.
* Color is not the only method of conveying state.
* Contrast is sufficient.
* High-contrast mode is supported.
* Reduced-motion settings are respected.
* Zoom does not break layout.
* Small displays and resized windows remain usable.

### Localization

* UI strings are externalized.
* Layout accommodates longer translations.
* Right-to-left layout is tested where supported.
* Dates, times, numbers, currency, and sorting use locale-aware rules.
* Paths and filenames support Unicode.
* Case-insensitive comparisons are not assumed to behave identically in every locale.
* Timezones and daylight-saving changes are handled.
* Error messages from lower layers are translated or contextualized appropriately.

## 17. Compatibility matrix

Create an explicit matrix rather than saying “works on Windows and Mac.”

Include:

* OS version
* CPU architecture
* Installation mode
* Upgrade source version
* RAM tier
* GPU tier and driver
* Display scale
* Single and multiple monitors
* Light, dark, and high-contrast mode
* Language and locale
* Administrator and standard user
* Offline, normal network, proxy, VPN, and captive portal
* Local, removable, network, and cloud-synced storage
* Antivirus or EDR
* Remote Desktop or VM
* Clean install versus upgraded system

Test particular desktop failure sources:

* Unsupported CPU instructions
* ARM emulation
* Missing system runtimes
* Old GPU drivers
* Corporate application-control policies
* Non-default temporary directories
* Roaming user profiles
* OneDrive, Dropbox, and iCloud-synced paths
* Network-mounted home directories
* Usernames containing spaces or non-Latin characters
* Very long paths
* Read-only or restricted environments
* Multiple logged-in OS users
* Device sleep and monitor changes
* OS updates occurring between application releases

Unsupported environments should fail with a clear message, not an unexplained crash.

## 18. Testing and quality engineering

### Automated testing

* Unit tests for domain logic
* Integration tests for storage, networking, IPC, and platform adapters
* End-to-end tests for critical user journeys
* Regression tests for previously escaped defects
* Migration tests using real historical fixtures
* Installer and updater tests
* Contract tests against backend APIs
* Property-based tests for state and serialization logic
* Fuzzing for parsers, protocol handlers, IPC, and import formats
* Visual regression tests where layout stability matters
* Accessibility automation supplemented by manual testing
* Performance benchmarks with regression thresholds
* Leak and soak tests
* Static analysis and type checking
* Dependency and secret scanning

### Manual testing

* Exploratory testing
* Clean-machine testing
* Upgrade testing
* Failure injection
* Accessibility testing with real assistive technology
* Localization review
* Multi-monitor and DPI testing
* Antivirus and enterprise environment testing
* Install, update, rollback, and uninstall testing
* Support-diagnostics testing
* First-time-user testing by someone unfamiliar with the product

### Test governance

* Critical paths have explicit acceptance criteria.
* Test failures cannot be casually ignored.
* Flaky tests are tracked and repaired.
* Test coverage is interpreted by risk, not only percentage.
* Production-like data sizes are used.
* Test credentials and endpoints cannot leak into release builds.
* The exact signed release artifact receives final smoke testing.
* A release candidate is not rebuilt after approval without repeating relevant validation.
* Beta or canary feedback is reviewed before broad rollout.

## 19. Observability, diagnostics, and supportability

### Logging

* Logs are structured.
* Log levels are consistent.
* Logs include application version and build identifier.
* Logs include enough context to trace an operation.
* Correlation identifiers connect client and server failures where appropriate.
* Logs rotate.
* Log size is capped.
* Sensitive data is redacted.
* Users can locate or export logs.
* Logging failure does not crash the application.
* Verbose logging has a controlled activation path.
* Logs do not become a covert telemetry channel.

### Crash reporting

* Native and managed crashes are captured.
* Child-process crashes are captured.
* Symbols or source maps are available to authorized maintainers.
* Crash reporting respects privacy settings.
* Crash dumps are reviewed for secrets.
* Crash upload failures are bounded.
* Crash loops are identifiable.
* Reports include version, OS, architecture, and relevant feature state.
* User content is not automatically included unless necessary and disclosed.

### Support tools

* A diagnostics bundle can be generated.
* Diagnostics can be generated when normal startup fails.
* The bundle previews what will be shared.
* Secrets and document contents are excluded by default.
* Installer and updater logs are included where useful.
* A self-check or “doctor” command detects common corruption.
* Safe mode or reset-config options exist where justified.
* Support documentation maps common symptoms to remediation.
* There is a defined escalation path from customer support to engineering.
* Users can report the exact build version easily.

### Operational controls

* Feature flags have audit logs and owners.
* Remote configuration has safe defaults.
* A rollback mechanism exists.
* A bad release can be paused.
* Telemetry distinguishes versions and release channels.
* Incident response contacts and procedures are current.
* Support can distinguish application defects from backend outages.

## 20. Dependencies, supply chain, and licensing

* Produce an SBOM for shipped artifacts.
* Pin dependencies with lockfiles.
* Review transitive dependencies.
* Scan for known vulnerabilities.
* Evaluate exploitability rather than blindly accepting scanner output.
* Identify abandoned or single-maintainer critical packages.
* Verify third-party binary hashes.
* Control package-manager install scripts.
* Review native prebuilt modules separately.
* Ensure development-only dependencies are not shipped.
* Verify dependency sources and registries.
* Avoid downloading executable dependencies at runtime.
* Record provenance for build inputs.
* Use controlled build environments.
* Protect package publishing and signing credentials.
* Review fonts, codecs, models, icons, and media assets for licensing.
* Generate required open-source notices.
* Comply with attribution, redistribution, source-offer, and copyleft requirements.
* Review commercial SDK redistribution terms.
* Track runtime and framework end-of-support dates.
* Review telemetry SDK behavior and data destinations.
* Ensure source maps and debug symbols are not unintentionally public.
* Verify bundled redistributables are licensed and current.
* Have a process for emergency dependency updates.

## 21. Build, signing, and release engineering

### Build integrity

* Builds run on clean agents.
* Builds are produced from a reviewed tag or immutable commit.
* Version numbers come from one authoritative source.
* Build inputs are pinned.
* Production configuration is explicit.
* Development endpoints are absent.
* Debug assertions and debug menus are disabled as intended.
* Test certificates and test credentials are absent.
* Build scripts fail on missing required configuration.
* Artifacts are reproducible where technically practical.
* Artifact provenance is recorded.
* Uncommitted local source cannot enter an official release.
* Generated files are either checked or reproduced deterministically.

### Secrets and signing

* Signing keys are not stored in the repository.
* Signing access is restricted.
* Signing operations are auditable.
* Keys are stored in secure signing infrastructure or hardware-backed systems where possible.
* Certificates are monitored for expiry.
* Signatures are timestamped where applicable.
* The application, installer, updater, helpers, drivers, and sidecars are signed as required.
* Post-signing modification is prevented.
* Final signed artifacts are hash-recorded.
* Signing failures cannot produce an apparently valid unsigned release.

### Release process

* Branch protection and review requirements are enforced.
* Release approvals are recorded.
* Release notes are prepared.
* Database and API compatibility are confirmed.
* Backend deployment ordering is defined.
* Rollback artifacts are retained.
* Symbols and source maps are uploaded before rollout.
* Staged rollout criteria are defined.
* Monitoring during rollout is defined.
* Artifact retention policy exists.
* Release channels cannot be mixed accidentally.
* Store packages and direct-download packages are both verified.
* The exact artifact approved by QA is the artifact distributed.

## 22. Licensing, trials, subscriptions, and entitlements

* Activation works.
* Deactivation works.
* Purchase restoration works.
* Device transfer works.
* Offline grace periods behave as documented.
* Subscription expiry behaves predictably.
* Expiry does not destroy or encrypt user data.
* Users can export their data after expiry.
* Server outages do not immediately invalidate legitimate users.
* Clock changes and timezone changes do not corrupt entitlement state.
* Receipt or license verification is secure.
* Tokens and license data are stored securely.
* Trials cannot accidentally become permanent due to bugs.
* Trial expiry is communicated clearly.
* Refund and cancellation states are handled.
* Plan upgrades and downgrades are handled.
* Legacy and lifetime licenses continue to work according to policy.
* Update entitlement rules are enforced correctly.
* Multiple accounts on one computer are handled.
* Multiple OS users are isolated.
* Billing failures do not create inconsistent local state.
* Anti-piracy measures do not require dangerous privileges.
* Licensing infrastructure has a degraded-mode and incident plan.

## 23. Documentation, legal, and support readiness

Before release, confirm the existence and accuracy of:

* System requirements
* Installation guide
* Upgrade guide
* Uninstallation and data-removal guide
* Backup and restore guidance
* User documentation
* Keyboard shortcut reference
* Accessibility information
* Privacy policy
* Terms or EULA
* Open-source notices
* Telemetry disclosure
* Permission explanations
* Data deletion procedure
* Account deletion procedure
* Security contact
* Vulnerability disclosure process
* Support contact and response path
* Known issues
* Release notes
* Update policy
* End-of-support policy
* Refund and cancellation policy where relevant
* Enterprise deployment documentation where relevant
* Export-control or cryptography disclosures where relevant
* App-store-specific disclosures and metadata

Documentation should be checked against the actual shipping build. Policies copied from a template are a liability when they contradict application behavior.

## 24. AI and automation-specific checks

For an application that uses LLMs, local models, agents, or automated actions:

### Permissions and agency

* The model has an explicit capability set.
* Reading files, writing files, using the network, and executing commands are separate permissions.
* Destructive actions require confirmation or a controlled policy.
* Shell access is constrained.
* File access is scoped.
* The model cannot silently expand its permissions.
* Tool calls validate all model-provided arguments.
* The user can stop an active task.
* Child agents inherit no more authority than necessary.
* Automation has recursion, cost, and time limits.
* Actions are auditable.

### Prompt injection and untrusted content

* Documents, websites, emails, and repository content are treated as untrusted instructions.
* System policies are separated from retrieved content.
* Tool authorization is not based solely on model judgment.
* Sensitive context is not automatically exposed to retrieved content.
* External content cannot cause silent data exfiltration.
* Tool output is validated before subsequent execution.
* Generated shell commands and code changes are reviewed according to risk.

### Data and provider behavior

* Users know which provider receives their data.
* Provider retention and training policies are represented accurately.
* API keys are stored securely.
* Secrets are removed from prompts and logs where possible.
* Local versus cloud processing is clearly distinguished.
* Model and provider fallback behavior is disclosed.
* Failed provider calls do not duplicate billable or destructive actions.
* Token and financial budgets are enforced.
* Conversation and document retention is controlled.
* Model output is not presented as deterministic fact where it is not.

### Local models and sidecars

* Model files are checksum-verified.
* Model licenses permit distribution.
* Model downloads resume safely.
* Corrupted models are detected.
* Resource requirements are checked before loading.
* Out-of-memory behavior is recoverable.
* GPU and CPU fallback paths work.
* Sidecar processes are supervised.
* Model updates can be rolled back.
* Local inference does not unintentionally expose a network port.

---

# Desktop-specific risks that are commonly missed

These deserve special emphasis because ordinary web-application audits often omit them:

1. **The updater is a remote-code-execution channel by design.** It must be treated as security-critical infrastructure.
2. **IPC is an authorization boundary.** A hidden renderer or local process may call it directly.
3. **Files are hostile input.** Documents, images, archives, HTML, PDFs, media, and project files require parser hardening.
4. **Paths are not simple strings.** Symlinks, junctions, aliases, network paths, case sensitivity, and race conditions matter.
5. **The installer may be more privileged than the app.** A weak installer or helper can undermine an otherwise secure application.
6. **The tested source is not the shipped product.** Signing, packaging, minification, bundling, runtime injection, and store processing can change behavior.
7. **Desktop applications live for a long time.** Sleep, resume, network changes, long sessions, memory leaks, and stale authentication matter.
8. **Localhost is not automatically trusted.** Local services require authentication and protection from browser-origin attacks.
9. **Uninstall and upgrade are core product paths.** They are not secondary packaging concerns.
10. **Crash dumps and logs can expose more data than network telemetry.**

# Stop-ship findings

The following should normally block release:

* Arbitrary code execution
* Privilege escalation
* Authentication or entitlement bypass affecting protected data or services
* Updater package or metadata not cryptographically verified
* Unsigned or incorrectly signed production artifacts
* Known critical exploitable dependency vulnerability
* User-data loss or corruption
* Migration that can irreversibly damage data
* Secrets, tokens, user content, or personal data exposed in logs or telemetry
* Common-path crash or hang
* Unbounded memory, CPU, disk, log, or network growth
* Installer or updater that can leave the application unusable
* Rollback that is unavailable or untested for a remotely deployed release
* Core workflow inaccessible to keyboard or assistive-technology users where accessibility is required
* Production build containing test credentials, development endpoints, debug servers, or unsafe developer tools
* License violations or missing required notices
* Privacy policy materially inconsistent with application behavior
* Release artifact not traceable to reviewed source
* QA approval performed on a different binary from the distributed binary

# Recommended audit outputs

A senior audit should produce evidence, not only a narrative report:

1. **Executive release-readiness summary**
2. **Supported platform and upgrade matrix**
3. **Architecture and process diagram**
4. **Data-flow and trust-boundary diagram**
5. **Threat model**
6. **Security findings and remediation register**
7. **Performance baseline and regression report**
8. **Reliability and fault-injection report**
9. **Migration test report**
10. **Installer, updater, and rollback test report**
11. **Accessibility and compatibility report**
12. **SBOM and license report**
13. **Dependency vulnerability report**
14. **Signed artifact hashes and provenance**
15. **Known-risk register with owners**
16. **Release rollback and incident-response plan**
17. **Final sign-off against the exact release build**

A practical finding record should contain:

```text
ID
Domain
Requirement
Affected component
Affected OS/version
Severity
Likelihood
User/business impact
Reproduction steps
Evidence
Recommended remediation
Owner
Status
Target release
Risk-acceptance approver
Verified build hash
```

Use a simple status model:

* **Pass**
* **Pass with accepted risk**
* **Fail**
* **Not applicable**
* **Not tested**

And a severity model:

* **S0 — Stop-ship:** exploitable security issue, data loss, update compromise, or unusable core path
* **S1 — High:** serious reliability, privacy, performance, accessibility, or compatibility failure
* **S2 — Medium:** meaningful degradation with a workaround
* **S3 — Low:** polish, maintainability, or low-impact defect

The release should not be approved based on an overall percentage score. A single updater compromise or data-loss defect outweighs hundreds of passed cosmetic checks. The decision should be based on open risk, evidence quality, rollback readiness, and whether the exact signed artifact has passed the required gates.
