# Rust, UniFFI & JNI

This reference records source inspection at RightKit commit
`70ee319aaf3f5bc22b966c8249e30f0982d8784b` on 2026-10-17. The module path below is
relative to the consuming RightKit checkout; paths listed inside it are relative to
`crates/rightkit-android/`. These are PROJECT_OVERLAY inputs, not files shipped in this
skill. Reinspect them before implementation.

## Shared owner

When the consuming RightKit checkout contains `crates/rightkit-android/`, it is the
shared Rust bridge and Gradle Android library. Within that module, read `README.md`,
`TOOLCHAIN.md`, `Cargo.toml`, `uniffi.toml`, `src/context.rs`, `src/jni_entry.rs`, Kotlin
`android/src/main/kotlin/com/orthiclabs/rightkit/android/RightKit.kt`,
`android/build.gradle.kts`, `android/settings.gradle.kts`, and
`scripts/toolchain.versions`. Its documented boundary centralizes shared JNI/context/
Keystore integration. App-specific exports belong in the app cdylib that consumes the
bridge. Preserve this owner instead of adding a second app-local Keystore/JVM layer.

The inspected source calls `RightKit.init(applicationContext, libraryName = ...)` from
`Application.onCreate` before bridge use, independently in each Android process. Init
captures JVM, application Context, and app directories. Follow actual signatures, load
name, and initialization errors; do not retain Activity Context for process lifetime.

The inspected documentation marks JNI/Keystore/device integration and toolchain pins
unverified. Source presence records implementation intent; it does not establish
compilation, native packaging, or device behavior. If the consuming checkout does not
contain this shared owner, preserve and inspect the project's existing bridge instead
of assuming RightKit is available.

## Language boundary

Generate Kotlin bindings with the project's matching UniFFI version and configuration.
Match generated package/library names, dependencies, and native libraries for every
advertised ABI. Wire generated sources before Kotlin compilation and native outputs
before packaging. UniFFI's general
[Gradle example](https://mozilla.github.io/uniffi-rs/latest/kotlin/gradle.html) may use
older Gradle APIs; adapt it to the project's pinned AGP.

Share `JavaVM`, never a `JNIEnv` across threads. Attach calling threads through the
existing bridge API; respect local/global reference lifetimes, JNI exceptions, and
class-loader context. Review callback lifetime, threading, and shutdown. Define
cancellation, resource release, and typed errors at the FFI boundary; do not let Rust
panics cross JNI. See Android's [JNI guidance](https://developer.android.com/ndk/guides/jni-tips).

Read the module's `scripts/toolchain.versions` and Gradle configuration together; do not promote
unverified pins into universal recommendations. Route Rust through managed workspace
tooling and preserve build admission. Check packaged ABI
directories, exported entry points, generated Kotlin linkage, transitive `.so`
dependencies, shrinker rules, and native-library loading assumptions. If loading via
`nativeLibraryDir`, verify packaging supports that lookup. Check 16 KB page-size
compatibility for bundled native libraries when relevant.

Runtime acceptance should cover initialization before use, separate service-process
initialization when present, native method loading, worker-thread JNI calls,
cancellation/release of app-specific sessions, and credential round trips. Exercise
claimed device and emulator ABIs. Host Rust tests do not establish Android JNI success.
