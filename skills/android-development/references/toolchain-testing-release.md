# Android toolchain, testing & release

Deliver the requested Android change with evidence from the affected app, target, and build variant. Read repository guidance and existing scripts first; preserve the app’s current architecture and pinned toolchain.

## Toolchain and Gradle

Identify the Gradle wrapper, included builds/modules, build variants, Android Gradle Plugin (AGP), Kotlin Gradle Plugin, Gradle JDK, compile/target/min SDK levels, and any NDK or native libraries. Keep wrapper and plugin versions from the project. Check their compatibility together against Android’s current [AGP compatibility notes](https://developer.android.com/build/releases/agp-9-2-0-release-notes) and JDK guidance; compatibility tables change, so verify the project’s pinned versions at execution time. A version shown in current release notes is not a reason to upgrade.

Use the project wrapper and checked-in configuration. Don’t install SDKs, NDKs, JDKs, or plugins ad hoc, or upgrade versions, unless requested and allowed by workspace policy. Before choosing a Gradle task, inspect available tasks and project scripts. Common task names such as `test<Variant>UnitTest`, `connected<Variant>AndroidTest`, `assemble<Variant>`, or `bundle<Variant>` are examples; confirm task names, module, and variant, then run only scope needed. Follow workspace RightKit ownership and shared build-admission rules before building.

## Testing and device evidence

Keep proof at the layer it exercises:

- Local JVM tests cover non-Android logic and fakes; they don’t prove framework or device behavior.
- Instrumented tests run on an Android runtime and cover framework/UI integration. For Compose, prefer stable semantics matchers, accessible labels, and deterministic state over screen coordinates; inspect the semantics tree when a node is unclear. See [Compose testing APIs](https://developer.android.com/develop/ui/compose/testing/apis).
- Emulator checks cover only configured virtual-device behavior. They don’t establish OEM, physical hardware, Bluetooth/NFC/USB, attached audio, or microphone behavior. Use a real device for affected hardware and vendor-specific paths. Emulator network and location simulation can help when those flows are in scope.
- Signed release validation exercises a different artifact and configuration from debug tests.

Select a device explicitly when more than one is attached: inspect `adb devices -l`, then use `adb -s SERIAL …` for every device command. For targeted logs, get the running process ID with `adb -s SERIAL shell pidof -s PACKAGE`, then use `adb -s SERIAL logcat --pid=PID`. Keep logs focused on the affected app and time window. Don’t clear app data, wipe an emulator, or reset permissions unless that state change is needed to reproduce the requested behavior.

Exercise permission denial, process death, rotation, or offline behavior only when the change touches those flows. Record device/emulator model, Android API, variant, command, and outcome. Don’t describe emulator evidence as physical-device evidence.

## Play release preparation

First establish whether deliverable is an APK for direct install or an Android App Bundle (AAB) for Play. Confirm `applicationId`, `versionCode`, variant, min/target SDK, and exact artifact. Play App Signing separates the upload key that signs the submitted bundle from Google’s app-signing key used for distribution; preserve existing signing configuration and never expose keys or passwords. See [app signing](https://developer.android.com/studio/publish/app-signing).

For apps with native libraries, inspect every bundled and prebuilt library for 16 KB page-size support; validate the exact artifact using Android’s [16 KB page-size guidance](https://developer.android.com/guide/practices/page-sizes). Check current Google Play target-API rules at execution time and for the app category, since deadlines and exemptions can change. Review [Data safety](https://support.google.com/googleplay/android-developer/answer/10787469), privacy policy, SDK data handling & applicable [foreground-service declarations](https://support.google.com/googleplay/android-developer/answer/13392821), including microphone use, against behavior in exact artifact. Check R8/minification and native-library packaging on the release variant when affected.

This capability prepares and validates release inputs. It does not authorize credential changes, upload, rollout, or publication. A successful build, signature check, or local install is not proof of release readiness.

[Source manifest](../config/source-manifest.json) records reviewed sources and retrieval date.
