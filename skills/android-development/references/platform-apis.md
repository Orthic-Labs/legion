# Android platform APIs

Sources retrieved 2026-10-17. Read only sections needed for current change. Runtime validation depends on the affected app and device.

## Establish compatibility & ownership

Record device API, `minSdk`, `targetSdk`, `compileSdk`, entry point, permission state & expected work lifetime before choosing APIs. API availability, target-dependent enforcement & current app visibility are separate inputs. Reopen linked guidance when changing targets or relying on an exemption; do not infer current Play requirements from this reference.

Implementation rule: assign one owner for each recorder, stream, descriptor & job. UI-scoped work ends with its lifecycle; background recording belongs to an eligible service. Serialize start/stop/release transitions, close resources on cancellation & failures, & prevent callbacks from using released objects. Coroutine cancellation alone does not release native resources. These are design rules, not claims that Android performs cleanup automatically.

## Request only needed access

Request dangerous permissions in context on Android 6.0/API 23+, using Activity Result permission contracts. Check access at each use; persisted UI state is not permission evidence. Show rationale when appropriate, allow cancellation, & keep unrelated features usable after denial or revocation. Do not repeatedly pressure users to grant access.

Android 11/API 30 introduced one-time microphone, camera & location access. Revocation can terminate app process, so recover from durable state rather than expecting cleanup callbacks. Handle denied, cancelled, one-time-expired & revoked access as normal feature states. [Request runtime permissions](https://developer.android.com/training/permissions/requesting)

## Choose work by required lifetime

Use coroutines for work allowed to end with its owning process or screen. Choose WorkManager when work must remain scheduled across app exits or device restarts; specify constraints, unique-work policy, retry behavior & cancellation. It supports Kotlin coroutines, flexible scheduling & expedited requests, but does not promise arbitrary immediate execution. Use AlarmManager for precise user-facing alarms, not recurring synchronization. [Task scheduling](https://developer.android.com/develop/background-work/background-tasks/persistent)

For user-visible ongoing work, first check purpose-built alternatives. For foreground services, declare service type & required permissions, satisfy runtime prerequisites, & promote with matching type. Android 14/API 34 type-specific enforcement requires particular attention when targeting 34+. Microphone capture requires `microphone`, `FOREGROUND_SERVICE_MICROPHONE`, base `FOREGROUND_SERVICE` & granted `RECORD_AUDIO`; implement notification & explicit stop behavior. [Foreground service types](https://developer.android.com/develop/background-work/services/fgs/service-types)

Apps targeting Android 12/API 31+ generally cannot start foreground services from background without an applicable exemption. Separately, while-in-use resource eligibility constrains microphone/camera/location services. On Android 14+ when targeting 34+, missing current permission eligibility can fail service creation with `SecurityException`; `PERMISSION_GRANTED` alone does not prove background eligibility. Earlier devices can create service yet deny resource access. Start microphone service from visible activity after grant unless documented while-in-use exemption applies. A general background-start exemption does not automatically satisfy this second gate. Handle denied starts without retry loops. [Foreground-service start restrictions](https://developer.android.com/develop/background-work/services/fgs/restrictions-bg-start)

## Capture audio with explicit resource state

Choose MediaRecorder for supported capture/encoding to output file. Configure source, format, destination & encoder before `prepare`, then start only after successful preparation. Stop according to actual recorder state & release promptly on every terminal path. Android 9/API 28+ background microphone access requires foreground operation or eligible foreground service; apply service rules above. Hardware capabilities determine available formats & sources, so exercise recording on physical device. [MediaRecorder overview](https://developer.android.com/media/platform/mediarecorder)

Choose AudioRecord for application-managed sample reads. Validate supported format & positive minimum buffer size, confirm `STATE_INITIALIZED`, & account for load when sizing buffers. Check read counts/error codes; process only returned samples. `ERROR_DEAD_OBJECT` requires recreation, not reuse; `release()` invalidates instance. Design reader shutdown so native blocking reads cannot strand resource ownership; coordinate stop, read-loop exit & release. Test device routing/interruption paths required by feature. [AudioRecord reference](https://developer.android.com/reference/android/media/AudioRecord)

## Store files by purpose

Use internal app-private storage for sensitive app-owned files; choose cache only for replaceable data. App-specific files disappear on uninstall. Choose MediaStore for shared media & Storage Access Framework for user-selected documents through system picker. Treat content URIs as access handles rather than assuming filesystem paths; handle access loss & cancellation.

Scoped storage applies by default for targets 29+; Android 10 permits a legacy opt-out, while targeting 30+ on Android 11+ removes that opt-out. `WRITE_EXTERNAL_STORAGE` has no effect for targets 30+. Select access permissions for actual device/target/media operation rather than copying legacy storage manifests. This overview's media-permission table does not establish modern granular-media requirements; fetch linked operation-specific guidance before implementing access to others' media. [Storage overview](https://developer.android.com/training/data-storage)

## Protect keys & design restore recovery

Use Android Keystore provider for app-owned cryptographic keys; set allowed purposes & authentication requirements deliberately. Key material remains non-exportable, but compromised app code can still use authorized operations. Hardware protection depends on device & key configuration; inspect `KeyInfo` before claiming it. StrongBox availability is optional & brings resource/performance tradeoffs. Authentication-bound keys can become unusable, including default invalidation after new biometric enrollment for biometric-only keys; define recovery before encrypting durable data. [Android Keystore](https://developer.android.com/privacy-and-security/keystore)

Auto Backup includes many private files by default, while cache & no-backup directories are excluded. For devices running Android 12/API 31+ with targets 31+, use data-extraction rules; retain legacy rules for older supported devices. Configure cloud & device-transfer exclusions separately; `allowBackup=false` may not prevent device transfers on some manufacturers' devices.

Derived design rule from backup coverage & Keystore's device-bound keys: restored ciphertext must tolerate missing, different or invalidated keys. Either exclude device-key-bound ciphertext from applicable transfers or provide deliberate reauthentication/recovery. Never silently generate replacement key then claim old ciphertext recovered. Exercise restore onto fresh installation/device. [Auto Backup](https://developer.android.com/identity/data/autobackup)

## Focused acceptance scenarios

Select scenarios affected by change: denied/revoked permission, one-time grant expiry, background transition, rejected service start, cancellation during capture, read/prepare failure, repeated start/stop, unavailable storage, restore without usable key & process recreation. Record exact device/API/target used for evidence.
