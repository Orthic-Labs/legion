# Build, archive & export

Examples below use raw external `asc` CLI path. Read [asc tool setup](../tool-setup.md#asc).
Before any `asc` call, export telemetry opt-outs, run known-version check, then
inspect `--help` plus relevant leaf help:

```sh
export ASC_TELEMETRY_DISABLED=1 DO_NOT_TRACK=1
asc version
```

Legion-native surfaces may expose different verbs/options & must not be
claimed to support these flags without observed help output.

## Version and build identity

Use explicit project/workspace, scheme, target, configuration & platform. Read current settings first. Resolve a remote-safe build number with `asc builds next-build-number`; update source using `asc xcode version edit --next-build-number` only when authorized. Record changed files and confirm all relevant configurations agree. Never assume “latest” when multiple versions or builds exist.

## Validation build

Use `asc xcode build` or existing project command for simulator/device/CI checks. Supply one project or workspace plus scheme, destination, result bundle path that does not already exist, and preserve raw stderr. Unsigned builds can prove compilation/packaging only; they cannot prove signing, installation, notarization, store acceptance or restricted-device operation.

## iOS archive/export

Archive for a generic physical platform with the intended Release configuration. Keep `.xcarchive`, result bundles, export options & IPA in an isolated artifact directory. Prefer `asc xcode archive` and `asc xcode export`; pass project-specific flags through `--xcodebuild-flag` before falling back to raw `xcodebuild`.

App Store Connect export uses the generated `app-store-connect` method. Registered-device export uses current Xcode `release-testing` (older `ad-hoc` spelling is deprecated in this adapter), manual signing and explicit team when required. `release-testing` exports locally and cannot combine with `--wait`; direct upload waits for App Store processing. Do not combine an explicit plist with method/signing-style/team flags.

Inspect archive/export contents: main app, extensions, Watch/App Clips, symbols, architectures, bundle IDs, version/build & entitlements. A private ad hoc workflow requires one main app target in its current plan; embedded apps/extensions may make that plan unavailable. Use existing private distribution workflow when device registration, profile reconciliation, immutable publication, resumability or live fetch verification is required.

## Upload & state checks

Use `asc builds upload` for upload-only, `asc publish testflight` for upload plus group distribution, and `asc publish appstore` for upload plus staged release. `--wait` means processing polling, not review approval or publication. Inspect build state after wait; branch on `processingState`/errors and only attach a processed, valid build. For a PKG, pass explicit version/build because metadata may not be extracted.

## Build retention & inspection

Resolve exact app, version & platform before selecting build state:

```bash
asc builds info --app "APP_ID" --latest --version "1.2.3" --platform IOS
asc builds list --app "APP_ID" --sort -uploadedDate --limit 10
asc builds info --build-id "BUILD_ID"
```

Use explicit IDs after inspecting results; never choose first row from an
ambiguous list. Build expiration is opt-in only when operator explicitly asks
for retention cleanup. Preview candidates & effects, then confirm exact scope;
read back affected IDs/state after mutation:

```bash
asc builds expire-all --app "APP_ID" --older-than 90d --dry-run
asc builds expire-all --app "APP_ID" --older-than 90d --confirm
asc builds info --build-id "BUILD_ID"
```

Use `asc builds expire --build-id "BUILD_ID" --confirm` only for explicitly
requested single-build expiry. Never expire builds unsolicited. A scheduled
cleanup is allowed only when explicitly requested with exact app/scope; each
run still requires dry-run, confirm & readback.

## macOS distinction

macOS Mac App Store packages follow App Store signing/export rules. Developer ID distribution produces a signed `.app`, then a ZIP, DMG or PKG for notarization. Verify nested signatures and secure timestamp before submission; see [signing](signing.md).
