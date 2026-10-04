# Build, archive & export

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

## macOS distinction

macOS Mac App Store packages follow App Store signing/export rules. Developer ID distribution produces a signed `.app`, then a ZIP, DMG or PKG for notarization. Verify nested signatures and secure timestamp before submission; see [signing](signing.md).
