# Release preparation & authorized execution

Use this page as router. Keep release work under [contract & adapter selection](release/contract.md):

- [contract & adapter selection](release/contract.md) — target inventory, asc vs ascctl, JSON/exit codes, dry-run, pagination & credentials.
- [build, archive & export](release/build.md) — version/build numbers, Xcode artifacts, iOS distribution methods & macOS package shape.
- [metadata & localization](release/metadata.md) — canonical metadata, `.strings`, fastlane migration, limits & previews.
- [screenshots & submission assets](release/screenshots.md) — device matrices, validation, upload & immutable evidence.
- [signing & notarization](release/signing.md) — profiles, certificates, Developer ID, notarization & stapling.
- [TestFlight & build processing](release/testflight.md) — upload, processing, groups, feedback, crashes & terminal checks.
- [review submission & workflows](release/submission.md) — readiness, stage, submit, multi-item submissions, workflow dry-runs & resume.

For every release, report exact artifact, app/version/build IDs, selected platform & terminal state. Transport/upload is an intermediate state: continue through processing, attachment, review submission, notarization or publication when requested, otherwise name unrun stages.

## Existing release contract

Before changing a project, identify product/bundle IDs, targets, supported OS/architectures, distribution channel, signing settings, entitlements, privacy usage descriptions, provisioning method, version/build numbers, archive/export commands & CI owner. Preserve existing Xcode, Cargo/Tauri or project-specific pipeline; do not create a second signing system. Keep credentials outside source, logs, chat & generated artifacts.

## Authorization boundary

Preparation, local inspection & dry-runs are read-only. Signing, account access, profile/certificate changes, uploads, metadata writes, submissions, publication, pricing, advertising, commercial optimization & account settings are separate effects. Execute only effects in current user scope. Never weaken code signing, Gatekeeper, sandboxing, library validation or macro validation to force a release.

## Platform state distinctions

iOS simulator build, device build, archive, export, upload, processed build, TestFlight assignment & App Store submission are separate states. macOS local bundle, signed app, notarized/stapled artifact, DMG/PKG & Mac App Store or Developer ID publication are separate states. Evidence for one state does not prove another.

## Out-of-scope routing

Apple Ads, ASO/keyword research, analytics interpretation, paid pricing/PPP, RevenueCat/catalog synchronization, marketing copy & subscription/IAP commercial strategy retain existing owners. Release may consume approved metadata or pricing inputs & verify readiness, but does not invent or apply commercial strategy. Crash/performance evidence may be collected here only for release triage; analysis routes to diagnostics/performance owners.

## Completion evidence

Use structured command output plus a final read-back. Record artifact path/hash where relevant, selected IDs, processing or review status, validation result & any unrun or blocked stage. A command's zero exit code is insufficient when JSON contains `ready:false`, `valid:false`, partial status or a non-terminal state.
