# Signing, profiles & notarization boundary

## iOS signing

Identify distribution method before selecting certificate/profile: development, simulator, App Store/TestFlight, registered-device release testing or another approved channel. Check entitlements, bundle IDs, provisioning profile application identifiers, team and expiry. Prefer existing automatic/manual signing contract. App Store Connect API can manage some certificates/profiles but cannot grant authority or replace local Xcode/keychain requirements.

For private registered-device distribution, protect devices JSON, PKCS#12 identity/password, plan/state and install-link artifact with owner-only permissions. Keep S3 credentials out of config/logs/chat; use approved environment credential chain. Plan is read-only and may return `ready:false`; inspect typed blockers and ordered effects. Apply only exact authorized plan hash. Input drift, expired signing material, immutable object conflict or expired link requires a new plan, never force/resume blindly. Verify publication/fetch; device install/launch is separate evidence.

## macOS Developer ID

Confirm a Developer ID Application identity exists with `security find-identity`; inspect trust settings only when a concrete signing error points there. Archive/export using project contract and `developer-id` method. Verify existing signature with `codesign --verify --deep --strict --verbose=2`, then inspect details separately. Confirm Developer ID authority chain, expected TeamIdentifier & secure timestamp. Never add `--sign` or `--force` to verification; those mutate bundles.

For PKG, use separate Developer ID Installer certificate and sign with `productsign`; App Store Connect does not create Developer ID certificates. Package only after app/nested code verification. Choose ZIP, DMG or PKG intentionally; staple final container when offline Gatekeeper operation is required.

## Notarization

Submit signed ZIP/DMG/PKG using existing `asc notarization` or approved notary workflow. `--wait` proves notarization result only when terminal status is accepted; otherwise query status and developer log. On invalid result, inspect log for unsigned nested binaries, hardened runtime, timestamps or entitlements; rebuild/re-export intended artifact. After acceptance, staple and verify ticket with existing platform tooling. Notarization is separate from App Store review/publication.

Never disable signing, Gatekeeper, sandbox, library validation, hardened runtime or macro security to bypass an error. Credentials, private keys and notarization logs remain private.
