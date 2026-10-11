# On-demand App Store submission repairs

Use this guide only after `asc validate` or `asc review doctor` identifies a blocker. `asc` is an external CLI; follow [external `asc` setup](../tool-setup.md#asc), then keep this process-scoped environment active before any command below:

```bash
export ASC_TELEMETRY_DISABLED=1
export DO_NOT_TRACK=1
asc version
```

Verify exact leaf `--help` & capability before using any command. Pinned examples target `IOS`; adapt only after help confirms a platform flag. This reference describes procedures; it does not claim Legion's native adapter supports these flags.

## Lock target & route

Resolve `APP_ID`, version string or exact `VERSION_ID`, `BUILD_ID` & platform. Prefer IDs after deterministic list/read commands. Inspect current state before each edit, repair one blocker class at a time, then read it back. Keep public App Store Connect API, authenticated web-session automation & manual App Store Connect work separate in reports.

Public API examples include builds, encryption declarations, content rights, age rating, metadata, app-info/privacy URL, screenshots, availability & review details. App Privacy publish state may require web-session or manual verification. A successful apply is an applied draft; it is not proof that answers are published.

Establish ordered evidence before repair:

```bash
asc validate --app "APP_ID" --version "1.2.3" --platform IOS --output table
asc review doctor --app "APP_ID" --version "1.2.3" --platform IOS --output table
```

Use `--version-id "VERSION_ID"` when resolved, & route only proven blocker classes below.

## Build processing & encryption

Inspect the selected build:

```bash
asc builds info --build-id "BUILD_ID" --output table
```

Require `processingState=VALID`. If encryption is unresolved, inspect declarations:

```bash
asc encryption declarations list --app "APP_ID" --output table
```

Create a declaration only when answers describe binary behavior, then assign it to exact build:

```bash
asc encryption declarations create \
  --app "APP_ID" \
  --app-description "Uses standard HTTPS/TLS" \
  --contains-proprietary-cryptography=false \
  --contains-third-party-cryptography=true \
  --available-on-french-store=true
asc encryption declarations assign-builds --id "DECLARATION_ID" --build-id "BUILD_ID"
```

Use plist exemption only when app truly qualifies, then rebuild:

```bash
asc encryption declarations exempt-declare --plist "./Info.plist"
```

Read back declaration assignment & build state before continuing.

## Content rights & age rating

Inspect full declarations before editing:

```bash
asc apps content-rights view --app "APP_ID" --output table
asc age-rating view --app "APP_ID" --output table
```

Edit only answers known to describe app:

```bash
asc apps content-rights edit --app "APP_ID" --uses-third-party-content=false
asc age-rating edit --app "APP_ID" --social-media false --social-media-age-restricted false
```

If social media is true, preserve required prerequisites: `userGeneratedContent=true`; `ageAssurance=true` plus `socialMedia=true` before `socialMediaAgeRestricted=true`. If an override is required, use `--age-rating-override-v2` when installed help exposes it; treat older override spelling as version-conditioned. Read back full declarations.

## Version metadata & localizations

Inspect version, build, submission relationship & localizations:

```bash
asc versions view --version-id "VERSION_ID" --include-build --include-submission --output table
asc localizations list --version "VERSION_ID" --output table
```

For canonical metadata, pull, validate, preview, then apply:

```bash
asc metadata pull --app "APP_ID" --version "1.2.3" --platform IOS --dir "./metadata"
asc metadata validate --dir "./metadata" --output table
asc metadata push --app "APP_ID" --version "1.2.3" --platform IOS --dir "./metadata" --dry-run --output table
asc metadata push --app "APP_ID" --version "1.2.3" --platform IOS --dir "./metadata"
```

Review dry-run diff before apply. Do not replace local source with remote pull unless that copy was selected as source of truth. Read back every affected localization & rerun readiness.

## App info & privacy policy URL

Resolve exact app-info record and localizations:

```bash
asc apps info list --app "APP_ID" --output table
asc localizations list --app "APP_ID" --type app-info --app-info "APP_INFO_ID" --output table
```

When missing, set approved URL:

```bash
asc app-setup info set \
  --app "APP_ID" \
  --primary-locale "en-US" \
  --privacy-policy-url "https://example.com/privacy"
```

Read back app-info localization & URL. Do not invent privacy content or use a placeholder in a release.

## Screenshots

Inspect current slots & accepted dimensions before producing or replacing assets:

```bash
asc screenshots list --version-localization "LOC_ID" --output table
asc screenshots sizes --output table
asc screenshots validate --path "./screenshots" --device-type "IPHONE_65" --output table
```

Use approved screenshot tooling to produce valid files, preview replacement set, upload through selected pipeline, then read back asset IDs, locale, dimensions, order & processing state. Upload success does not prove review acceptance.

## Initial availability

Inspect before creating a record:

```bash
asc pricing availability view --app "APP_ID" --output table
```

If absent, use approved territories in public API create:

```bash
asc pricing availability create \
  --app "APP_ID" \
  --territory "USA,GBR" \
  --available true \
  --available-in-new-territories true
```

If Apple rejects public-API bootstrap because availability is not configured, route to authenticated web session or manual App Store Connect:

```bash
asc web auth login --apple-id "EMAIL"
asc web apps availability create --app "APP_ID" --territory "USA,GBR" --available-in-new-territories true
```

Use `asc pricing availability edit` only after a record exists. Territory selection is product intent; preserve it explicitly. Read back availability before continuing.

## Review details

Inspect, create only when missing, update resolved record otherwise:

```bash
asc review details-for-version --version-id "VERSION_ID" --output table
asc review details-create \
  --version-id "VERSION_ID" \
  --contact-first-name "Dev" \
  --contact-last-name "Support" \
  --contact-email "dev@example.com" \
  --contact-phone "+1 555 0100" \
  --notes "Explain the reviewer access path here."
asc review details-update --id "DETAIL_ID" --notes "Updated reviewer instructions."
```

Set demo-account fields only when review needs credentials. Never put secrets in logs or handoff text. Read back details.

## App Privacy: API, web session & manual states

Public readiness can raise an App Privacy advisory, but public API may not confirm final published state. For web-session repair, pull current answers to a reviewable file, inspect plan, apply reviewed file, then publish separately:

```bash
asc web privacy pull --app "APP_ID" --out "./privacy.json"
asc web privacy plan --app "APP_ID" --file "./privacy.json"
asc web privacy apply --app "APP_ID" --file "./privacy.json"
asc web privacy publish --app "APP_ID" --confirm
```

Before the `publish --confirm` line, run `asc web privacy publish --app "APP_ID" --help`; if it lists `--dry-run`, run that first and inspect the planned effects. Otherwise the `plan` output and the readback of the App Privacy draft are the effect inspection. The `publish --confirm` step makes App Privacy answers live for this app and needs explicit user authorization in chat for this app and version.

`apply` means answers were written to an App Privacy draft; it does not mean they were published. Verify published state after the separate publish step. If web automation is declined or unavailable, inspect App Privacy manually at `https://appstoreconnect.apple.com/apps/APP_ID/appPrivacy` & report that manual evidence.

## Return to release flow

Rerun readiness after each repair class. Return to release only when blocking validation issues are gone, build is `VALID`, metadata/screenshots/review details/content rights/encryption/age rating/pricing/availability are resolved, relevant product validators pass, Game Center items are prepared through release flow, & App Privacy is confirmed or published. Product version `PREPARE_FOR_SUBMISSION` still requires separate review-draft inspection before multi-item assembly.

## Multi-item draft assembly

Use this section only after product version & every intended item are ready. Inspect all submissions, then branch:

```bash
asc review submissions list --app "APP_ID" --platform IOS --include "items,appStoreVersionForReview" --paginate --output json
```

If a handed-off `SUBMISSION_ID` exists, inspect exact draft:

```bash
asc review submissions-get --id "SUBMISSION_ID" --include "items,appStoreVersionForReview" --output json
```

Reuse only intended `READY_FOR_REVIEW` draft. Without handed-off ID, reuse exactly one matching draft; create only when no matching draft or active submission exists:

```bash
asc review submissions-create --app "APP_ID" --platform IOS --output json
```

Zero matching drafts permits create. One matching draft permits reuse. Multiple drafts or active mismatch blocks assembly and routes to submission health. Never create a second submission.

List current items, compare exact type plus version resource ID, & attach only missing IDs:

```bash
asc review items list --submission "SUBMISSION_ID" --paginate --output json
asc review items add --submission "SUBMISSION_ID" --item-type appStoreVersions --item-id "VERSION_ID"
asc review items add --submission "SUBMISSION_ID" --item-type inAppPurchaseVersions --item-id "IAP_VERSION_ID"
asc review items add --submission "SUBMISSION_ID" --item-type subscriptionVersions --item-id "SUBSCRIPTION_VERSION_ID"
asc review items add --submission "SUBMISSION_ID" --item-type subscriptionGroupVersions --item-id "GROUP_VERSION_ID"
```

Add required Game Center *version* item IDs only. Do not attach parent product IDs or unresolved placeholders. Read back submission & items before final confirm:

```bash
asc review submissions-get --id "SUBMISSION_ID" --include items --output table
asc review items list --submission "SUBMISSION_ID" --paginate --output table
asc review submissions-submit --id "SUBMISSION_ID" --dry-run --output table
asc review submissions-submit --id "SUBMISSION_ID" --confirm
```

Run the `--dry-run` first and inspect its planned effects against the readback above. The `--confirm` line submits the draft for App Review and needs explicit user authorization in chat for this submission.
