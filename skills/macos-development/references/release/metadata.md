# Metadata, localization & release notes

## Canonical workflow

Pull current state first: `asc metadata pull --app APP_ID --version VERSION --platform IOS --dir ./metadata`; pass explicit app-info ID when multiple records exist. App-level JSON lives under `metadata/app-info/<locale>.json`; version fields under `metadata/version/<version>/<locale>.json`. Keep copyright as version property, not localization.

Run `asc metadata validate` before any remote write; include subscription checks where applicable. Preview `asc metadata push ... --dry-run` or use `metadata plan` + scoped `approve`/`status` + confirmed apply when a durable review artifact is needed. Use JSON for automation and table output for human review.

Fields have hard limits: name 30, subtitle 30, keywords 100 comma-separated characters, description 4000, what's new 4000, promotional text 170. Validate each locale before upload; shorten semantically, never cut mid-sentence. Keep app-info fields separate from version fields.

## Lower-level & legacy paths

Use `asc localizations download/upload` for explicit `.strings` trees, with dry-run before upload. Use `asc migrate export/validate/import` only for existing fastlane metadata. Deliverfile `metadata_path` and `screenshots_path` resolve relative to Deliverfile; avoid accidental `fastlane/fastlane` paths. Keep external-path trust flags off unless explicitly scoped. Inspect validation JSON: `valid:false` or `errorCount` can fail despite exit 0; confirmed imports may return partial status and nonzero exit.

## Localization procedure

Read current source locale and existing translations; do not overwrite without requested update. Version localization and app-info localization are distinct resources. Resolve explicit version/app-info/localization IDs. Show proposed locale values, limits & diff before upload when content is being authored. Keywords need locale-specific search judgment; do not mechanically translate or stuff them. Promotional text can change without a new version; what's new is version-scoped.

## Release notes

Write concrete user-facing improvements, front-load the first visible sentence, keep primary notes roughly 500–1500 characters when possible and ≤4000 always. What's new is not an organic search index; use approved product facts, then localize for locale/register. Upload only after review of all locale text & counts.

ASO audits, keyword-gap research, Apple Ads, paid pricing and marketing strategy route to their existing owners. Release consumes approved output and validates limits only.
