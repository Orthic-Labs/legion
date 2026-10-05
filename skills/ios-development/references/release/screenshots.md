# Screenshots & submission assets

Examples below use raw external `asc` CLI plus host tools. Read [asc tool setup](../tool-setup.md#asc).
Before any `asc` call, export telemetry opt-outs, run known-version check, then
inspect `asc screenshots --help` & each leaf help:

```sh
export ASC_TELEMETRY_DISABLED=1 DO_NOT_TRACK=1
asc version
```

Legion-native surfaces may differ & must not be claimed to support these
options without observed help output.

## Plan the matrix

Resolve platform, supported device families, orientations, locales and required App Store Connect slots from current product state. Capture the intended build/configuration on representative devices or simulator; keep device model, OS, locale, build ID, capture date & source revision with each asset. Do not fabricate screenshots or claim device coverage from one simulator.

Use the existing screenshot pipeline when present. Resize only within Apple-supported dimensions and preserve readable UI, safe areas, localization and orientation. Validate image type, pixel dimensions, file size, ordering, locale and slot count before upload. Treat screenshot resizing as packaging, not ASO or marketing strategy.

Discover current size matrix at runtime; do not maintain hard-coded dimensions:

```bash
asc screenshots sizes --output table
asc screenshots sizes --all --output table
asc screenshots validate --path "./screenshots/iphone" --device-type "IPHONE_65" --output table
```

Inspect `pixelWidth`, `pixelHeight`, `hasAlpha` & color space. App Store
Connect rejects alpha; preserve originals, then round-trip through JPEG when
removing alpha. Convert non-sRGB assets only when required & revalidate:

```bash
sips -g pixelWidth -g pixelHeight -g hasAlpha -g space screenshot.png
sips -s format jpeg input.png --out /tmp/asc-screenshot-no-alpha.jpg
sips -s format png /tmp/asc-screenshot-no-alpha.jpg --out output.png
sips -m "/System/Library/ColorSync/Profiles/sRGB IEC61966-2.1.icc" input.png --out output-srgb.png
asc screenshots validate --path "./screenshots/validated" --device-type "IPHONE_65" --output table
```

## Upload safely

Download current assets or list current slots first. Stage new files outside source, name them deterministically by locale/device/orientation/sequence, preview the exact replacement set, then upload through the selected `asc` command or project pipeline. Use dry-run where supported; never delete existing evidence to make a slot pass. Keep signed upload URLs and raw API responses private.

## Verify

Read back uploaded asset IDs, locale, dimensions, display order and processing status. An upload receipt does not prove App Store availability or review acceptance. Report rejected/processing assets individually and preserve original files for retry. If a screenshot failure reflects metadata, product positioning or ad spend, route diagnosis to ASO/marketing/ads owners.

## Optional capture pipeline

When requested & supported by host, retain existing settings/plan paths, then
sequence build/install/launch → capture → frame → review → plan/apply:

1. Record bundle ID, project/scheme, simulator UDID, raw/framed dirs & upload
   switch in a settings JSON.
2. Use host's existing Xcode path to build, install & launch; capture via
   `asc screenshots run --plan ...` or an already available AXe integration.
   Preserve build/run/capture evidence with exact UDID & source revision.
3. Discover frame devices with `asc screenshots list-frame-devices`; run
   `asc screenshots frame` only when compatible framing support already exists.
4. Generate/open/approve review artifacts with
   `asc screenshots review-generate`, `review-open` & `review-approve`; use
   `asc screenshots plan` to account for remote slots before
   `asc screenshots apply --confirm`, or upload validated files directly.

```bash
xcodebuild -project "App.xcodeproj" -scheme "App" -destination "platform=iOS Simulator,id=$UDID" -derivedDataPath ".build/DerivedData" build
xcrun simctl install "$UDID" ".build/DerivedData/Build/Products/Debug-iphonesimulator/App.app"
xcrun simctl launch "$UDID" "com.example.app"
asc screenshots run --plan ".asc/screenshots.json" --udid "$UDID" --output json
asc screenshots list-frame-devices --output json
asc screenshots frame --input "./screenshots/raw/home.png" --output-dir "./screenshots/framed" --device "iphone-air" --output json
asc screenshots review-generate --framed-dir "./screenshots/framed" --output-dir "./screenshots/review"
asc screenshots review-open --output-dir "./screenshots/review"
asc screenshots review-approve --all-ready --output-dir "./screenshots/review"
asc screenshots plan --app "APP_ID" --version "1.2.3" --review-output-dir "./screenshots/review" --output json
asc screenshots apply --app "APP_ID" --version "1.2.3" --review-output-dir "./screenshots/review" --confirm --output json
```

AXe & Koubou are optional host-compatible helpers. Do not require installation,
network setup or foreign choreography; use existing supported capture/framing
tools when available & retain raw assets when a framing step cannot run.
