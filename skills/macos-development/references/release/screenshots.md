# Screenshots & submission assets

## Plan the matrix

Resolve platform, supported device families, orientations, locales and required App Store Connect slots from current product state. Capture the intended build/configuration on representative devices or simulator; keep device model, OS, locale, build ID, capture date & source revision with each asset. Do not fabricate screenshots or claim device coverage from one simulator.

Use the existing screenshot pipeline when present. Resize only within Apple-supported dimensions and preserve readable UI, safe areas, localization and orientation. Validate image type, pixel dimensions, file size, ordering, locale and slot count before upload. Treat screenshot resizing as packaging, not ASO or marketing strategy.

## Upload safely

Download current assets or list current slots first. Stage new files outside source, name them deterministically by locale/device/orientation/sequence, preview the exact replacement set, then upload through the selected `asc` command or project pipeline. Use dry-run where supported; never delete existing evidence to make a slot pass. Keep signed upload URLs and raw API responses private.

## Verify

Read back uploaded asset IDs, locale, dimensions, display order and processing status. An upload receipt does not prove App Store availability or review acceptance. Report rejected/processing assets individually and preserve original files for retry. If a screenshot failure reflects metadata, product positioning or ad spend, route diagnosis to ASO/marketing/ads owners.
