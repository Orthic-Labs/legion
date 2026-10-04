# SwiftUI accessibility & localization

## Source-aligned detail

For custom controls, grouping, Dynamic Type, and locale examples, read [accessibility patterns](donor-lee-accessibility-patterns.md),
[localization](donor-lee-localization.md), and [Hudson accessibility rules](donor-hudson-accessibility.md).

Use native `Button`, `Toggle`, `Menu`, `Link`, and controls. `onTapGesture` is for tap count or
location only; if unavoidable add button traits. Give image-labeled controls text labels and
use `.labelStyle(.iconOnly)` only to preserve intentional visuals. Decorative images use
`Image(decorative:)`/`accessibilityHidden`; informative images get a concise label. Group rows
with `.accessibilityElement(children: .combine/.contain/.ignore)` according to semantics, not
layout. Model custom sliders/pages with `accessibilityValue`, adjustable actions, or
`accessibilityRepresentation`.

Use Dynamic Type styles and `@ScaledMetric(relativeTo:)` for custom dimensions. Avoid forced
font sizes, fixed text frames, and color-only state; honor differentiate-without-color. Respect
Reduce Motion by replacing large motion with opacity/short transitions. Test VoiceOver order,
keyboard/focus, contrast, long strings, empty/error states, and hit targets (44x44 on iOS).

SwiftUI localizes literal keys passed directly to `Text`, `Button`, `Label`, titles, and alerts;
do not eagerly wrap literals in `String(localized:)`. In packages/frameworks, pass `bundle:
#bundle`. Model known user-facing variants as `LocalizedStringResource`, interpolate in one
sentence rather than concatenate `Text` fragments, and provide translator comments. Use
locale-aware `FormatStyle` for dates/numbers/currency, `.leading`/`.trailing`, and
`@Environment(\.locale)` in views. Use `String(localized:)` only when a resolved String is
needed outside a view. String catalogs and existing `.strings` conventions take precedence.

