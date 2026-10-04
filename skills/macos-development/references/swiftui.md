# SwiftUI implementation

Use this page as router. Read only topic refs needed by request; shared refs are mirrored
in iOS development so platform work has same state, identity, accessibility, localization,
animation, performance, and API-migration rules. Keep existing architecture and deployment
targets; version-specific APIs below always require availability gates and a useful fallback.

## Topic router

- [State & environment](swiftui/state-environment.md) — ownership, `@State`, `@Observable`,
  bindings, focused values, `@Entry`, dependency granularity, task cancellation.
- [Views & layout](swiftui/views-layout.md) — invalidation boundaries, extraction, builders,
  identity, adaptive sizing, safe areas, fold/large-display regions, representables.
- [Lists & scrolling](swiftui/lists-scroll.md) — stable IDs, unary rows, tables, reorder,
  swipe actions, refresh, scroll position, targets, transitions.
- [Navigation & presentation](swiftui/navigation-presentation.md) — typed stacks, split views,
  sheets, alerts, inspectors, tabs, deep links, restoration.
- [Accessibility & localization](swiftui/accessibility-localization.md) — Dynamic Type,
  VoiceOver, custom controls, RTL, string catalogs, locale-aware formatting.
- [Animation](swiftui/animation.md) — scoped implicit/explicit animations, transitions,
  transactions, phases, keyframes, reduced motion, `@Animatable` availability.
- [Images, web, charts & text](swiftui/media-web-charts-text.md) — `AsyncImage`, downsampling,
  WebKit, Charts, rich `AttributedString` editing, image scale.
- [Documents & macOS](swiftui/documents-macos.md) — `Document`/`DocumentReader`, scenes,
  windows, menus, commands, AppKit boundaries, pasteboard and file operations.
- [Liquid Glass](swiftui/liquid-glass.md) — macOS 26+ (and aligned platform) adoption, morphing, materials fallback,
  accessibility, contrast, and performance.
- [Performance & tracing](swiftui/performance-tracing.md) — invalidation diagnostics, Instruments
  capture/analysis, trace evidence, hot-path fixes, parser helpers.
- [API migration](swiftui/api-migrations.md) — hard/soft deprecations, conditional replacements,
  current SDK additions, and maintenance-scan disposition.
- [Focus, toolbars & previews](swiftui/focus-toolbars-previews.md) — keyboard focus, toolbar
  overflow/minimization, previews, mocks, and availability.
- [Source-aligned detail index](swiftui/donor-index.md) — full concrete Hudson/SwiftLee examples
  routed by topic after native integration.

Source-aligned detailed examples remain available for focused review in `swiftui/donor-hudson-*.md`
and `swiftui/donor-lee-*.md`; topic files above reconcile their overlapping rules. Upstream
Python trace helpers remain source evidence in the ledger; shipped helper behavior is described
for root's Rust implementation.

## Review posture

Report genuine correctness, accessibility, lifecycle, availability, or measured performance
issues. Soft-deprecated APIs are informational when untouched; do not bundle migrations into
feature work. Prefer native SwiftUI, but preserve an established UIKit/AppKit bridge when it
is the appropriate boundary. Avoid blanket current-SDK adoption or an architecture rewrite.

## Establish ownership before choosing wrappers

- Keep the app's existing observation architecture. Identify the source of truth, its
  lifetime, and who may mutate it; do not replace a working model solely for newer syntax.
- Use local state for view-owned transient state and bindings for an existing owner's
  editable state. Stable feature/model identity matters more than recreating objects in
  a view initializer. Inspect lifecycle when a view seems to reset or update too often.
- Observation availability and the project's minimum OS constrain use of @Observable.
  Keep ObservableObject/@StateObject/@ObservedObject where those are the established fit.
- In an @Observable model, @ObservationIgnored excludes a property from observation.
  Combining it with @AppStorage can avoid a macro conflict but does not prove defaults
  changes invalidate views. Prefer view-level @AppStorage or a tested observable bridge.
- @Query is SwiftUI-view-bound. Keep fetching outside views in the persistence layer with
  explicit context/isolation rather than copying a view property wrapper into a service.

## Identity, updates, and work

- Give collections stable semantic identifiers. A freshly generated UUID, index identity
  across reordering, or duplicate ID can lose state or associate it with the wrong row.
- Make body evaluation cheap and side-effect-free. Move I/O, expensive transformations,
  and uncached parsing out of it; measure before adding caching or view indirection.
- Use task lifetime appropriate to the owning view or feature; a view disappearing can
  cancel its task. Make keyed tasks respond to the real identity of the requested work.
- Keep UI-bound mutation on its declared actor. async alone does not make expensive work
  leave the main actor; consult the project's Swift isolation defaults and task context.
- Model loading, empty, failure, cancellation, and success states explicitly when they
  affect UI behavior. A stale response must not replace newer user intent.

## UI changes

- Preserve the existing navigation/state restoration scheme. Avoid a broad NavigationStack
  or architecture migration while repairing a local screen defect.
- Extract components when ownership or reuse becomes clearer, not by an arbitrary line
  count. Maintain explicit inputs, stable identity, and testable actions across extraction.
- Use native controls and semantics where practical. Check labels, focus, keyboard access,
  larger text, contrast, reduced motion, localization, and long/empty content as relevant.
- Guard newer platform-specific visual APIs with availability and a useful fallback.
  Do not apply iOS interaction assumptions to Mac windows and menu commands.
- Use previews to iterate, then build and exercise the affected runtime state. Preview
  success alone does not establish lifecycle, permissions, persistence, or device behavior.

## Conditional Liquid Glass adoption

When the user asks for Liquid Glass or the app already uses it, check SDK/API availability,
deployment targets, and Apple's current adoption guidance. Prefer appropriate system
controls/material behavior; do not turn every content surface into glass or replace the
existing design system incidentally. Provide an intentional older-OS fallback and verify
contrast, legibility, Reduce Transparency/Reduce Motion, interaction, and performance on
the actual affected platform. A screenshot does not prove material behavior or accessibility.

Primary adoption guidance: https://developer.apple.com/documentation/technologyoverviews/adopting-liquid-glass

## Evidence

For a state/identity fix, reproduce the transition that failed (including reorder, re-entry,
or cancellation). For a rendering/performance fix, compare the same data and interaction
before/after. Report any accessibility or platform state that was not exercised.

Primary documentation: https://developer.apple.com/documentation/swiftui/managing-model-data-in-your-app
and https://developer.apple.com/documentation/observation
