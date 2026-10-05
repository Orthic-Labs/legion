# Conditional Liquid Glass

Use system-adaptive materials only when active SDK, deployment target, and product design
support them. Keep an older-system fallback and test legibility, contrast, reduced
transparency/motion, interaction, and performance. Do not treat a visual screenshot as
proof of material semantics or accessibility.

Begin with structure: `NavigationSplitView`, `TabView`, sheets, inspectors, toolbars,
search placement, and standard controls. Remove opaque fills, scrims, and hand-painted
toolbar/sheet chrome that obscures system material before adding custom effects. On Mac,
keep conventional toolbar/search placement rather than importing iPhone tab-bar behavior.

Use standard SwiftUI controls and system glass styles first. Where supported, use
`ToolbarSpacer` to express fixed/flexible grouping, `sharedBackgroundVisibility` for a
standalone toolbar item, `badge` for status, `controlSize` and `buttonBorderShape` for
density/shape, and semantic `tint` only for meaning. Attach `searchable` to the container
that owns search scope (split, tab view, or dedicated search surface).

On macOS 26, use `scrollEdgeEffectStyle(_:for:)` when automatic scroll-edge treatment
does not fit content or pinned controls, for example
`.scrollEdgeEffectStyle(.soft, for: .top)`. Use `searchToolbarBehavior(.automatic)`
after `searchable` when you need an explicit macOS toolbar policy; minimized search
presentation is platform-specific, so do not import iPhone-only behavior into a Mac
toolbar. Keep both modifiers behind a macOS 26 availability check with existing search
and scroll treatment as fallback.

For hero artwork in a split view, align media to detail edges, then apply
`backgroundExtensionEffect()` to that media only. It mirrors and blurs copies under an
open sidebar or inspector; apply it before any title or control overlay so controls do
not extend under the side panel. This is a macOS 26 effect and should remain a single,
deliberate hero-media surface for clarity and rendering cost.

For app-specific surfaces, use `glassEffect` with explicit shape where capsule is wrong,
`.interactive()` for interactive elements, and one `GlassEffectContainer` for nearby
related glass. Use `glassEffectID` with stable identity and a local namespace when states
should morph. These names are availability-gated; wrap them and preserve useful fallback.
Do not tint every icon or scatter related glass across separate containers.

For discrete controls on macOS 26, use Slider's `step`, `ticks`, `neutralValue`, and
value-label parameters rather than drawing a custom track. `step` uses Slider's regular
step/tick overload; `ticks` supplies specific marks through its explicit tick-builder
overload, so don't pass both. `neutralValue` defines a baseline for values that move in
either direction; `label`, `currentValueLabel`, `minimumValueLabel`, and
`maximumValueLabel` preserve purpose and value semantics even when a style does not draw
every label:

```swift
Slider(value: $speed, in: 0.5...2.0,
       neutralValue: 1.0,
       label: { Text("Playback speed") },
       currentValueLabel: { Text(speed, format: .number.precision(.fractionLength(2))) },
       minimumValueLabel: { Text("Slower") },
       maximumValueLabel: { Text("Faster") },
       ticks: {
    SliderTick(0.75)
    SliderTick(1.5)
})
```

When regular intervals are preferred, use `step: 0.25` with the step/tick overload;
when explicit marks are preferred, use the builder shown above. If both step behavior
and per-value customization are needed, use singular `tick: (value) -> SliderTick`.

For nested custom controls, use macOS 26 `ConcentricRectangle()` so inner corners follow
their container across window sizes; set `.containerShape(...)` when parent shape is
custom. This is SwiftUI's container-concentric (`containerConcentric`) corner treatment;
do not pass it to `cornerRadius`, which expects a numeric radius. Keep this behind
macOS 26 availability and use the existing rounded shape on older targets.

Use semantic styles for content that must work in Light and Dark appearances:
`foregroundStyle(.primary)` or `.secondary` for text/icons, and adaptive backgrounds
such as `.background(.regularMaterial)` or another product-appropriate `ShapeStyle`.
Avoid hardcoded white/black foregrounds and fixed light fills unless product policy
requires a fixed theme.

Liquid Glass is a macOS 26 SDK/API path. Keep its fallback in the same view so older
systems retain an intentional surface:

```swift
struct ActionChrome: View {
    @State private var expanded = false
    @Namespace private var glassNamespace

    var body: some View {
        Group {
            if #available(macOS 26.0, *) {
                GlassEffectContainer(spacing: 12) {
                    HStack(spacing: 12) {
                        Button("Open") { expanded.toggle() }
                            .buttonStyle(.glass)
                            .glassEffectID("open", in: glassNamespace)
                        if expanded {
                            Button("Close") { expanded = false }
                                .buttonStyle(.glassProminent)
                                .glassEffectID("close", in: glassNamespace)
                        }
                    }
                    .glassEffect(.regular.interactive(),
                                 in: RoundedRectangle(cornerRadius: 14))
                }
            } else {
                Button("Open") { expanded.toggle() }
                    .buttonStyle(.bordered)
            }
        }
        .animation(.default, value: expanded)
    }
}
```

Use stable IDs only for elements that represent the same transition. Keep the container
small: Apple's guidance warns that too many simultaneous effects or containers can hurt
rendering performance. When custom effects are unnecessary, standard toolbar/control
materials remain the better fallback.

Primary references: [Applying Liquid Glass to custom views](https://developer.apple.com/documentation/swiftui/applying-liquid-glass-to-custom-views),
[GlassEffectContainer](https://developer.apple.com/documentation/swiftui/glasseffectcontainer),
[backgroundExtensionEffect](https://developer.apple.com/documentation/swiftui/view/backgroundextensioneffect()),
[scrollEdgeEffectStyle](https://developer.apple.com/documentation/swiftui/view/scrolledgeffectstyle(_:for:)),
[searchToolbarBehavior](https://developer.apple.com/documentation/swiftui/view/searchtoolbarbehavior(_:)),
[Slider](https://developer.apple.com/documentation/swiftui/slider/init(value:in:neutralvalue:enabledbounds:label:currentvaluelabel:minimumvaluelabel:maximumvaluelabel:ticks:oneditingchanged:)),
[ConcentricRectangle](https://developer.apple.com/documentation/swiftui/concentricrectangle),
and [macOS 26 release notes](https://developer.apple.com/documentation/macos-release-notes/macos-26-release-notes).
