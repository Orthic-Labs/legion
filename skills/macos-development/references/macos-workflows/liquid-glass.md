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

For app-specific surfaces, use `glassEffect` with explicit shape where capsule is wrong,
`.interactive()` for interactive elements, and one `GlassEffectContainer` for nearby
related glass. Use `glassEffectID` with stable identity and a local namespace when states
should morph. These names are availability-gated; wrap them and preserve useful fallback.
Do not tint every icon or scatter related glass across separate containers.

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
and [macOS 26 release notes](https://developer.apple.com/documentation/macos-release-notes/macos-26-release-notes).
