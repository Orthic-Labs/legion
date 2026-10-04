# SwiftUI Liquid Glass

## Source-aligned detail

For API shapes, effect unioning, modifier order, and material fallbacks, read [Liquid Glass detail](donor-lee-liquid-glass.md).

Liquid Glass is conditional iOS 26+ design guidance, not a default restyle. Confirm SDK and
deployment availability, apply glass to controls/navigation surfaces that benefit from hierarchy,
and keep content surfaces readable. Use `glassEffect`, `GlassEffectContainer`, glass button
styles, and morphing source/destination APIs only behind `#available`; older systems use a
material/color fallback with equivalent contrast and hierarchy.

Group nearby glass elements in `GlassEffectContainer` when they should merge/morph, use stable
IDs and matching namespaces for transitions, and order clipping/background/material modifiers
deliberately. Avoid applying glass to every row, stacking translucent layers, or replacing an
existing design system incidentally. Verify contrast, Reduce Transparency, Reduce Motion,
VoiceOver labels, hit targets, scroll-edge behavior, and GPU/memory impact on each platform.

```swift
@ViewBuilder
func surface<Content: View>(_ content: Content) -> some View {
    if #available(iOS 26, *) {
        content.glassEffect(.regular, in: .rect(cornerRadius: 16))
    } else {
        content.background(.thinMaterial, in: .rect(cornerRadius: 16))
    }
}
```
