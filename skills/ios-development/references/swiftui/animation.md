# SwiftUI animation

## Source-aligned detail

For transactions, phases, keyframes, transitions, and custom animatable values, read [animation basics](donor-lee-animation-basics.md),
[transitions](donor-lee-animation-transitions.md), and [advanced animation](donor-lee-animation-advanced.md).

Property animation interpolates an existing view's values; transitions animate insertion or
removal and require animation context outside the conditional. Use `.animation(_:value:)` for
specific dependencies and `withAnimation` for event-driven mutations. Scope animation to the
smallest affected view, place it after properties it should animate, and avoid animating every
scroll/geometry update. Prefer transforms for hot paths; layout changes cost more. Use suitable
springs/ease curves, not long/robotic timing for interaction.

```swift
Button("Show details") {
    withAnimation(.spring) { isExpanded.toggle() }
}
if isExpanded { Details().transition(.move(edge: .bottom).combined(with: .opacity)) }
```

Use asymmetric transitions when insertion/removal differ. Identity changes (`.id`, different
branches) trigger transitions; stable identity enables property interpolation. For custom
animation, `Transition` (iOS 17+) or `Animatable` must expose interpolated data. Use
`@Animatable` when the SDK/compiler provides the macro; the installed interface marks the macro
iOS 13+ while generated conformance can back-deploy to iOS 13. Compiling use still requires
that newer SDK/compiler; `AnimatableValues` remains iOS 26+. Use `animatableData`/`AnimatablePair` when the macro is unavailable.

Transactions can disable or override animation for a subtree; use them instead of zero-duration
hacks. Phase/keyframe animators and completion handlers are conditional by SDK; gate them and
preserve simpler fallback. Respect `accessibilityReduceMotion`; use opacity or disable decorative
motion. Avoid delayed chained `withAnimation`; use completion handlers or a state machine.
