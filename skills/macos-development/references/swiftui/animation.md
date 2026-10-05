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
animation, `Transition` (macOS 14+) or `Animatable` must expose interpolated data. The installed
SDK declares `@Animatable`/`@AnimatableIgnored` as external macros with macOS 10.15+ availability;
compiling their use still requires an SDK/compiler that provides `SwiftUIMacros`, while generated
`Animatable` conformance can back-deploy to macOS 10.15. `AnimatableValues` is macOS 26+; use
`AnimatablePair` on earlier deployment targets and keep availability branches.

Transactions can disable or override animation for a subtree; use them instead of zero-duration
hacks. Phase/keyframe animators and completion handlers are conditional by SDK; gate them and
preserve simpler fallback. Respect `accessibilityReduceMotion`; use opacity or disable decorative
motion. Avoid delayed chained `withAnimation`; use completion handlers or a state machine.
