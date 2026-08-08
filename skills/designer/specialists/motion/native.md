# Native motion — SwiftUI / AppKit / UIKit / Slint

Load this file INSTEAD OF the web assumptions in `stack.md` and the web-scoped hard rules in
`SKILL.md` whenever the surface is a native toolkit. `principles.md` (motion language, hierarchy,
choreography) still applies — it is toolkit-agnostic. The *mechanics* below are not.

**Routing gate — answer before writing a single line of animation code:**

| Surface | Toolkit | This file's section |
|---|---|---|
| macOS/iOS app, `.swift` files, `App`/`Scene`/`View`, `NSWindow`/`NSPanel`/`NSHostingView` | SwiftUI + AppKit | §1–§4 |
| UIKit surface (`UIView`, `UIViewController`, `UIViewPropertyAnimator`) | UIKit + Core Animation | §3A + §4 |
| `.slint` markup, Rust/C++/JS host binding | Slint | §5 |
| Porting Swift UI code to Slint (or the reverse) | both | §6 |
| Tauri app (`src-tauri` + React/web frontend) | **web** — the frontend is a WebView | `stack.md`, not this file |

A Tauri window is a browser. `stack.md` is correct there. Everything below is for surfaces where
there is no DOM, CSS, or `prefers-reduced-motion` media query; native compositing and accessibility
APIs apply instead.

---

## §0 — The one rule that generates every other rule

> **One owner per animated quantity, for the whole duration of the animation.**

Every native motion failure that costs real debugging time is two systems animating the same number
on different clocks. The symptoms are always the same and always misread as "easing feels wrong":

| Symptom | Actual cause |
|---|---|
| Content snaps, then the window catches up | SwiftUI animated layout; AppKit resized the window on a separate timer |
| Panel shifts down/up at the end of the transition | Window height changed after the visual settled; the anchor was recomputed from the *final* frame, not preserved per-frame |
| Second interaction jumps from the wrong place | New animation started from the *model* value instead of the current *presentation* value |
| Open is smooth, close is janky (or vice versa) | Forward and reverse take different code paths |
| Everything is fine until it's interrupted | A non-interruptible primitive (`setFrame(_:display:animate:)`, `NSViewAnimation`) is in the path |

Owner selection, in preference order:

1. **SwiftUI owns everything; window geometry is constant.** Size the window/panel once for the
   largest state, make the container transparent, and animate content inside. This is the correct
   default for hubs, palettes, Spotlight-style panels, and HUDs. No window animation exists, so it
   cannot desynchronize.
2. **AppKit owns geometry; SwiftUI content is layout-passive.** The window animates; the hosted view
   fills whatever it is given and animates nothing positional. Use only when the window must
   genuinely change size (a real resize the user can see the edges of).
3. **Both animate the same quantity.** Always a defect. There is no configuration of durations and
   easing that fixes it — the two timelines are driven by different clocks and interruption resets
   only one of them.

If you cannot say in one sentence which system owns the height, you are about to ship option 3.

---

## §1 — SwiftUI: the current animation API

Use the duration/bounce spring family (macOS 14+/iOS 17+). It is interruptible and retargetable by
construction: an in-flight spring that receives a new target carries its current velocity into the
new animation instead of restarting from rest.

```swift
// Presets — reach for these first. They are the system's calibrated defaults.
.smooth      // no bounce, general-purpose
.snappy      // slight bounce, responsive UI (default choice for most product motion)
.bouncy      // pronounced bounce, playful

// Parameterized. `duration` here is perceptual settling time, not a hard cutoff.
.spring(duration: 0.35, bounce: 0.15)
.smooth(duration: 0.3)
.snappy(duration: 0.25, extraBounce: 0.05)
```

Prefer `bounce:` over the legacy `response:`/`dampingFraction:` pair — `bounce` is normalized
(`0` = critically damped, `>0` = overshoot) and reads directly as intent.

**Never** use `.linear` for interactive UI. **Never** use `.easeIn` on an entrance (same rule as
web — the element appears to hesitate then lunge).

### Where to attach the animation

```swift
// Preferred: scoped to a specific value. Only this change animates.
.animation(.snappy, value: isExpanded)

// Use when a single gesture/action must animate several unrelated properties coherently.
withAnimation(.snappy) { isExpanded.toggle() }

// Explicitly opt a subtree OUT of an inherited animation.
.transaction { $0.animation = nil }
```

Bare `.animation(_:)` without a `value:` is deprecated and animates changes you did not intend.
Treat it as a finding.

### Geometry morphs

`matchedGeometryEffect(id:in:)` is the native equivalent of a shared-layout transition. Both views
must be in the same `@Namespace`, and exactly one must be the `isSource: true` side at any moment.

```swift
@Namespace private var hub

// collapsed
Capsule().matchedGeometryEffect(id: "shell", in: hub, isSource: !isExpanded)
// expanded
RoundedRectangle(cornerRadius: 20).matchedGeometryEffect(id: "shell", in: hub, isSource: isExpanded)
```

**Before hand-building a morph, check whether the system already does it.** On macOS 26 / iOS 26+,
`GlassEffectContainer` + `.glassEffectID(_:in:)` morphs Liquid Glass elements natively — the system
blends and re-forms the material as elements appear, merge, and split:

```swift
GlassEffectContainer {
    Capsule().glassEffect().glassEffectID("shell", in: hub)
}
```

For an expanding hub, palette, or action cluster this is the supported material-morph path. It avoids
hand-building the glass interpolation, but it solves §0 only when window geometry remains constant or
has one separately declared owner. Reach for it before `matchedGeometryEffect` + a panel resize. Design-side material rules are in
`designer/references/native-app.md` §3.

`.geometryGroup()` (macOS 14+/iOS 17+) makes a subtree resolve its geometry as a unit before
handing it to children. Apply it when a parent's size/position animates and children visibly lag or
skew during the transition — the classic "the label slides diagonally while the card resizes" bug.

### Multi-step motion

- `PhaseAnimator` — discrete named phases, cycled automatically or driven by a trigger. Use for
  repeating attention motion and for A→B→C sequences.
- `KeyframeAnimator` — independent per-property tracks on one timeline. Use when position, scale,
  and rotation need different curves across the same beat.

Both rebuild their content per frame. Isolate the animating state in the smallest possible view, and
verify the rebuilt-view count with the **SwiftUI instrument** in Xcode before shipping either one.

### Reduced motion

There is no media query. The environment value is the contract:

```swift
@Environment(\.accessibilityReduceMotion) private var reduceMotion
// ...
.animation(reduceMotion ? nil : .snappy, value: isExpanded)
```

From AppKit: `NSWorkspace.shared.accessibilityDisplayShouldReduceMotion`. Replace movement with a
cross-fade; do not merely shorten the duration.

---

## §2 — AppKit window and panel animation

### The primitives, and which are interruptible

| API | Interruptible | Use |
|---|---|---|
| `NSAnimationContext.runAnimationGroup { window.animator().setFrame(_:display:) }` | Implicit animation; no documented scrubbing or presentation-frame API | Default AppKit primitive for a non-interactive animated frame change; verify reversal if interruption matters. |
| `window.setFrame(_:display:animate:)` | Not designed for interactive control | Avoid in interruption-sensitive paths; duration comes from `animationResizeTime(_:)`. |
| `NSViewAnimation` | No | Legacy. Do not introduce. |
| Layer-backed `CABasicAnimation` on the content layer | Yes, via `presentation()` | Sub-window element motion when SwiftUI is not in the path. |

```swift
NSAnimationContext.runAnimationGroup { ctx in
    ctx.duration = 0.28
    ctx.timingFunction = CAMediaTimingFunction(name: .easeOut)
    ctx.allowsImplicitAnimation = true          // required for constraint/layout changes to animate
    panel.animator().setFrame(target, display: true)
}
```

### Do not invent presentation geometry for windows

Core Animation layers expose a documented presentation layer. `NSWindow` does not expose an
equivalent documented presentation-frame API, and reading `panel.animator().frame` is not a supported
substitute. Use presentation geometry only for layer-backed element motion:

```swift
// Layer-level only: the presentation layer is the on-screen truth.
let current = layer.presentation()?.frame ?? layer.frame
```

If window-frame interruption must be seamless, prefer §0 option 1 (constant window geometry) or own
the interpolation with an explicit driver that stores the current value. Always run the 50% reversal
test; do not claim retargetability from API shape alone.

### Anchor preservation — the bottom-center case

Cocoa window frames use a **bottom-left origin**, which is a gift here: holding the bottom edge
fixed means holding `minY` constant. No compensation needed on the vertical axis at all. Only the
horizontal center needs arithmetic.

```swift
/// Returns a frame of `size` whose bottom-center stays at `anchor` (screen coords, bottom-left system).
func frame(size: NSSize, bottomCenteredAt anchor: NSPoint) -> NSRect {
    NSRect(x: (anchor.x - size.width / 2).rounded(),   // round to whole points: subpixel origins blur text
           y: anchor.y,                                 // bottom edge is invariant — do not recompute from height
           width: size.width,
           height: size.height)
}
```

Compute the anchor **once**, when the interaction begins, and hold it for the whole transition.
Recomputing the anchor from the live frame each tick feeds the frame back into itself and is the
direct cause of the panel drifting downward as it grows.

### Hard sequencing rule

> Window geometry and content must begin as one coordinated transition, with no trailing geometry
> change after the content settles.

Resizing a window after its contents have visually settled is perceived as a second, unexplained
movement. If a resize is genuinely required, coordinate it with content under one declared owner and
one tested timeline; pre-size when possible. There is no
`DispatchQueue.main.asyncAfter` that makes a trailing resize look intentional.

### Forward and reverse share one path

Open and close must call the same function with swapped endpoints. Two functions drift: one gets a
duration tweak, the other doesn't, and close ends up feeling broken while open feels fine.

```swift
private func setHub(expanded: Bool, animated: Bool = true) { /* one implementation, both directions */ }
```

---

## §3 — SwiftUI hosted in an NSPanel

The bridge is where ownership gets lost. Configure the panel so SwiftUI can own everything visible.

```swift
final class HubPanel: NSPanel {
    init(view: some View) {
        super.init(contentRect: .zero,
                   styleMask: [.nonactivatingPanel, .fullSizeContentView, .borderless],
                   backing: .buffered, defer: false)
        isFloatingPanel = true
        level = .floating
        hidesOnDeactivate = false
        isOpaque = false
        backgroundColor = .clear          // the panel is a stage, not a surface
        hasShadow = false                 // shadow follows the panel rect, not the SwiftUI shape —
                                          // draw the shadow in SwiftUI or it will animate wrong
        contentView = NSHostingView(rootView: view)
    }
    override var canBecomeKey: Bool { true }   // borderless panels need this for text input
}
```

Then apply option 1 from §0: give the panel a frame sized for the **largest** state, keep it
constant, and let SwiftUI animate the visible shell inside a transparent stage. The panel never
animates, so it cannot fight SwiftUI, and the bottom-center anchor is preserved trivially because
the frame never changes.

```swift
VStack { ... }
    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .bottom)  // pin to the bottom edge
    .animation(reduceMotion ? nil : .snappy, value: isExpanded)
```

Only reach for content-driven panel sizing (`NSHostingView.sizeThatFits`,
`NSHostingSizingOptions`, `.windowResizability(.contentSize)`) when the window's own edges are
visible and must track content. When you do, that resize is now the sole owner of geometry — remove
the corresponding SwiftUI size animation, per §0.

### §3A — UIKit / Core Animation boundary

Use `UIViewPropertyAnimator` when UIKit motion must pause, scrub, reverse, or change timing while
running. It explicitly supports interruption and interactive control. For simple one-shot state
changes, SwiftUI animation or `UIView.animate` remains smaller. Layer-level custom motion may use
`CALayer.presentation()`, but one owner per quantity still applies: do not animate the same property
through both UIKit layout and an added Core Animation object.

Reduced motion comes from `UIAccessibility.isReduceMotionEnabled`; observe
`UIAccessibility.reduceMotionStatusDidChangeNotification` when a long-lived surface must react while
open. Replace large spatial movement with a stable state change or short cross-fade.

---

## §4 — Native review gate

Replaces the web checks in `reviews.md` for native surfaces. Web-only items (CLS, hydration, bundle
size, `will-change`, `translate3d`) do not apply and must not be reported as findings on a native
surface.

- [ ] **Ownership** stated in one sentence per animated quantity; no quantity has two owners.
- [ ] Every `withAnimation` / `.animation` uses a spring, not `.linear`; entrances are not `.easeIn`.
- [ ] No `.animation(_:)` without `value:`.
- [ ] No `setFrame(_:display:animate:)` and no `NSViewAnimation` in an interactive path.
- [ ] Interruption test: trigger the transition, then re-trigger at ~50% — motion continues from the
      current position and does not restart or jump. **Capture this on video; it is not provable from code.**
- [ ] Anchor test: run the transition and confirm the anchored edge does not move by even one point.
      Screenshot first and last frame, diff the anchored edge.
- [ ] No geometry change occurs after the visual transition completes.
- [ ] Forward and reverse resolve to the same implementation.
- [ ] Reduce-motion variant verified with System Settings → Accessibility → Display → Reduce Motion
      **actually on** — reading the environment value in code is not evidence.
- [ ] `PhaseAnimator`/`KeyframeAnimator` view-rebuild count checked in the SwiftUI instrument.
- [ ] Verified on the **connected physical device** for iOS (CLAUDE.md §4B) — never a simulator.

---

## §5 — Slint

Slint's animation model is declarative and CSS-shaped, but it is a retained-mode native renderer,
not a browser.

```slint
// Property animation
animate x, y { duration: 250ms; easing: ease-out-quart; }

// Full parameter set
animate opacity {
    delay: 50ms;
    duration: 300ms;
    iteration-count: 1;      // negative = infinite
    direction: normal;       // normal | reverse | alternate | alternate-reverse
    easing: ease-in-out;
    enabled: !root.reduce-motion;   // false → value jumps to target, no easing
}
```

Easing set: `linear`, `ease`, `ease-in`, `ease-out`, `ease-in-out`, plus `-quad`, `-quart`,
`-quint`, `-expo`, `-sine`, `-back`, `-circ`, `-elastic`, `-bounce` variants in `in`/`out`/`in-out`
forms, and `cubic-bezier(a,b,c,d)`.

States and transitions carry choreography:

```slint
states [
    expanded when root.is-expanded: {
        shell.height: 320px;
        in  { animate shell.height { duration: 280ms; easing: ease-out-quart; } }
        out { animate shell.height { duration: 200ms; easing: ease-in-quad; } }
    }
]
```

`in-out` applies one animation to both directions — use it as the default so forward and reverse
cannot drift apart (§2's rule, enforced by the language).

**Slint-specific constraints:**

- **Animating `width`/`height`/`x`/`y` is correct and idiomatic here.** The web prohibition in
  `SKILL.md` is about browser layout/paint invalidation and does not transfer. Do not carry it over.
- **No spring/physics primitive.** There is no velocity-carrying spring and no gesture-velocity
  handoff. Everything is duration + easing.
- **Retargeting semantics are not documented.** Before relying on mid-flight interruption behaving
  smoothly, write a two-line probe against the pinned Slint version and watch it. Assume it restarts
  until proven otherwise.
- `animation-tick()` drives continuous, permanently-running motion (loaders, ambient) — not state
  transitions.
- `enabled:` bound to a reduce-motion property is the accessibility hook. Wire that property from
  the host platform; Slint does not read the OS setting for you.

---

## §6 — Swift → Slint conversion

Do the conversion at the level of *intent*, not API. Translating call-for-call produces motion that
is technically present and feels wrong, because the two runtimes disagree about physics.

| SwiftUI | Slint | Fidelity |
|---|---|---|
| `.smooth(duration: d)` | `animate { duration: d; easing: ease-in-out; }` | Close |
| `.snappy` | `duration: 250ms; easing: cubic-bezier(0.22, 1, 0.36, 1)` | Close |
| `.bouncy` / `bounce > 0.2` | `easing: ease-out-back` (single overshoot only) | **Lossy** — no true oscillation |
| `.spring` retargeted mid-flight with velocity | *(no equivalent)* | **Lost.** Redesign the interaction. |
| `withAnimation { }` around several properties | one `states` entry, several `animate` blocks | Close |
| `.animation(_:value:)` | `animate <property>` on the element | Direct |
| `matchedGeometryEffect(id:in:)` | *(no equivalent)* | **Hand-build:** one persistent element in a shared parent, animate its `x`/`y`/`width`/`height` between measured endpoints |
| `.geometryGroup()` | not needed | N/A — Slint resolves layout per-frame as a unit |
| `PhaseAnimator` | `states` + `in-out` transitions, or `iteration-count: -1` | Close |
| `KeyframeAnimator` (independent tracks) | separate `animate` blocks with different `delay`/`duration` | Close |
| `.transition(.opacity.combined(with: .move))` | animate `opacity` + `y` together under a `states` guard | Close |
| `@Environment(\.accessibilityReduceMotion)` | host-provided property → `enabled:` on every `animate` | Manual wiring required |
| Gesture velocity → momentum (`fluid.md`) | *(no equivalent)* | **Lost.** Use a fixed-duration commit animation. |

**Conversion procedure:**

1. Inventory every animated quantity in the Swift source and its owner (§0). Ownership bugs port
   across unchanged — fix them before converting, not after.
2. Flag every spring. For each, decide: does this motion depend on *velocity continuity* (drag
   handoff, interruptible pull) or only on *feel* (a bouncy tap)? Feel converts to an easing curve.
   Velocity continuity does not convert — that interaction needs redesigning for Slint, and saying so
   is the correct output, not approximating it and hoping.
3. Convert state machines before curves. Slint's `states` block is stricter than SwiftUI's implicit
   animation and will expose transitions the Swift version left ambiguous.
4. Use `in-out` unless forward and reverse are deliberately asymmetric.
5. Re-tune by eye against the Swift original running side by side. Numeric equivalence between a
   spring and a bezier does not exist; the match is perceptual and the approving human's eyes are the gate
   (CLAUDE.md §8).

Reverse direction (Slint → Swift) can preserve duration/easing motion directly or deliberately adopt
a Swift spring. A spring is not automatically an improvement: preserve the original interaction
intent, then retune and verify interruption behavior by eye.
