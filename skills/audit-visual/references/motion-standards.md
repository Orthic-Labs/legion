# Motion Standards — review bar + exact values

The motion lens's full rule catalog. Distilled from Emil Kowalski's design engineering philosophy
([animations.dev](https://animations.dev/)); absorbs the retired `emil-design-eng` and
`review-animations` skills. Cite these exact values in findings instead of approximating.

**Producer/reviewer split:** producer-side motion guidance lives in `/designer motion`. This file is the reviewer bar: escalation triggers, remedial hierarchy, & findings format. For shared easing curves and hard rules, Designer's motion specialist is canonical.

Posture: senior motion reviewer with a brutal eye for craft. Bias toward **motion that feels
right**, not motion that merely runs. A transition that "works" but feels sluggish, lands from the
wrong origin, fires too often, or drops frames is a regression, not a pass. Default to flagging;
approval is earned. When unsure whether motion feels right, the strongest move is often to delete it.

**Register-aware review (`/designer motion` registers).** Read the declared register from `motion-gate.json`
before reviewing. Product register: everything below applies as written. Showpiece register
(immersive marketing/campaign surfaces): restraint-class findings (pattern count, "could this be
removed", parallax/pin/3D presence) are replaced by the choreography bar — every effect must belong
to a declared scene advancing one narrative, threaded by a persistent object; JS budget 120KB.
Floors (reduced motion, transform/opacity, CLS, origin, easing, hydration, CTA ≤ 1.5s) are findings
in BOTH registers. A showpiece pattern (pin-scrub, Lenis, parallax) on a product-register surface
is itself a finding.

## The ten non-negotiable standards

Every animation in scope is measured against these. A violation is a finding.

1. **Justified motion.** Every animation answers "why does this animate?" — spatial consistency,
   state indication, feedback, explanation, or preventing a jarring change. "It looks cool" on a
   frequently-seen element is a block.
2. **Frequency-appropriate.** Keyboard-initiated and 100+/day actions get **no** animation.
   Tens/day gets reduced motion. Occasional gets standard. Rare/first-time can have delight.
3. **Responsive easing.** Entering/exiting elements use `ease-out` or a strong custom curve.
   `ease-in` on UI is a block — it delays the moment the user watches most.
4. **Sub-300ms UI.** Anything slower on a UI element needs justification.
5. **Origin & physical correctness.** Popovers/dropdowns/tooltips scale from their trigger, not
   center. Never animate from `scale(0)`. (Modals are exempt — they stay centered.)
6. **Interruptibility.** Rapidly-triggered or gesture-driven motion must retarget from current
   state (transitions/springs), not restart from zero (keyframes).
7. **GPU-only properties.** `transform` and `opacity` only; layout properties are a performance finding.
8. **Accessibility.** `prefers-reduced-motion` honored (gentler, not zero); hover motion gated
   behind `@media (hover: hover) and (pointer: fine)`.
9. **Asymmetric enter/exit.** Deliberate actions animate slower; system responses snap.
10. **Cohesion.** Motion matches the component's personality and the rest of the product.

## Toolkit gate — resolve before applying any trigger below

This file's triggers assume CSS/DOM. On a **SwiftUI/AppKit** or **Slint** surface, most of them are
category errors — animating `width`/`height`/`x`/`y` is idiomatic there, and `prefers-reduced-motion`
does not exist. Load `motion/native.md` and review against its §4 gate instead. Reporting
`translate3d`, CLS, hydration, or bundle-budget findings on a native surface is itself a defect.

Native surfaces have their own flag-on-sight list (details in `motion/native.md` §0–§2):

- Two systems animating the same quantity — SwiftUI animating layout while AppKit resizes the window
- `NSWindow.setFrame(_:display:animate:)` or `NSViewAnimation` in an interactive path (not interruptible)
- A window/panel frame change scheduled *after* the visual transition (any `asyncAfter` around geometry)
- Layer animation restarted from `layer.frame` instead of `layer.presentation()`; for windows, any
  claim that `window.animator().frame` is presentation truth (AppKit documents no such API)
- An anchored edge recomputed from the live frame each tick rather than captured once
- Separate open/close implementations of one transition
- `.animation(_:)` with no `value:`; `.linear` on interactive UI
- Slint: reliance on mid-flight retargeting without a probe against the pinned version (no springs exist)

On a **Tauri/embedded-webview** surface the triggers below DO apply — it is a browser — but the
engine is WKWebView on Apple platforms, WebView2 on Windows, WebKitGTK on Linux, and Android System
WebView on Android. Add `motion/webview.md` §5 and treat single-engine evidence as no evidence.
Flag there: missing version-appropriate `backdrop-filter` fallback, an unprofiled animated filter value, CSS blur
stacked over native vibrancy, transformed drag-region hit testing without built-runtime evidence, or
View Transitions used without a minimum-version gate and a legible no-transition fallback.

See also `native-feedback.md` for per-platform reduced-motion mechanisms, response budgets, and
Apple's real spring defaults.

## Escalation triggers — flag on sight (WEB)

- `transition: all` (unbounded property animation)
- `scale(0)` or pure-fade entrances with no initial transform
- `ease-in` on any UI interaction; weak built-in easing on a deliberate animation
- Animation on a keyboard shortcut, command-palette toggle, or 100+/day action
- UI duration > 300ms with no stated reason
- `transform-origin: center` on a trigger-anchored popover/dropdown/tooltip
- Keyframes on toasts, toggles, or anything added/triggered rapidly
- Animating layout properties (`width`/`height`/`margin`/`padding`/`top`/`left`)
- Framer Motion `x`/`y`/`scale` props on motion that runs while the page is busy
- Updating a CSS variable on a parent to drive a child transform (style recalc storm)
- Missing `prefers-reduced-motion` handling on movement
- Ungated `:hover` motion
- Symmetric enter/exit timing on a press-and-release or hold interaction
- Everything-at-once entrance where a 30–80ms stagger belongs
- Reveal gated on a class-triggered transition (ships blank in hidden tabs / headless renderers)

## Remedial preference hierarchy

Prefer earlier moves over later ones when proposing fixes:

1. **Delete the animation** (high-frequency / no purpose / keyboard-triggered)
2. **Reduce it** — shorter duration, smaller transform, fewer animated properties
3. **Fix the easing** — `ease-in`→`ease-out`/strong custom curve
4. **Fix the origin/physicality** — correct `transform-origin`; `scale(0)`→`scale(0.95)`+opacity
5. **Make it interruptible** — keyframes → transitions, or a spring for gesture-driven motion
6. **Move it to the GPU** — layout props → `transform`/`opacity`; shorthand → full `transform` string
7. **Asymmetric timing** — slow the deliberate phase, snap the response
8. **Polish** — blur to mask crossfades, stagger for groups, `@starting-style` for entry
9. **Accessibility & cohesion** — reduced-motion + hover gating; tune to the component's personality

## Motion-code findings format

When reviewing motion CODE (not just pixels), findings use a Before/After table — never a
"Before:/After:" list:

| Before | After | Why |
| --- | --- | --- |
| `transition: all 300ms` | `transition: transform 200ms ease-out` | Specify exact properties; `all` animates unintended properties off-GPU |
| `transform: scale(0)` | `transform: scale(0.95); opacity: 0` | Nothing appears from nothing |
| `ease-in` on dropdown | `ease-out` + custom curve | `ease-in` delays the moment the user watches most |
| `transform-origin: center` on popover | `var(--radix-popover-content-transform-origin)` | Popovers scale from their trigger (modals exempt) |

---

# The exact values

## Should it animate? (frequency table)

| Frequency | Decision |
| --- | --- |
| 100+ times/day (keyboard shortcuts, command palette toggle) | No animation. Ever. |
| Tens of times/day (hover effects, list navigation) | Remove or drastically reduce |
| Occasional (modals, drawers, toasts) | Standard animation |
| Rare / first-time (onboarding, feedback, celebrations) | Can add delight |

**Never animate keyboard-initiated actions** — they repeat hundreds of times daily; animation makes
them feel slow and disconnected. (Raycast has no open/close animation — correct for something used
hundreds of times a day.)

Valid purposes for motion: spatial consistency, state indication, explanation, feedback, preventing
jarring change.

## Easing

Decision order:
- Entering or exiting → **`ease-out`** (starts fast, feels responsive)
- Moving / morphing on screen → **`ease-in-out`**
- Hover / color change → **`ease`**
- Constant motion (marquee, progress) → **`linear`**
- Default → **`ease-out`**

**Never `ease-in` on UI entrances.** It starts slow, delaying the exact moment the user is watching.
`ease-out` at 200ms *feels* faster than `ease-in` at 200ms. (Exception: exits may use `ease-in` —
see Exit animations below.)

Built-in CSS easings are too weak. Use strong custom curves:

```css
--ease-out: cubic-bezier(0.23, 1, 0.32, 1);        /* strong ease-out for UI */
--ease-in-out: cubic-bezier(0.77, 0, 0.175, 1);    /* strong ease-in-out for on-screen movement */
--ease-drawer: cubic-bezier(0.32, 0.72, 0, 1);     /* iOS-like drawer curve (Ionic) */
```

Find curves at [easing.dev](https://easing.dev/) or [easings.co](https://easings.co/).

## Duration

| Element | Duration |
| --- | --- |
| Button press feedback | 100–160ms |
| Tooltips, small popovers | 125–200ms |
| Dropdowns, selects | 150–250ms |
| Modals, drawers | 200–500ms |
| Marketing / explanatory | Can be longer |

**UI animations stay under 300ms.** A 180ms dropdown feels more responsive than a 400ms one. Faster
spinners make load feel faster (same actual time). Instant tooltips after the first (skip delay +
animation) make a toolbar feel faster.

## Physicality

- **Never `scale(0)`.** Start from `scale(0.9–0.97)` + `opacity: 0`.
- **Origin-aware popovers.** Scale from the trigger, not center:
  ```css
  .popover { transform-origin: var(--radix-popover-content-transform-origin); } /* Radix */
  .popover { transform-origin: var(--transform-origin); }                       /* Base UI */
  ```
  **Modals are exempt** — centered in the viewport, keep `transform-origin: center`.
- **Button press feedback.** `transform: scale(0.96–0.97)` on `:active`,
  `transition: transform 150–160ms ease-out`. Never below 0.95 — feels exaggerated. Applies to any
  pressable element.

## Enter / exit shape

- **Enters: split and stagger.** Don't animate one large container — split into semantic chunks
  (title, description, buttons) and stagger ~100ms between groups (words within a title ~80ms).
  Combine `opacity` + `blur` + small `translateY`.
- **Exits: softer and shorter than enters.** User focus is moving on. Small fixed `translateY`
  (~-12px), exit ~150ms vs enter ~300ms, `ease-in` for exits. Never remove the exit entirely.
  Full-distance exits only when spatial context matters (drawer closing, card returning to list).
- **Skip animation on page load.** Elements in their default state on load should not animate in —
  only on subsequent state changes (`initial={false}` on AnimatePresence). Exception: deliberate
  first-time entrances (staggered heroes, loading states).

## Contextual icon animations

Icons that appear/disappear on hover or state change: `opacity 0→1` + `scale 0.25→1` +
`blur(4px)→blur(0px)`, spring `{ duration: 0.3, bounce: 0 }` — bounce must be 0. Without Framer
Motion: keep both icons in the DOM, absolutely position one over the other, cross-fade.

Animate icons when: they appear on hover, represent state changes (play→pause), sit in contextual
toolbars, or indicate loading/success. Do NOT animate: static navigation icons, decorative icons,
always-visible icons, icon labels.

## Springs

Use for: drag with momentum, "alive" elements (Dynamic Island), interruptible gestures, decorative
mouse-tracking (interpolate with `useSpring`, never tie values directly to mouse position).

```js
{ type: "spring", duration: 0.5, bounce: 0.2 }        // Apple-style — recommended
{ type: "spring", mass: 1, stiffness: 100, damping: 10 } // traditional physics
```

Bounce subtle (0.1–0.3); avoid bounce in most UI. Springs maintain velocity when interrupted —
ideal for gestures users may reverse mid-motion.

## Interruptibility

CSS **transitions** retarget mid-animation; **keyframes** restart from zero. Prefer transitions for
interactive elements (hover, toggle, open/close); reserve keyframes for one-shot sequences.

```css
.toast { transition: transform 400ms ease; }                    /* interruptible — good */
@keyframes slideIn { from { transform: translateY(100%); } }    /* restarts — avoid for dynamic UI */
```

Entry without JS:

```css
.toast {
  opacity: 1; transform: translateY(0);
  transition: opacity 400ms ease, transform 400ms ease;
  @starting-style { opacity: 0; transform: translateY(100%); }
}
```

Legacy fallback: `useEffect(() => setMounted(true), [])` + `data-mounted` attribute.

## Asymmetric timing

Slow where the user is deciding, fast where the system responds.

```css
.overlay { transition: clip-path 200ms ease-out; }            /* release: fast */
.button:active .overlay { transition: clip-path 2s linear; }  /* press: slow, deliberate */
```

## Performance

- **Only animate `transform` and `opacity`** — GPU-composited; `padding`/`margin`/`height`/`width`/
  `top`/`left` trigger layout+paint+composite.
- **Don't drive child transforms via a CSS variable on the parent** — recalcs all children. Set
  `transform` directly on the element.
- **Framer Motion shorthands (`x`/`y`/`scale`) are NOT hardware-accelerated** — main-thread rAF,
  drops frames under load. Use the full transform string: `animate={{ transform: "translateX(100px)" }}`.
- **CSS animations beat JS under load** — off main thread. CSS for predetermined motion; JS for
  dynamic/interruptible.
- **WAAPI** gives JS control with CSS performance:
  ```js
  el.animate([{ clipPath: 'inset(0 0 100% 0)' }, { clipPath: 'inset(0 0 0 0)' }],
    { duration: 1000, fill: 'forwards', easing: 'cubic-bezier(0.77, 0, 0.175, 1)' });
  ```

## Transforms & clip-path

- `translate` percentages are relative to the element's own size — `translateY(100%)` moves by its
  height regardless of dimensions (Sonner/Vaul pattern). Prefer over hardcoded px.
- `scale()` scales children too (font, icons) — a feature for press feedback.
- 3D: `rotateX/Y` + `transform-style: preserve-3d` for depth/orbit/flip without JS.
- `clip-path: inset(t r b l)`: reveal-on-scroll, hold-to-delete overlays, seamless tab color
  transitions (duplicate + clip the active copy), comparison sliders.

## Gestures & drag

- **Momentum dismissal**: compute velocity (`Math.abs(distance)/elapsedMs`); dismiss if `> ~0.11` —
  a flick is enough, don't require crossing a distance threshold. Commit-vs-revert decided by
  **velocity sign**, not position.
- **Damping at boundaries**: over-drag moves less the further it goes —
  `rubberband(o, dim, c=0.55) = (o·dim·c)/(dim + c·|o|)`.
- **Pointer capture** once dragging starts; **ignore extra touch points** after the drag begins.
  Track 1:1 and **respect the grab offset** (snapping to element center on grab is a finding).
- **Friction over hard stops.**
- **Velocity handoff**: the release spring must start at the finger's release velocity — a visible
  seam between drag and settle is a finding. Momentum projection to pick the snap target:
  `projected = current + (v/1000)·d/(1−d)`, `d ≈ 0.998`.
- **Interrupt from the presentation value**: a grabbed mid-flight element must continue from its
  live on-screen transform, never jump to/from the logical target. Fixed-duration CSS
  transitions/keyframes on gesture-driven motion are a finding — springs only.
- **Spring parameterization** (Apple terms): damping 1.0 (no overshoot) is the UI default; bounce
  (~0.8 damping) only where the gesture carried momentum. Overshoot on a menu that faded in is a
  finding. Producer doctrine + code: `motion/fluid.md`.

## Masking imperfect crossfades

When a crossfade shows two overlapping states despite easing/duration tuning, add subtle
`filter: blur(2px)` during the transition. Keep blur < 20px (expensive, especially Safari).

## Stagger

30–80ms between items; longer feels slow. Stagger is decorative — never block interaction while it
plays.

## Accessibility

```css
@media (prefers-reduced-motion: reduce) {
  .element { animation: fade 0.2s ease; } /* keep opacity/color, drop transform-based motion */
}
@media (hover: hover) and (pointer: fine) {
  .element:hover { transform: scale(1.05); } /* touch fires false hovers on tap */
}
```

Reduced motion means fewer and gentler animations, not zero.

## Debugging (recommend when feel is uncertain)

- **Slow motion**: 2–5× duration or DevTools animation inspector — check crossfade cleanliness,
  abrupt stops, wrong `transform-origin`, out-of-sync coordinated properties.
- **Frame-by-frame**: Chrome DevTools Animations panel reveals timing drift.
- **Real devices** for gestures (phone on the dev server by IP + Safari remote devtools).
- **Fresh eyes next day.**

## Cohesion

Match motion to the component's personality: playful can be bouncier; a professional dashboard is
crisp and fast. Sonner feels right because easing, duration, design, and name are in harmony —
slightly slower, `ease` rather than `ease-out`, elegant. Opacity + height in entering/exiting lists
is trial and error — adjust until it feels right.
