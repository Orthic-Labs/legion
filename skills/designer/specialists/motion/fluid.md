# Fluid Interfaces — gesture physics and app-feel motion

Absorbs Emil Kowalski's `apple-design` skill (WWDC *Designing Fluid Interfaces* distilled to the web).
Load this file when the surface has **gesture-driven or continuously interactive motion**: drags,
sheets/drawers, swipe-to-dismiss, carousels, draggable cards, momentum scrolling, morphing controls.
For static entrances/scroll reveals, the pattern files are enough — skip this.

The through-line: **motion starts from the current on-screen value, inherits the user's velocity,
projects momentum forward, and can be grabbed and reversed at any instant.** Springs make this
natural because they are inherently interruptible and velocity-aware.

## 1. Response — kill latency

- Feedback on **pointer-down**, not release. Waiting for click/touch-up reads as dead.
- Feedback is continuous **during** the interaction — a drag/slider/drawer tracks the pointer 1:1
  the whole way, never animating only at the end.
- Audit everything on the input path: debounces, artificial timers, transition waits.

## 2. Direct manipulation — 1:1 tracking

- `setPointerCapture` so tracking survives the pointer leaving the element's bounds.
- **Respect the grab offset** — snapping the element's center to the finger breaks the illusion.
- Keep a short position+timestamp history from `pointermove`; you need velocity at release.

## 3. Interruptibility — the most important rule

- Never lock out input during a transition. A closing sheet the user grabs must follow the finger.
- **Animate from the presentation (live) value, never the logical target** — on interrupt, read the
  element's current on-screen transform and start there, or you get a visible jump.
- No CSS transitions/keyframes for gesture-driven motion — they can't be grabbed mid-flight. Springs
  retarget from current value + velocity by default.
- On reversal, **blend velocity** (springs that carry velocity through a re-target); a hard cut is a
  "brick wall".
- Decompose 2D motion into **independent X and Y springs** — one spring on a 2D distance desyncs.

## 4. Springs in designer terms — damping + response

Think in Apple's two parameters, not mass/stiffness/damping triplets:

- **Damping ratio** — overshoot. `1.0` = critically damped (no bounce). Lower = bouncier.
- **Response** — seconds to reach the target area. Lower = snappier. Not a fixed "duration".

Defaults: **damping `1.0` for most UI**; add bounce (**~`0.8`**) only when the gesture itself
carried momentum (flick, throw, drag release). Overshoot on a menu that faded in is wrong;
overshoot on a card you flicked is right.

| Interaction | Damping | Response |
|---|---|---|
| Move / reposition | 1.0 | 0.4 |
| Rotation | 0.8 | 0.4 |
| Drawer / sheet | 0.8 | 0.3 |

Web mapping (Motion): `{ type: 'spring', bounce: 0, duration: 0.4 }` ≈ damping 1.0 / response 0.4;
`bounce: 0.2` ≈ damping ~0.8. House style: bounce 0 everywhere by default.

## 5. Velocity handoff — the seam between drag and animation

The release animation must continue at the finger's exact velocity. Pass release velocity as the
spring's initial velocity (Motion takes raw px/s via `velocity`). If an API wants relative velocity:
`relativeVelocity = gestureVelocity / (target − current)`.

## 6. Momentum projection — animate to where the gesture is going

Don't snap to the nearest point from the *release position*; project where momentum would land,
then pick the snap target nearest that projection. This is what makes a flick feel like a throw.

```js
// decelerationRate ≈ 0.998 normal scroll feel; 0.99 snappier
function project(velocityPxPerS, decelerationRate = 0.998) {
  return (velocityPxPerS / 1000) * decelerationRate / (1 - decelerationRate);
}
const target = nearestSnapPoint(current + project(releaseVelocity));
// then spring to target WITH the release velocity (§5)
```

Decide commit-vs-revert by **velocity sign**, not position: a fast flick back cancels even past the
halfway point. Combine with the dismissal threshold `Math.abs(distance)/elapsedMs > ~0.11`.

## 7. Rubber-banding — soft boundaries

Resist progressively past an edge; a hard stop reads as frozen.

```js
function rubberband(overshoot, dimension, constant = 0.55) {
  return (overshoot * dimension * constant) / (dimension + constant * Math.abs(overshoot));
}
```

## 8. Gesture feel checklist

- Tap: highlight on touch-down, commit on touch-up; ~10px hysteresis/hit padding; cancel by
  dragging away (and back).
- Drag/swipe: ~10px movement threshold before committing to a direction, then 1:1.
- Detect plausible gestures in parallel from the first move; cancel losers once intent is clear.
  Avoid final-state-only recognizers (`swipeleft` events) — they discard continuous tracking.
- Pay double-tap disambiguation delay only where double-tap actually exists.
- Enter and exit along the **same path**; anchor popovers/menus/sheets to their trigger
  (`transform-origin` at the trigger); mirror easing on reversible transitions.
- Intermediate motion should **hint at the outcome** (grow toward the finger), not blindly interpolate.

## 9. Frame-level smoothness

- Keep per-frame positional change below the strobing threshold; for very fast motion a subtle
  blur/stretch reads better than a sharp streak.
- `requestAnimationFrame` is the display-synced clock; still animate only `transform`/`opacity`.

## 10. Reduced motion — three signals, not one

- `prefers-reduced-motion: reduce` → cross-fades instead of slides/springs; drop overshoot; keep
  comprehension-aiding opacity/color.
- `prefers-reduced-transparency: reduce` → raise surface opacity, drop blur (see `../glass/GUIDE.md`).
- `prefers-contrast: more` → near-solid surfaces with a defined border.

Also avoid: full-viewport moving backgrounds, ~0.2Hz slow loops, abrupt dark↔light jumps; make
large moving surfaces semi-transparent while traveling.

## Cross-references

- Materials/translucency/vibrancy (the `apple-design` §12 content) is owned by `../glass/GUIDE.md` — don't
  duplicate it here.
- Typography optical sizing/tracking is owned by `/designer` craft rules +
  `tools/skills/audit-visual/references/typography.md`.
- Reviewer-side values (dismissal threshold, spring configs, boundaries): `tools/skills/audit-visual/references/motion-standards.md`
  — keep shared values in sync; this guide is canonical on conflict.
- Prototype interactively: an interactive demo beats static mocks; review motion in slow motion /
  frame-by-frame before shipping.
