# Gesture Patterns

User-driven motion. The user provides the input; the motion responds.

**Default motion language fit:** Precision, Playfulness, Technical.

---

## drag

**Use when:** an element should follow the user's pointer/touch. Draggable cards, kanban boards, sliders, scrubbable timelines.

**Avoid when:** the action could be a click (don't add drag overhead). When the user is on a non-touch device without a mouse (rare).

**Defaults:**
- Response: 1:1 with pointer (no lag) for direct manipulation
- Release: spring back to origin or commit to drop target
- Constraints: optional (axis lock, bounds)
- Momentum: optional, on release (velocity-based)

**Reduced motion:** no drag; element stays at its resting position. Use click/tap for primary action.

**Performance:** GPU-only. Use pointer events; avoid `mousedown`/`touchstart` parallel handlers.

---

## swipe

**Use when:** a horizontal gesture should trigger an action. Carousel navigation, dismiss-to-archive, swipe-to-delete.

**Avoid when:** the action is destructive without confirmation (swipe-to-delete with no undo is hostile). When a button would be more discoverable.

**Defaults:**
- Threshold: 30-50% of element width to commit
- Response: 1:1 with pointer; spring back if under threshold
- Direction: usually horizontal; support both directions
- Visual feedback: element follows finger; background color change on commit threshold

**Reduced motion:** swipe still works but no follow-the-finger animation; instant commit.

**Performance:** GPU-only. Use pointer events.

---

## magnetic-cursor

**Use when:** a button or interactive element should subtly attract the cursor when nearby. Premium CTAs, hero buttons, navigation items.

**Avoid when:** the surface has many interactive elements (magnetic everywhere = performance + noise). On touch devices (no cursor).

**Defaults:**
- Pull range: 20-50px from element center
- Pull strength: 0.2-0.4 (subtle; never 1.0 — that's snapping)
- Easing: spring (natural)
- Trigger: only with `@media (hover: hover) and (pointer: fine)`

**Reduced motion:** no magnetic effect.

**Performance:** requires rAF loop or pointer events with debouncing. Use transform interpolation, not direct position binding.

---

## hover-lift

**Use when:** a card or button should subtly rise on hover. The most common interactive feedback.

**Avoid when:** the surface has many cards in a grid (performance + noise). On touch devices (no hover).

**Defaults:**
- Duration: 150-200ms
- Easing: strong ease-out
- Transform: `translateY(-2px)` to `translateY(-4px)` (subtle)
- Optional: shadow grow, scale 1 → 1.02
- Trigger: only with `@media (hover: hover) and (pointer: fine)`

**Reduced motion:** no transform; only color/border change.

**Performance:** GPU-only. Cheap.

---

## pinch

**Use when:** a zoomable surface should respond to two-finger pinch. Maps, images, configurators.

**Avoid when:** the surface is not zoomable (pinch is hostile). When a +/- button would suffice.

**Defaults:**
- Response: 1:1 with finger distance
- Constraints: min/max scale (e.g., 0.5x to 4x)
- Easing: spring on release if outside constraints
- Implementation: pointer events with multi-touch tracking

**Reduced motion:** pinch still works but no animation; instant scale.

**Performance:** GPU-only. Multi-touch event handling is well-supported.

---

## Canonical code

Gesture physics doctrine (velocity handoff, momentum projection, rubber-banding, interrupt-from-
presentation-value) lives in `../fluid.md` — read it before building any drag/swipe surface.

```tsx
// drag + swipe-to-dismiss — Motion; velocity-based commit, not distance-only
<motion.div
  drag="x"
  dragConstraints={{ left: 0, right: 0 }}
  dragElastic={0.55}                       // rubber-band feel past the bounds
  onDragEnd={(_, info) => {
    const flick = Math.abs(info.velocity.x) > 400;         // px/s
    const past = Math.abs(info.offset.x) > width * 0.4;    // distance threshold
    if (flick || past) dismiss(Math.sign(info.velocity.x || info.offset.x));
  }}
  transition={{ type: 'spring', bounce: 0.2, duration: 0.5 }} // release spring carries velocity
/>
```

```css
/* hover-lift — always hover-gated */
@media (hover: hover) and (pointer: fine) and (prefers-reduced-motion: no-preference) {
  .card { transition: transform 0.18s cubic-bezier(0.23, 1, 0.32, 1); }
  .card:hover { transform: translateY(-3px); }
}
```

magnetic-cursor: full spring implementation in `designer/references/components/micro-interactions.md` §1.
