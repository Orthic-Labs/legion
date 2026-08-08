# Spatial Patterns

Scroll-linked, scroll-driven, scroll-locked. Use sparingly — most surfaces should be scroll-triggered (via CSS or IntersectionObserver), not scroll-driven.

**Default motion language fit:** Editorial, Authority, Luxury (rarely Playfulness or Energy).

---

## parallax-scroll

**Use when:** background elements move at a different rate than foreground content as the user scrolls. Editorial imagery, hero depth, atmospheric.

**Avoid when:** mobile or low-end devices (parallax can jank). When the user is mid-task (forms, checkout). Always respect `prefers-reduced-motion`.

**Defaults:**
- Speed differential: 0.3-0.7x scroll rate
- Direction: opposite to scroll for depth illusion, or same direction for foreground push
- Trigger: scroll position via `transform: translateY(scrollY * factor)`

**Reduced motion:** remove parallax; elements stay at their final position.

**Performance:** GPU-only. Test on mid-tier Android — large translateY values on background images can drop frames.

---

## scroll-progress

**Use when:** an animation's progress is bound to the user's scroll position. Progress bars, scroll-driven reveals, color changes.

**Avoid when:** the user is reading (constant motion is distracting). When the content is task-focused.

**Defaults:**
- Trigger: scroll position within a target element's viewport
- Range: usually full viewport (0-100% scroll within element)
- Easing: per-element; consider no easing (linear scroll mapping is more natural)

**Reduced motion:** either remove the binding or trigger at one specific point (e.g., when element is 50% visible).

**Performance:** usually fine. Avoid scroll listeners on the main thread; use CSS `animation-timeline: scroll()` or rAF-based updates.

---

## pinned-section

**Use when:** a section should stay in the viewport while content progresses within it. Long-form storytelling, scene transitions, product configurators.

**Avoid when:** short pages, content-heavy reading pages, mobile (pinning can be janky on touch devices).

**Defaults:**
- Pin duration: viewport-height multiples (1x = 1 viewport of pinned scroll)
- Release: spring or ease-out depending on energy
- Internal content: scrolls or animates within the pinned area

**Reduced motion:** remove pinning; content becomes regular scrolling.

**Performance:** complex. Test extensively. Pinned content with internal motion can saturate the main thread.

---

## scrubbed-timeline

**Use when:** the user scrubs through a timeline by scrolling, with the animation playing in lockstep. The animation's progress = scroll position. Storytelling, product demos, scene transitions.

**Avoid when:** most surfaces. This is a high-effort, high-attention pattern. Use only when warranted.

**Defaults:**
- Scrub direction: forward with scroll down
- Easing: linear scrub (or ease in/out at the start/end of the timeline)
- Trigger: scroll position through a defined range
- Length: usually 1-3 viewports of scroll

**Reduced motion:** jump to the final state at the appropriate scroll point; no scrub.

**Performance:** expensive. GSAP ScrollTrigger is the most battle-tested; CSS `animation-timeline: scroll()` is native but limited.

---

## pinned-storytelling

**Use when:** a multi-scene narrative that pins each scene as the user scrolls, transitioning between them. Linear/Apple-style product stories.

**Avoid when:** the surface has multiple navigation paths or is content-rich. This pattern is single-narrative.

**Defaults:**
- Each scene: 1-2 viewports of pinned scroll
- Transitions: between scenes, via opacity or transform
- Total length: 4-8 viewports typically; longer is a slog
- Content: minimal per scene — one idea, one image, one motion

**Reduced motion:** unpin; show each scene as a regular section.

**Performance:** the most expensive spatial pattern. Use only when the narrative justifies it.

---

## Canonical code

Pinning, scrubbing, and horizontal-scroll full implementations live in `showpiece.md` +
`designer/references/components/hero-scroll-scene.md` (they are showpiece-register patterns).

```css
/* scroll-progress — CSS-native, no JS (progress bar bound to page scroll) */
.progress { position: fixed; top: 0; left: 0; height: 2px; width: 100%; background: var(--accent);
  transform-origin: left; animation: grow linear both; animation-timeline: scroll(root); }
@keyframes grow { from { transform: scaleX(0); } to { transform: scaleX(1); } }

/* parallax via view timeline — element drifts as it crosses the viewport */
.drift { animation: drift linear both; animation-timeline: view(); animation-range: entry exit; }
@keyframes drift { from { transform: translateY(4vh); } to { transform: translateY(-4vh); } }

@media (prefers-reduced-motion: reduce) { .progress, .drift { animation: none; } }
```

```js
// GSAP fallback where animation-timeline support is missing, or when scenes need sequencing
gsap.to('.drift', { yPercent: -8, ease: 'none',
  scrollTrigger: { trigger: '.drift', start: 'top bottom', end: 'bottom top', scrub: true } });
```
