# Showpiece Patterns

Immersive-register patterns — for surfaces where motion IS the experience (campaign pages,
portfolios, product-story pages, award-bar marketing sites). These are ONLY valid in the
**showpiece register** (SKILL.md §Registers); in the product register most of them are findings.

**Floors still apply:** reduced-motion variant, transform/opacity only, no CLS, no hydration
mismatch, content in initial HTML, CTA reachable ≤ 1.5s. Full section exemplars with complete code:
`designer/references/components/` (hero-scroll-scene, text-effects, micro-interactions).

**Default motion language fit:** Editorial, Luxury, Energy, Authority.

---

## pin-and-scrub

Pin a section; scroll drives a timeline through scene states. THE showpiece anchor pattern.

- Length: 1.5-3 viewports of scrub (`end: '+=250%'`); 4+ is a slog.
- Easing: `ease: 'none'` — linear scroll↔progress mapping reads most natural.
- One per page by default; never two back-to-back.
- Mobile + reduced motion: unpin via `gsap.matchMedia`, show scenes as static sections.

```js
gsap.timeline({
  scrollTrigger: { trigger: el, start: 'top top', end: '+=250%', scrub: 0.6, pin: true },
  defaults: { ease: 'none' },
});
```

Full component: `designer/references/components/hero-scroll-scene.md`.

---

## parallax-layers

2-4 depth layers moving at different scroll rates. Ambience, not information.

- Rates: background 0.2-0.4x, midground 0.6-0.8x, foreground 1x (or 1.1x for push).
- Transform-only; never parallax a text block the user is reading.
- Reduced motion: all layers at 1x.

```js
gsap.utils.toArray('[data-depth]').forEach((layer) => {
  gsap.to(layer, {
    yPercent: () => -30 * Number(layer.dataset.depth), // depth 0.2-1
    ease: 'none',
    scrollTrigger: { trigger: layer.parentElement, start: 'top bottom', end: 'bottom top', scrub: true },
  });
});
```

CSS-native alternative for simple cases: `animation-timeline: view()`.

---

## horizontal-scroll-section

Vertical scroll drives a horizontal track — gallery, timeline, process steps.

- Track: 2-4 panels; pin duration = track overflow width.
- Keyboard/AT: the track must remain reachable in DOM order; horizontal presentation is visual only.
- Mobile: replace with native horizontal scroll-snap or a vertical stack.

```js
const track = document.querySelector('.h-track');
gsap.to(track, {
  x: () => -(track.scrollWidth - innerWidth),
  ease: 'none',
  scrollTrigger: { trigger: '.h-wrap', start: 'top top', end: () => `+=${track.scrollWidth - innerWidth}`, scrub: 0.5, pin: true },
});
```

---

## scroll-scrub-text-fill

Words brighten/fill in lockstep with scroll through a manifesto block. One per page.

Implementation: `designer/references/components/text-effects.md` §2 (Motion `useScroll` +
per-word `useTransform`). Reduced motion: full-opacity static text.

---

## load-choreography

Orchestrated page-load sequence: eyebrow → masked headline words → sub → CTA → visual.

- Total ≤ 1.2s; value prop visible < 1s; stagger 0.05-0.09s; ease `[0.16, 1, 0.3, 1]`.
- Runs once per session-entry page, not on every route change.

Implementation: `designer/references/components/hero-load-choreography.md`.

---

## smooth-scroll (Lenis)

Inertial scroll for the whole surface. Showpiece-only; on product surfaces it's a finding
(hijacks native feel on repeated-use UI).

- `lerp: 0.1-0.14`. Skip entirely under reduced motion. Wire `lenis.on('scroll', ScrollTrigger.update)`.
- Never combine with CSS `scroll-behavior: smooth` or scroll-snap sections.

Implementation: `designer/references/components/hero-scroll-scene.md` (SmoothScroll component).

---

## magnetic-hover

CTA/nav elements attract toward the cursor. Pointer-fine + no-preference only.

- Pull factor 0.15 (luxury) - 0.35 (energy); spring `stiffness ~220, damping ~18`.
- 2-4 elements per page max — magnetic everything is noise.

Implementation: `designer/references/components/micro-interactions.md` §1.

---

## marquee

Continuous proof/logo strip. Allowed in both registers.

Implementation: `designer/references/components/marquee-logos.md` (CSS-only, hover-pause,
reduced-motion static wrap).

---

## Composition rules (per showpiece page)

- ONE pin-and-scrub anchor + supporting patterns. Not three anchors.
- Persistent objects (principles.md §2) carry the narrative BETWEEN showpiece moments — the
  patterns are beats, the object is the thread.
- Budget: showpiece engine set (GSAP+ScrollTrigger+Lenis ≈ 50KB gz) counts against the 120KB
  showpiece ceiling; pick ONE engine family per site.
- Every pattern above must appear in the scene breakdown of `motion-plan.md` with its purpose named
  — showpiece drops the restraint test, not the choreography test.
