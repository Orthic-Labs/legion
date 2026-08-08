# Entrance Patterns

Elements appearing. The most-used category — most surfaces have at least one entrance.

**Default motion language fit:** Precision, Editorial, Authority, Luxury (depending on intent).

---

## fade-in

**Use when:** a single element should appear without movement. State change, content reveal, modal-open at the same position.

**Avoid when:** the element has a meaningful origin (e.g., opening from a trigger — use that pattern instead). When spatial context matters (use slide).

**Defaults:**
- Duration: 200-300ms (standard)
- Easing: strong ease-out `(0.23, 1, 0.32, 1)`
- Distance: 0
- Opacity: 0 → 1

**Reduced motion:** skip or 80ms opacity fade.

**Performance:** minimal cost. GPU-only. No layout impact.

---

## slide-up

**Use when:** content reveals from below — copy blocks, cards, sections. The most common entrance.

**Avoid when:** the element has a trigger-anchored origin (use a popover-origin instead). When the slide is so long it competes with attention.

**Defaults:**
- Duration: 300-400ms
- Easing: strong ease-out
- Distance: 8-16px (sm or md token)
- Opacity: 0 → 1

**Reduced motion:** skip translation, keep 100ms opacity fade.

**Performance:** GPU-only via `transform: translateY()`. Safe.

---

## scale-up

**Use when:** element grows from a smaller version. Tooltips, popovers, buttons on appearance, image zoom-in.

**Avoid when:** starting from `scale(0)` — never. Always from `scale(0.9-0.97)`.

**Defaults:**
- Duration: 200-300ms
- Easing: strong ease-out
- Scale: 0.95 → 1
- Origin: element center (or trigger anchor for popovers)
- Opacity: 0 → 1

**Reduced motion:** skip scale, keep 100ms opacity fade.

**Performance:** GPU-only. Safe.

---

## stagger-children

**Use when:** a list or grid reveals its children one after another. Cards, list items, nav items, table rows.

**Avoid when:** more than 8 children (stagger becomes slow). When the visual emphasis is on a single item.

**Defaults:**
- Per-item duration: 200-300ms
- Stagger delay: 60-80ms between siblings (stagger token)
- Direction: top-to-bottom, left-to-right (reading order)
- Easing: strong ease-out

**Reduced motion:** keep stagger but reduce per-item duration to 100ms; consider showing all at once.

**Performance:** scales with item count. Keep items <12 or use IntersectionObserver to only animate visible.

---

## mask-reveal

**Use when:** a hero image, large visual, or section reveals from behind a mask. Premium product reveals, editorial imagery.

**Avoid when:** the content is text-only (use slide-up or fade-in). When performance budget is tight (masks can be expensive on low-end mobile).

**Defaults:**
- Duration: 600-1000ms (slow or reveal)
- Easing: ease-out-expo for cinematic feel
- Mask type: clip-path or mask-image (CSS); 3D scene for complex
- Direction: usually top-to-bottom or left-to-right

**Reduced motion:** skip mask animation, fade in the content over 200ms.

**Performance:** mask-image is GPU-accelerated but can drop frames on mid-tier Android. Test on real devices.

---

## type-on

**Use when:** typographic emphasis. Headlines that reveal word-by-word or letter-by-letter. Editorial-style emphasis.

**Avoid when:** the copy is body text (use fade-in). When the type-on is so slow it competes with reading.

**Defaults:**
- Per-word duration: 200-300ms
- Stagger between words: 80ms (within title)
- Stagger between letters (rare): 30-40ms
- Easing: strong ease-out
- Mask or split: per-word opacity + 4-8px translateY

**Reduced motion:** reveal all at once or skip the per-word animation.

**Performance:** depends on DOM manipulation. Splitting into spans adds elements; budget accordingly.

---

## Canonical code

Copy these working values; don't re-derive them. Full section-level implementations:
`designer/references/components/` (hero-load-choreography, text-effects, feature-bento).

```tsx
// Motion (motion/react) — fade-in / slide-up / scale-up / stagger-children in one variant set
const EASE = [0.23, 1, 0.32, 1] as const; // strong ease-out
const parent = { hidden: {}, show: { transition: { staggerChildren: 0.07 } } };
const child = {
  hidden: { opacity: 0, y: 12 },              // slide-up; y: 0 = fade-in; add scale: 0.95 = scale-up
  show: { opacity: 1, y: 0, scale: 1, transition: { duration: 0.4, ease: EASE } },
};
<motion.ul variants={parent} initial="hidden" whileInView="show" viewport={{ once: true, amount: 0.2 }}>
  {items.map((it) => <motion.li key={it.id} variants={child}>{it.label}</motion.li>)}
</motion.ul>
// Gate with useReducedMotion(): pass variants={undefined} / initial={false} when reduced.
```

```css
/* CSS-only equivalents — slide-up + stagger via animation-delay */
.enter { animation: rise 0.4s cubic-bezier(0.23, 1, 0.32, 1) both; }
.enter:nth-child(2) { animation-delay: 70ms; }
.enter:nth-child(3) { animation-delay: 140ms; }
@keyframes rise { from { opacity: 0; transform: translateY(12px); } }

/* mask-reveal (hero image) */
.reveal { clip-path: inset(0 0 100% 0); animation: unmask 0.8s cubic-bezier(0.16, 1, 0.3, 1) both; }
@keyframes unmask { to { clip-path: inset(0 0 0 0); } }

@media (prefers-reduced-motion: reduce) {
  .enter, .reveal { animation: fade 0.15s ease both; }
  @keyframes fade { from { opacity: 0; } }
}
```

type-on and per-word masked headlines: `designer/references/components/text-effects.md`.
