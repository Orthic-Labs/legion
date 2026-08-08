# Layout Patterns

Position and size changes. The most powerful category for app UI.

**Default motion language fit:** Precision, Technical, Editorial.

---

## shared-layout-morph

**Use when:** the same element exists across views and should morph between them. Card → detail page, list item → expanded view, thumbnail → full image.

**Avoid when:** the elements are visually dissimilar (no morph path). When performance budget is tight.

**Defaults:**
- Duration: 300-500ms
- Easing: strong ease-out for forward, ease-in for reverse
- Implementation: requires layoutId or equivalent (Motion, GSAP Flip, Rive)
- Properties animated: position, size, border-radius, opacity

**Reduced motion:** instant jump; no morph.

**Performance:** depends on what's being morphed. Image morphing is fine; text morphing can reflow.

---

## list-reorder

**Use when:** items in a list change order (drag-to-reorder, sort, filter). Tasks, kanban boards, sortable lists.

**Avoid when:** the list is very long (>50 items — animation becomes sluggish). When the user is mid-task (motion can feel like delay).

**Defaults:**
- Duration: 200-300ms per item movement
- Easing: spring (natural) — feels organic
- Trigger: when the data changes
- Reflow: layout animations via FLIP (Motion, GSAP Flip)

**Reduced motion:** instant reorder; no animation.

**Performance:** scales with list length. Use `will-change` on items being moved; remove after.

---

## accordion-height

**Use when:** a section expands or collapses. FAQs, settings groups, expandable cards.

**Avoid when:** the content is very long (animation becomes slow). When the user is mid-task.

**Defaults:**
- Duration: 200-300ms
- Easing: ease-in-out (symmetric — both directions)
- Property: `height` (animate via `grid-template-rows: 0fr → 1fr` for performance) or scale-Y
- Opacity: 0 → 1 on content (subtle)

**Reduced motion:** instant expand; no animation.

**Performance:** animating `height` triggers layout. Prefer `grid-template-rows` trick or `max-height` with a known final value.

---

## tabs-indicator

**Use when:** a tab bar's active indicator slides between tabs. The bottom border, the pill background.

**Avoid when:** tabs are dynamically added/removed (animation breaks). When the indicator is a different element (icon swap) — use that pattern instead.

**Defaults:**
- Duration: 200-300ms
- Easing: strong ease-out (or spring for "alive" feel)
- Implementation: shared layout (Motion `layoutId`) or absolute positioning with transform
- Properties: x position, width

**Reduced motion:** instant indicator jump.

**Performance:** GPU-only. Very cheap.

---

## Canonical code

```tsx
// tabs-indicator / toggle pill — Motion shared layout
{tabs.map((t) => (
  <button key={t} onClick={() => setActive(t)} className="relative px-4 py-1.5">
    {active === t && (
      <motion.span layoutId="tab-pill" className="absolute inset-0 rounded-full bg-[var(--accent)]"
                   transition={{ type: 'spring', stiffness: 400, damping: 32 }} />
    )}
    <span className="relative">{t}</span>
  </button>
))}

// list-reorder / shared-layout-morph — the layout prop does the FLIP
<motion.li layout key={item.id} transition={{ type: 'spring', stiffness: 350, damping: 30 }} />
```

```css
/* accordion-height — grid-rows trick, no layout thrash, unknown content height */
.acc { display: grid; grid-template-rows: 0fr; transition: grid-template-rows 0.25s cubic-bezier(0.77, 0, 0.175, 1); }
.acc[data-open] { grid-template-rows: 1fr; }
.acc > div { overflow: hidden; }
@media (prefers-reduced-motion: reduce) { .acc { transition: none; } }
```
