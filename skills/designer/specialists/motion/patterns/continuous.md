# Continuous Patterns

Loops and loading states. Only when semantically meaningful.

**Default motion language fit:** Precision, Technical, Calm (rarely Playfulness).

---

## spinner

**Use when:** content is loading and the wait time is unknown. Async data fetches, processing actions.

**Avoid when:** the wait time is short (<300ms — spinner flashes and feels broken). When the loading state can be a skeleton instead (preferred).

**Defaults:**
- Duration: 800-1500ms per rotation
- Easing: linear (continuous rotation)
- Style: simple arc rotating, dot pulsing, or three-dot cascade — not an elaborate 3D scene
- Pause control: not needed (loaders are exempt from the >5s rule)
- Reduced motion: static circle, no rotation; or fade in/out between states

**Performance:** GPU-only. Cheap. Avoid elaborate loaders on mobile.

---

## marquee

**Use when:** a horizontal list scrolls continuously. Logo strips, partner lists, ticker for news/announcements.

**Avoid when:** the content needs to be read (continuous motion competes with reading). When the list is critical info (use pagination).

**Defaults:**
- Duration: 20-60s for one full cycle (slow — readable per item)
- Easing: linear
- Direction: usually left
- Pause on hover: yes
- Pause control: required if > 5s (user can pause for reading)
- Reduced motion: static list, no scroll

**Performance:** GPU-only via `transform: translateX()`. Cheap. Test on mid-tier mobile.

---

## skeleton-shimmer

**Use when:** content is loading and the layout is known. Card lists, article previews, profile pages.

**Avoid when:** the layout is unknown (use spinner). When the skeleton is so elaborate it competes with the loaded content visually.

**Defaults:**
- Shimmer duration: 1500-2000ms per cycle
- Easing: linear
- Property: `background-position` or `transform: translateX()` on a gradient overlay
- Reduced motion: static grey blocks, no shimmer

**Performance:** GPU-only. Cheap. The shimmer gradient should be a single layer, not animated per element.

---

## Canonical code

```css
/* spinner — arc rotation, linear */
.spinner { width: 18px; height: 18px; border-radius: 50%;
  border: 2px solid var(--border); border-top-color: var(--accent);
  animation: spin 0.9s linear infinite; }
@keyframes spin { to { transform: rotate(1turn); } }

/* skeleton-shimmer — one gradient layer sweeping via transform */
.skeleton { position: relative; overflow: hidden; background: var(--surface); border-radius: 6px; }
.skeleton::after { content: ''; position: absolute; inset: 0;
  background: linear-gradient(90deg, transparent, color-mix(in srgb, var(--text) 6%, transparent), transparent);
  transform: translateX(-100%); animation: shimmer 1.8s linear infinite; }
@keyframes shimmer { to { transform: translateX(100%); } }

@media (prefers-reduced-motion: reduce) { .spinner { animation-duration: 1.5s; } .skeleton::after { animation: none; } }
```

marquee: full component (duplicated track, hover-pause, reduced-motion wrap) in
`designer/references/components/marquee-logos.md`.
