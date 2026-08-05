# Surface Craft Rules

Folded from make-interfaces-feel-better. Border radius, optical alignment, shadows, image outlines, and hit areas. Apply during Visual Architecture (Phase 2) and Craft & Delight (Phase 4).

## Concentric Border Radius

When nesting rounded elements: `outerRadius = innerRadius + padding`.

Most useful when nested surfaces are close. If padding > 24px, treat layers as separate surfaces and choose each radius independently.

```css
/* Good */
.card { border-radius: 20px; padding: 8px; }   /* 12 + 8 */
.card-inner { border-radius: 12px; }

/* Bad — same radius on both */
.card { border-radius: 12px; padding: 8px; }
.card-inner { border-radius: 12px; }
```

Tailwind: `rounded-2xl p-2` (outer, 16px radius, 8px padding) → `rounded-lg` (inner, 8px radius = 16 − 8 ✓).

Mismatched radii on nested elements is one of the most common things that makes interfaces feel off.

## Optical Alignment

When geometric centering looks off, align optically instead.

**Buttons with text + icon:** `icon-side padding = text-side padding - 2px`.

```css
.button-with-icon { padding-left: 16px; padding-right: 14px; }
```

**Play button triangles:** geometric center ≠ visual center. Shift the SVG ~2px right:

```css
.play-button svg { margin-left: 2px; }
```

**Asymmetric icons (stars, arrows, carets):** fix in the SVG viewBox directly. If not possible, adjust with a `margin-left: 1px` fallback.

## Shadows Instead of Borders

For buttons, cards, and containers using a border for depth or elevation, prefer layered `box-shadow` over solid `border`. Shadows use transparency and morph to any background; solid borders don't.

Do NOT apply to dividers (`border-b`, `border-t`) or layout separators — those should stay as borders.

### Shadow as Border

```css
/* Light mode */
:root {
  --shadow-border:
    0px 0px 0px 1px rgba(0, 0, 0, 0.06),
    0px 1px 2px -1px rgba(0, 0, 0, 0.06),
    0px 2px 4px 0px rgba(0, 0, 0, 0.04);
  --shadow-border-hover:
    0px 0px 0px 1px rgba(0, 0, 0, 0.08),
    0px 1px 2px -1px rgba(0, 0, 0, 0.08),
    0px 2px 4px 0px rgba(0, 0, 0, 0.06);
}

/* Dark mode — single white ring */
--shadow-border: 0 0 0 1px rgba(255, 255, 255, 0.08);
--shadow-border-hover: 0 0 0 1px rgba(255, 255, 255, 0.13);
```

```css
.card {
  box-shadow: var(--shadow-border);
  transition-property: box-shadow;
  transition-duration: 150ms;
  transition-timing-function: ease-out;
}
.card:hover { box-shadow: var(--shadow-border-hover); }
```

| Use shadows | Use borders |
|---|---|
| Cards, containers with depth | Dividers between list items |
| Buttons with bordered styles | Table cell boundaries |
| Elevated elements (dropdowns, modals) | Form input outlines (accessibility) |
| Elements on varied backgrounds | Hairline separators in dense UI |

## Image Outlines

Add a subtle 1px outline with low opacity to images for consistent depth.

```css
/* Light mode */
img { outline: 1px solid rgba(0, 0, 0, 0.1); outline-offset: -1px; }

/* Dark mode */
img { outline: 1px solid rgba(255, 255, 255, 0.1); outline-offset: -1px; }
```

Tailwind: `outline outline-1 -outline-offset-1 outline-black/10 dark:outline-white/10`

Use `outline` (not `border`) because it does not affect layout, and `outline-offset: -1px` keeps it inset.

## Minimum Hit Area

Interactive elements: minimum 44×44px (WCAG 2.5.5) or at least 40×40px. If the visible element is smaller, extend with a pseudo-element.

```css
.checkbox { position: relative; width: 20px; height: 20px; }
.checkbox::after {
  content: ""; position: absolute;
  top: 50%; left: 50%; transform: translate(-50%, -50%);
  width: 40px; height: 40px;
}
```

Tailwind: `relative size-5 after:absolute after:top-1/2 after:left-1/2 after:size-10 after:-translate-1/2`

Collision rule: if the extended hit area overlaps another interactive element, shrink — but make it as large as possible without collision. Overlapping hit areas are never acceptable.
