# Transition & Compositing Performance Rules

Folded from make-interfaces-feel-better. Apply during Kinesthetics & States (Phase 3) and Craft & Delight (Phase 4).

## Transition Only What Changes

Never use `transition: all` or Tailwind's bare `transition` shorthand (maps to `transition-property: all`). Always specify exact properties.

### Why

- `transition: all` forces the browser to watch every property for changes
- Causes unexpected transitions on unintended properties (colors, padding, shadows)
- Prevents browser optimizations that allow GPU compositing

```css
/* Good */
.button { transition-property: scale, background-color; transition-duration: 150ms; transition-timing-function: ease-out; }

/* Bad */
.button { transition: all 150ms ease-out; }
```

Tailwind:
- Good: `transition-[scale,background-color] duration-150 ease-out`
- Bad: `transition duration-150 ease-out`

Note: Tailwind's `transition-transform` maps to `transition-property: transform, translate, scale, rotate` — covers all transform-related properties. Use it when only animating transforms. For mixed properties, use bracket syntax: `transition-[scale,opacity,filter]`.

## `will-change` — Sparse Use Only

`will-change` hints the browser to pre-promote an element to its own GPU compositing layer. Without it, promotion happens when the animation starts — causing a one-frame micro-stutter.

Only helps for `transform`, `opacity`, `filter` (blur/brightness), and `clip-path`. Not helpful for `background-color`, `padding`, `border`, `color` — those can't be GPU-composited.

```css
/* Good — specific compositor-friendly property */
.animated-card { will-change: transform; }
.animated-card { will-change: transform, opacity; }

/* Bad */
.animated-card { will-change: all; }
.animated-card { will-change: background-color, padding; }
```

| Property | GPU-compositable | Worth `will-change` |
|---|---|---|
| `transform` | Yes | Yes |
| `opacity` | Yes | Yes |
| `filter` (blur, brightness) | Yes | Yes |
| `clip-path` | Yes | Yes |
| `top`, `left`, `width`, `height` | No | No |
| `background`, `border`, `color` | No | No |

When to skip: modern browsers optimize well on their own. Only add `will-change` when you observe first-frame stutter (Safari particularly benefits). Each extra compositing layer costs memory — do not add preemptively.
