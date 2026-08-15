# Typography Craft Rules

Folded from make-interfaces-feel-better. Implementation-level rules for the Visual Architecture pass (Phase 2) and Craft & Delight pass (Phase 4).

## Text Wrapping

### `text-wrap: balance`

Distributes text evenly across lines. Prevents orphaned words on headings and short text blocks. **Only works on blocks of 6 lines or fewer** (Chromium) or 10 lines or fewer (Firefox). Computationally expensive — browsers limit it to short text.

```css
h1, h2, h3 { text-wrap: balance; }      /* Good */
.article-body p { text-wrap: balance; } /* Bad — silently ignored on long text */
```

Tailwind: `text-balance`

### `text-wrap: pretty`

Optimizes the last line to avoid orphans. Works on longer text — use this for body copy.

```css
p { text-wrap: pretty; }
```

### When to Use Which

| Scenario | Use |
|---|---|
| Headings, titles, short text (≤6 lines) | `text-wrap: balance` |
| Body paragraphs, descriptions | `text-wrap: pretty` |
| Code blocks, pre-formatted text | Neither — leave default |

## Font Smoothing (macOS)

On macOS, text renders heavier than intended by default. Apply antialiased smoothing to the root layout.

```css
html { -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale; }
```

Tailwind: `<html className="antialiased">` — apply once at root.

Only affects macOS. Other platforms ignore it — safe to apply universally. Do not apply per-element; inconsistent rendering is worse than none.

## Tabular Numbers

When numbers update dynamically (counters, prices, timers, table columns), use `font-variant-numeric: tabular-nums` to make all digits equal width. Prevents layout shift as values change.

```css
.counter { font-variant-numeric: tabular-nums; }
```

Tailwind: `tabular-nums`

| Use tabular-nums | Don't use tabular-nums |
|---|---|
| Counters, timers | Static display numbers |
| Prices that update | Decorative large numbers |
| Table/grid number columns | Phone numbers, zip codes |
| Dashboards, scoreboards | Version numbers (v2.1.0) |

Caveat: some fonts (Inter) change the visual appearance of `1` with this property — it becomes wider and centered. Verify in context. This is expected and usually desirable for alignment.
