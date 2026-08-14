# Reference Capture Template (DESIGN.md format)

The format used to capture every reference site at Phase 0.6 (3 competitors + 2 aspirational per brand). The format is adopted from Google's open DESIGN.md specification — machine-readable, structured for AI consumption, no attribution required.

The capture methodology is ours. The format is open. We use it natively.

---

## Per-site capture pipeline

1. **Visit URL, capture at 5 breakpoints** via the qa-engine: `lib/qa-engine/qa-shot.mjs --url <url> --breakpoints 375,414,768,1024,1440 --out <dir>/screenshots/`
2. **Extract tokens** by inspecting the live DOM (computed styles via DevTools or Playwright). Output to `<dir>/design.md`.
3. **Extract copy samples** by curling the rendered HTML or via /content transcribe. 5-10 real blocks. Output to `<dir>/copy-samples.md`.
4. **Map sitemap** by crawling or reading navigation. Output to `<dir>/sitemap.md`.
5. **Judgment notes:**
   - `borrow.md` — 3-5 specific things to take, each with a citation to the live DOM
   - `avoid.md` — 2-3 specific things NOT to take, each with reason
6. **Document URLs and reasoning** — what's the 1-line takeaway from this site for our brand?

**Per-site effort:** 30-45 min via the qa-engine + curl/playwright + judgment notes.

**Refresh:** per brand, refresh when the brand's project changes. Quarterly check that captured sites haven't themselves redesigned.

---

## Per-site directory structure

```
Content/<brand>/references/competitors/<competitor-name>/
├── url.txt
├── screenshots/
│   ├── 375.png
│   ├── 414.png
│   ├── 768.png
│   ├── 1024.png
│   └── 1440.png
├── design.md
├── copy-samples.md
├── sitemap.md
├── borrow.md
└── avoid.md
```

Aspirational references live at `Content/<brand>/references/aspirational/<reference-name>/` with the same structure.

---

## design.md (the structured analysis)

```markdown
# <Site name> — reference capture

**URL:** https://...
**Captured:** YYYY-MM-DD
**Captured by:** <agent or human>
**Refreshing:** quarterly or when site materially changes
**Brand relevance:** <which of our brands this informs, why>

## Visual system

### Color
- bg-base: <hex> (where used)
- bg-elevated: <hex>
- ink-primary: <hex>
- ink-muted: <hex>
- accent: <hex> (where used)
- accent-hover: <hex>
- semantic-success: <hex>
- semantic-error: <hex>
- semantic-warning: <hex>

### Type
- display: <font, weights>
- body: <font, weights>
- label: <font, weights>
- scale: { h1, h2, h3, body, small, micro } with rem values
- leading: { display, heading, body } with unitless values

### Spacing
- scale: { 0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32 } with rem values
- container: { max-width, gutter }

### Radius
- { none, sm, md, lg } with px values

### Breakpoints
- { sm, md, lg, xl } with px values

### Other tokens (if material)
- shadows, transitions, easings, durations

## Components (catalogued, not re-implemented)

- Hero: <pattern name, what's distinctive>
- Card: <pattern>
- CTA: <pattern>
- Section transition: <pattern>
- Form: <pattern> (if applicable)
- Modal/drawer: <pattern> (if applicable)
- Navigation: <pattern>

## Copy samples (real, not paraphrased)

### Hero
"<exact text from the live site>"

### CTA labels
- "<exact text 1>"
- "<exact text 2>"

### Section opener
"<exact text>"

### Microcopy
- "<exact text 1>"
- "<exact text 2>"

## Sitemap

- /
- /products
- /products/[slug]
- /cart
- /checkout
- /about
- /contact
- /legal/privacy
- /legal/terms
```

---

## copy-samples.md

Real copy from the site. 5-10 blocks. Used as inspiration for our own voice (paraphrased, never copied verbatim).

---

## sitemap.md

The site's information architecture as a bullet list. Helps understand the structure, not the styling.

---

## borrow.md

3-5 specific things to take. Each must have:
- A concrete reference (e.g., "their hero uses 4rem h1 + 1.5rem sub + 1rem body")
- A reason ("the ratio feels premium without being heavy")
- A source location (e.g., "live DOM /products page, h1 selector")

Without these three elements, the entry isn't specific enough.

---

## avoid.md

2-3 specific things NOT to take. Each must have:
- A concrete reference (e.g., "their footer has 6 columns of links")
- A reason ("too dense for our brand voice")
- A source location

Without these three elements, the entry isn't specific enough.

---

## Top of file (1-line takeaway)

End every site's capture with:

```markdown
## 1-line takeaway

For our <brand>, this site informs <X> because <Y>.
```

This becomes the input to Phase 1 (signature mechanism) and Phase 2 (three directions). It's the one-line summary that guides decisions.
