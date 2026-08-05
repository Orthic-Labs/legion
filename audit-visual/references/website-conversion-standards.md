# Website Conversion Standards — the measured floor for landing/marketing surfaces

The evidence-based framework behind the detector's `structure` rule pack and the Lens 2/3 judgment
bar. Agents building or reviewing websites follow THIS, not remembered taste. Every numbered
standard maps to a deterministic rule id where one exists; the rest are judgment checks the lenses
must run explicitly.

Sources: Julian Shapiro's landing-page handbook (Demand Curve), StoryBrand "grunt test",
NN/g homepage/scrolling research, Baymard Institute ecommerce guidelines, Unbounce
conversion-centered design. Convergent, not contested, across all of them.

## The model

```text
Conversion = Desire − (Labor + Confusion)
```

Every above-the-fold decision either raises desire, cuts labor, or cuts confusion. A hero that
does none of those is decoration. ~57–80% of user attention stays above the fold (NN/g) — the
first viewport IS the page.

## The five-second grunt test (Lens 2 must answer, per viewport)

A first-time visitor reading ONLY the first viewport must be able to answer:

1. **What is this?** — descriptive, not clever.
2. **What's in it for me?** — one concrete benefit.
3. **What do I do next?** — one visible action.

If any answer requires scrolling or interpretation, that is a Blocker-class finding regardless of
how good the page looks.

## Hero contract (detector-backed)

| # | Standard | Threshold | Rule id |
|---|---|---|---|
| 1 | Primary CTA fully visible in the first viewport, desktop AND mobile | CTA bottom ≤ fold | `cta-below-fold` |
| 2 | One primary CTA decision above the fold; at most one visually secondary action | <3 distinct filled CTAs above fold | `hero-cta-competition` |
| 3 | Headline states the offer in ~10 words | h1 ≤ 14 words (hard) | `headline-word-wall` |
| 4 | Headline reads as set lines, not a word stack | <4 lines, or ≥2.6 words/line at display size | `one-word-lines` |
| 5 | A visual anchor shows the product or a purposeful image | media ≥ 8% of first viewport | `missing-hero-media` (advisory — a deliberate type-only hero can pass on typographic strength, and the lens must say so explicitly) |
| 6 | The hero fits its message in about one viewport | hero section ≤ 1.15 viewports, or it contains the media that earns the height | `hero-viewport-hog` |
| 7 | Headline is fully descriptive of what is being sold | judgment — Lens 2 | — |
| 8 | Subheader elaborates the headline's claim, doesn't repeat it | judgment — Lens 2 | — |
| 9 | CTA copy states the action's value ("Start free trial"), never "Submit"/"Learn more" as primary | judgment — Lens 3 | — |
| 10 | Social proof or a trust signal appears above or immediately below the fold | judgment — Lens 13 | — |

## Header and hover contract (detector-backed)

| # | Standard | Threshold | Rule id |
|---|---|---|---|
| 11 | Header stays a signature, not a billboard | header block ≤ 128px; wordmark/logo ≤ 64px inside it (convention: 56-88px header, 20-40px wordmark) | `oversized-header` |
| 12 | Every hover state stays legible | :hover text/background pairs keep WCAG contrast (4.5:1 body, 3:1 large) | `hover-contrast` |
| 13 | Content column is constrained | body text ≤ ~80 chars/line; text never touches the viewport edge | existing `line-length` + `body-text-viewport-edge` |
| 14 | Menu items legible in every state | resting contrast via `low-contrast`; hover via `hover-contrast`; focus visible (Lens 11) | — |

## Site completeness contract (detector-backed via `--site`)

Run on the homepage: `detect.mjs --json --site --site-type=<app|ecommerce|content> <url>`

| Requirement | Rule id |
|---|---|
| Every same-origin link resolves (< 400) | `broken-internal-link` |
| Privacy policy + Terms linked (all commercial sites) | `missing-required-page` |
| App sites: pricing + download pages linked | `missing-required-page` |
| Ecommerce: returns/refunds, shipping, contact, about linked | `missing-required-page` |
| Every page reachable from nav/footer; no orphan sections (judgment — Lens 2 over the sitemap/nav) | — |

The sweep reads static HTML; on a client-rendered SPA nav it reports its own blindness instead of
passing. Legal-page LINKS existing is the measured floor — whether the pages' content is real is a
Lens 14 judgment check.

## Page-body contract (below the fold)

- Section order follows the objection sequence: what it is → proof it works → how it works →
  who it's for → pricing/offer → final CTA. Deviations need a reason.
- The primary CTA repeats after the proof sections and at page end.
- One idea per section; a section that needs a paragraph to explain its own heading is two sections.
- Specific numbers beat adjectives ("ships in 2 days", not "blazing fast") — but NEVER fabricated
  ones (cross-brand rule).
- Every claim a competitor could also make is positioning noise; every claim only this product can
  make is positioning signal.

## Laws applied (what "Hick's law and this and that" actually gates)

| Law | Applied check |
|---|---|
| Hick's law | Every decision point offers ≤3-4 options; hero offers ONE. Detector: `hero-cta-competition`; Lens 2 flags >4 visible options at any decision point |
| Jakob's law | Navigation, cart, auth, and form patterns match category conventions; novelty budget is spent on the offer, not the chrome |
| Fitts's law | Primary CTA is large, isolated, and near the natural scan terminus; ≥44px touch targets (Lens 8 floor) |
| Miller/chunking | Feature lists group into 3-5 chunks, never 9 flat bullets |
| Von Restorff | Exactly one element above the fold is visually singular — the CTA. If everything pops, nothing does |
| Serial position | The strongest proof point leads the proof section; the final CTA restates the core benefit |

## Mandatory scan protocol for any website/landing audit

```text
node D:/Claude/tools/skills/designer/engine/scripts/detect.mjs --json --viewport=1440x900 <url>
node D:/Claude/tools/skills/designer/engine/scripts/detect.mjs --json --tablet <url>
node D:/Claude/tools/skills/designer/engine/scripts/detect.mjs --json --mobile <url>
node D:/Claude/tools/skills/designer/engine/scripts/detect.mjs --json --site --site-type=<app|ecommerce|content> <homepage-url>
```

- All runs are REQUIRED before a verdict (site sweep once, on the homepage); save the JSON outputs
  into the audit's evidence directory and cite the paths in "Evidence inspected".
- Browser mode runs via puppeteer when installed, else automatically via installed Chrome/Edge
  over raw CDP. If a URL scan was impossible, structure rules are UNTESTED — say so; a static
  scan never clears them.
- Structure blockers (`cta-below-fold`, `hero-viewport-hog`, `one-word-lines`,
  `hero-cta-competition`, `headline-word-wall`, `hover-contrast`, `oversized-header`,
  `broken-internal-link`, `missing-required-page`) on a marketing/landing surface floor the
  verdict at REVISE. Only Adrian can waive one, explicitly, per finding. Agents — including this
  one — cannot argue a measured structure blocker down to a Note.
- Re-runnable proof of the whole rule pack:
  `node tools/skills/designer/engine/scripts/detector/tests/structure/run-structure-smoke.mjs`
