# Website surface — gates and tests (absorbs the retired /website skill)

Non-app web work: sites, landing/marketing/product pages, brand sites, portfolios, ecommerce
front-of-house, content pages. Design IS the product here — first impression and conversion carry
the weight.

## Banned defaults

If two appear, the site has failed:

- Centered hero headline + subhead + two buttons + abstract visual.
- Left-copy/right-card SaaS hero.
- Purple/blue gradients, default safe blue, pale-blue SaaS tinting, blobs, or decorative orbs.
- Color palettes picked only because they are trendy, "modern", calming, premium, or trustworthy.
- One-note palettes where the whole site is variations of one hue without semantic roles.
- Generic product cards, card grids, nested cards, rounded-everything.
- Inter everywhere or one sans/serif pairing as the whole concept.
- Fade-up-on-scroll as the only motion.
- Stock photos, abstract tech renders, AI screenshots with garbled text.
- CTA color sprinkled everywhere with no attention logic.

(Full anti-slop catalog + the three AI-look clusters: `audit-visual/references/design-slop.md`.)

## Phase 0 — Site truth

> "This site helps [audience] do/understand/buy [specific thing] by showing [specific
> product/service truth], and must be remembered for [signature perception]."

No abstract value-prop hero. The first viewport must reveal the brand/product/service reality.

## Phase 0.5 — Existing product parity (HARD GATE for app/product sites)

If the site is for an existing app, tool, desktop product, dashboard, editor, or workflow:

1. Inspect the strongest source of truth before designing: live app / QA harness screenshot >
   user-provided screenshot > product code and component structure > existing website (secondary).
2. State the product UI truth in concrete interface terms: shell, navigation model, density,
   primary workflow, states, visual material.
3. The first-viewport mechanism must visually inherit the real product: recognizable shell/layout,
   correct navigation model, comparable density and information rhythm, true labels/actions,
   brand colors/materials calibrated from the product — not invented for the site.
4. Fail and rework if the mockup becomes a toy abstraction, generic wireframe, decorative concept
   scene, or transplantable SaaS visual. Abstraction is allowed only after the real product is
   recognizable.

## Phase 1 — Signature mechanism (HARD GATE, loop until pass)

Invent an interactive or live-feeling hero mechanism built around Phase 0. Generative, not a
catalog. State: "The hero is a live [X] that does [Y] as you [Z]."

All five must pass:

1. **Product-truth:** shows the thing the user literally gets, sees, does, buys, or experiences.
2. **Non-transplant:** swapping logo/copy to another site makes it false.
3. **Live:** state, motion, interaction, reveal, comparison, or progression demonstrates the promise.
4. **Nameable:** concrete nouns and verbs, not "dynamic visual".
5. **Not generic hero:** not headline/buttons/blob/product-card.

## Phase 2 — Three divergent directions

Three renderings of the same signature mechanism, differing in register, not just color: visual
register, type system, color strategy (base environment, accent behavior, semantic roles, contrast,
sibling differentiation), layout grid, motion character, how the signature works in hero and body,
strengths/risks/failure modes. Recommend one; park for user choice on major work. The shared Option
Divergence Gate (SKILL.md) applies.

## Website color gate

State the palette logic:

> "The site uses [base environment] plus [accent behavior] to make [product mechanism] visible and
> to separate it from [sibling/category overlap]."

Pass requires:

- Colors derived from the product's real mechanism, material, state, or customer moment — not taste.
- Base theme and accent family differ from sibling brands on at least one obvious first-viewport axis.
- Modern calibration favors tinted neutrals, grounded earth/ink/clay/olive/brass/oxblood bases,
  dark-first systems where the product is serious/operator-grade, and vivid accents as
  state/proof/command signals.
- Default pale blue, generic SaaS blue, purple-blue gradients, beige/copper warmth, and arbitrary
  CTA colors rejected unless explicitly product-true.
- Every strong color has a job: CTA, command, proof, alert, local/private, editorial, material, state.
- Text/background contrast accessible; hero-scale type cannot compensate for weak body contrast.
- Accent use restrained enough to preserve attention hierarchy.

## Phase 3 — Differentiation guard (HARD GATE)

Read `references/portfolio-registry.md`. The candidate must differ from every sibling on ≥3 of the
5 axes: base theme, type category, accent family, layout grid, motion signature. Fail -> adjust and
re-run. After approval, update the registry row.

## Phase 4 — Build

Build the artifact structure the user asked for. Multiple requested options = standalone HTML files
per option plus an index linking all of them — never collapsed into one page with sections unless a
gallery was explicitly requested. **Build exemplar-first:** start each section from the nearest
exemplar in `components/_index.md` (retheme via tokens, rewrite copy in brand voice); the exemplars
carry the motion and accessibility floor so the build effort goes into brand identity and the
signature mechanism. Apply the audit-visual gates as build checklist items while constructing each
section. `references/design-reference-library.md` is taste calibration only — never a substitute
for site truth, signature, or differentiation.

## Phase 5 — QA block list

**Structure gate first (HARD GATE, deterministic).** Before any judgment QA, run the detector's
website-structure scan against the rendered page at both viewports:

```text
node D:/Claude/tools/skills/designer/engine/scripts/detect.mjs --json --viewport=1440x900 <url>
node D:/Claude/tools/skills/designer/engine/scripts/detect.mjs --json --tablet <url>
node D:/Claude/tools/skills/designer/engine/scripts/detect.mjs --json --mobile <url>
node D:/Claude/tools/skills/designer/engine/scripts/detect.mjs --json --site --site-type=<app|ecommerce|content> <homepage-url>
```

Any `structure` hit (`cta-below-fold`, `hero-cta-competition`, `headline-word-wall`,
`one-word-lines`, `hero-viewport-hog`, `hover-contrast`, `oversized-header`,
`broken-internal-link`, `missing-required-page`; advisory `missing-hero-media`) is a build
defect — fix and re-scan before proceeding. These are measured viewport geometry, not taste; do not rationalize
them. Thresholds and the hero contract: `../../audit-visual/references/website-conversion-standards.md`.
The same contract applies while building: primary CTA inside the first viewport on desktop AND
mobile, h1 ≤ ~10 words, one primary action, a visual anchor (or a deliberately defended type-only
hero), hero ≤ ~1 viewport.

Then run `/audit-visual` (it runs the impeccable detector as its scan stage). Block completion on:
design-law failures, generic AI tells, color-gate failures (default blue, one-note palette, low
contrast, trend-only palette, accents with no job), weak hierarchy, bad responsive behavior,
inaccessible contrast/focus/hit targets, missing loading/error/success states for interactive
pages, AI imagery with garbled text.

For redesign follow-ups, also apply
`../../audit-visual/references/website-regression-gotchas.md`. In particular: capture section
boundaries, audit dark/light cadence by viewport count, preserve one-to-one example semantics,
separate wide feature canvases from prose measure, and prove motion from rendered state changes.
