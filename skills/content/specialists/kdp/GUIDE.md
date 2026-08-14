---
name: content-kdp
description: Use when working on Kindle Direct Publishing, Amazon KDP, Etsy/KDP books, coloring books, journals, kids mythology books, book validation, manuscripts, covers, listings, keywords, categories, A+ content, print QA, or A Modern Yogi publishing work.
---

# KDP

Bundled workflow for Adrian's KDP/Etsy publishing lane: brainstorm the book, validate the market, write or review the manuscript, enforce brand voice, prepare listing copy, and check KDP production risk.

## First Choice

Before acting, identify the work type and read only the matching references:

| Work type | Read |
|---|---|
| KDP strategy, book idea, product choice | `references/research-validation.md`, then `references/workflows.md` |
| A Modern Yogi voice, yoga/mythology/kids books | `references/a-modern-yogi-brand.md` |
| Manuscript review, story coherence, image placeholders | `references/manuscript-and-art-qa.md` |
| Amazon listing, title, subtitle, description, keywords | `references/listing-copy.md` |
| Trim, margins, bleed, AI disclosure, low-content, upload QA | `references/kdp-official-requirements.md` |
| Interior image/PDF readiness, cover readiness, KDP upload gate | `references/kdp-official-requirements.md`, then `references/workflows.md` |
| Full build from idea to upload | all references, in the workflow order below |

## Operating Rules

1. For new KDP/Etsy products, validate before production. Do not write/generate/render first and justify later. Hard gate: before ANY KDP/Etsy book work — generation, manuscript, cover, listing copy, or PDF conversion — `/product-validation` must pass first.
2. For mythology, yoga, religion, health, policy, pricing, or KDP rules, use current official/reliable sources. KDP rules change.
3. Build manuscript-first: page map, story spine, reader text, art specs, review, then image/PDF production.
4. Treat Adrian as final owner of taste, but do not dump preventable review work on him. The skill should catch mechanical, cultural, policy, and quality issues first.
5. Never fabricate quotes, scripture, statistics, testimonials, or cultural backstory.
6. Do not recommend generic AI slop, recycled content, pet portraits, or low-originality repost channels.

## Full Workflow

1. **Frame:** audience, use case, format, promise, series role.
2. **Research:** Amazon/Etsy demand, competitors, review gaps, format norms, policy risks, and `PRODUCT-VALIDATION.md`.
3. **Concept:** title, subtitle, reader promise, table/page map, differentiation.
4. **Manuscript:** complete reader-facing pages plus separate production notes.
5. **Art specs:** one valid art brief per image/page; no text in generated art unless explicitly intended.
6. **Review:** run manuscript/art QA and, when Adrian explicitly requests an external panel, `/covenant` with the correct non-code rubric.
7. **Listing:** title/subtitle, description, 7 keyword slots, 3 categories, age/grade, A+ content plan.
8. **Production:** image actuals gate, interior PDF gate, cover gate, barcode, spine, PDF preview, proof copy.
9. **Launch:** stagger risky releases, disclose AI content in KDP, order proof before pushing live.

## Required Outputs

Use the smallest useful output. For reviews, lead with:

```markdown
Verdict: READY / NEEDS FIX / DO NOT PRODUCE
Blockers:
- [Page/file] concrete issue and why it blocks production.
Recommended:
- [Page/file] useful fix that does not block production.
Adrian decisions:
- Taste/cultural/positioning calls only Adrian can own.
Checked:
- Mechanical checks performed.
```

For production reviews, do not collapse the gates. State them separately:

```markdown
Interior images: READY / NEEDS FIX
Interior PDF: READY / NEEDS FIX / NOT BUILT
Cover: READY / NEEDS FIX / NOT BUILT
KDP upload: READY / NEEDS FIX
```

Only call a product "KDP-ready" when the interior PDF, full wrap cover, metadata/listing, AI disclosure path, and proof-preview checks are all accounted for. A set of page PNGs can be "PDF-layout ready" without being "KDP-ready."

For new products, save a one-page validation memo named `PRODUCT-VALIDATION.md` in the book folder before production.

## Common Failure Modes

- Treating an outline as a validated product.
- Building art before the manuscript is locked.
- Letting layout scaffolding leak into reader files.
- Using hard scriptural certainty where traditions vary.
- Calling AI images "hand drawn."
- Forgetting KDP AI disclosure.
- Adding spine text to books under 80 pages.
- Calling low-resolution or mixed-size page PNGs print-ready.
- Missing the actual pixel-size gate: images must be at least 300 DPI at trim size, uniform dimensions, flattened RGB, and consistent with the chosen bleed/no-bleed canvas before PDF layout.
- Treating a KDP paperback inside front cover as a normal printable color-reference surface.
- Adding one color page to a black-and-white interior without warning that the whole interior must use the chosen color/ink option and pricing.
- Calling a book KDP-ready before the full back+spine+front cover is built from the final page count and KDP cover template/calculator.
- For story + coloring books, placing story text on top of coloring art or shrinking a promised full-page coloring section into a story-page inset.
- Ignoring physical spread logic. In KDP paperbacks, even pages are left-hand pages and odd pages are right-hand pages.
- Verifying that text renders without verifying that the page is designed: text overflowing decorative frames, jammed at the page top with dead space below, colliding with frame art, or pasted at hardcoded pixel coordinates that drift the moment the art changes.
- Reviewing text-bearing pages from contact-sheet thumbnails, where text-art collisions and overflow are invisible. Hybrid text+art pages must be reviewed at full size.
- Using a cold system serif or a cursive/decorative font for kids 4-8 body text instead of a rounded high-x-height literacy font; putting handwritten styling anywhere but headings/accents.
- Reusing/recycling pages until the book feels low-content-coded.
- Writing keyword-stuffed Amazon descriptions instead of simple, compelling, professional copy.
- **Kids line — title-deity-alone-teaching.** Generating manuscripts where the title-deity teaches abstract lessons on most spreads (big ears teach listening, trunk teaches flexibility, mouse teaches small-helps, etc.), producing 8-12 nearly-identical coloring pages of the same character in slightly different poses. Failure mode for character-thin books. Fix: mine the canon for mythological side-characters and tell story-beats where they appear. See `references/a-modern-yogi-brand.md` § "Story canon mining" for per-book side-character lists.
- **Kids line — activity pages in a coloring book.** Match-the-symbols, count-the-objects, framed "draw your X" reflection prompts, symbol mandala coloring, symbol icon sheet coloring. These read as KDP filler, break the coloring + story rhythm, and give kids nothing varied to color. Forbidden in this series. The grown-ups note is the only allowed framed-content page.
- **Kids line — coloring page redundancy.** Two coloring pages that share the same subject, composition, or focal cluster (e.g. a symbol mandala AND a symbol icon sheet, two pages of the title-deity seated in slightly different poses). Drop one; replace with a different character-driven scene from the canon.
