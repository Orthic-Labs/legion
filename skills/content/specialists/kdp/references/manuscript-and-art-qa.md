# Manuscript And Art QA

Use for reader-clean manuscript review, story coherence, page maps, art specs, image placeholders, and pre-render checks.

## Review Output

```markdown
Verdict: READY / NEEDS FIX / DO NOT PRODUCE
Blockers:
- [Page X] issue, evidence, required fix.
Recommended:
- [Page X] improvement and rationale.
Adrian decisions:
- Taste/cultural/positioning calls only Adrian can own.
Checked:
- pages, art briefs, placeholders, banned words, KDP risks, cultural notes
```

## Mechanical Checks

- Count pages and confirm expected page count.
- Confirm one valid art brief/spec for every art/coloring/image page.
- Confirm no `TODO`, `TBD`, `FIXME`, stale placeholders, or internal scaffolding in reader-facing text.
- Confirm page map, production notes, reader file, and listing do not contradict each other.
- Confirm title, subtitle, author/imprint, series, age, trim, and page count are consistent.
- Confirm bracketed placeholders are intentional layout objects, not leaked instructions.

## Rendered Image Actuals Checks

When final page images exist, inspect the files themselves before giving a production verdict:

- Count image files and confirm they match the page map.
- Confirm all page images share one exact pixel size.
- Confirm pixel dimensions support at least 300 DPI at the chosen trim and bleed size. For 8.5 x 11 in no bleed, the target is 2550 x 3300 px.
- Confirm image mode is consistent and flattened for PDF assembly, normally RGB with no transparency.
- Confirm artwork stays inside the live-area margins for the final page count.
- Confirm there are no black trim-edge artifacts, visible generation frames, unwanted borders, watermarks, or crop marks.
- Confirm text-bearing pages have legible text and no fake scripts unless the page intentionally uses non-reader decorative marks.
- For story + coloring spread books, confirm story text is not placed on top of coloring art and coloring pages are not shrunk into story-page insets unless that was explicitly approved.
- Confirm the physical spread model is clear: KDP paperback facing spreads are even page on the left and odd page on the right.
- Run a page-by-page brief diff: required subject, props, placement, activity text, exclusions, and cultural/iconographic essentials.

Do not mark rendered images "READY FOR LAYOUT" from a visual contact sheet alone. Contact sheets are useful for taste review but can hide low resolution, mixed dimensions, color mode problems, and brief regressions.

## Layout & Typesetting Checks

The single biggest review hole: verifying that text *renders* without verifying that the page is *designed*. A page can render with no error and still be unshippable. For every page where text coexists with art (titles, framed notes, activities, hero+text pages), inspect at FULL SIZE — text-art collisions are invisible at contact-sheet thumbnail scale.

- **Text stays inside the safe zone.** Text must never overflow a decorative frame border or collide with frame decorations (corner motifs, top/bottom art). If the page has a baked-in frame, the text box must fit *inside* the frame interior with padding.
- **Text is composed, not jammed.** Short text blocks (blessings, notes, headings) must be centered or balanced within their zone — not pinned to the page top with dead white space below. The page should read as designed, not as text pasted at a hardcoded coordinate.
- **Activity pages must be doable as printed.** On match/draw/write activities, answer text must render *inside* its box, connector dots must align to their cells, drawing areas must stay clear. If the activity cannot be completed as laid out, it is a blocker. Prefer deterministic builder-drawn activity layouts over text pasted onto baked-in activity art.
- **Font fits the audience.** For kids 4-8: body text in a rounded, high-x-height literacy font with single-story a/g (e.g. Andika) — not a cold system serif, not a cursive or decorative font. Handwritten styling belongs on headings/accents only. Confirm fonts are embedded/embeddable for KDP.
- **No stray edge artifacts.** Check for small isolated strokes, dashes, or generation marks near page margins in the line art — common AI-generation debris, easy to miss, looks like garbage on a printed coloring page.
- **Interior matches the cover.** Title page, author line, and imprint on the interior must match the final cover (e.g. do not leave "By [name]" on the interior title page if the cover dropped it).
- **Raster text is positioned by content, not coordinates.** If text is rasterized into page images, it must be placed by content-aware safe-zone detection — never hardcoded pixel boxes that drift the moment the art changes.

### Text-only / blank-source framed pages — safe-margin trap (learned 2026-05-16)

The single biggest pre-upload margin trap on text-bearing pages: framed-text pages (notes, activities, write/draw prompts) where the source art is a **blank or near-blank placeholder PNG with no decorative frame baked in**. Content-aware composers like `largest_empty_rect` return nearly the full page when given a blank source, so text lands wherever the default `inset + pad` happens to fall. With the v3 32pp Krishna build, default `inset=54` + `pad=40` placed text at ~94 px from page edge — **INSIDE KDP's 120 px (0.4") no-bleed safe margin**. KDP preflight catches this as "image outside margins" on framed_activity pages (because the builder draws a draw-box + write-lines, which read as image). On pure text-framed pages KDP does NOT flag it — but the text visibly hugs the dashed safe-margin guide in Print Previewer, which is the human-eye signal you missed it.

**Pre-upload margin checks (run BEFORE clicking upload on KDP):**

1. **Measure where text actually starts.** For every framed/activity page, open the rendered PNG at full size and measure the pixel distance from the page edge to the first glyph of the leftmost line. At 300 DPI, the minimum is 120 px (0.4") from edge for outside margin; the comfortable target is 150–170 px (0.5–0.57"). Anything under 120 px is a blocker.
2. **Inspect the safe-margin guide in KDP Print Previewer page-by-page.** Don't trust contact sheets. Open the Previewer, page through every framed/activity/note page, and confirm the text block sits clearly INSIDE the dashed safe-area guide on all four sides — not touching it, not overlapping it. KDP only blocks upload when an *image* crosses the margin; text crossings ship silently.
3. **Look for the blank-source case specifically.** If the source PNG for a framed page has no visible decorative frame (the dashed guides in Previewer are KDP's safe-area, NOT a printed frame), the composer was working off a near-white canvas and the text inset will be at its default. Patch the composer to detect blank source (≥99.5% near-white pixels) and widen the inset to ≥130 px before re-rendering.
4. **Pure text pages (`compose_story_text`) are safer** because they hardcode a large outer margin (e.g. 320 px). The trap is specifically framed/activity composers that derive their text zone from `largest_empty_rect`.
5. **Apply this check whenever the builder switches between art-on-page and text-on-blank.** Mixing a content-aware composer with a blank source is the pattern to watch for. If the manuscript declares a page as `framed` / `framed_activity` but the rendered art file is a placeholder, the composer will quietly drop text into the bleed-adjacent zone.

If a margin issue is caught after the PDF is built, fix the builder (not just the manifest) so the bug doesn't return on the next title in the series.

## Story Checks

- One clear spine: beginning, progression, payoff.
- Each page has a job: story, character-driven coloring, parent note, or closing.
- No abrupt jumps without a bridge.
- No filler pages that exist only to hit page count.
- Read-aloud cadence works for the target age.
- Emotional promise returns in the closing.

## Coloring-book-first structural gate (kids line — locked 2026-05-16)

For any A Modern Yogi kids title (or any KDP coloring book + story hybrid), these are SHIP-BLOCKING checks before image generation begins. Catching this after Codex has generated 17 lame raw images costs days of rework.

- **Story + coloring lockstep.** Every story page is paired with a coloring page that depicts that story's content. Story on page N; coloring on N+1 (or N-1). No exceptions. If a story spread has no companion coloring page, the spread is doing two jobs the book pays for separately — split it.
- **Distinct visual per coloring page.** Every coloring page must depict a different character-driven scene. If two coloring pages share the same subject, composition, or focal cluster — drop one. A symbol mandala and a symbol icon sheet are the same page twice; both go.
- **Character ecology mined from the canon.** Title-deity-alone-teaching on 60-80% of spreads is the failure mode. Before drafting, list every mythological side-character that could appear in the book and pick the strongest 4-8. A Ganesha book without Kartikeya, Vyasa, and Parvati is character-thin. A Lakshmi book without Brahma, the hamsa swan, and the humble-home characters is character-thin. Mine first; draft second.
- **No activity pages.** Banned page types: match-the-symbols, count-the-objects, framed "draw your X" reflection prompts with builder-drawn boxes and lines, symbol mandalas, symbol icon sheets. These are KDP filler. The grown-ups note is the only allowed framed-content page.
- **One symbol cluster icon is OK at title or closing.** A full-page symbol-only coloring is not.
- **Page count follows content.** Don't pad to hit 40pp. Don't crush to fit 32pp. Krishna shipped at 32. Ganesha new at 34. Hanuman new at 32. Rama new at 32. Lakshmi new at 30. All driven by the story arc.
- **The coloring page is the marketing.** Back-cover thumbnails are pulled from interior coloring pages. The strongest 3 character-driven scenes go on the back cover. If a book has no 3 strong character coloring pages, it has no back cover.

If any of these fail, fix the manuscript BEFORE Codex generates images. Image regen is expensive in time and money; manuscript regen is cheap.

## Antagonist + feelings-first checks (kids line)

- **Antagonists must be framed with complexity.** No "demon," no "bad guy," no faceless villain. Reference framework in `~/.claude/projects/D--Claude/memory/ravana_kids_complexity_2026_05_16.md`. The line is: "Even a clever/learned person can choose a path that hurts."
- **Hard emotional moments must use feelings-first language.** Name the feeling explicitly, validate it, acknowledge adult repair. Reference framework in `~/.claude/projects/D--Claude/memory/kids_line_parenting_psych_feelings_first.md`. Required wherever a story touches grief, fear, hurt, exclusion, social violence (being laughed at), or loss.

## Cultural / Religious Checks

- Use hedges where traditions vary.
- Do not fabricate direct quotes, scripture, or canonical certainty.
- Do not overstate "the meaning" when a symbol has many readings. Prefer "can remind us" or "a traditional meaning."
- Kids books must remove or soften gore, severed heads, explicit battle violence, sexual imagery, and weapon glamour.
- Art specs should include iconographic essentials and prohibit wrong motifs.
- No fake Sanskrit, fake Devanagari, pseudo-script, or unreadable sacred text.

## Art Brief Checks

Each art brief should specify:

- focal subject
- supporting props
- composition/placement
- mood/expression
- age/complexity level
- white space or detail density
- exclusions: no text, no fake script, no gore, no clutter, no tiny patterns, no gray shading for coloring pages

For kids coloring pages:

- thick bold lines
- large colorable shapes
- friendly faces
- simple backgrounds
- no dense ornamental overload

For adult coloring pages:

- print-safe line weight
- rich detail without hairline fragility
- coherent cultural/artistic frame

## Banned / Risky Tells

Flag:

- "ancient wisdom" without a concrete teaching
- "manifest abundance" register
- fake certainty
- hollow inspirational cadence
- repeated "not just X but Y" patterns
- excessive em dashes
- AI-ish recap loops
- "hand-drawn" for generated art
- **Kids-line story pages — literary/contemplative register instead of dialogic.** *"More than a boy in a story — a small piece of the big love that holds the whole world together"* register loses 3-7 year olds. Story pages must use the dialogic-reading principles in `/content kdp` `references/a-modern-yogi-brand.md` Kids Line Voice (interactive prompts, repetition, dramatic emphasis, call-and-response, shared-laughter beats). Contemplative phrasings belong on parent-facing pages only (grown-ups note, closing blessing, back-matter) — never on story pages. Locked 2026-05-15.

## KDP Readiness

Do not call a manuscript ready for render until:

- reader copy is clean
- production notes list open decisions
- image specs are valid
- review blockers are fixed
- KDP official constraints are checked for the target format

Do not call rendered pages PDF-layout ready until:

- image actuals pass the rendered checks above
- the print target is named, including trim, bleed/no-bleed, paper/ink assumption, and page count
- any remaining brief deviations are explicitly accepted or fixed

Do not call the book KDP-ready until:

- the interior PDF exists and passes KDP page/margin/font/image checks
- the full exterior cover exists as one back+spine+front file, sized from the final page count and KDP cover template/calculator
- cover title/subtitle/author match metadata
- spine text is omitted when the page count is under KDP's spine-text threshold
- barcode safe zone is clear if KDP auto-barcode is used
- color guidance strategy is resolved without accidentally changing B&W interior pricing
- AI disclosure path, listing metadata, and proof-copy/preview checks are accounted for

## Escalation

Use `/covenant` when Adrian explicitly requests a multi-model second opinion:

- brand or reader voice: `brand-voice`
- launch/package readiness: `launch`
- policy, cultural, medical, AI, platform risk: `compliance-risk`
- cover/interior visual assets: `image`

Do not use code/architecture rubrics for manuscripts.
