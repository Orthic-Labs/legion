# Parametric Design Contract (shared reference)

Canonical distillation of parametric-design research (2026-07) for every skill that produces
a designed or written artifact. Loaded on demand by skill
routers; do not inline this whole file into prompts — apply the contract.

## What parametric design is (one paragraph)

Design expressed as explicit parameters, constraints, and relationships instead of one-shot
prose-to-artifact generation. The design intent lives in a named parameter vector; changing a
parameter regenerates the artifact; revisions are mutations of the vector, not fresh redesigns.
Research through 2026 is consistent: the LLM default (one-shot generation from a vibes brief)
collapses to the median — hero + 3 cards + pastel gradient + Inter, or the equivalent median in
copy. Parameters, variant search, and a separate critic are what move the ceiling.

## The contract (apply to every generated artifact)

1. **Parametrize before generating.** Convert the brief into an explicit parameter vector and
   show it. No free-prose → final artifact. If the brief is ambiguous on a high-impact axis,
   ask once or state the assumption in the vector.
2. **Separate hard constraints from soft preferences.** Hard = brand tokens, palette, fonts,
   accessibility floors (contrast, focus, body size), banned vocabulary, legal/claim rules —
   violations reject the candidate. Soft = tone, density, risk — violations score down.
   The consuming project's own brand rules source is always a hard constraint.
3. **Generate variants, not a single answer.** For anything non-trivial, produce k ≥ 3
   candidates that differ on at least 2 named high-impact axes (e.g. density × hero pattern,
   or tone × structure). Sweep axes deliberately; do not generate 3 near-duplicates.
4. **Critique separately from generation.** Score candidates against the vector with a
   distinct critic pass (different prompt/lens, ideally different model tier). Demand specific,
   actionable findings; cap refine loops at 2–4; never let the generator certify itself.
5. **Penalize the default region.** Every space has a known "LLM starter kit" cluster — see
   the fingerprints below. Nearness to it is a scored defect even when the artifact is clean.
6. **Record the vector.** State the winning parameter vector with the deliverable. A later
   "make it bolder" is a mutation (`cta_aggression ↑`, `copy_tone → bold`), not a redesign.
   Human override ("I just like this one") is allowed and logged as such.

## Parameter axes by domain

Every space covers four categories: **formal** (structure/look), **performance** (hard quality
bars), **semantic** (tone/brand/risk), **context** (audience/viewport/locale).

| Domain | Example axes |
|---|---|
| Landing page / site | hero_pattern (split/centered/product_frame/editorial), section_count, visual_density 0–1, cta_aggression 0–1, social_proof_weight, copy_tone, palette, brand_axis weights, a11y target, seo_intent |
| App UI / dashboard | layout_grid, visual_density, info_density, chrome_complexity, typography_style, motion (none/subtle/expressive), interaction_risk, a11y target |
| Static creative / social graphic | composition (grid/asymmetric/full-bleed), text_weight 0–1, palette discipline, brand-mark prominence, risk level |
| Prose / copy | tone axis (clinical↔bold↔witty↔plain), sentence-length distribution, structure (narrative/listicle/essay), evidence density, reading grade, hook style, CTA strength |
| Social content | platform, format, hook type, pacing, caption length, hashtag strategy, risk/experiment level |
| SEO content | search intent (brand/commercial/educational), entity density, E-E-A-T level, SERP risk, passage citability |
| Campaign / marketing plan | channel mix, budget split, message risk, proof type, funnel stage weighting |

Rule of thumb: if a domain produces artifacts more than twice a month, it deserves a named
axis list in the owning skill — not a fresh ad-hoc brief each time.

## Default-region fingerprints (penalize proximity)

- **Web/UI:** centered hero + 3 feature cards + testimonial strip + gradient blob; Inter/12-col
  everything; purple-to-blue gradient; glassmorphism on white; identical border-radius on all.
- **Copy:** "In today's fast-paced world…" openers, rule-of-three benefit lists, "Unlock/
  Elevate/Transform" CTAs, em-dash-heavy punchlines (see anti-slop.md for the full list).
- **Social:** hook–value–CTA template applied identically across platforms, emoji-bullet
  captions, engagement-bait questions.
- **SEO:** H2-per-keyword scaffolds, definition-paragraph-then-list for every section, FAQ
  blocks with restated headings.

## Phase tagging (divergent vs convergent)

State the phase before generating. **Divergent** = list 5–10 directions before evaluating,
no favorites yet, spread across axes. **Convergent** = hard filters first, score survivors on
the rubric, pick top 1–3 with reasons. Research finding: AI injected in the wrong phase
reduces creativity (fixation); the phase tag is the cheap fix.

## Scope limit

This contract is workflow discipline, not a runtime. The full PDS (pd_* tools, design-record
DB, novelty embeddings) is a separate build decision; nothing in this file requires it. Skills
apply the contract with judgment, in-session.
