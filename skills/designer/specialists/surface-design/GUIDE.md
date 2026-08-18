---
name: designer-surface
description: "THE design/redesign skill for anything rendered in a browser or app window — new builds and redesigns alike. Use when creating, redesigning, or polishing: websites, landing pages, marketing/product pages, brand sites, portfolios, ecommerce front-of-house, content pages, AND product/application UI — desktop apps, SaaS dashboards, tools, editors, inboxes, queues, settings, forms, data tables, workflows, stateful screens. Replaces the retired /website and /app skills (their gates live at the designer skill root: designer/references/website.md and designer/references/app.md). Routes static creative (flyers/OG/banners/print) → /designer static, brand systems → /brand-identity, review-only → /audit-visual."
---

# Surface Design — websites and app UI

This guide owns designing and redesigning every rendered surface. "Redesign" includes fresh
designs — the name is the workflow, not a precondition.

## Step 0 — Mode gate (before anything else)

Declare **draft** or **ship** per the mode table in the designer `SKILL.md`. **Draft mode runs
only:** brand card + Phase 0 truth sentence -> exemplar-first build (Step "Phase 4" craft rules +
`../../references/components/`) with motion register declared inline from `../motion/GUIDE.md` -> detector structure scan
(Phase 5 structure gate commands) -> human eyes. Phases 0.5-3, the artifact files, motion-plan/gate
files, and the QA multi-gate are **ship-mode only**. Promoting an approved draft to production =
running the remaining spine on it. Everything below describes ship mode unless marked otherwise.

Route away first:

- Static creative (flyers, social posts, OG images, banners, print) -> `/designer static`
- Brand identity system (when none exists) -> `/brand-identity` first
- Review/critique of an existing surface with no build work -> `/audit-visual`
- Deep specialist passes and deliverables (PPTX decks, motion renders, voiceover, live in-browser
  variants) -> `/designer <command>` — this skill is the entry; impeccable is the engine room for
  `critique/polish/bolder/quieter/typeset/colorize/layout/delight/live/deck/motion/video/voiceover`.

## Step 1 — Classify the surface, load its reference

| Surface | Signals | Reference (MANDATORY read) |
|---|---|---|
| **Website** | landing page, marketing/product page, brand site, portfolio, ecommerce front-of-house, content page — design IS the product | `../../references/website.md` |
| **App UI** | dashboard, tool, editor, inbox, queue, settings, forms, data tables, workflows, repeated-use stateful screens — design SERVES the product | `../../references/app.md` |

Both files live at the designer skill root (`designer/references/`), not next to this guide.

An app is not a landing page: it must be fast to understand, efficient to repeat, state-complete,
and accessible without burying the work surface. A website's first viewport must reveal the
product/service reality, not an abstract value-prop hero. Misclassifying the surface fails the
audit later (lens 0), so classify out loud.

Brand-first: run `/brand <code>` for any branded venture surface before designing. If no brand
identity exists, run `/brand-identity` or do a lightweight brand-truth/signature pass first.

For per-brand operational material, also load (when the brand project starts):
- `Content/<brand>/copy/bible.md` — 30+ worked copy blocks in voice
- `Content/<brand>/design/tokens.json` — color / type / space / radius / breakpoints
- `Content/<brand>/anti-patterns.md` — 8+ brand-specific anti-patterns
- `Content/<brand>/patterns/above-the-fold/` — 5-8 above-the-fold patterns filtered for the brand
- `../../references/above-the-fold-patterns.md` — 15 cross-brand above-the-fold patterns
- `../../references/banned-words.md` — cross-brand banned vocabulary + detection
- `../../references/reference-capture-template.md` — DESIGN.md format for capturing competitor/aspirational references

Without these loaded, Phase 0 fails. Phase 0.5 (competitor analysis), Phase 0.6 (reference capture), and Phase 0.75 (page inventory) are the new hard gates that follow.

## Step 2 — The shared spine (both surfaces)

Both references share this state machine; the reference file defines each phase's surface-specific
tests.

| # | Phase | Mode |
|---|---|---|
| 0 | Truth sentence (brand/site truth · brand/task truth) + brand load (5 files) | auto **HARD GATE** |
| 0.5 | Competitor analysis | auto **HARD GATE** |
| 0.6 | Reference set capture (DESIGN.md format) | auto **HARD GATE** |
| 0.75 | Page inventory | auto **HARD GATE** |
| 1 | Signature (hero mechanism · workspace signature) | auto **HARD GATE** — loop until its five tests pass |
| 1.5 | Motion signature (loads `../motion/GUIDE.md`) | auto **HARD GATE** |
| 2 | Three divergent directions/registers | present, then **PARK** for user choice on major work |
| 2.5 | Option Divergence Gate | auto **HARD GATE** |
| 3 | Surface-specific guard (differentiation registry · IA/state model · SEO surface) | auto **HARD GATE** |
| 4 | Build (with continuous verification — runtime enforces) | auto |
| 5 | QA: multi-gate (5a audit-visual · 5b /seo · 5c judge [deferred] · 5d design-gate.mjs) | auto **HARD GATE** — fail -> fix -> re-run |
| 6 | Human eyes — approving human's taste gate | render screenshots, then **PARK** |
| 7 | Handoff (docs, tokens, registry row for websites) | auto |

### Phase 0 — Truth + brand load (HARD GATE)

State the truth sentence AND load the 5 per-brand files (see Step 1). Without the 5 files, Phase 0 fails. Generic truth sentences ("modern, premium, trustworthy") are an automatic fail.

### Phase 0.5 — Competitor analysis (HARD GATE)

Output: `artifacts/competitor-analysis.md`. Required content: 5 direct competitors (URL, what they do, what they don't), 3 aspirational references (from Phase 0.6 capture), 5 specific things we'll match (with proof), 3 specific things we'll surpass (the differentiators), 1 sentence: "Our surface will be remembered for [X] because [Y]."

### Phase 0.6 — Reference set capture (HARD GATE)

Output: `Content/<brand>/references/{competitors,aspirational}/`. Per-site, all 6 capture items per `../../references/reference-capture-template.md` (DESIGN.md format). Scope: 3 competitors + 2 aspirational per brand, captured once per brand, refreshed when site materially changes.

### Phase 0.75 — Page inventory (HARD GATE)

Output: `artifacts/page-inventory.md`. Every page in the build, with: URL, primary purpose, signature moment (if any), content blocks, primary CTA, supporting CTAs, states (loading/empty/error/success). 1-page builds: 1 page fully specified. Multi-page builds: 4-12 pages typical.

### Phase 1.5 — Motion signature (HARD GATE)

Output: `artifacts/motion-plan.md` only at this phase. **`motion-gate.json` may NOT be written here** —
its verdict requires prototype evidence (see Phase 4 inner loop). A gate self-graded before any
pixel renders is theater; that failure mode shipped a dead pin on 2026-07-17. Routing contract:
`docs/ARCHITECTURE-MOTION.md` §9.

### Phase 4 — the build inner loop (HARD, per section — this is where quality lives)

The 2026-07-17 orthiclabs post-mortem: every phase artifact existed, the build still came out flat,
because all the enforcement sat before and after the pixels. These four rules are the fix. Skipping
any of them is a defect, not a style choice.

1. **Exemplar code in context, verified.** Before writing a section, `Read` the actual exemplar
   file from `../../references/components/` — the catalog line in `_index.md` does NOT count.
   Record it in `artifacts/build-manifest.md`: `section → exemplar file read → what was kept /
   changed`. A section with no manifest row is unbuilt. The model that skips this ALWAYS believes
   it remembers the exemplar. It doesn't.
2. **Render every section before building the next.** One section built → screenshot it (qa-shot /
   preview) at desktop + mobile → one self-critique pass against the exemplar and the banned lists
   → revise → only then the next section. Build-everything-look-once is the single biggest source
   of AI-flat output. Evidence lands in `artifacts/qa/sections/`.
3. **Motion prototype gate.** The FIRST section built is the one carrying the motion anchor.
   Prove it in a rendered browser — pin-spacer exists, timeline scrubs, reduced-motion variant
   works — and only then write `artifacts/motion-gate.json` with the evidence noted. Dead motion
   discovered at Phase 5 means Phase 4 was skipped, not failed.
4. **Visual material is required, not optional.** Phase 0 must inventory the brand's real assets
   (product screenshots, renders, photography, marks) and the build must consume them or generate
   new ones through the image pipeline. A showpiece-register page with zero imagery is a defect
   unless the type-only choice is explicitly defended in `directions.md`.

**Fresh-context lane:** ship-mode Phase 4 runs at the START of a session or in a dedicated one —
a compact build brief (brand card, tokens, exemplar code, copy blocks, asset list) and nothing
else. Building at the tail of a long operational session measurably degrades generation quality.

### Phase 5 — Multi-gate QA (HARD GATE)

Four sub-gates, all must pass before Phase 6:

- **5a** — `/audit-visual` (impeccable detector incl. website-structure rules + 16 lenses + motion lens).
- **5b** — `/seo` technical audit (meta, schema, OG, sitemap, robots, semantic HTML, CWV).
- **5c** — Fresh-context judge agent (deferred; no-op in v1 — see `<local-path>` §11).
- **5d** — `tools/lib/design-gate.mjs` deterministic runner. Verifies motion-plan.md + motion-gate.json exist and pass, runs 14 deterministic checks, outputs `artifacts/qa/gate.json` with motion + design-system results aggregated into one top-level verdict.

`verdict: pass` requires every check green or explicitly waived with reason. `fail` requires fix + re-run.

**Continuous verification during Phase 4** is owned by the Phase 4 inner loop above — "runtime
enforces" previously meant nobody enforced it. The per-section pass runs at desktop + mobile only —
two viewports do NOT subsume five, so the full 5-breakpoint screenshot sweep still runs ONCE here at
Phase 5, over the assembled surface. Axe-core, banned-words/anti-pattern greps, em-dash detection,
and bundle-size deltas run inside the same per-section pass.

**Option Divergence Gate (shared, phase 2.5).** When multiple directions/registers are presented
for ONE surface, each must diverge from the OTHERS on **≥3 of 5 axes** (base theme, type category,
accent family, layout grid, motion signature), including — mandatory — a **distinct base
environment** AND a **distinct accent family**. Two options sharing a palette that differ only in
typeface or density are one option with a font swap: automatic fail, rework and re-run. Run the
surface's color gate independently per option; never reuse one palette across options.

**Color gate (shared logic; surface variants in the references).** Before styling, state the
palette logic in one sentence: base environment + accent behavior + what it makes visible + what
separates it from siblings/category. Every strong color has a job (CTA, command, proof, alert,
state, selection); color is never the only indicator of state; all text/control states meet
accessible contrast. Default pale blue, generic SaaS blue, purple-blue gradients, and mood-only
palettes are rejected unless product-truth demands them.

**QA gate (phase 5).** Run `/audit-visual` — its lenses, floors, coverage matrix, and detector scan
are canonical; do not restate them. Route pixel evidence through the qa-engine (project `qa:browser`
contract, `lib/qa-engine/qa-shot.mjs`, `lib/qa-engine/qa-functional.mjs`); never foreground desktop screenshots for routine QA.
Pass surface context to the audit: website = first-impression + conversion weighting; app =
repeated-use weighting (action count, keyboard/focus, state completeness over drama).

**Human eyes (phase 6).** The approving human approves with their eyes before final. Open what they should review
via `node tools/lib/open-for-review.mjs <path>`.

## Craft rules (absorbed from Anthropic's frontend-design — apply while building)

- **Exemplar-first generation (both modes).** Build each marketing-surface section by adapting the
  nearest exemplar in `../../references/components/` (see `_index.md` for the catalog + token
  contract): retheme through tokens, rewrite all copy in brand voice, restructure freely, keep the
  motion values and accessibility guards. Synthesize from scratch only when no exemplar is
  structurally close — and consider adding the result back to the library afterward. A model
  remixing strong components inherits their quality floor; a model synthesizing from constraint
  lists inherits the generic default.
- **Ground it in the subject.** Pin one concrete subject, its audience, and the page's single job
  before designing; state your choice. The subject's own world — its materials, instruments,
  vernacular — is where distinctive choices come from.
- **The hero is a thesis.** Open with the most characteristic thing in the subject's world in
  whatever form makes sense (headline, image, animation, live demo, interactive moment).
- **Typography carries the personality.** Pair display and body deliberately on a contrast axis
  (serif+sans, geometric+humanist), never two similar-but-not-identical families; set a real type
  scale. Make the type treatment memorable, not a neutral delivery vehicle.
- **Structure is information.** Numbering, eyebrows, dividers, labels must encode something true
  about the content, not decorate it. Numbered markers only when the content actually IS a sequence.
- **Spend your boldness in one place.** The signature element is the one memorable thing;
  everything around it stays quiet and disciplined. Chanel: before leaving the house, remove one
  accessory. Not taking a risk is also a risk — one real aesthetic risk you can justify.
- **Work in two passes.** First a compact plan: palette as 4-6 named hex values, 2+ type roles, a
  layout concept (one-sentence prose + ASCII wireframe), the signature. Then CRITIQUE the plan
  against the brief before building: any part that reads like the generic default you'd produce
  for any similar brief gets revised — say what changed and why. Only then write code, deriving
  every color/type decision from the revised plan.
- **Match complexity to the vision.** Maximalist directions need elaborate execution; minimal
  directions need precision in spacing, type, and detail.
- **Copy is design material.** Words exist to make the design easier to understand. Write from the
  user's side of the screen (what people control, not how the system is built). Active voice; a
  control says exactly what happens ("Save changes", not "Submit"); the same action keeps the same
  name through the flow. Errors explain what went wrong and how to fix it — never apologize, never
  vague. An empty state is an invitation to act. Sentence case, plain verbs, no filler.
- **Quality floor, unannounced:** responsive down to mobile, visible keyboard focus, reduced
  motion respected.
- **CSS discipline:** mind selector specificity (type-based vs element-based rules cancelling
  each other's spacing); test heading copy at every breakpoint — the viewport is part of the design.
- Anti-slop is canonical in `skills/audit-visual/references/design-slop.md` (absolute bans, the three
  AI-look clusters, category-reflex check) — design against it, don't rediscover it at QA.
- Motion bar is canonical in `skills/audit-visual/references/motion-standards.md` (frequency table,
  easing/duration values, physicality) — build motion to it, don't wait for review to learn it.
- Native app feedback is canonical in `skills/audit-visual/references/native-feedback.md` (haptic
  semantics, 0.1s/1s/10s response budgets, per-platform target minimums, per-OS reduced-motion
  APIs, Fluent 2 + Material 3 tokens, SwiftUI spring defaults) — for any desktop or mobile app
  surface, build to it. `motion-standards.md` is the **web** bar; it does not cover haptics or
  native OS motion settings.
- **Motion craft → `../motion/GUIDE.md`. Motion review → `skills/audit-visual/references/motion-standards.md`.** Contract: `docs/ARCHITECTURE-MOTION.md` §9.

## Completion checklist

- Surface classified; its reference read; brand loaded or brand-truth pass done.
- Truth sentence exists. Signature passes its five tests.
- Three directions/registers explored for major work; divergence gate passed; user picked.
- Surface guard passed (registry diff for websites; IA/state model for apps).
- Built with the craft rules; all states designed (apps: the hard-stop state list in `../../references/app.md`).
- `/audit-visual` passed with pixel evidence via the qa-engine.
- Human eyes approved. Registry/docs updated (websites: `../../references/portfolio-registry.md`).
