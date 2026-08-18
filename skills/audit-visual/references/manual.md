# Audit-Visual — Strict Rendered Frontend/UI Audit

MODE: DIAGNOSE
PRIMARY_DELIVERABLE: Bounded rendered-surface findings for exact granted routes, screens, or assets.
DISCOVERY_PROFILE: D1_SCOPED_SOURCE
EFFECT_PROFILES: asset_read
SPECIALIST_REFS_MAX: 0
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Rendered findings meet frozen review criteria.

`audit-visual` is the canonical review gate for **rendered frontend reality** and **motion craft**.
Do not route frontend critique, visual QA, rendered UI polish, design-law review, animation review,
or "this page feels off" work to a separate skill.

The job is not to be nice. The job is to determine whether the rendered surface works, reads, feels
intentional, and deserves to ship.

## Scope

Use this for:

- Website, landing page, blog page, ecommerce, checkout, and pricing-page review.
- App, dashboard, desktop UI, Tauri frontend, SaaS workflow, settings, table/list, editor, and component review.
- Screenshot-based regression checks after UI changes.
- Animation/motion review — rendered motion AND motion code (the review-animations fold; bar in `references/motion-standards.md`).
- "Feels off", "too generic", "make it sharper", "is this good?", or "does this ship?" frontend questions.
- External vision-model review over screenshots when the pixels need a second set of eyes.

Do not use this to create a new UI from scratch:

- New or redesigned website / app UI -> `/designer`
- Static creative -> `/designer static`
- Brand identity system -> `/brand-identity`
- Code/repo health/security/performance audit -> `/audit`

**Source-hygiene boundary (websites).** Code slop, bloat, duplication, and dead code in a
repo-backed site belong to `/audit` (its `ai-slop`/`dead-file` lenses with jscpd/knip/lint) — run
it alongside this skill, don't duplicate it here. For a standalone HTML artifact with no repo
(designer one-pagers), this skill DOES own a light source pass: run the detector in static file
mode on the artifact, and flag obvious hygiene defects as findings — dead/unreferenced CSS and JS
blocks, copy-pasted duplicated sections, unminified megabyte inline blobs, leftover commented-out
markup, unused font/library loads. Cite file+line. This is a hygiene sweep, not a substitute for
`/audit` on real repos.

## Thesis

Interface quality is:

```text
(task clarity x visual precision x state completeness) + craft - slop
```

A beautiful screen fails if users cannot decide what to do. A logical flow fails if hierarchy,
spacing, typography, color, motion, or states make it feel broken. Every finding must connect the
visible UI issue to the user consequence.

## Why scan → inventory → reason (the anti-miss architecture)

A holistic eyeball of a screenshot reports what jumps out and misses the rest — that is the failure
mode this skill exists to kill. Same hybrid as `/audit`: deterministic scanners produce facts, a
forced inventory fixes the coverage denominator, and only then do the reasoning lenses judge — every
region gets a verdict or an explicit "untested", never a silent skip.

| Stage | What runs |
|---|---|
| 0 · Anchor | Brand card / brief / PRODUCT.md-DESIGN.md if present — what SHOULD this look like? |
| 1 · Capture | Pixels per the capture protocol (viewports, states, dark mode, full-page + region crops) |
| 2 · Scan (deterministic) | Designer engine detector · axe (app runtime pass) · computed-style probes |
| 3 · Inventory | Region list + interactive-element inventory — the coverage denominator, written BEFORE judging |
| 4 · Reason | The 16 lenses over every region; region × lens coverage matrix |
| 5 · States | Interaction-state matrix over the element inventory |
| 6 · Vision jury | External lane when warranted |
| 7 · Verdict | Dedupe → severity → floors → scores → SHIP/REVISE/DON'T-SHIP |

## Stage 0 — Anchor: review against intent, not taste alone

Before judging, load what the surface is SUPPOSED to be, in priority order: the brand card
(`/brand <code>` tokens — accent, bg, type), a `PRODUCT.md`/`DESIGN.md` (impeccable projects), a
`.design/<feature>/DESIGN_BRIEF.md`, or the user's stated expectation. Findings that contradict the
anchor cite it ("brief says X, render shows Y"). No anchor available → judge by surface class +
craft bar and say so.

## Non-Negotiable Evidence Gate

A visual audit must inspect pixels. Text-only descriptions, design specs, DOM summaries, remembered
layouts, or "faithful descriptions" are not visual QA.

Before giving a visual verdict, obtain one of:

- User-provided screenshots/images.
- Screenshots from a live page/app/local route through the shared `/qa` skill.
- Generated renders/thumbnails of the artifact.
- Direct image/browser inspection through an available visual tool.

For interactive UI, inspect relevant states: default, hover, focus, pressed, active/selected,
disabled, loading, error, empty, expanded/open, and at least one real click/toggle/menu outcome
where the workflow depends on it.

If no pixels can be obtained, say:

> I cannot give a visual verdict without seeing pixels. I can only do a text/spec review.

Then label the output **Spec Review Only - Not Visual QA** and do not use Pass/Fail, SHIP, or
visual quality scores. (Exception: a pure motion-CODE review — findings against
`references/motion-standards.md` cite `file:line` instead of pixels and are labeled **Motion Code
Review**.)

## Stage 1 — Capture Protocol

For live/local websites, apps, dashboards, Tauri frontends, or rendered routes, use `/qa` for the
capture and interaction layer.

Default order:

1. Project `qa:browser` contract when present.
2. `qa-shot --url <url> --out <dir>` for app-viewport screenshots.
3. `qa-functional ...` for hover/click/type/key/assert evidence.
4. Built-in browser/image inspection fallback.
5. Native foreground screenshots only when the operator explicitly asks or native-window behavior is genuinely required.

Do not improvise foreground desktop capture for routine visual QA. Do not reach first for
Playwright, Puppeteer, raw CDP, or desktop screenshots when `/qa` is available. If a fallback is
used, state why.

Capture set:

- **Viewports:** website/landing → desktop 1440 + tablet 768 + mobile 390; desktop app → realistic
  window size (mobile only when relevant); ecommerce → listing/product/cart/checkout;
  stateful app → core workflow screens + key panels.
- **Dark mode:** when the surface supports theming, capture BOTH themes at the primary viewport —
  a simple inversion, hardcoded hexes that don't switch, or unadjusted shadows are findings. Identify
  whether the theme is driven by an **in-app toggle** or the **OS-level `prefers-color-scheme`** media
  query (common in Tauri/Electron/mobile): if OS-driven, toggle the OS/emulated theme to capture the
  real second theme — a hardcoded hex that ignores the OS setting is a finding an in-app-toggle-only
  capture would miss.
- **Full-page + region crops:** a full-page screenshot alone hides small defects — vision misses
  details at page zoom. For any surface taller than ~2 viewports or denser than a simple page,
  ALSO capture per-region crops (project `clip`/`selector` wrappers, or scroll-and-shoot) and
  inspect each crop at full resolution. The region list from Stage 3 is the crop list.
- **Throttling (required for Lens 12 to be valid).** A localhost capture on an unbottlenecked machine
  renders instantly and hides loading states, layout shifts, and input jank — so Lens 12 (performance
  perception) reports a false Pass. Before capturing initial-load and interaction states for the perf
  lens, apply standard throttling via `/qa`/CDP: **~Slow-4G (≈400 ms RTT) network + 4× CPU slowdown**.
  If throttling could not be applied, say so and mark Lens 12 **Undetermined**, not Pass.

**Native / cross-platform mobile capture (iOS/Android).** `qa-shot`/CDP drives Chrome and cannot see
native pixels. If the target is a native or RN/Flutter app in a Simulator/Emulator, capture statics
via the platform tools instead: iOS `xcrun simctl io booted screenshot <path>`; Android
`adb exec-out screencap -p > <path>`. Interaction states (Stage 5) then require native automation
(Appium/Detox or `adb shell input …`) — the `/qa` functional runner cannot drive native UI, so if it
is unavailable, capture what statics you can and mark the interaction matrix Undetermined for that
surface rather than claiming coverage.

## Stage 2 — Deterministic scan (before any judgment)

Run the machine checks first; their output feeds the lenses as facts. Same honesty rules as
`/audit`: an absent tool is `skipped` and named in the report — never silently treated as clean.

| Scanner | Command | Catches |
|---|---|---|
| Designer engine detector | `designer-detect --json <url\|file\|dir>` | ~20 slop/craft rules: `low-contrast`, `gray-on-color`, `gradient-text`, `side-tab`, `hero-eyebrow-chip`, `repeated-section-kickers`, `bounce-easing`, `layout-transition`, `line-length`, `cramped-padding`, `body-text-viewport-edge`, … (full map in `references/design-slop.md`) |
| Website-structure rules (in the detector, URL mode only) | `detect.mjs --json --viewport=1440x900 <url>`, `--tablet`, AND `--mobile` | measured conversion geometry: `cta-below-fold`, `hero-cta-competition`, `headline-word-wall`, `one-word-lines`, `missing-hero-media`, `hero-viewport-hog`, `hover-contrast`, `oversized-header` (thresholds + evidence base in `references/website-conversion-standards.md`) |
| Site sweep | `detect.mjs --json --site --site-type=<app\|ecommerce\|content> <url>` (run on the homepage) | `broken-internal-link` (every same-origin link must resolve) and `missing-required-page` (privacy, terms + per-type: pricing/downloads for app sites, returns/refunds/shipping/contact/about for ecommerce) |
| axe (apps) | already produced by `/audit`'s runtime pass (`runtime.json` → `findings[].a11y[]`) when auditing an app; cite it, don't re-run | WCAG 2 A/AA mechanical violations |
| computed-style probes | `qa-functional.mjs` `eval` actions | exact cursor/color/spacing/font values behind any claim the lenses need verified |

Rules:

- Run the detector on the live URL when a dev server exists (browser mode measures rendered
  contrast and structure geometry); on the source/HTML files otherwise. Record which mode ran.
  URL mode needs no puppeteer — it falls back to installed Chrome/Edge over raw CDP automatically.
- **Websites/landing pages: both URL scans (desktop + `--mobile`) are mandatory**, their JSON
  saved to the audit's evidence directory and cited in "Evidence inspected". Structure rules
  cannot be evaluated statically — without the URL scans they are UNTESTED and the coverage cap
  applies. A missing scan is never reported as clean.
- A detector hit is a confirmed finding with scanner evidence (cite rule id + snippet). A clean
  detector run clears ONLY the greppable tells — the judgment tells still need eyes.
- Screenshots are evidence, not the only oracle: verify any exact-value claim (contrast ratio,
  spacing, cursor) with a computed-style probe before stating it as fact.

## Stage 3 — Inventory before judgment (the coverage denominator)

**Enumerate first, judge second.** Two lists, written into the report before any finding:

1. **Region list.** Walk each captured screenshot top-to-bottom and name every distinct region —
   header/nav, hero, each content section, sidebars, footer, floating elements (FAB, toasts,
   banners, chat bubbles), overlays/modals/menus discovered via interaction. Per viewport when
   layouts differ. Number them (`R1..Rn`).
2. **Interactive-element inventory.** Every control visible or reachable: buttons, links, inputs,
   selects, toggles, tabs, menus, cards-that-click, drag handles. From the DOM
   (`qa-functional.mjs` can enumerate) or visually when only pixels exist. Number them (`E1..En`).

These lists ARE the audit's denominator: Stage 4 runs lenses per region, Stage 5 runs states per
element. Anything not in a list wasn't audited — and the report must say so, not imply coverage.
This is the mechanism that stops "so many things get missed": misses become visible as `untested`
cells instead of silent absences.

## Stage 4 — Strict Lens Matrix (reason pass)

Run every lens that applies **over every region in the inventory**. Blockers first, polish last.

| Lens | What A Specialist Looks For | Automatic Fail / Blocker |
|---|---|---|
| 0. Surface classification | Website vs app vs ecommerce vs content vs form vs data workflow; judge by domain, not generic taste | Applying landing-page taste to an operational app, or app-density taste to a marketing page |
| 1. Rendered truth | What is literally on screen: strings, buttons, layout, viewport, state | No pixels; stale screenshot; wrong route; blank or loading-only capture |
| 2. Task cognition | Primary user goal, decision path, cognitive load (>4 visible options at a decision point is a flag), error recovery, next step; on websites: the five-second grunt test per `references/website-conversion-standards.md` — what is this / what's in it for me / what do I do next, answered inside the first viewport; **copy meaning gate**: cold-read the hero and every section h2/deck literally from the rendered page (who is the subject, what does the sentence claim to a stranger) and check each deck follows from its h2 as one argument — run the writing-copy gate table, never judge copy from memory | Core task cannot be completed or primary action is not discoverable; grunt test fails on a landing surface; hero line misattributes agency or is meaning-empty on cold read |
| 3. Visual hierarchy | First read, second read, CTA weight, scan path, grouping, salience; on websites: the hero contract (one primary CTA above the fold, headline ≤ ~10 words, visual anchor) per `references/website-conversion-standards.md` | Equal-weight CTAs/actions make the user choose blindly; any `structure` detector blocker |
| 4. Layout and whitespace | Grid, alignment, rhythm, density, proximity, stable dimensions, no nested-card mush; **i18n resilience**: does the layout survive longer strings (German/Finnish run ~30% longer than English) and RTL (Arabic/Hebrew) direction | Overlap, clipped text, content escaping, accidental grouping, broken responsive fit; **i18n breakage**: buttons/labels truncate or wrap ungracefully under a ~30% string-expansion mental model (or an actual locale switch when available); RTL flips break visual hierarchy or absolute positioning |
| 5. Typography | Font fit, hierarchy, line length (65-75ch), readable sizes, weight contrast, wrapping, numeric alignment, fonts actually loading (FOIT/FOUT) | Body text is hard to read; headings overflow; compact UI uses hero-scale type |
| 6. Color and contrast | Semantic roles, brand truth, state colors, contrast (verify with detector/probe, not eyeball), one-note palettes, default-blue/purple-gradient tells; **dark mode**: intentional palette not inversion, vars not hardcoded hexes, shadows adjusted, accents keep contrast | Body contrast fails, color-only state, CTA/alert/success/error meanings conflict |
| 7. Iconography and assets | Icons carry meaning, style consistency, labels/tooltips, real product/brand assets, image quality | Decorative icon spam; broken/placeholder image; fake product silhouette where real asset is required |
| 8. Responsive/device fit | Runs as THREE sub-lenses on websites — 8a desktop 1440, 8b tablet 768, 8c mobile 390 — each a separate coverage column, never one merged verdict. Mobile is the priority pass: single-column reflow (not just shrink), CTA still above the fold, ≥44px touch targets, ≥16px body text, no squeezed multi-column grids, nav collapses to a usable menu. Tablet: the awkward middle — grids must choose 1 or 2 columns deliberately, not render desktop-at-70%. Apps: realistic window sizes + min-size behavior | Any target viewport has horizontal scroll, clipped core content, or unusable controls; mobile CTA below fold; untested mobile on a website = coverage gap (≤79 cap) |
| 9. Interaction states | Default, hover, focus, pressed, active, disabled, loading, error, empty, expanded/open | Missing focus state, untested changed control, missing error/loading/empty state on core workflow |
| 10. Motion and micro-interactions | Purpose, frequency, duration, easing, origin, interruptibility, tactile feedback, reduced motion — full bar + exact values in `references/motion-standards.md` (web) and `references/native-feedback.md` (desktop/mobile apps: haptic semantics, response budgets, per-OS reduced-motion APIs, Fluent/M3 tokens) (the ten standards + escalation triggers) | Motion blocks task progress, animates keyboard actions, has no UX purpose, `ease-in`/`scale(0)`/`transition: all` on key UI |
| 11. Accessibility and usability | Keyboard path, semantics, labels, focus, hit targets, readable copy, motion reduction; axe results as mechanical floor, judgment on top | Keyboard trap, missing accessible name on core control, color-only error, unusable target size |
| 12. Performance perception | Skeleton vs spinner, stable loading, input latency feel, no layout shift, smoothness under load — **only valid on a throttled capture** (Slow-4G + 4× CPU per Stage 1); an unthrottled localhost capture that renders instantly is Undetermined, not Pass | Stuck spinner, layout shifts during interaction, janky core motion, blank reveal awaiting JS |
| 13. Brand/domain specificity | Product truth, real assets, signature mechanism, anti-AI-slop per `references/design-slop.md` (incl. the absolute bans + category-reflex check), non-transplantability | Looks like a generic AI/SaaS template; fake stats/quotes; stock-like imagery replacing product truth |
| 14. Peak and end states | Memorable product-value moment; success/confirmation/footer/empty state quality; **real content** — truncation behavior, long-text fit, no lorem-ipsum remnants | Key moment is visually flat; final/success/error state feels default or abandoned |
| 15. Platform fidelity (apps) | Per-OS rendered correctness per `references/platform-fidelity.md`: macOS overlay traffic lights, Windows custom caption buttons, per-OS `<Kbd>` chords, mac↔win divergence diff, iOS safe areas/44pt targets/gestures, Android back handling. Each shipped OS audited from its own capture or marked untested. Feedback-layer specs (haptic semantics, per-OS reduced-motion API, per-platform control minimums, Dynamic Type range) in `references/native-feedback.md` | Fake mac traffic lights on Windows; wrong modifier rendering for the OS; content under iOS system UI; a shipped OS claimed passing with zero captures |

**Coverage rule:** the report carries a region × lens outcome (pass / finding / untested / n-a).
Compact form — one row per region, one column per lens group (hierarchy · layout · type · color ·
icons · states · motion · a11y · slop), each cell `✓`/`✗`/`—`/`?`. `?` (untested) must say why.
A region with all-`?` was not audited; the verdict must acknowledge it.

Use `references/specialist-lenses.md` for deeper per-lens prompts. Supporting references:

- `references/design-slop.md` — AI-tell catalog + Designer engine absolute bans + detector rule map
- `references/website-conversion-standards.md` — the website floor: grunt test, hero contract, header/hover contracts, required page set, applied UX laws (Hick/Jakob/Fitts), structure-rule thresholds, mandatory three-viewport scan protocol
- `references/platform-fidelity.md` — Lens 15: per-OS app checks (mac traffic lights, Windows caption buttons, per-OS chords, mac↔win divergence, iOS safe areas/HIG, Android back handling)
- `references/motion-standards.md` — the motion bar: ten standards, escalation triggers, remedial hierarchy, exact values (Emil Kowalski distillation; absorbs emil-design-eng + review-animations)
- `references/native-feedback.md` — the **native** counterpart to motion-standards: haptic semantics (UIFeedbackGenerator / `.sensoryFeedback`), 0.1s/1s/10s response budgets, per-platform target-size floors, pointer-vs-touch degradation, per-OS reduced-motion APIs, Fluent 2 + Material 3 motion tokens, SwiftUI spring defaults
- `references/craft-tests.md`
- `references/typography.md`
- `references/surfaces.md`
- `references/performance.md`
- `references/ui-ux-checklist.md`
- `references/visual-qa-capture.md`
- `references/website-regression-gotchas.md` — whole-page boundary, semantic, conversion, and visible-motion regression gates

### Shared lenses — parametric fingerprint + anti-slop (mandatory adjuncts)

Two shared references apply as scored lenses on every audit, alongside Lens 2 (copy) and Lens 13
(brand/domain specificity):

- **Default-region-fingerprint proximity** (`skills/_shared/parametric-design.md`) — score how close the
  surface sits to its domain's known "LLM starter kit" cluster (centered hero + 3 cards + gradient
  blob, and the copy/social/SEO equivalents). Proximity is a scored finding even on an otherwise
  clean render.
- **Anti-slop sweep, detect mode** (`skills/_shared/anti-slop.md`) — sweep all visible copy (headlines,
  CTAs, body, microcopy) in detect mode: name the pattern, quote the line (<=125 chars), give the
  fix. No rewrite, no authorship guessing.
- **Parameter-vector conformance** — if the artifact shipped with a stated parameter vector, audit
  the render against that vector and flag drift as a finding, not a style note.

## Stage 5 — Interaction-state matrix

For every element in the inventory (or the workflow-critical subset on huge surfaces — say which):

| Element | Default | Hover | Focus | Click/pressed | Active/selected | Disabled/error/loading/empty | Evidence |
|---|---|---|---|---|---|---|---|
| E3 Settings tabs | pass/fail/untested | pass/fail/untested | pass/fail/untested | pass/fail/untested | pass/fail/untested | pass/fail/untested | screenshot path / note |

Use "untested" honestly. A single default screenshot does not pass an interactive workflow.

**Website functional sweep (minimum click-through, via `qa-functional.mjs --url <live-url>`):**
the state matrix on a website must include at least — desktop nav menus open/close; the mobile
hamburger opens, links work, and it closes; every form validates (submit empty → visible error;
valid input → success path) without actually submitting to production; primary CTA click lands on
the right target; ecommerce: add-to-cart → cart reflects it (stop before checkout submission).
`/qa` works against any live URL (`--url`), not only dev servers — "it's a deployed site" is not
a reason to skip interaction testing.

## Stage 6 — Optional External Vision Jury Lane (explicit opt-in only)

The external vision jury is an explicit opt-in lane inside this skill, not a default audit stage.

Run it when:

- the operator explicitly asks for `/audit-visual`, visual jury, or external review.

Do not infer external-review authority from a post-change gate, screenshot availability, commercial
importance, or visual stakes. When not explicitly requested, record `external jury: not requested`.

### Jury Input

Write `input.md` with absolute screenshot paths plus context:

```markdown
# Visual audit - <app/page>, <what changed>
Expectation: <what should look right / what should not regress>
Brand tokens: <accent, bg, type, known constraints if relevant>
Viewports: desktop 1440, tablet 768, mobile 390

<replace-with-absolute-screenshot-path-1>
<replace-with-absolute-screenshot-path-2>
<replace-with-absolute-screenshot-path-3>
```

Cap around 6 images per jury run because the vision pipeline caps images by count/size.

Run:

```powershell
jury audit-visual --input input.md --json
```

Vision juror routing lives in `src/lib/review/models.yaml`; rubric lives at
`src/lib/review/rubrics/audit-visual.md`. Do not duplicate provider rosters in this skill.

Hard rule: vision models can hallucinate. Before surfacing any jury blocker, open/inspect the
actual PNG yourself and confirm the defect is visible.

## Stage 7 — Verdict: scoring, floors, synthesis

Synthesis rules (before scoring):

- **Group by pattern, not instance.** One root cause flagged across 30 components is ONE finding
  with an affected-locations list ("×30"), not 30 findings.
- **Stop-and-scope at ~50 findings.** A 200-finding report isn't actionable — report the top
  patterns, say the surface needs structural work, and propose scope.
- **Dedupe across detectors:** a defect caught by the detector AND a lens AND the jury is one
  finding citing all three.
- **What works well** — a short factual section naming the strongest aspects. Not padding: it
  prevents "fixes" that destroy what's good, and confirms practices to keep.
- **Regression context (when the audit is triggered post-change).** A finding is not automatically a
  ship-blocker just because it exists — what changed matters. Ask for the "before" state (previous
  screenshots or a prior audit baseline). A finding **present in the baseline** is a *pre-existing
  condition* → **Note** severity; do not block the ship for it unless the operator explicitly scoped it in.
  A finding that is **new or worse than the baseline** is a *regression* → at least **Major**, and a
  visible regression of a core surface is a **Blocker**. If no baseline is available, say so and judge
  on absolute quality (the floors below still apply); don't imply a regression comparison you didn't do.

Report:

- **UX Health (0-100):** task flow, comprehension, decision path, recovery.
- **UI Health (0-100):** hierarchy, typography, spacing, color, render integrity.
- **Motion Health (0-100 or n/a):** micro-interactions, timing, purpose, smoothness.
- **A11y/Responsive Health (0-100):** focus, labels, target sizes, contrast, breakpoints.
- **Overall:** SHIP / REVISE / DON'T-SHIP, or **Spec Review Only - Not Visual QA**.

Critical floors:

- No pixels -> no visual verdict.
- Core task impossible -> UX Health floors to F / DON'T-SHIP.
- Body text contrast visibly unreadable or likely below WCAG AA -> UI floor.
- Zero visible focus states on an interactive surface -> A11y floor.
- Core content clipped/overlapping on a target viewport -> DON'T-SHIP.
- Broken placeholder/raw token visible (`undefined`, `NaN`, `{{var}}`, broken image) -> DON'T-SHIP if prominent.
- Motion blocks completion, hides content, or delays a frequent action -> at least Major; Blocker when it blocks the task.
- **Structure floor (websites/landing pages):** any measured `structure` detector hit —
  `cta-below-fold`, `hero-viewport-hog`, `one-word-lines`, `hero-cta-competition`,
  `headline-word-wall`, `hover-contrast`, `oversized-header`, `broken-internal-link`,
  `missing-required-page` — floors the verdict at REVISE. These are deterministic measurements,
  not taste; no lens, juror, or agent may argue one down to a Note or average it away. Only
  the operator can waive one, explicitly, per finding. (`missing-hero-media` is advisory: the lens
  must either confirm the gap or explicitly defend the type-only hero.)

Do not average critical failures away. Coverage gaps cap the score: a surface with untested regions
or all-untested states cannot score above 79 or receive SHIP — the verdict is REVISE with the gaps
listed. On a website audit, missing desktop or mobile URL scans are a coverage gap: structure rules
untested → the same ≤79/REVISE cap applies.

## Required Output

Lead with:

```text
UX Health: XX/100
UI Health: XX/100
Motion Health: XX/100 or n/a
A11y/Responsive Health: XX/100
Overall: SHIP / REVISE / DON'T-SHIP / Spec Review Only - Not Visual QA
Coverage: R regions x L lenses swept, N untested cells; E elements state-checked, M untested
```

Then include:

- Evidence inspected: screenshot paths, URL, viewport/state list, scanner runs (detector mode, axe source).
- Anchor used (brand card / brief / none).
- Critical failures first.
- Findings by severity: Blocker -> Major -> Minor -> Note; each with lens, region/element id,
  visible evidence/location, user consequence, exact fix. Pattern-grouped (×N).
- Region × lens coverage table (compact form).
- Interaction-state matrix for interactive surfaces.
- External vision jury summary when run, with hallucinated/dropped claims noted.
- What works well (short, factual).
- Residual risks: untested viewports/states/regions or unavailable tooling.

## Completion Checklist

Before passing a frontend/UI surface:

- Anchor loaded (brand/brief) or its absence stated.
- Pixels captured and inspected — full-page AND region crops on dense surfaces; dark mode when themed.
- Website boundaries and color cadence checked against `references/website-regression-gotchas.md`.
- Deterministic scan ran (detector; axe for apps) or named as skipped.
- Websites: structure scan ran at desktop, `--tablet`, AND `--mobile` viewports, JSON saved +
  cited; hero contract and grunt test judged per `references/website-conversion-standards.md`.
- Websites: site sweep ran on the homepage (`--site --site-type=<type>`) — internal links resolve,
  required page set (privacy/terms + type-specific) is linked.
- Apps: each shipped OS captured and swept by Lens 15 per `references/platform-fidelity.md`, or
  named untested.
- Region list + element inventory written BEFORE judging.
- Surface/domain classified; core user task and primary action identified.
- Every region swept by every applicable lens — coverage table has no silent gaps.
- Hover/focus/click/active/disabled/loading/error/empty/open states checked or marked untested.
- Motion checked against `references/motion-standards.md` (purpose, frequency, timing, easing, origin, interruptibility, reduced-motion).
- Visible motion proven with timed and scroll-position samples; motion code alone is not evidence.
- Accessibility checked for contrast, labels, keyboard/focus, targets, and semantics.
- Anti-AI-slop / absolute bans / brand-domain specificity checked.
- External vision jury run or deliberately skipped with reason.
- Vision blockers verified against the actual PNG.
- Findings pattern-grouped; what-works-well stated; verdict and exact fix list are explicit.
