# Brand Identity

PRIMARY_DELIVERABLE: Requested identity-system output for exact granted assets or paths.
SPECIALIST_REFS_MAX: 0
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Requested identity deliverable meets frozen output criteria.

The job is not "make a nice logo/palette." The job is to create an identity system that feels product-true, ownable, differentiated, repeatable, and hard to mistake for any sibling brand or generic AI output.

This skill uses the same mechanism as the `/designer` website surface: product/brand truth first, a generative signature mechanism, three divergent renderings, automated hard gates, visual/design QA, then human approval and guidelines.

## Parametric Design + Anti-Slop Contract

Brand identity work IS parameter-space definition, per `skills/_shared/parametric-design.md`:
every phase below already outputs explicit axes (signature mechanism, color roles, type
roles, voice dimensions) — treat these as the parameter vector, not incidental prose, so
downstream skills (`/designer`, `/audit-visual`, Sage) consume `.brand/tokens.json`
as hard constraints rather than vibes. When creating identities, generate the Phase 2
divergent renderings by deliberately sweeping named axes (base theme, accent family, type
category, voice signature — see the Option Divergence Gate) before converging on one
direction; never present near-duplicates as separate options.

All voice/guideline prose — banned/owned vocabulary, positioning statements, do/don't copy,
example headlines — gets the anti-slop pass per `skills/_shared/anti-slop.md`
(embedded mode: apply silently before Phase 6 human eyes). A brand may deliberately claim a
device the anti-slop inventory flags (e.g. a counter-culture streetwear brand's ALL-CAPS
staccato headlines, per `anti-slop.md`'s own false-positive note) — that is not a failure; record it in the brand's
guidelines/registry row as an explicit, named exception, not a silent override.

## Artifact Boundary: Identity First

When the user asks for **brand identity**, produce an identity system artifact first, not website mockups. The primary proof must be:

- Logo / wordmark direction
- Icon / symbol direction
- Color palette with semantic roles
- Typography system and fallback behavior
- Mark construction, spacing, shape, or grid logic
- Voice posture and short message rules
- Do / don't usage rules

Website, app, social, or deck examples are allowed only as small usage proofs. They must not become homepage layouts, hero sections, full page mockups, or conversion copy unless the user explicitly asks for website/app design. If the artifact starts looking like a website concept board, stop and reframe it as an identity board.

## The AI Tell: Banned Defaults

If two or more appear, the identity has failed and must be reworked:

- **Strategy:** vague values like "trusted", "innovative", "premium", "simple", or "human" without behavior/proof.
- **Naming/voice:** generic startup phrasing, "unlock", "leverage", "seamless", "next-gen", "in today's fast-paced world".
- **Logo:** shield, sparkle, bolt, generic monogram, abstract loop, chat bubble, leaf, cup, brain, robot, or orbit mark with no product-truth reason.
- **Color:** purple-blue gradients, default safe blue, warm paper plus copper by habit, one accent sprinkled everywhere, one-note hue families, or palettes picked only for mood/trend.
- **Type:** Inter everywhere, one sans plus one serif as the only idea, mono used only as a "tech" flavor.
- **Layout/application:** floating style tile with no real use case, card grids as the main proof, nested cards, rounded-everything, or website mockups presented as brand identity.
- **Imagery:** stock photos, abstract tech renders, AI images with garbled text, decorative blobs/orbs.
- **Guidelines:** logo/color/type only, with no voice, usage rules, UX/application rules, or evolution rules.

Naming these is the point. Models default to them; this skill exists to override that drift.

## Phase Flow: State Machine

Linear with two human touchpoints and three automated hard gates. Never skip a gate.

| # | Phase | Mode | Emits / blocks on |
|---|---|---|---|
| 0 | **Brand truth** | auto, one optional query if core truth is unknown | the brand-truth sentence |
| 1 | **Signature Identity Mechanism** | auto-generate + self-check, loop until tests pass | the signature one-liner |
| 2 | **Divergent renderings (3)** | present directions, then **PARK** | options differ in register/base/accent, **not just type**; human picks one. Three is the standard; fewer only when you can honestly justify fewer distinct directions (see the N-options honesty rule below) |
| 2.5 | **Option Divergence Gate** | auto **HARD GATE** | each option differs from the OTHER options on ≥4/7 axes incl. distinct base AND accent; fail -> rework the colliding option(s) and re-run |
| 3 | **Differentiation guard** | auto **HARD GATE** | compare vs `references/brand-registry.md`; fail -> adjust and re-run |
| 4 | **Build the identity system** | auto | strategy, visual, voice, assets, applications |
| 5 | **Impeccable / anti-slop QA** | auto **HARD GATE** | fail -> fix and re-run |
| 6 | **Human eyes** | render or present proof, then **PARK** | user approves or gives taste feedback |
| 7 | **Guidelines + registry update** | auto | `BRAND.md`/brand book + registry row |

Human approvals are Phase 2 and Phase 6. Phases 3 and 5 are automated gates, not subjective review steps.

## Phase 0: Brand Truth

Before any visual decision, answer in one sentence:

> "This brand helps [audience] do/feel/achieve [specific outcome] by [specific product/service behavior], and must be recognized as [desired perception]."

Extract or infer:

- Brand/product name
- Audience and customer problem
- Customer value proposition
- Brand promise
- The literal product/service behavior customers experience
- Mission, vision, values
- Category and competitor set
- Desired perception and emotional territory
- Channels where the identity must work

If more than two essentials are missing and cannot be safely inferred, ask concise questions. Otherwise state assumptions and proceed.

## Phase 1: Signature Identity Mechanism

Invent an ownable mechanism based on Phase 0. This is generative, not a menu. The mechanism can be a visual behavior, composition rule, mark logic, motion language, voice ritual, naming rhythm, packaging gesture, UI behavior, or cross-channel brand moment.

State the candidate in one line:

> "The identity is built around a live/recurring [X] that does [Y] whenever the brand [Z]."

It must pass all seven tests. If any fail, discard and invent again.

1. **Brand-truth:** It reflects the real promise, behavior, or customer transformation. Not a metaphor floating above it.
2. **Non-transplant:** Swap the logo/copy onto another brand and it becomes false. If it still works for a generic SaaS, agency, cafe, or wellness brand, it fails.
3. **Nameable:** The mechanism can be named with concrete nouns and verbs. "Dynamic visual energy" fails.
4. **Systemizable:** It can repeat across logo/mark, typography, color, layout, voice, website/app, deck, social, and support/onboarding where relevant.
5. **Memorable:** It creates a recognizable mental hook, not just a good-looking mood.
6. **Usable:** It works in small, monochrome, low-motion, and non-hero contexts.
7. **Not the generic kit:** It is not merely palette + font + logo + abstract imagery.

Output the passing one-liner plus a 2-3 sentence description of how it behaves across channels.

## Color Strategy Gate

Color is a strategic system, not a decoration pass. Before naming a palette, answer:

> "The color system makes [brand/product mechanism] legible by using [base environment], [accent behavior], and [state semantics], while differing from siblings on [specific axes]."

The palette must pass:

1. **Product mechanism:** colors map to a real brand behavior, material, state, artifact, workflow, or customer moment. If the palette would still work after swapping in another brand's logo, revise it.
2. **Role clarity:** every major color has a job: base, surface, text, accent, CTA, state, warning, success, data, proof, premium, craft, or environmental mood.
3. **Sibling differentiation:** never reuse a sibling's base theme + accent family + layout mood unless the relationship is intentional and named.
4. **Palette range:** before presenting multiple directions, list the hue families already used in the set and reject lazy repeats. Options must differ meaningfully by hue family, temperature, saturation, value, and role behavior. Do not keep returning to the same lime/terracotta/clay/brass lane with new names.
5. **Modern calibration:** prefer tinted neutrals over plain gray, grounded earth/ink/clay/olive/brass/oxblood bases where product-true, dark-first systems for serious software when appropriate, and vivid accents only when they carry state, proof, command, or attention. Current trend references may widen the palette, but product truth chooses the final colors.
6. **Anti-default:** do not default to pale blue, generic SaaS blue, purple-blue gradients, beige/copper warmth, terracotta/clay, citron/lime, brass/olive, or "trustworthy green" unless the product truth specifically earns it. If the user flags a repeated swatch, treat that hue family as temporarily banned for the next exploration pass.
7. **Contrast:** normal text meets WCAG AA at minimum; important product/app text should aim higher. Do not trade readability for trend.
8. **Restraint:** accents should be scarce enough to mean something. If the CTA color appears everywhere, it stops being a signal.
9. **System durability:** the palette works in light/dark, monochrome, print/screenshot, disabled/error/success states, and small marks.

If referencing current design trends, use them as taste calibration only. Do not write "2026 palette" into a brand unless the colors still make sense when the trend cycle changes.

### Color Science & Production Grounding

The strategic tests above decide *which* colors. This subsection grounds *how* they are derived, balanced, and verified, against standards rather than taste alone.

1. **Derive and audit in a perceptual space (OKLCH/OKLab).** Pick and audit palettes in OKLCH, not raw hex/HSL — its lightness axis is perceptually calibrated, so equal L *looks* equally bright across hues. Source: Björn Ottosson's OKLab (2020), in the W3C CSS Color 4 draft and supported in all evergreen browsers. Use it to (a) audit accent balance — list each accent's L and reject an unintended spread (e.g. a set ranging L 0.58–0.92 will have one accent that screams and one that recedes); (b) generate even tonal steps by fixing L and varying C/H.
2. **Know the neon/cusp trap.** Each hue's maximum-chroma ("neon") cusp sits at a *different* lightness — yellow-greens peak high, blues peak low. Therefore strictly matching vivid accents to one L **desaturates them into pastels** (a blue forced to L0.80 loses most of its chroma). For vivid/neon systems, do NOT force equal L: keep each accent near its own cusp, then tame only the outliers into a tighter band. Match by *intent*, not by identical L.
3. **Contrast standard = WCAG 2.2 AA (normative).** Normal text ≥ 4.5:1, large text / UI components ≥ 3:1. This is the operative legal/audit benchmark in 2026. Verify every text-on-color and accent-on-base pair numerically; eyeballed darkening routinely lands at ~4.1–4.3 and silently fails AA. When deriving a light-theme accent, compute the *highest-lightness value that still clears 4.5:1* so it stays as vivid as accessibility allows.
4. **APCA is supplementary, not a substitute.** APCA (the perceptual contrast model) was pulled from the WCAG 3 working draft in 2023 and is non-normative; WCAG 3 is not expected to reach Recommendation before ~2028–2030. Use APCA/real-world reading checks to catch "technically-AA but hard to read" cases, but if a color fails WCAG 2 contrast, document it — do not ship it as compliant on APCA alone.
5. **Color-blind safety.** ~8% of men have red-green color vision deficiency. Never encode meaning (state, success/error, data series, active/inactive) in hue alone — pair hue with lightness, shape, icon, or label. Check status dots, diff colors, and chart palettes specifically.
6. **Generate theme tokens as perceptual ramps.** For multi-theme or light/dark token systems, derive each theme as a tonal ramp in a perceptual space (e.g. an OKLCH lightness ladder, or Material 3's HCT tonal palettes) rather than hand-picking each stop. This keeps surfaces, lines, and text steps consistent across themes and makes a shared theme pool coherent.

**Verify with the script, never from memory (HARD).** Do NOT report an OKLCH value or a WCAG ratio you computed in your head — a hallucinated "4.6:1" that is really 4.2:1 ships an inaccessible palette under a false compliance claim. Run the zero-dependency checker for every pair before recording it:

```bash
color-check contrast "#FF5630" "#211D1A"   # ratio + AA/AAA
color-check oklch "#B87333"                 # sRGB -> L/C/H
color-check audit '[{"name":"body/bg","fg":"#211C18","bg":"#F7F3EC","min":4.5}]'   # whole-palette table, exits 1 on ANY fail
```

If a text/accent pair fails its `min`, loop back and adjust lightness (use `oklch-to-hex` to find the highest-L value that still clears the bar), then re-run — do not record a failing pair as compliant. Record the final palette's per-color OKLCH (L/C/H) and the **script-measured** WCAG ratios against its real backgrounds in the guidelines, so the system is auditable later, not re-eyeballed.

## Type Strategy Gate

Type is a strategic system, not a font-picking pass. The banned-default line and the Phase 3 type-category axis catch bad type; this gate drives good type. Before naming a type system, answer:

> "The type system makes [brand/product mechanism] legible by using [display role], [text role], [UI/mono-data role], with a defined fallback stack, while differing from siblings on [type category or named flavor within a category]."

The type system must pass:

1. **Product-truth mapping:** the display register matches the product's real behavior and audience (reading serif for a reading product, mono for a terminal/dev tool, expressive display for a voice/expressive product), not chosen for mood. If the face would suit any generic startup equally, revise it.
2. **Pairing harmony:** display and text share connective tissue — similar x-height, a compatible contrast model, or a true superfamily relationship. Contrast between faces must read as intentional, not random.
3. **Role clarity:** every face has exactly one job — display, text/body, UI, mono/data, fallback. No face used outside its role; mono is not sprinkled as "tech flavor."
4. **Distinctiveness / anti-slop:** the display face is NOT from the current overused cluster unless product-truth specifically earns it. Treat this list as **rotating, not fixed** — re-check it against current "slop font" discourse each pass. As of 2026 the flagged cluster includes Inter, Roboto, Arial, Geist, Space Grotesk, Space Mono, Fraunces, Instrument Serif, Syne, and Bricolage Grotesque. If a chosen face is in the everywhere-right-now set, either justify it from product truth or replace it. Avoiding "Inter everywhere" by switching to the next fashionable monoculture is still a fail.
5. **Sibling differentiation:** differs from every sibling on type *category*, or on a clearly *named flavor* within a shared category (e.g. neutral-Swiss grotesque vs geometric-mechanical grotesque). Do not let two siblings sit in the same face cluster by habit.
6. **Legibility at target sizes:** body legible at 14–18px, UI labels at 12–13px, display tested at hero size. Tabular/lining numerals wherever the type carries data, counts, dates, or prices.
7. **Production reality:** licensing is explicit and recorded (OFL / free-for-commercial / paid), the face is self-hostable as subset **WOFF2**, a variable font is used where it saves weight, and a real OS fallback stack is defined to survive FOUT/FOIT. A face that cannot ship is not a candidate. **Emit the production `@font-face` CSS block as a deliverable**, not just font names — the exact `@font-face` declarations with a `font-display` strategy (`swap` for display, `optional` for body-critical to avoid layout shift), the self-hosted WOFF2 `src`, and the full OS fallback stack, e.g. `font-family: "Brand Display", ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;`. A type system without shippable CSS is a mood board, not a system.
8. **System durability:** the type system holds in light/dark, all-caps/small-caps where used, monochrome, long-form reading, dense UI, and at small mark/wordmark sizes.

If referencing current type trends, use them as taste calibration only. A distinctive free-or-FFC face self-hosted as WOFF2 usually beats a top-20 default; product truth chooses the final faces.

## Logo / Mark Strategy Gate

The banned-logo line kills clichés; this gate drives a real mark system. The mark must render the signature mechanism, not decorate it. Before finalizing a mark, answer:

> "The mark expresses [signature mechanism] as [wordmark / symbol / monogram / system-mark logic], built on a [grid/base-unit] so it stays legible from [hero size] down to a 16px favicon, and differs from siblings on mark logic."

The mark system must pass:

1. **The five classic principles** (established identity practice — Rand, Airey, and standard logo literature): **simple, memorable, timeless, versatile, appropriate**. Trendy = dated; if a current style would look old in three years, drop it. "Appropriate" means it communicates the product's purpose/personality, not just looks nice.
2. **Mechanism-true:** the mark encodes the brand's signature behavior or product truth (a render device, a waveform, a triage action, an approval state), not a generic object. Re-check against the banned cliché list (shield, bolt, sparkle, chat bubble, leaf, brain, robot, orbit, generic monogram).
3. **Construction grid:** built on a defined base unit / grid (modular for geometric, baseline for text/wordmark, circular for curves) so proportions, spacing, and alignment are systematic and reproducible — not hand-nudged.
4. **Responsive / adaptive ladder:** ship a scalable system, not one lockup — full lockup → compact lockup → symbol/icon → favicon. Each tier drops detail deliberately while staying recognizable. (Responsive-logo practice; the same idea as a responsive layout.)
5. **16px favicon test:** the smallest tier must read at 16×16. No text smaller than ~16pt, bold/high-contrast shapes, simplify to an initial/symbol/brand element. Provide SVG (sharp) + PNG (transparent) + ICO (compat). If it's unrecognizable at 16px, the system fails.
6. **Monochrome + one-color behavior:** the mark works in single-color, knockout (white-on-dark), and pure black/white. If it only works in full color, it's underbuilt.
7. **Accessibility & surface:** the mark holds on light and dark backgrounds, and anywhere it carries information meets the same contrast bar as text. Define clearspace (a repeatable unit) and minimum sizes.
8. **Sibling mark-logic differentiation:** differs from every sibling on mark logic (wordmark vs symbol vs monogram vs system-mark vs kinetic), so a suite doesn't read as one template with swapped colors.

Record the grid, clearspace, min sizes, the responsive tiers, and favicon files in the guidelines.

**Hand-code the SVG for geometric/monogram/system marks (do not delegate what you can build precisely).** For a mark built on a geometric, modular, or typographic grid — which this gate pushes over generic illustration — output the raw, hand-written `<svg>` markup for the primary mark AND the favicon tier, built on the declared construction grid: an explicit `viewBox`, `<path>`/`<rect>`/`<circle>` primitives placed on the base unit, and `<g>` groupings that mirror the construction logic (so the file *is* the grid, reproducibly). Only *illustrative/painted/photographic* marks go to the user's image pipeline; a precise scalable mark is code, and shipping it as SVG makes it crisp at every tier including the 16px favicon.

## Voice & Messaging Gate

Voice is a plotted decision, not a pile of adjectives. "Friendly, professional, bold" describes almost any brand and is an AI tell.

1. **Plot the four tone dimensions** (Nielsen Norman Group): **formal ↔ casual**, **serious ↔ funny**, **respectful ↔ irreverent**, **matter-of-fact ↔ enthusiastic**. Place the brand on each axis with a concrete reason tied to audience and product truth. The plot, not the adjectives, is the spec.
2. **Context shifts:** state how the tone moves between contexts — marketing vs onboarding vs error vs success vs legal. NN/g research: tone should shift by situation (an error message is not the place for funny), so define the shifts, don't pick one global tone.
3. **Show, don't assert:** every voice principle carries a real before/after example in the brand's actual domain — a headline, an empty state, an error, a CTA — not a description of the tone.
4. **Banned & owned vocabulary:** output two explicit arrays, not prose, so downstream copywriting (marketing, UX strings, email) can use them as hard string filters: `banned_phrases[]` (generic startup filler the brand never uses, e.g. `["leverage","seamless","unlock","revolutionary"]`) and `owned_terms[]` (the specific terms/phrasing it owns). These land verbatim in `.brand/tokens.json` (Phase 7).
5. **Message architecture:** one-line positioning, 3–5 message pillars, and proof for each. Claims map to real proof, never fabricated stats/quotes/testimonials.
6. **Consistency across channels:** the plotted voice must hold across website, app UI strings, email, social, and support, with the documented context shifts.

## Phase 2: Three Divergent Renderings

Create three style registers that all render the same signature mechanism. They are not three unrelated brand concepts.

Each direction must include:

- Direction name
- Visual register
- Strategic thesis
- Audience fit
- Type category
- Color strategy, including base environment, accent behavior, semantic roles, contrast notes, and sibling-differentiation axes
- Composition/grid logic
- Mark/logo logic
- Motion or interaction character where relevant
- Voice posture
- How the signature mechanism appears in at least three small identity applications, such as favicon/app icon, wordmark lockup, one-color mark, document/header strip, badge, deck title, social avatar, product icon, or packaging label. Do not use full website mockups unless requested.
- Strengths
- Risks
- What would make it fail
- Completeness score from 1 to 10

Use genuinely different registers, for example editorial, Swiss-utilitarian, brutalist, luxury-minimal, warm-craft, technical-blueprint, kinetic, folk-modern, acoustic, archive, clinical, street, or calm-terminal.

Recommend one direction, but park for the user to choose when doing major creation/redesign work. Build the winner and graft only specifically compatible pieces from the runners-up.

### Option Divergence Gate

When a brand is presented as MULTIPLE OPTIONS (A/B/…), each option is a separate identity system and must diverge from the OTHER OPTIONS — not only from siblings. The Phase 3 axes apply option-vs-option here, not just brand-vs-sibling.

- Each option must differ from every other option of the same brand on **at least 4 of the 7 axes**.
- **Mandatory among those:** a **distinct base environment** (a different dark background AND a different light background) **and** a **distinct accent family**. Two options that share the same palette and differ only in typeface are NOT two options — they are one option with a font swap. **Automatic fail.**
- Run the **Color Strategy Gate and Color Science Gate independently for each option's palette.** Never reuse one palette across options.
- State, per option, a one-line color thesis and exactly how its base + accent differ from the other options.

This closes the gap where "divergent renderings" silently collapse to same-color / different-font. If asked for N options and you can only justify one palette, you have 1 option, not N — say so.

## Phase 3: Differentiation Guard

Read `references/brand-registry.md` before building. Compare the chosen direction against every sibling brand in the registry. **The registry only sees your own siblings — the market is the other half of differentiation.** When the brand competes in an external category, first invoke `/research competitors <category>` and consume its brief (rival positioning, visual identity, naming, voice, category norms) so the seven-axis check below runs against the *real market*, not just internal siblings. A mechanism that's distinct from your other brands but identical to the category leader is still a clone.

The chosen direction must differ on at least four of these seven axes from every sibling:

1. **Base theme:** light, dark, paper, night, vivid, neutral, high-contrast.
2. **Type category:** reading serif, grotesque, humanist sans, mono-forward, display, script/hand, slab.
3. **Accent family:** hue family and usage behavior.
4. **Composition system:** editorial, Swiss grid, deck, radial, spine, asymmetrical, dense utility, cinematic.
5. **Mark logic:** wordmark, symbol, monogram, seal, system mark, kinetic mark, no-logo identity.
6. **Asset language:** photography, illustration, iconography, pattern, texture, motion, UI-native.
7. **Voice signature:** plainspoken, editorial, precise, warm, provocative, ceremonial, technical, playful.

If it fails the threshold, it is a sibling clone. Redesign the weakest overlapping axes and re-run the guard. On Phase 7 approval, write the chosen row back to the registry.

## Phase 4: Build The Identity System

Build the chosen direction into a working system:

- Brand essence
- Customer value proposition
- Brand promise
- Positioning statement
- Personality traits with behaviors
- Voice principles and examples
- Message architecture
- Logo/mark direction if applicable
- Logo suite requirements: primary, secondary, icon/avatar, one-color, small-size behavior
- Color palette with semantic roles, contrast constraints, anti-default rationale, and light/dark behavior where relevant
- Type system: display, body, UI, fallback
- Composition/layout rules
- Imagery/illustration/iconography rules
- Motion/interaction rules where relevant
- Social, deck, website/app, product, packaging, or service touchpoint applications as relevant
- Accessibility and production constraints

Every major decision must trace back to strategy. If a decision is only "looks nice," revise it.

Optional inspiration references live in `references/visual-reference-libraries.md`; use them as taste inputs only, never as substitutes for brand truth, signature mechanism, or registry differentiation.

## Phase 5: Impeccable / Anti-Slop QA

This is a hard gate. A failing identity cannot be called done.

Manual detector:

- Does the signature mechanism pass all seven tests?
- Does the system differ from siblings on four of seven axes?
- Does every visual decision trace to brand truth?
- Does the color system pass the Color Strategy Gate?
- Does it avoid the banned AI tells?
- Does it work at small sizes and in monochrome/low-color contexts?
- Does it produce consistent voice across channels?
- Does it include realistic application proof?
- Does it include do/don't examples and operational rules?

If a visible artifact is produced:

- Run `designer-detect --json <dir>` when available; otherwise run the 9-item manual checklist above and label the result "Manual QA — detector not run."
- Use `audit-visual` for UI/site/app visual QA only when the requested deliverable is a UI/site/app artifact. For a brand identity artifact, QA the board as identity proof: small mark legibility, one-color behavior, palette contrast, type fit, sibling separation, and absence of full website mockups.
- Inspect screenshots/artifacts for hallucinated text, bad hierarchy, weak spacing, inaccessible contrast, cramped line length, generic gradients, and stock-like imagery.

Failure loops back to Phase 4 fixes, then Phase 5 re-runs.

## Phase 6: Human Eyes

Present the real proof of the identity before finalizing:

- Brand board or guidelines preview
- Website/app/deck/social/product mockups as relevant
- Voice examples
- Do/don't examples
- Registry diff summary

Ask for approval or taste feedback. Do not bury the user in process notes; show the work clearly.

## Phase 7: Guidelines And Registry Update

Produce a usable `BRAND.md`, brand book outline, or guidelines document:

```markdown
# Brand Identity - [Brand]

## Brand Truth
## Signature Identity Mechanism
## Audience
## Customer Value Proposition
## Brand Promise
## Positioning
## Personality
## Voice
## Messaging
## Visual Identity
## Logo / Mark System
## Color
## Typography
## Composition
## Imagery And Assets
## Motion / Interaction
## Applications
## Do / Don't
## Accessibility
## Evolution Rules
## Decisions Log
```

**Also emit a machine-readable `<repo>/.brand/tokens.json`** — the deterministic source of truth that downstream skills consume (`/designer` builds UI from it, `/audit-visual` checks a rendered surface against it, Sage plans the theme-variable refactor from it). Human `BRAND.md` is for people; this JSON is for agents. Minimum shape:

```json
{
  "brand": "<Name>",
  "signature_mechanism": "<the one-liner>",
  "color": {
    "base": "#…", "surface": "#…", "border": "#…", "text": "#…", "muted": "#…",
    "accent": "#…", "cta": "#…",
    "state": { "success": "#…", "warning": "#…", "error": "#…", "info": "#…" },
    "oklch": { "accent": {"L":0.0,"C":0.0,"H":0.0} },
    "contrast": [ {"name":"body/bg","fg":"#…","bg":"#…","ratio":0.0,"passesAA":true} ],
    "themes": { "dark": { "base":"#…" }, "light": { "base":"#…" } }
  },
  "type": { "display": "…", "body": "…", "mono": "…", "fallback": "…", "fontface_css": "@font-face{…}" },
  "voice": { "banned_phrases": ["…"], "owned_terms": ["…"] }
}
```

The `contrast[]` ratios MUST be the script-measured values from the Color Science gate, never re-typed from memory. Then update `references/brand-registry.md` with the approved axes so future work differentiates against it.

## Audit Mode

When auditing an existing identity, score it out of 100:

| Category | Weight |
| --- | ---: |
| Brand truth and promise clarity | 15 |
| Signature mechanism | 15 |
| Audience/customer fit | 12 |
| Differentiation vs category/siblings | 15 |
| Visual system coherence | 12 |
| Voice and messaging | 10 |
| Application proof | 8 |
| Operational guidelines | 8 |
| Accessibility and production readiness | 5 |

Report:

- Overall identity score
- Gate failures
- Top 5 strengths
- Top 5 risks
- Missing signature or weak signature diagnosis
- Sibling/category overlap
- Fast fixes
- Deeper rebrand work
- What to keep, change, and retire

## Completion Checklist

Before saying the brand identity is complete, verify:

- Phase 0 brand-truth sentence exists
- Phase 1 signature mechanism passes all seven tests
- Phase 2 three divergent renderings were explored for major work
- Phase 3 differentiation guard passed
- Phase 4 system was built with strategy-to-form traceability
- Phase 5 impeccable/anti-slop QA passed
- Phase 6 human eyes completed when visual output is involved
- Phase 7 guidelines produced, `.brand/tokens.json` emitted, and registry updated
- Open assumptions are clearly named

**Post-approval handoff (offer the next step, don't just finish).** Once the user approves the identity, route them to execution — the tokens file makes each of these a real, wired next action:
- Audit how an existing UI adheres to the new brand → `/audit-visual` (checks the rendered surface against the tokens).
- Refactor the codebase theme variables to match the tokens → apply directly; escalate to Sage only if the token ownership boundary is disputed.
