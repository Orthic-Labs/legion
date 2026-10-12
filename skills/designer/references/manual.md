# Designer

PRIMARY_DELIVERABLE: Design route or bounded design artifact
SPECIALIST_REFS_MAX: 1
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 3 (web-search for fact checks; official brand-channel page and asset fetches; public asset-library downloads)
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: brand (brand code known or customer-facing output), qa (rendered evidence), writing (copy handoff), audit-visual (coverage evidence)
TERMINAL: Return one bounded route or artifact; do not widen scope.

Use one memorable design entrypoint. Classify the requested outcome, then load only the matching
guide. Do not load the surface, static, and deep-craft branches together by default.

## Mode — declare before routing (surface work only)

| Mode | When | What runs |
|---|---|---|
| **exploration** (draft, rough direction, options, internal test) | The user explicitly asks to explore, see a rough draft, or compare directions; output is labeled exploratory | Use the relevant branch and requested fidelity. Do not imply completion. Run the parametric contract for non-trivial choices and any requested alternatives or critique. No production claim, registry work, or ship artifacts. |
| **deliverable** (finished one-shot artifact) | The user asks for a finished artifact or something ready to use or hand off, even when it will not be deployed | Use a bounded craft path: apply the selected branch's design constraints, render at requested/target dimensions, inspect relevant states and interactions, check fit/clipping/overflow, and run a separate qualitative critique. For non-trivial work or requested options, show materially distinct candidate designs (at comparable fidelity to the decision) and score them against the brief before selecting. Do only acceptance checks that fit the artifact; no automatic competitor, registry, or full production spine. |
| **ship** (production work going live) | The output will be integrated, deployed, or released as a production surface | Run the full phase spine in `specialists/surface-design/GUIDE.md` (applicable hard gates, artifacts, and QA multi-gate). |

Choose by requested finish state, not by whether deployment is mentioned: “one-shot” alone does not
mean exploration. An explicitly rough draft can stay exploratory; a finished standalone page or
graphic uses deliverable mode and receives proportionate craft, render, fit, state, and critique
checks. Production ship mode retains its full spine. State the mode out loud when starting.

## Route

Paths are under `skills/designer/` unless shown from `skills/`.

| Primary outcome | Read next |
|---|---|
| Build/redesign a website, landing page, product page, portfolio, ecommerce front | `specialists/surface-design/GUIDE.md`, then `references/website.md` |
| Build/redesign product or app UI, dashboard, tool, settings, table, workflow | `specialists/surface-design/GUIDE.md`, then `references/app.md` |
| Flyer, social post, OG image, banner, ad creative, poster, print, packaging insert | `specialists/static-creative/GUIDE.md`, then `specialists/static-creative/references/marketing.md` |
| Deep craft command: craft, shape, polish, bolder, quieter, colorize, typeset, layout, delight, harden, live, document | `engine/GUIDE.md`, then exactly one `engine/reference/<command>.md` |
| Slide deck, editable PPTX, motion render, device frame | `engine/huashu/GUIDE.md` |
| Qualitatively critique an existing rendered surface | `designer` critique via `engine/GUIDE.md` |
| Enumerate/capture rendered states or prove visual regression coverage | `audit-visual` |
| Create or evolve the underlying brand identity | `brand-identity` |
| Design animation language, tokens, choreography, or implementation | `specialists/motion/GUIDE.md`, then one platform reference |
| Design glass, frosted, translucent, or liquid-glass-like UI | `specialists/glass/GUIDE.md` |
| Direct illustration for any surface | `specialists/illustration/GUIDE.md`; the consuming project supplies the visual style |
| Build/redesign a **platform-native** app surface (SwiftUI/AppKit macOS or iOS, `NSPanel`/HUD/palette, or Slint) | `references/app.md` → `references/native-app.md`; add `specialists/motion/native.md` for motion or window geometry |
| Build/redesign a **Tauri** app surface | `references/app.md` → `references/native-app.md` §7; add `specialists/motion/webview.md` for per-OS engine split |
| Port a Swift/SwiftUI surface to Slint, or reverse | `specialists/motion/native.md` §6 |

## Operating contract

1. Load the relevant `/brand` before brand-specific work. **If `<repo>/.brand/tokens.json` exists (emitted
   by `/brand-identity`), read it and apply its exact hex/OKLCH values, font stacks, and voice arrays
   deterministically — never hallucinate brand colors when the token file is authoritative.** Missing
   token file → ask for the palette or state you're using placeholders; do not invent brand hexes.
1a. Build exemplar-first: start every marketing-surface section from the nearest exemplar in
   `references/components/` (catalog: `references/components/_index.md`), retheme via tokens,
   rewrite copy in brand voice. Generate from scratch only when no exemplar is structurally close.
2. Inspect the existing design system, tokens, representative components, and rendered state before
   proposing a direction. Preserve intentional identity unless the user asks to replace it.
3. For a new or redesigned surface, classify it as website or app and follow that reference's gates.
4. For static creative, produce the artifact through the available image/design workflow; do not
   turn it into a frontend build unless the requested deliverable is HTML.
5. Use the engine branch for a named deep-craft command or when the surface workflow explicitly
   needs its detector/live tooling. The engine is implementation detail, not another user-facing skill.
6. For a rendered ship claim, run Designer's qualitative critique, Audit Visual's declared rendered-state
   coverage/regression checks, & QA's declared functional/browser/runtime checks. Approving human eyes
   approve visual taste.

## Parametric generation contract (mandatory)

Every generated artifact — surface, static creative, or the copy riding on it — is parametrized,
not one-shot vibes-to-final. Full axis tables, fingerprints, and phase tagging: `skills/_shared/parametric-design.md`.

1. Convert the brief into an explicit parameter vector before generating; state assumptions on any
   ambiguous high-impact axis.
2. Hard vs soft: brand tokens/palette/fonts, a11y floors, banned vocabulary are hard constraints —
   reject on violation. Tone/density/risk are soft — score down. Brand rules (the consuming project's
   brand token source) are always hard.
3. For non-trivial work, generate k >= 3 concrete candidates differing on >= 2 named axes (e.g.
   hero_pattern x visual_density) — never near-duplicates. Show actual comparable design material
   for non-trivial choices and whenever the user asks for options (rendered variants, component
   studies, or wireframes at a fidelity suited to the decision); three prose labels or parameter
   vectors alone are not alternatives. For a simple or explicitly exploratory request, keep the
   comparison proportional.
4. Critique separately from generation. Score candidates against the brief and hard constraints in
   a distinct critic pass; when the user asks for a critique, include specific evidence and
   actionable findings. Cap refine loops at 2-4; the generator never certifies itself.
5. Penalize proximity to the default-region fingerprint (centered hero + 3 cards + gradient blob,
   and equivalents per domain) even on an otherwise clean build.
6. State the winning parameter vector alongside the deliverable. A later "make it bolder" is a
   mutation of that vector, not a fresh redesign.

All copy/microcopy this skill produces (headlines, CTAs, body, captions) gets the anti-slop pass in
embedded mode before it ships — `skills/_shared/anti-slop.md`, silent unless findings change the output.

## Boundaries

- Words as the primary deliverable -> hand off to the host's writing capability if one is available.
- Images/video/media production rather than design of a surface -> hand off to the host's media
  production capability if one is available; this skill does not call it as a skill.
- Paid-media campaign strategy -> hand off to the host's ads capability if one is available; this
  skill may still produce its creative assets.
- No five simultaneous design guides. Start with one primary branch and add one specialist only when
  the deliverable genuinely spans both.
