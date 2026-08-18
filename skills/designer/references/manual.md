# Designer

MODE: OUTPUT_ONLY
PRIMARY_DELIVERABLE: Design route or bounded design artifact
DISCOVERY_PROFILE: D1_SCOPED_SOURCE
EFFECT_PROFILES: asset_read,output_write
SPECIALIST_REFS_MAX: 1
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: audit-visual,brand,brand-identity,content
TERMINAL: Return one bounded route or artifact; do not widen scope.

Use one memorable design entrypoint. Classify the requested outcome, then load only the matching
guide. Do not load the surface, static, and deep-craft branches together by default.

## Mode — declare before routing (surface work only)

| Mode | When | What runs |
|---|---|---|
| **draft** (default for explorations, one-shot pages, options, internal tests, "show me something") | No ship claim will be made | Brand card + truth sentence -> build exemplar-first from `references/components/` with the craft rules + ONE banned list (`references/website.md` §Banned defaults) -> detector structure scan -> human eyes. No gate artifacts, no competitor analysis, no registry work. |
| **ship** (branded production work going live) | The output will be deployed or delivered | The full phase spine in `specialists/surface-design/GUIDE.md` (all hard gates + artifacts + QA multi-gate). |

Draft exists so generation quality gets the model's full attention; ship exists so nothing ships
unaudited. A draft the user approves gets promoted by running the ship spine on it — the gates are
deferred, never skipped for shipped work. State the mode out loud when starting.

## Route

Paths are under `skills/designer/` unless shown from `skills/`.

| Primary outcome | Read next |
|---|---|
| Build/redesign a website, landing page, product page, portfolio, ecommerce front | `specialists/surface-design/GUIDE.md`, then `references/website.md` |
| Build/redesign product or app UI, dashboard, tool, settings, table, workflow | `specialists/surface-design/GUIDE.md`, then `references/app.md` |
| Flyer, social post, OG image, banner, ad creative, poster, print, packaging insert | `specialists/static-creative/GUIDE.md`, then `specialists/static-creative/references/marketing.md` |
| Deep craft command: craft, shape, polish, bolder, quieter, colorize, typeset, layout, delight, harden, live, document | `engine/GUIDE.md`, then exactly one `engine/reference/<command>.md` |
| Slide deck, editable PPTX, motion render, voiceover, device frame | `engine/huashu/GUIDE.md` |
| Review an existing rendered surface without implementation | `audit-visual` |
| Create or evolve the underlying brand identity | `brand-identity` |
| Design animation language, tokens, choreography, or implementation | `specialists/motion/GUIDE.md`, then one platform reference |
| Design glass, frosted, translucent, or liquid-glass-like UI | `specialists/glass/GUIDE.md` |
| Direct or adapt biological-mechanical illustration language | `skills/_shared/illustrate/GUIDE.md` |
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
6. Run `audit-visual` and the hidden `qa` workflow before making a rendered ship claim. the approving human's eyes
   approve visual taste.

## Parametric generation contract (mandatory)

Every generated artifact — surface, static creative, or the copy riding on it — is parametrized,
not one-shot vibes-to-final. Full axis tables, fingerprints, and phase tagging: `skills/_shared/parametric-design.md`.

1. Convert the brief into an explicit parameter vector before generating; state assumptions on any
   ambiguous high-impact axis.
2. Hard vs soft: brand tokens/palette/fonts, a11y floors, banned vocabulary are hard constraints —
   reject on violation. Tone/density/risk are soft — score down. Brand rules (`.claude/rules/brands.md`)
   are always hard.
3. Generate k >= 3 variants differing on >= 2 named axes (e.g. hero_pattern x visual_density) —
   never near-duplicates.
4. Critique in a separate pass from generation; cap refine loops at 2-4; the generator never
   certifies itself.
5. Penalize proximity to the default-region fingerprint (centered hero + 3 cards + gradient blob,
   and equivalents per domain) even on an otherwise clean build.
6. State the winning parameter vector alongside the deliverable. A later "make it bolder" is a
   mutation of that vector, not a fresh redesign.

All copy/microcopy this skill produces (headlines, CTAs, body, captions) gets the anti-slop pass in
embedded mode before it ships — `skills/_shared/anti-slop.md`, silent unless findings change the output.

## Boundaries

- Words as the primary deliverable -> `writing`.
- Images/video/media production rather than design of a surface -> `content`.
- Paid-media campaign strategy -> `ads`; this skill may produce its creative assets.
- No five simultaneous design guides. Start with one primary branch and add one specialist only when
  the deliverable genuinely spans both.
