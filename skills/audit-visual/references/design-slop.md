# Design-Slop / AI-Stink Catalog

These are tells that a UI was generated from defaults, not designed. Flag any that appear. Each is a blocker for "looks intentional."

## Visual / Aesthetic Defaults

| Tell | Why it's a default |
|---|---|
| **Default blue `#3B82F6` or Tailwind generic blue** | First color in every Tailwind config; not a product choice |
| **Generic purple-blue gradients (hero backgrounds, cards)** | GPT-UI default; appears in ~40% of AI-generated interfaces |
| **Linear spinners (rotation-only)** | Default browser loading pattern; skeletons communicate content shape |
| **Obstructive motion** (entrance animations that block interaction, full-screen wipes) | Animation without UX purpose |
| **Overly-rounded everything** (`rounded-full` on cards, badges, containers) | Safety choice; removes visual tension |
| **Nested cards inside cards inside cards** | Layout confusion from lack of hierarchy thinking |
| **Decorative abstract tech blobs/meshes** | Stock AI hero background |
| **Mixed icon styles** (outline + filled + duotone in same surface) | No icon system decision |
| **Color-only state indicators** (error = red only, no icon or pattern) | Accessibility failure + default pattern |
| **Flat/washed-out disabled states** (low opacity, no visual distinction from loading)  | Not designed, just de-emphasized |

## UX / Flow Defaults

| Tell | Why it's a default |
|---|---|
| **Two equal-weight hero CTAs** (Hick's Law violation) | "Cover all cases" without hierarchy decision |
| **Hidden fees appearing late in checkout** | Pattern that maximizes friction/drop |
| **Forced account creation before checkout** | Conversion killer; Baymard-documented default failure |
| **Coupon/promo field on cart before address** | Sends users away to find codes |
| **Generic empty states** ("No items found.") | Not designed; every surface deserves a specific empty state |
| **Validation that clears all fields on error** | Punishment UX; not a design choice |
| **No immediate feedback on tap/click** | Missing press/active state |
| **Jarring un-eased transitions** (snap, no timing function) | CSS default; `transition: all` or no transition |
| **Conversational vague error text** ("Something went wrong.") | Friendly-sounding but uninformative |
| **Sub-44px touch targets** (WCAG 2.5.5) | Mobile default when desktop constraints are copy-pasted |
| **Missing loading, error, or empty states** | Only default/happy-path state was designed |

## Token / Naming Defaults

| Tell | Why it's a default |
|---|---|
| **CSS variables named `--gray-700`, `--surface-2`, `--blue-500`** | Generic scales, not product language |
| **`--primary` / `--secondary` without semantic meaning** | Placeholder naming from starter kits |

## Motion Defaults

| Tell | Why it's a default |
|---|---|
| **`transition: all`** | Watches every property; browser default shorthand |
| **Bounce animations on UI elements** (drawers, modals bouncing in) | Framer Motion spring defaults, not a UX choice |
| **`will-change: all`** | Cargo-cult GPU hint |
| **Animation on page load for already-visible elements** | Missing `initial={false}` on AnimatePresence |
| **Icons toggling visibility with no transition** | `display: none` swap, not a transition |

## Absolute bans (folded from impeccable — match-and-flag)

| Tell | Why it's a default |
|---|---|
| **Side-stripe borders** (`border-left/right` >1px as a colored accent on cards/callouts/alerts) | Never intentional; rewrite with full borders, bg tints, leading icons, or nothing |
| **Gradient text** (`background-clip: text` + gradient) | Decorative, never meaningful; emphasis via weight or size |
| **Glassmorphism as default** (decorative blur/glass cards) | Rare and purposeful, or nothing |
| **The hero-metric template** (big number, small label, supporting stats, gradient accent) | SaaS cliché |
| **Identical card grids** (same-sized icon+heading+text cards, repeated endlessly) | The lazy answer; nested cards are always wrong |
| **Tiny uppercase tracked eyebrow above every section** ("ABOUT" "PROCESS" kickers) | Appears on 55–95% of AI generations regardless of brief — the definition of a tell. One named kicker as a brand system is voice; an eyebrow on every section is AI grammar |
| **Section furniture restating its heading** (kicker text ≈ h2, deck ≈ headline — "Available now / four working paths" over "Four working paths, available now.") | The copy-level half of the kicker tell; not machine-detectable, read the words. Every label must add information its neighbor doesn't — keep the stronger line, delete the echo. A kicker survives only when it carries a real axis (e.g., the contrasting pair AVAILABLE TODAY / NOT INCLUDED TODAY) |
| **Numbered section markers as scaffolding (01 / 02 / 03)** | Earned only when the content actually IS a sequence and order carries information |
| **Cream/sand/beige body bg** (OKLCH L 0.84–0.97, C<0.06, hue 40–100; token names `--paper`/`--cream`/`--sand`/`--linen`/`--parchment`) | The saturated AI default of 2026; "warmth" belongs in accent + typography + imagery, not body bg |
| **Warm cream bg + high-contrast serif display + terracotta accent** | AI-look cluster #1 (per Anthropic's frontend-design calibration) |
| **Near-black bg + single acid-green or vermilion accent** | AI-look cluster #2 |
| **Broadsheet layout: hairline rules, zero border-radius, dense newspaper columns** | AI-look cluster #3 |
| **Text overflowing its container** (long headings × large clamp × narrow grids) | The viewport is part of the design; test heading copy at every breakpoint |

**Category-reflex check (two altitudes):** First-order — if someone could guess the theme + palette
from the product category alone, it's the first training-data reflex. Second-order — if someone could
guess the aesthetic family from category-plus-anti-reference ("AI tool that's not SaaS-cream →
editorial-typographic"), it's the trap one tier deeper. Both must be non-obvious.

## Deterministic backing — the impeccable detector

Most of this catalog is machine-detectable. The scan stage runs
`node D:/workspace/tools/skills/designer/engine/scripts/detect.mjs --json <url|file|dir>` and its findings
carry these rule ids — cite them as scanner evidence:

`side-tab` · `border-accent-on-rounded` · `gradient-text` · `gray-on-color` · `low-contrast` ·
`ai-color-palette` · `icon-tile-stack` · `italic-serif-display` · `hero-eyebrow-chip` ·
`repeated-section-kickers` · `bounce-easing` · `layout-transition` · `dark-glow` ·
`monotonous-spacing` · `repeating-stripes-gradient` · `theater-slop-phrase` ·
`image-hover-transform` · `line-length` · `cramped-padding` · `body-text-viewport-edge`

**Website-structure rules (browser mode ONLY — rendered viewport geometry).** These measure the
conversion failures prose lenses keep missing; thresholds and evidence base live in
`references/website-conversion-standards.md`:

`cta-below-fold` · `hero-cta-competition` · `headline-word-wall` · `one-word-lines` ·
`missing-hero-media` (advisory) · `hero-viewport-hog` · `hover-contrast` · `oversized-header` ·
`broken-internal-link` (`--site`) · `missing-required-page` (`--site`)

Structure rules require a URL scan (`detect.mjs --json --viewport=1440x900 <url>`, then `--tablet`,
then `--mobile`; site sweep via `--site --site-type=<app|ecommerce|content>` on the homepage). A
static/file scan CANNOT evaluate them — a clean static run does not clear them, and the report must
say which mode ran.

A detector hit is a confirmed finding (cite the snippet); a clean detector run does NOT clear this
catalog — the non-greppable tells (hero-metric template, card grids, category-reflex,
furniture-restates-heading) still need eyes.

---

When any of these appear in a review, name the exact tell, cite which gate it fails (design-law, craft, motion, etc.), and provide the fix. "Looks generic" is not a finding — the specific default must be named.
