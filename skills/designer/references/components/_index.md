# Exemplar Component Library

Production-grade section exemplars with motion baked in. **Generation is exemplar-first:** pick the
nearest exemplar, morph its structure, retheme it through tokens, rewrite every word of copy in
brand voice. Generate a section from scratch only when no exemplar is structurally close.

Why this exists: LLMs imitate exemplars far better than they follow prose rules. A build that
remixes these sections inherits their quality floor; a build synthesized from constraint lists
inherits the model's generic default. This library is the positive counterpart to the banned lists.

> **ENFORCEMENT (added 2026-07-17, orthiclabs post-mortem).** This index is a catalog, not the
> library. Reading THIS file does not count as exemplar-first — you MUST `Read` the exemplar
> file itself before building its section, and log the row in `artifacts/build-manifest.md`
> (`section → exemplar file → kept/changed`). The failure mode this kills: the model reads the
> catalog, believes it remembers what a strong section looks like, synthesizes from memory, and
> ships the generic default while calling it exemplar-first. Code in context or it didn't happen.

## Token contract (every exemplar uses ONLY these)

Exemplars never hardcode brand values. They consume CSS custom properties; brand swap is mechanical.

| Token | Meaning | Source |
|---|---|---|
| `--bg` | page base | `Content/<brand>/design/tokens.json` or `.claude/rules/brands.md` |
| `--surface` | card/raised surface | same |
| `--border` | hairlines, dividers | same |
| `--text` | primary text | same |
| `--muted` | secondary text | same |
| `--accent` | THE brand accent (one job per use) | same |
| `--accent-contrast` | text on accent fills | same |
| `--font-display` | display face | brand fonts |
| `--font-body` | body face | brand fonts |
| `--font-mono` | labels/data face | brand fonts |

Set them once on `:root` (or a theme wrapper), then drop exemplars in. Tailwind users: map them in
the config (`colors: { bg: 'var(--bg)', ... }`) or use arbitrary values (`bg-[var(--surface)]`).

## Catalog

| File | Section | Register | Engine |
|---|---|---|---|
| `hero-load-choreography.md` | Hero with staggered load choreography + word-mask headline | product or showpiece | Motion (motion/react) |
| `hero-scroll-scene.md` | Pinned, scroll-scrubbed hero scene (+ Lenis) | showpiece | GSAP ScrollTrigger |
| `nav-sticky.md` | Sticky nav that condenses + gains material on scroll | both | Motion |
| `feature-bento.md` | Bento feature grid, in-view stagger, hover lift | both | Motion |
| `marquee-logos.md` | Logo marquee, pause on hover, reduced-motion safe | both | CSS only |
| `pricing.md` | Pricing cards with billing toggle (layoutId pill) | both | Motion |
| `social-proof.md` | Testimonial columns + count-up stat row | both | Motion |
| `text-effects.md` | Split-text word reveal, scroll-scrub text fill, type-on | showpiece mostly | Motion / CSS |
| `micro-interactions.md` | Magnetic button, tilt card, press compress, underline | both | Motion / CSS |

## Adaptation rules

1. **Retheme, always.** Tokens carry identity. An exemplar shipped with placeholder values is a defect.
2. **Rewrite copy, always.** Placeholder copy never ships. Copy comes from `Content/<brand>/copy/bible.md`
   and the brand voice; the exemplar only proves the layout and motion.
3. **Restructure freely.** Exemplars are starting points, not components to preserve. Change grid
   counts, swap visual slots, merge sections. Keep the motion values (easing, durations, stagger)
   unless the brand's motion language says otherwise.
4. **Floors still apply.** `prefers-reduced-motion` variants, transform/opacity-only animation,
   keyboard focus, contrast. Every exemplar ships with these built in — do not strip them.
5. **Banned defaults still apply.** Exemplars are designed to not be the centered-hero/blob/SaaS-blue
   slop, but a lazy adaptation can regress into it. `../website.md` banned list is the one list to hold.
6. **Grow the library.** When a build produces a new section that would survive `/audit-visual`, add
   it here in the same format: intent header, token-only styling, full code, adaptation notes.

## Format of each exemplar file

```
# <name>
Intent · register · engine · brand-swap points
<full self-contained TSX/CSS code block>
Adaptation notes (what to change per brand, what to keep)
```
