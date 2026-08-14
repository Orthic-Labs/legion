# Self Review: Design

Run roles independently, then synthesize.

## Product Designer

- Mandate: Check task clarity, information architecture, hierarchy, and interaction flow.
- References: Nielsen Norman heuristics, Hick's law, Gestalt grouping.
- Evidence: screenshots, live page, user flow, states, copy, controls.
- Veto power: blocks unclear primary action, broken hierarchy, missing states, confusing flow.
- Ignore: code style and implementation internals.

## Interaction Designer

- Mandate: Find control, state, feedback, keyboard, responsive, and motion issues.
- References: Apple HIG, platform conventions, direct manipulation, predictable controls.
- Evidence: hover/focus/disabled/loading/error states, mobile/desktop screenshots.
- Veto power: blocks inaccessible or non-obvious controls, layout shifts, overlapping text.
- Ignore: marketing strategy.

## Visual Designer

- Mandate: Check craft, spacing, typography, color discipline, density, and visual system coherence.
- References: active design system, Gestalt, typography hierarchy, brand visual rules.
- Evidence: screenshots, component spacing, type scale, palette, imagery, repeated patterns.
- Veto power: blocks incoherent visual hierarchy, one-note palettes, amateur spacing, and off-system visuals.
- Ignore: backend implementation details.

## Conversion UX Reviewer

- Mandate: Check forms, checkout, pricing, trust, scanability, and decision friction.
- References: Baymard, CRO basics, clear comparison and repeated-use ergonomics.
- Evidence: form fields, validation, cards, tables, pricing, trust cues.
- Veto power: blocks avoidable abandonment, unclear pricing, hidden costs, weak trust.
- Ignore: artistic novelty unless it affects conversion.

## Accessibility Reviewer

- Mandate: Check WCAG 2.1 AA basics, focus order, contrast, labels, text overflow.
- References: WCAG, ARIA only when native controls cannot work.
- Evidence: colors, tab order, semantic controls, labels, zoom/mobile behavior.
- Veto power: blocks unreadable text, inaccessible controls, focus traps, overlap.
- Ignore: brand preference when it conflicts with accessibility.

## UX Copy Editor

- Mandate: Find vague labels, error-message confusion, tone mismatch, and cognitive load.
- References: plain-language UX writing, concrete nouns, one action per label.
- Evidence: labels, helper text, empty/error states, CTA text.
- Veto power: blocks misleading CTAs, unclear errors, unsupported proof claims.
- Ignore: layout unless copy cannot fit.
