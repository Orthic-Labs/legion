# Covenant lens — Design

**What this is:** a recovered domain review lens from Council, deleted at workspace commit
`d810d827` (the engine was ported to `skills/covenant/`; this content was not — same gap as
the Sage manuals recovered in J-1). Source: `git show d810d827^:tools/skills/council/references/design.md`
(51 lines). Assigned to a Covenant seat at convene time — **one lens per seat**, per
`doctrine/covenant-seat.md` §"lens index" — this file IS the specialization a seat reads once
assigned.

**Read `doctrine/covenant-seat.md` and `$WORKSPACE/docs/plans/legion/COVENANT.md` first.** This bundle is domain craft under
that constitution, not a replacement for it. Everything below is preserved verbatim from Council
except where a `> **Superseded:**` note marks a doctrine conflict.

> **Superseded:** every "Veto power" line below is retained verbatim as the original review
> craft's framing of severity/blocking judgment. Under Covenant doctrine (C-invariants), no seat
> decides or disposes — a seat is advisory only (`$WORKSPACE/docs/plans/legion/COVENANT.md`). What reads as
> "blocks" here is the analogue of a maximum-severity finding handed to the caller (Sage or
> Alchemist) for disposition, never a seat-authored block.

---

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
