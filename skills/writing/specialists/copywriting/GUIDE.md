---
name: writing-copy
description: Use when writing, auditing, or improving conversion copy, landing-page copy, sales pages, offers, email/DM scripts, bios, CTAs, ad copy, product copy, positioning copy, or any copy meant to persuade someone to click, buy, book, reply, subscribe, or trust.
---

# Copywriting

This guide owns persuasive/conversion copy. Use `/writing blog` for blog posts. Use `brand-identity` first if brand voice/promise is missing. Use `ads` for media-plan/campaign structure after copy passes offer/proof gates.

If the task asks to judge or improve copy in a rendered landing page, app screen, checkout, or live URL context, pair this with `audit-visual` and the shared `qa` skill for hidden screenshots and interaction evidence. Do not make visual hierarchy, above-fold, or CTA placement claims from copy text alone.

## Ad creative + scroll-stopping hooks (owned surfaces)

This skill also owns **ad copy/creative** (headlines, descriptions, primary text, RSA/Meta/LinkedIn/TikTok/X variations, performance iteration, generative ad visuals/voice) and **scroll-stopping hooks** (pattern-break openers, the 0.3s algorithm filter). Load the matching reference on demand:

| Intent / phrasing | Read reference |
|---|---|
| Ad copy/creative — headlines, descriptions, ad variations, bulk/CSV output, iterate from performance data | `references/ad.md` |
| Ad platform character limits + format rules (Google RSA, Meta, LinkedIn, TikTok, X) | `references/ad-assets/platform-specs.md` |
| Generative ad visuals/video/voice tooling (Nano Banana, Flux, Veo, ElevenLabs, Remotion) | `references/ad-assets/generative-tools.md` |
| Scroll-stopping hook, opening line, pattern-break, 0.3s algorithm filter ("would this stop scroll?") | `references/hook.md` |
| Stronger copy craft, line edits, landing-page hero fixes, specificity, proof, "why is this generic?" | `references/craft-research.md` |

The 0.3s algorithm filter in `references/hook.md` and the Three-Question gate in `references/craft-research.md` are reusable final gates on any hook/headline before delivery. For campaign strategy/targeting/budgets (not copy), route to `ads`. For social-platform-native scripts, route to `social`/`writing-pro`.

## State Machine

| # | Phase | Mode | Emits / blocks on |
|---|---|---|---|
| 0 | **Context** | auto | audience, offer, action |
| 1 | **Promise gate** | auto **HARD GATE** | sharp promise |
| 2 | **Proof gate** | auto **HARD GATE** | evidence, mechanism, credibility |
| 3 | **Craft gate** | auto **HARD GATE** | visualizable, falsifiable, ownable, fast |
| 4 | **Message architecture** | auto | hook, value, objection, CTA |
| 5 | **Variants** | auto | 3 distinct copy registers |
| 6 | **Anti-slop QA** | auto **HARD GATE** | no generic copy, no unsupported claims |
| 7 | **Final copy + notes** | auto | recommended version and why |

## Inherited-copy rule (HARD GATE — no exceptions)

Copy inherited from a reference artifact (a user-loved comp, a previous version, a competitor
page) is NOT pre-approved. A user approving a design or reference approves its look, never its
lines. Every inherited line runs the same Phase 1-3 gates as fresh copy. "The user said they love
this file" is a design signal, not a copy waiver. (Added 2026-07-16 after an agency-broken hero
line was shipped verbatim from a reference comp.)

## Rendered-page gate table (HARD GATE when copy ships to a rendered surface)

Before delivery — and on EVERY audit or challenge pass — read the rendered page top to bottom
(not from memory) and emit a gate table: one row per hero line and per section kicker/h2/deck,
with (a) the literal cold-read meaning — who is the subject, what does the sentence claim to a
stranger; (b) visualizable / falsifiable / ownable verdicts; (c) an adjacency verdict — does the
deck/lede follow from its h2 as one argument. Agency-broken lines (the product owning the user's
action), meaning-empty lines, and title↔deck non-sequiturs are automatic fails. No table, no pass.

## Phase 0: Context

Identify:

- Audience
- Their current pain/desire
- Offer/product/service
- Desired action
- Channel/page placement
- Brand voice
- Constraints and banned claims

## Phase 1: Promise Gate

Hard stop until the promise is:

- Specific
- Audience-relevant
- Outcome-oriented
- Believable
- Differentiated
- Short enough to say aloud

Reject promises that are only "save time", "grow faster", "premium quality", "trusted", or "AI-powered" unless made specific with proof and mechanism.

## Phase 2: Proof Gate

Every persuasive claim needs support:

- Numbers
- Customer evidence
- Founder/operator experience
- Demonstrable product mechanism
- Before/after
- Guarantee/risk reversal
- Credible constraint or tradeoff

No fabricated stats, testimonials, case studies, or press.

## Phase 3: Craft Gate

For meaningful conversion copy, hero copy, audit/rewrite work, or any draft that feels generic, load `references/craft-research.md` and run these gates before building the page:

- **Visualizable**: can the reader picture a person, action, object, number, scene, before/after, or workflow?
- **Falsifiable**: could a skeptical reader check, disagree with, or disprove the claim?
- **Ownable**: could a competitor paste this under their logo? If yes, fail.
- **Speed-to-value**: is the topic and payoff clear in the first line or CTA context?
- **Pointable proof**: does each strong claim point to evidence, mechanism, example, or constraint?
- **Every word works**: remove neutral words, throat-clearing, and adjectives that do not clarify proof or action.

Use the Zoom-In Worksheet from `references/craft-research.md` for vague claims: move from abstraction to a concrete, demonstrable, or photographable phrase.

## Phase 4: Message Architecture

Build:

- Hook
- One-sentence promise
- Mechanism: why this works
- Benefits tied to customer pains/desires
- Objections and answers
- Proof points
- CTA
- Fallback/secondary CTA if needed

## Phase 5: Variants

Produce three distinct registers:

- Safe/commercial
- Distinctive/opinionated
- Bold/high-variance

They should share the same promise and proof, not become unrelated offers.

## Phase 6: Anti-Slop QA

Fail if copy contains:

- "Unlock", "leverage", "seamless", "game-changer", "next-gen", "in today's fast-paced world"
- Generic benefits without concrete user situation
- Unsupported superlatives
- CTA not matched to audience readiness
- Long paragraphs that bury the action
- Overpromising beyond proof
- Voice that could fit any competitor
- Claims that are not visualizable, falsifiable, or ownable
- A hook that delays the topic beyond the first sentence
- Sentences that can be deleted without changing meaning
- Section furniture that restates its neighbor — a kicker/eyebrow restating the h2, a deck
  restating the headline, a subhead restating the paragraph ("Available now / four working paths"
  over "Four working paths, available now."). Every label must carry information the adjacent copy
  doesn't; otherwise delete it and let headline + deck carry. A kicker is earned only when it adds
  a real axis (e.g., a contrasting pair like AVAILABLE TODAY / NOT INCLUDED TODAY)

## AUDIT MODE — Conversion Copy Audit

Trigger: existing copy is provided for review rather than new copy being requested. Trigger phrases: "audit this copy," "score this page," "what's wrong with this copy," "review my landing page copy," "is this converting."

**Role: Conversion Copy Auditor.** You are a master of direct-response conversion copywriting. You evaluate text based on cognitive fluency and persuasion. You know that if a user has to think for even one second about what to do next, you have lost them. You despise AI-generated corporate jargon.

### Audit checks (run in order)

1. **Grunt test** — Can a stranger identify What / Why / What-next in 5 seconds? If not, fail.
2. **Three-Question line gate** — The hook and major claims must be visualizable, falsifiable, and ownable. Competitor-signable copy fails.
3. **Speed-to-value** — Topic and payoff must arrive before preamble. Delay, confusion, irrelevance, and disinterest are failures.
4. **Features → benefits translation** — Every feature claim must map to a customer outcome. "Fast" is not a benefit. "Back in your inbox before the meeting ends" is.
5. **Pointable proof** — Strong claims need adjacent evidence, mechanism, example, number, before/after, constraint, or proof placeholder. Unsupported proof is a fail.
6. **Objection handling** — Price / trust / effort objections. Are they addressed? Where? Objection copy buried below the fold is the same as missing.
7. **Social proof placement** — Must sit adjacent to the claim it supports. Testimonials at page-bottom are inert. Score as misplaced if they are not next to the claim.
8. **Microcopy friction** — Error messages, form labels, empty states, CTA button text. Passive CTAs ("Submit," "Click Here," "Learn More") are a fail. CTA must name the outcome ("Get my free audit," "Start saving").
9. **Slop eradication** — Fail on any of: leverage, synergy, seamless, elevate, delve, innovative, revolutionary, disruptive, game-changing, unlock, "In today's fast-paced world," cliché openers ("Are you tired of…"), passive CTAs.
10. **Redundant section furniture** — Compare every kicker/eyebrow, deck, and subhead against its adjacent heading. If one restates the other, it fails: keep the stronger line, delete the echo. Repeated kicker-then-h2 scaffolding on every section is the AI-template tell even when each line is individually fine.

### Audit output (required sections)

**Conversion Clarity Score: X/10** — single score with one-sentence rationale.

**1. Clarity Score breakdown** — which checks passed and failed, one line each.

**2. Hook Rewrite** — rewrite the opening hook only. Show original → rewrite. Explain what was wrong.

**3. Specificity + Proof Gaps** — list vague, unsupported, non-visualizable, non-falsifiable, or competitor-signable claims with a concrete replacement or proof request.

**4. Unhandled Objections** — list the top 2-3 objections the copy ignores, with a suggested one-liner for each.

**5. Slop Eradication** — quote every slop phrase found; suggest a concrete replacement for each.

**6. Microcopy Fixes** — list every passive CTA, generic label, or error-tone problem with a specific fix.

**7. Redundancy Kills** — list every furniture/heading pair that says the same thing twice; name which line survives.

Do not rewrite the entire page in audit mode — that is the write/rewrite flow above. Audit = score + targeted fixes only.

## Completion Checklist

- Audience and action clear
- Promise gate passed
- Proof gate passed
- Craft gate passed: visualizable, falsifiable, ownable, fast
- Message architecture complete
- Three variants explored for major copy
- Unsupported claims removed
- CTA matches intent
- Proof gaps marked instead of invented
- Recommended version selected
