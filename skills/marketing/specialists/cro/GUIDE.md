---
name: marketing-cro
description: >
  CRO branch for measurable conversion improvements. Routes to specialized references for
  form CRO, onboarding/activation, marketing page CRO, paywalls/upgrades, popups/modals, retention/churn,
  signup. Use when user says "/marketing cro", "improve conversion", "CRO", "increase signups", "reduce churn",
  "optimize page", "fix paywall", "popup conversion", "improve form", "onboarding flow".
argument-hint: "form | onboarding | page | paywall | popup | retention | signup | <freeform>"
---

# CRO Guide

Single entry for all CONVERSION OPTIMIZATION work (improving an existing flow for measurable outcome). Sub-references in `references/` are loaded on demand.

**Live-URL gate (MANDATORY):** When the flow/page/paywall/popup/signup exists as a live URL, localhost route, or app preview, the shared `qa` skill chain is required — not optional — before issuing any visual or interaction verdict. Use the project `qa:browser` contract when available; otherwise use the `qa` skill's `scripts/qa-functional.mjs` for click/hover/type/assert flows and `scripts/qa-shot.mjs` for viewport screenshots. A CRO verdict issued without browser evidence for a live URL is invalid. Do not use foreground desktop screenshots for routine CRO QA.

## Routing - match user intent to a reference

| Intent / phrasing | Read reference |
|---|---|
| Lead capture / contact / demo request / application / survey / checkout form (NOT signup) | `references/form.md` |
| Post-signup onboarding, activation, first-run, time-to-value | `references/onboarding.md` |
| Homepage / landing / pricing / feature page / blog conversion | `references/page.md` |
| In-app paywall, upgrade screen, upsell modal, feature gate | `references/paywall.md` |
| Popup, modal, overlay, slide-in, banner, exit intent | `references/popup.md` |
| Churn reduction, cancellation flow, save offer, failed payment recovery | `references/retention.md` |
| Signup / registration / account creation / trial activation | `references/signup.md` |

When invoked, decide which reference matches, Read it, follow its instructions.

## Internal CRO Council

Run this internally after identifying the flow and metric. It improves the test plan; it is not `/review`.

| Reference | Role pass |
|---|---|
| `form.md` | Friction auditor, trust/privacy skeptic, field-logic simplifier, validation/error UX lead |
| `onboarding.md` | Activation strategist, product educator, dropoff analyst, habit/retention lead |
| `page.md` | Message-match lead, hierarchy/CRO designer, proof skeptic, analytics lead |
| `paywall.md` | Pricing/value strategist, buyer objection skeptic, UX friction lead, revenue-risk analyst |
| `popup.md` | Timing/intent strategist, annoyance skeptic, offer quality lead, accessibility guard |
| `retention.md` | Churn analyst, customer-success advocate, save-offer skeptic, dunning/payment operator |
| `signup.md` | Activation designer, account-friction auditor, trust/privacy skeptic, experimentation lead |

Output standard: measurable hypothesis, proposed change, expected impact, risk, instrumentation, and decision rule.

**Each reference outputs a measurable hypothesis + test plan, not just opinions.** Pair with `/marketing growth ab-test` to ship the experiment.
