---
name: ads
description: "Audit, plan, create, or optimize paid campaigns across Google, Meta, YouTube, LinkedIn, TikTok, Microsoft, or Apple. Use for PPC, ROAS, CPA, targeting, bidding, retargeting, budgets, creative, or ad-spend questions."
kind: capability
capabilityClass: domain
discoverability: public
domain: commercial
operations:
  - analyze
  - decide
  - produce
effects:
  - source-read
  - network-request
hostRequirements:
  - banana-image
  - web-search
---

# Ads

PRIMARY_DELIVERABLE: Evidence-bound paid-media findings or plan.
SPECIALIST_REFS_MAX: 1
CHILD_AGENTS_MAX: 6
EXTERNAL_REQUESTS_MAX: 12
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: writing, designer, audit-visual, qa
TERMINAL: Paid-media findings or plan answer frozen scope with evidence.

Work only within granted accounts, URLs, files, dates, platforms, & spend.

## Route

- Platform audit: read `references/google-audit.md`, `references/meta-audit.md`, `references/linkedin-audit.md`, `references/tiktok-audit.md`, or `references/microsoft-audit.md` for the matching platform; use `references/scoring-system.md`. YouTube and Apple have no audit reference: read `references/youtube.md` or `references/apple.md` instead.
- Platform strategy: read `references/<platform>.md` plus only relevant targeting, bidding, budget, tracking, compliance, or benchmark reference.
- Creative: read `references/create.md`; add exact platform creative spec & `references/compliance.md`.
- Landing page: read `references/landing.md`.
- Competitor or brand DNA: read `references/competitor.md` or `references/dna.md`.
- Full multi-platform plan or unfamiliar command: read `references/manual.md`.
- Agent briefs: the 10 files in `agents/` are role briefs, not registered plugin agents. Only a full `/ads audit` fans out, to at most six subagents (`audit-google`, `audit-meta`, `audit-creative`, `audit-tracking`, `audit-budget`, `audit-compliance`), each started with the full text of its `agents/<name>.md` as its brief. The creative briefs (`creative-strategist`, `copy-writer`, `visual-designer`, `format-adapter`) are run inline, in order, by the main agent; they never spawn.

### Shared preflight for strategy, optimization, & creative

Apply these minimum checks to every route, without requiring a full audit for a narrow request:

- **Offer & proof:** identify audience, promise, mechanism, CTA, conversion event, and any offer terms. Support claims with supplied evidence or remove them; never invent proof.
- **Measurement:** identify the conversion event, tracking/reporting source, attribution window, and whether value is recorded. For creative-only work, unknown tracking may be recorded as an open launch blocker; never imply optimization or launch readiness without it.
- **Destination:** check message-to-landing-page match, visible offer, trust/proof, CTA, and basic mobile/function readiness when a destination is supplied. If it cannot be inspected, say so and leave launch readiness unverified.
- **Platform & compliance:** use the exact platform/placement specification and check applicable policy, privacy, and claim constraints.
- **Spend bounds:** distinguish a proposed budget from an enforced cap. Verify a cap control is supported for the actual campaign type, duration, & account before claiming a hard ceiling. If no eligible control is verified, name a numeric stop threshold, monitoring owner/cadence, & headroom grounded in spend behavior and pause/reporting delay; if those cannot be established, keep launch blocked and label spend control unverified. Do not infer eligibility from a feature available only to other or new campaigns.

Creative may proceed as a **provisional draft** when a missing input does not prevent safe concept or copy work. Mark assumptions and unresolved gates; do not call it launch-ready or recommend launch until applicable offer, proof, tracking, destination, platform, and compliance gates pass. A missing or unsupported claim is omitted or labeled for substantiation, not filled in.

## Execute

1. Freeze objective, platform, market, account scope, dates, budget, conversion event, & available evidence.
2. Label missing access or data; never invent performance, spend, benchmarks, or attribution.
3. Prefer official platform sources for unstable policies or specifications.
4. Separate observed facts, calculations, assumptions, & recommendations.
5. Return prioritized actions with owner, expected effect, confidence, & verification.
6. Require explicit current-build authority before spend, publication, or live account mutation.
