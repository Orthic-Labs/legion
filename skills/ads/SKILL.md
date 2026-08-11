---
name: ads
description: "Audit, plan, create, or optimize paid campaigns across Google, Meta, YouTube, LinkedIn, TikTok, Microsoft, or Apple. Use for PPC, ROAS, CPA, targeting, bidding, retargeting, budgets, creative, or ad-spend questions."
---

# Ads

MODE: DIAGNOSE
PRIMARY_DELIVERABLE: Evidence-bound paid-media findings or plan.
DISCOVERY_PROFILE: D3_EXTERNAL
EFFECT_PROFILES: external_research, connector
SPECIALIST_REFS_MAX: 1
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 12
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Paid-media findings or plan answer frozen scope with evidence.

Work only within granted accounts, URLs, files, dates, platforms, & spend.

## Route

- Platform audit: read `references/<platform>-audit.md`; use `references/scoring-system.md`.
- Platform strategy: read `references/<platform>.md` plus only relevant targeting, bidding, budget, tracking, compliance, or benchmark reference.
- Creative: read `references/create.md`; add exact platform creative spec & `references/compliance.md`.
- Landing page: read `references/landing.md`.
- Competitor or brand DNA: read `references/competitor.md` or `references/dna.md`.
- Full multi-platform plan or unfamiliar command: read `references/manual.md`.

## Execute

1. Freeze objective, platform, market, account scope, dates, budget, conversion event, & available evidence.
2. Label missing access or data; never invent performance, spend, benchmarks, or attribution.
3. Prefer official platform sources for unstable policies or specifications.
4. Separate observed facts, calculations, assumptions, & recommendations.
5. Return prioritized actions with owner, expected effect, confidence, & verification.
6. Require explicit current-build authority before spend, publication, or live account mutation.
