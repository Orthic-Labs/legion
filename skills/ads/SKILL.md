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

## Execute

1. Freeze objective, platform, market, account scope, dates, budget, conversion event, & available evidence.
2. Label missing access or data; never invent performance, spend, benchmarks, or attribution.
3. Prefer official platform sources for unstable policies or specifications.
4. Separate observed facts, calculations, assumptions, & recommendations.
5. Return prioritized actions with owner, expected effect, confidence, & verification.
6. Require explicit current-build authority before spend, publication, or live account mutation.
