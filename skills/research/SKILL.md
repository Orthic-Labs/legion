---
name: research
description: "Sole top-level evidence router: general, market, technical, scientific, medical, legal, competitor, Reddit, audience, trends, scholarly, documents, authority, and NotebookLM. Medical and legal are private internal routes; India consumer-commission filing is a Legal workflow."
---

# Research

MODE: ROUTE · DISCOVERY_PROFILE: D3_EXTERNAL
PRIMARY_DELIVERABLE: Frozen `ResearchRoute` plus route-scoped evidence artifact.
EFFECT_PROFILES: external_research, sensitive_source, connector, output_write, child_packet
RESOURCE_BUDGET: hook-metered by route scale, never model-counted.
MAY_ADD_TASKS: NO · MAY_CALL_SKILLS: NONE
TERMINAL: Receipt records route, effects, evidence, gaps, checks, verdict.

`doctor`, `legal`, `consumer-court`, `notebooklm` are internal routes, never catalog entries.


1. Freeze `references/route-schema.json` via `router/route_resolve.py` (Stage 1, zero effects);
   run `references/route-gates.md`; resume Stage 2 only on recorded approval receipts.
2. Load ≤1 domain, ≤2 method, ≤1 assurance guide via `resource_guard.py` with the run id;
   direct reads are invalid.
3. Execute through `run.py` on the hook meter.
4. A hit is a lead; evidence needs an opened source and located passage; preserve atomic
   claims, contradictions, dates, scope, uncertainty.
5. `verified` adds domain verification, citation-support, DOI retraction checks; corrections
   use a Read+Edit-only patch receipt with hunk caps.

Paths: `src/lib/research-core/`; routing: `references/router.md`.
