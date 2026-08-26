---
name: research
description: "Sole top-level evidence router: general, market, technical, scientific, medical, legal, competitor, Reddit, audience, trends, scholarly, documents, authority, and NotebookLM. Medical and legal are private internal routes; India consumer-commission filing is a Legal workflow."
kind: capability
capabilityClass: domain
discoverability: public
domain: research
operations:
  - route
  - analyze
  - produce
effects:
  - source-read
  - artifact-write
  - network-request
hostRequirements: []
---

# Research

PRIMARY_DELIVERABLE: Frozen `ResearchRoute` plus route-scoped evidence artifact.
RESOURCE_BUDGET: hook-metered by route scale, never model-counted.
MAY_ADD_TASKS: NO · MAY_CALL_SKILLS: NONE
TERMINAL: Receipt records route, effects, evidence, gaps, checks, verdict.

`doctor`, `legal`, `consumer-court`, `notebooklm` are internal routes, never catalog entries.

1. Freeze `references/route-schema.json` through native `legion research --query <query>` routing;
   run `references/route-gates.md`; resume only on recorded approval receipts.
2. Supply host-opened evidence as `--source-record <record.json>` inputs; native route validation
   enforces provider denominator & resource bounds.
3. Execute only through installed `legion research`; Python product runtime is retired.
4. A hit is a lead; evidence needs an opened source and located passage; preserve atomic
   claims, contradictions, dates, scope, uncertainty.
5. `verified` adds domain verification, citation-support, DOI retraction checks; corrections
   use a Read+Edit-only patch receipt with hunk caps.

Routing: `references/router.md`; runtime contract: `legion research --help`.
