---
name: research
description: "Find and synthesize external information for research deliverables, including market, technical, scientific, medical, legal, competitor, Reddit, audience, trends, scholarly, and NotebookLM research. Excludes local transcript inspection, repository reading, and simple supplied-source reading."
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
hostRequirements:
  - legion
  - web-search
---

# Research

Use Research only when requested outcome requires finding or synthesizing external information.
Reading local transcripts, inspecting repository files, or opening/summarizing a supplied source
without external investigation stays direct. Medical and legal are private internal routes; India
consumer-commission filing is a Legal workflow.

PRIMARY_DELIVERABLE: Frozen `ResearchRoute` plus route-scoped evidence artifact.
RESOURCE_BUDGET: hook-metered by route scale, never model-counted.
MAY_ADD_TASKS: NO · MAY_CALL_SKILLS: NONE
TERMINAL: Receipt records route, effects, evidence, gaps, checks, verdict.

`doctor`, `legal`, `consumer-court`, `notebooklm` are internal routes, never catalog entries.

1. Freeze `references/route-schema.json` through native `legion research --query <query>`, with
   optional `--domain` (`general` default, `market`, `technical`, `scientific`, `medical`, `legal`)
   and `--sensitivity` (`public` default, `private`, `highly-sensitive`). The CLI does not classify
   the query; the caller chooses the domain. Supply complete typed medical or legal subject context
   with `--route-json <route.json>` when needed; route JSON must bind the same query, and explicit
   convenience flags must agree. Anonymous medical and jurisdiction-complete legal routes are
   reachable. Personal medical routes retain their existing history and approval gates; typed
   input does not grant approvals or perform stateful/external effects. See `references/router.md`.
2. Supply host-opened evidence as `--source-record <record.json>` inputs; native route validation
   enforces provider denominator & resource bounds.
3. Execute only through installed `legion research`; Python product runtime is retired. Do not
   instruct a reader to run any `src/lib/research-core/**` script — it does not ship.
   NotebookLM stateful work (search, create, upload, generate, download) requires a callable
   `notebooklm` host adapter actually exposed in the current host. The native command only consumes
   host-opened source records; with no callable adapter, preserve the route and report
   `unavailable`. See `references/providers/notebooklm.md`.
4. A hit is a lead; evidence needs an opened source and located passage; preserve atomic
   claims, contradictions, dates, scope, uncertainty.
5. `verified` adds domain verification, citation-support, DOI retraction checks. Corrections
   use native `issue-patch` and `apply-patch` steps; run ID, canonical draft path and source
   hash are HMAC-bound to an existing key file, with an exact Read+Edit grant and bounded
   hunks. Create the key file from OS cryptographic randomness before invoking the CLI.
   This receipt is CLI integrity evidence, not hook attestation.

Routing: `references/router.md`; runtime contract: `legion research --help`.
