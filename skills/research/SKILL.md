---
name: research
description: "Research a question from external sources and produce a cited, evidence-backed brief or analysis: current public guidance, market, competitor, technical, scientific, medical, legal, audience, scholarly, or trend questions, or NotebookLM work. Use when the answer requires searching and opening outside sources and recording dated claims and uncertainty. Not for reading local files or transcripts, or summarizing a source the user already supplied."
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
   enforces provider denominator & resource bounds. Order is fixed: (a) open the 2 or 3 most
   authoritative sources from distinct domains, at most 3 fetches in total (an unreadable fetch
   counts; take the next source instead of retrying); (b) write one record per file with Edit
   (replace an empty `{}` stub after Reading it), or Write for a new file; (c) run the route as the
   very next call. Search or fetch more only after the route returns, and only to close the gaps it
   reports. Shape: `references/source-record.example.json`; unknown keys are rejected. Give each
   record the real page URL in `uri`: independence is counted from its domain, not from `provider`.
   Records without an http(s) URL are reported self-declared and do not meet the default
   requirement. `content_digest` (`sha256:` + hex of `text`) and `byte_length` (UTF-8 byte count of
   `text`) are optional: omit both and the route computes them and flags `digestComputedByRoute`.
   Never invent either value; a present value that does not match `text` is rejected. Run the route
   as ONE plain command, binary path and flags exactly as the request or plan gives them: `legion
   research --query '<query>' --source-record <f1> [--source-record <f2> ...]`. Do not chain (`;`
   `&&` `|`), prefix `cat`/`ls`/`echo`, or add `--help`; hosts that permit the route often permit
   only that exact command. The command runs even when records are incomplete and returns a typed
   result (`unproven` with per-record rejection reasons); report that result verbatim. Never
   replace the route with web search, and never say it cannot run before issuing it once.
3. Execute only through installed `legion research`; Python product runtime is retired. Do not
   instruct a reader to run any `src/lib/research-core/**` script — it does not ship.
   NotebookLM stateful work (search, create, upload, generate, download) requires a callable
   `notebooklm` host adapter actually exposed in the current host. The native command only consumes
   host-opened source records; with no callable adapter, preserve the route and report
   `unavailable`. See `references/providers/notebooklm.md`. To record it, write a route JSON
   (`provider: notebooklm`, matching operation and effects) and run
   `legion research --query <q> --route-json <route.json>`; the typed `unavailable` result is the
   evidence.
4. A hit is a lead; evidence needs an opened source and located passage; preserve atomic
   claims, contradictions, dates, scope, uncertainty.
5. `verified` adds domain verification, citation-support, DOI retraction checks. Corrections
   use native `issue-patch` and `apply-patch` steps; run ID, canonical draft path and source
   hash are HMAC-bound to an existing key file, with an exact Read+Edit grant and bounded
   hunks. Create the key file from OS cryptographic randomness before invoking the CLI.
   This receipt is CLI integrity evidence, not hook attestation.

Routing: `references/router.md`; source-record contract: `references/source-record.example.json`
(`legion research --help` lists flags only, not record fields; do not run it to learn them).
