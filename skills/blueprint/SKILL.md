---
name: blueprint
description: Build, query, or reconcile a repository graph or current-state map when that map is requested or required. Use for /blueprint, repository onboarding, architecture/flow maps, impact analysis, docs reconciliation, or grounding Audit/Architect. Excludes chat transcripts and ordinary bounded file inspection.
kind: capability
capabilityClass: context
discoverability: public
domain: engineering
operations:
  - analyze
  - produce
effects:
  - source-read
  - process-exec
  - artifact-write
hostRequirements:
  - blueprint-graph
metadata:
  legion:
    provenance: legion-authored
    licenseState: licensed
    rightsReceipt: LICENSE
    publish: true
---

# Blueprint

Blueprint owns current repository truth: source identity, graph structure, symbols, references,
flows, impact, freshness, doc truth, contradictions, coverage gaps, & re-anchoring.

Invoke Blueprint only when a repository graph/current-state map is requested or needed to resolve
material relationships. Chat transcripts, supplied prose, & ordinary bounded file inspection stay
direct. The no-grep-substitution rule applies only to claims requiring graph completeness.

## Entry routes

- Explicit `/blueprint`, “map/onboard to this repo,” or current-state architecture requiring a map →
  `blueprint doctor --json`; build when missing/stale; query `graph architecture`, `graph flows
  --complete`, & bounded `search|resolve|neighbors|path|impact` as needed.
- Current documentation truth, drift, or reconciliation → same fresh graph plus
  `blueprint reconcile --json`; report changed/current/superseded claims from generated evidence.
- Architecture judgment or design → Blueprint produces current state; Architect owns target-state
  choices, quality attributes, tradeoffs, ADRs, migrations, & acceptance.
- Audit → Blueprint supplies frozen audit projection & generation binding; Audit owns diagnosis,
  provider execution, findings, & report reconciliation.

Use resident Membrane transport when available, otherwise bounded one-shot CLI regardless of
enrollment. Preserve packet bytes, generation, freshness, manifest digest, source revision, &
receipt when forwarding. Never substitute ad-hoc grep for graph evidence or call partial output
complete. If both transports fail, return typed `membrane-unavailable`/`blueprint-graph`
degradation.
