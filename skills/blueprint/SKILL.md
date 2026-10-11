---
name: blueprint
description: Query or reconcile a repository graph or current-state map through the optional Blueprint host capability (blueprint-graph) when that map is requested or required. Use for /blueprint, repository onboarding, architecture/flow maps, impact analysis, docs reconciliation, or grounding Audit/Architect. Excludes chat transcripts and ordinary bounded file inspection. Without the host capability it returns a NO_CAPABILITY result.
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

This skill queries and reconciles current repository truth that the Blueprint host capability
(`blueprint-graph`) provides: source identity, graph structure, symbols, references, flows, impact,
freshness, doc truth, contradictions, coverage gaps, & re-anchoring. The package does not build the
graph itself.

The Blueprint host capability is optional; this package does not ship it. When it is unavailable,
this skill does not build or fake a graph: it returns the typed `NO_CAPABILITY` result naming
`blueprint-graph`, and the caller continues with ordinary bounded file inspection while stating that
no graph evidence was produced.

Invoke this skill only when a repository graph/current-state map is requested or needed to resolve
material relationships. Chat transcripts, supplied prose, & ordinary bounded file inspection stay
direct. Never substitute ad-hoc grep for graph evidence, and never present partial graph output as
complete.

## Entry routes

- Explicit `/blueprint`, “map/onboard to this repo,” or current-state architecture requiring a map →
  `blueprint doctor --json`; if doctor reports the graph missing or stale, return that status to the
  caller instead of building it; otherwise query `graph architecture`, `graph flows --complete`, &
  bounded `search|resolve|neighbors|path|impact` as needed.
- Current documentation truth, drift, or reconciliation → same fresh graph plus
  `blueprint reconcile --json`; report changed/current/superseded claims from generated evidence.
- Architecture judgment or design → Blueprint produces current state; Architect owns target-state
  choices, quality attributes, tradeoffs, ADRs, migrations, & acceptance.
- Audit → Blueprint supplies frozen audit projection & generation binding; Audit owns diagnosis,
  provider execution, findings, & report reconciliation.

Use resident Blueprint transport when available, otherwise bounded one-shot CLI regardless of
enrollment. Preserve packet bytes, generation, freshness, manifest digest, source revision, &
receipt when forwarding. Never substitute ad-hoc grep for graph evidence or call partial output
complete. If both transports fail, return the typed `NO_CAPABILITY` result naming `blueprint-graph`.
