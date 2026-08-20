---
name: brand
description: "Load a source-bound brand card before branded content, design, marketing, social, or media work. Use /brand when a named brand or approved identity source governs an output."
kind: capability
capabilityClass: context
discoverability: public
domain: null
operations:
  - analyze
  - produce
effects:
  - source-read
hostRequirements: []
---

# Brand

PRIMARY_DELIVERABLE: Source-bound Brand Card.
SPECIALIST_REFS_MAX: 0
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: One source-bound Brand Card is ready for downstream use.

1. Resolve one named brand or approved identity source. Do not infer brand facts from a name.
2. Load only its authorized private overlay or supplied source. This package carries no brand corpus.
3. Extract voice, visual system, restrictions, required assets, approval state, & source identity into a compact Brand Card.
4. Treat locked identity rules as invariants. Separate source facts from open decisions.
5. If no authorized source is available, return `brand-source-unavailable`; do not create, substitute, or expose a private identity.
6. Hand the Brand Card to downstream Writing, Content, Designer, Ads, Social, or Marketing work.

Use `/brand-identity` to create or evolve an identity system.
