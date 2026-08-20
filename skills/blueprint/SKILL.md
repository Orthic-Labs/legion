---
name: blueprint
description: Build or consume current source-grounded repository truth through Membrane's Blueprint packet. Use /blueprint before inheriting, changing, auditing, or judging unfamiliar code.
kind: capability
capabilityClass: context
discoverability: public
domain: engineering
operations:
  - analyze
  - produce
effects:
  - source-read
hostRequirements: []
---

# Blueprint

Blueprint owns repository truth: source identity, graph structure, symbol/reference relations,
impact, freshness, & re-anchoring. Legion consumes only a typed Membrane packet.

Legion must not invoke a repository mapper, walk source files, open Blueprint storage, select
evidence, or synthesize a fallback. If Membrane transport is unavailable, return typed
`membrane-unavailable` degradation.

Use `/blueprint` for a current repository map. Preserve packet bytes & receipt binding when
forwarding to planning, audit, dispatch, or Oracle.
