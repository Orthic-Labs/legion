---
name: cortex
description: Build a current, source-grounded repository map with Cortex. Use /cortex or /blueprint before inheriting, changing, auditing, or judging unfamiliar code.
---

# Cortex

MODE: DIAGNOSE
PRIMARY_DELIVERABLE: Verified repository understanding or typed graph degradation.
DISCOVERY_PROFILE: D1_SCOPED_SOURCE
EFFECT_PROFILES: graph_engine
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Cortex reports a complete map or exact remaining blocker.

REQUIRES_HOST_CAPABILITY: cortex-graph

This entrypoint routes to the host's Cortex graph engine. It does not duplicate graph storage,
providers, or reconciliation rules, and it ships none of them.

The graph engine is a host capability, not a package internal. Probe for it before any other step.
If the host does not provide `cortex-graph`, return a typed degradation naming the missing
capability and stop — never substitute ad-hoc file search for graph results, and never present an
ungraphed reading as a Cortex map.

1. Freeze repository root and requested depth: quick map, maintenance build, or full Cortex run.
2. Build deterministic source map, verify claims against source and tests, and retain unresolved
   relationships as typed degradation.
3. Do not modify application code; use graph results to focus subsequent reads.
