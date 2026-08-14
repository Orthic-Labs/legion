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

This entrypoint routes to existing Cortex graph engine. It does not duplicate graph storage,
providers, or reconciliation rules.

1. Freeze repository root and requested depth: quick map, maintenance build, or full Cortex run.
2. Build deterministic source map, verify claims against source and tests, and retain unresolved
   relationships as typed degradation.
3. Do not modify application code; use graph results to focus subsequent reads.
