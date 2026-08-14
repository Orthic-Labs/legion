---
name: qa
description: "Add, run, or audit app QA for local web or Tauri apps: hidden QA servers, deterministic mocks, functional assertions, viewport or selector captures, visual evidence, app-only captures, and contract-test authoring."
---

# QA

MODE: EXECUTE
PRIMARY_DELIVERABLE: Bounded behavior & artifact evidence.
DISCOVERY_PROFILE: D1_SCOPED_SOURCE
EFFECT_PROFILES: runtime
SPECIALIST_REFS_MAX: 0
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Frozen QA criteria have exact behavior or artifact evidence.

1. Read repository QA contract first; do not invent a second harness.
2. Read `references/manual.md` for new harnesses, full QA, native or Tauri foreground QA, or visual evidence.
3. Use existing scripts for deterministic start, probe, capture, assertion, cleanup, & report steps.
4. Freeze revision, routes, viewports, selectors, states, data, environment, & acceptance criteria.
5. Prefer deterministic QA mode & local fixtures over network-dependent state.
6. Test behavior before screenshots; inspect final rendered states after source checks.
7. Record exact commands, artifact paths, failures, skipped coverage, & cleanup.

## Contract tests

Use `/qa contract-tests`; the legacy test-author command resolves here.

1. Derive observable contracts from requirements, public interfaces, incidents, or bugs.
2. Add smallest tests that fail for defect & pass for correct behavior.
3. Cover boundary, negative, state-transition, & regression cases proportional to risk.
4. Avoid tests that only mirror implementation details.
