---
name: qa
description: Add, run, or audit local web or Tauri app QA: hidden servers, deterministic mocks, functional assertions, viewport captures, visual evidence, & contract-test authoring.
kind: capability
capabilityClass: domain
discoverability: public
domain: engineering
operations:
  - analyze
  - evaluate
  - execute
  - produce
effects:
  - source-read
  - artifact-write
  - process-exec
---

# QA

PRIMARY_DELIVERABLE: Bounded behavior & artifact evidence.
SPECIALIST_REFS_MAX: 1
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Frozen criteria have exact passing evidence or failing artifact.

1. Read project QA contract; reuse it rather than inventing another harness.
2. Freeze revision, route, viewport, selector, state, fixture, environment, & acceptance criteria.
3. Test behavior first with `scripts/qa-functional.mjs`; capture app viewport with `scripts/qa-shot.mjs`; inspect final rendered states.
4. Record commands, artifact paths, failures, skipped coverage, & cleanup.

Read `references/manual.md` for harness, full visual, native, or Tauri QA. `/qa contract-tests` derives smallest observable boundary, negative, transition, & regression tests.
