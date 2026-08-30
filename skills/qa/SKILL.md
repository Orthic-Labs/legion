---
name: qa
description: "Add, run, or audit local web or Tauri app QA: hidden servers, deterministic mocks, functional/browser assertions, supporting viewport captures, runtime checks, & contract-test authoring."
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
hostRequirements: []
---

# QA

PRIMARY_DELIVERABLE: Bounded functional, behavioral, browser, & runtime evidence.
SPECIALIST_REFS_MAX: 1
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Frozen criteria have exact passing evidence or failing artifact.

1. Read project QA contract; reuse it rather than inventing another harness.
   EXECUTOR:
     semantic: required
     capabilities:
       - source-read
2. Freeze revision, route, viewport, selector, state, fixture, environment, & acceptance criteria.
   EXECUTOR:
     semantic: required
     capabilities:
       - repository-truth-read
       - source-read
3. Test behavior with `scripts/qa-functional.mjs`; use `scripts/qa-shot.mjs` only for supporting viewport artifacts against frozen observable criteria.
   EXECUTOR:
     semantic: conditional
     capabilities:
       - process-exec
       - source-read
4. Record commands, artifact paths, failures, skipped coverage, & cleanup.
   EXECUTOR:
     semantic: forbidden
     capabilities:
       - source-read
       - artifact-write

Read `references/manual.md` for harness, rendered browser acceptance, native, or Tauri QA. `/qa contract-tests` derives smallest observable boundary, negative, transition, & regression tests.
