---
name: qa
description: "Write tests only for native, backend, or web behavior, or add, run, or audit web app QA with hidden servers, deterministic mocks, functional/browser assertions, viewport evidence, and runtime checks. Desktop and Tauri app QA runs through RightKit QA on the real installed build."
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
hostRequirements:
  - legion
---

# QA

PRIMARY_DELIVERABLE: Bounded functional, behavioral, browser, & runtime evidence; or a contract-matching test for an explicitly test-only request.
SPECIALIST_REFS_MAX: 1
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Runtime QA has exact evidence against frozen criteria; test-only authoring has a contract-matching test and truthful red/green status.

For a test-authoring-only request, follow `Test-only authoring` in `references/manual.md`.
That branch writes tests only and applies to native, backend, & web targets; ordinary QA
execution/reporting below remains unchanged. Skill-creation and skill-editing workflow belongs to
the host's skill-creator capability; see `references/skill-evaluation.md` only for QA-specific
evaluation coverage.

1. For runtime QA, read and reuse the project QA contract. For test-only authoring, discover the
   repository's test runner and conventions as described in the manual; do not require a browser
   QA harness.
   EXECUTOR:
     semantic: required
     capabilities:
       - source-read
2. Freeze acceptance criteria plus only observables relevant to actual failure surface. Record
   revision/environment when needed for reproducibility; route, viewport, selector, state, & fixture
   apply only when implicated.
   EXECUTOR:
     semantic: required
     capabilities:
       - repository-truth-read
       - source-read
3. Use smallest decisive project-native check. Choose the scenario kind first:
   `kind = "functional"` (default) for clicks, typing, and assertions; agents never take screenshots
   in a functional run. `kind = "visual"` only for appearance checks that feed audit-visual. Set `kind`
   on every scenario (needs rightkit-qa 0.5.0 or later); a functional run refuses screenshot steps.
   For web/browser behavior, test with `legion script qa/qa-functional`; use `legion script qa/qa-shot`
   only in a visual scenario, for viewport artifacts against frozen observable criteria. Focused native
   checks need no browser ceremony. Evidence lives only in git-ignored `.cache/rightkit-qa`; never
   commit it or copy it elsewhere.
   EXECUTOR:
     semantic: conditional
     capabilities:
       - process-exec
       - source-read
4. For runtime QA, record commands, artifact paths, failures, skipped coverage, & cleanup. For
   test-only authoring, use the manual's test report format.
   EXECUTOR:
     semantic: forbidden
     capabilities:
       - source-read
       - artifact-write

Desktop and Tauri app QA runs headless and agent-driven through RightKit QA against the real installed build, with `kind = "functional"` or `kind = "visual"` scenarios. A dev server, a `?qa=1` route, a localhost URL, or a browser mock is never proof of a desktop or Tauri app, and the loopback runners in step 3 do not apply to it.

Read `references/manual.md` for the web harness, rendered browser acceptance, or native checks. Desktop and Tauri QA follow the rule above, not the web harness.

For an existing coverage, duplication or mutation report, use `references/quality-observations.md`
and `legion quality summarize --input normalized.json --report original.json`. This interprets
imported evidence without executing tools or turning unavailable measurements into passing scores.
