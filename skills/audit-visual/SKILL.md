---
name: audit-visual
description: "Enumerate, capture, compare, and reconcile rendered UI evidence through Legion's shared Audit visual provider. Use for /audit-visual, visual regressions, screenshot baselines, or rendered-state coverage."
kind: capability
capabilityClass: domain
discoverability: public
domain: engineering
operations:
  - analyze
  - evaluate
  - produce
effects:
  - source-read
  - artifact-write
  - process-exec
hostRequirements: []
metadata:
  legion:
    provenance: legion-authored
    licenseState: licensed
    rightsReceipt: LICENSE
    publish: true
---

# Audit Visual

```text
PRIMARY_DELIVERABLE: Shared-provider visual findings with exact evidence.
SPECIALIST_REFS_MAX: 0
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: visual.core reconciles its frozen matrix or reports typed UNPROVEN coverage.
```

`/audit-visual` uses client-native capture tools plus Legion's shared frozen Audit plan.

1. Freeze repository, Blueprint generation, routes/screens, viewports, states, themes, locales,
   platforms, interactions, references, & acceptance criteria.
2. Create an explicit visual specification with expected matrix & capture artifacts; never invent evidence.
3. Capture specified runtime states through client-native browser tools, then run
   `legion audit <root> --out <run-dir>` with captured evidence bound into provider results.
4. Read frozen `plan.json` before `visual.json`; `visual.core` must be selected before execution.
5. Missing captures, baselines, matrix cases, readable PNGs, runtime states, or required evidence are
   `UNPROVEN`; zero pixel findings is not a pass without complete coverage.
6. Finalize through shared report & SARIF pipeline. Do not emit an incompatible report shape.

Use `/designer` for qualitative critique/remediation, `/qa` for functional/browser/runtime checks, & `/audit` for full repository provider set.
