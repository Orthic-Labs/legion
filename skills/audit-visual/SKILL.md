---
name: audit-visual
description: "Enumerate, capture, and reconcile rendered UI evidence through Legion's shared Audit visual provider. Use for /audit-visual or rendered-state coverage."
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
hostRequirements:
  - legion
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
MAY_CALL_SKILLS: qa (capture and interaction procedure only)
REQUIRED_READS:
- `references/manual.md` for the visual method and output shape
- `references/visual-qa-capture.md` for step 3 capture
- `references/platform-fidelity.md` when a desktop or mobile app ships on more than one OS
TERMINAL: visual.core reconciles its frozen matrix or reports typed UNPROVEN coverage.
```

`/audit-visual` uses client-native capture tools plus Legion's shared frozen Audit plan.

1. Freeze repository, routes/screens, viewports, states, themes, locales, platforms (each shipped
   OS is its own dimension per `references/platform-fidelity.md`), interactions, references, &
   acceptance criteria. Bind a Blueprint generation only when graph grounding is used through the
   optional `blueprint-grounding` method in [route resources](references/route-resources.json).
2. Use an explicit visual specification when comparing against baselines or asserting richer matrix
   dimensions; never invent evidence.
3. Capture specified states through host browser tools, following `references/visual-qa-capture.md`.
   Run every capture as a `kind = "visual"` scenario (rightkit-qa 0.5.0 or later); functional checks
   without screenshots belong to the `qa` skill.
   When runtime & visual providers are both selected with `--url` and no explicit spec, the frozen plan
   orders runtime before visual & binds resulting PNGs as supplemental captures. They have no inferred
   baselines and remain review-required. Otherwise record unavailable captures as `UNPROVEN`.
4. Read frozen `plan.json` before `visual.json`; `visual.core` must be selected before execution. Explicit
   specs remain authoritative and runtime screenshots are never merged into their matrix.
5. Missing captures, baselines, matrix cases, readable PNGs, runtime states, or required evidence are
   `UNPROVEN`; zero pixel findings is not a pass without complete coverage.
6. Finalize through shared report pipeline. Do not emit an incompatible report shape. `legion audit
   --out <run-dir>` writes `report.json` and `report.sarif` together.

Use `/designer` for qualitative critique/remediation, `/qa` for functional/browser/runtime checks, & `/audit` for full repository provider set.
