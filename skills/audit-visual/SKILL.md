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
  - blueprint-graph
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

1. Freeze repository, Blueprint generation, routes/screens, viewports, states, themes, locales,
   platforms (each shipped OS is its own dimension per `references/platform-fidelity.md`),
   interactions, references, & acceptance criteria.
2. Create an explicit visual specification with expected matrix & capture artifacts; never invent evidence.
3. Capture specified runtime states through the host's client-native browser tools, following
   `references/visual-qa-capture.md`. If the host provides no browser capability, record the states as
   `UNPROVEN`. Then run `legion audit <root> --out <run-dir>` for the repository provider run. The native
   runner does not read captured evidence; its visual options are inert (see `references/manual.md` section 5).
4. Read frozen `plan.json` before `visual.json`; `visual.core` must be selected before execution. The native
   runner's frozen provider registry has no `visual.core` provider, so this step cannot pass natively.
5. Missing captures, baselines, matrix cases, readable PNGs, runtime states, or required evidence are
   `UNPROVEN`; zero pixel findings is not a pass without complete coverage.
6. Finalize through shared report pipeline. Do not emit an incompatible report shape. `legion audit
   --out <run-dir>` writes `report.json` and `report.sarif` together.

Use `/designer` for qualitative critique/remediation, `/qa` for functional/browser/runtime checks, & `/audit` for full repository provider set.
