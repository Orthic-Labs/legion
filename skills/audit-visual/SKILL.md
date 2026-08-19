---
name: audit-visual
description: "Review rendered UI through Legion's shared Audit visual provider. Use for /audit-visual, visual regressions, screenshot baselines, or rendered-state coverage."
metadata:
  legion:
    provenance: legion-authored
    licenseState: licensed
    rightsReceipt: LICENSE
    publish: true
---

# Audit Visual

```text
MODE: DIAGNOSE
PRIMARY_DELIVERABLE: Shared-provider visual findings with exact evidence.
DISCOVERY_PROFILE: D1_SCOPED_SOURCE
EFFECT_PROFILES: audit_engine
SPECIALIST_REFS_MAX: 0
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: visual.core reconciles its frozen matrix or reports typed UNPROVEN coverage.
```

`/audit-visual` is a thin entrypoint over `../../src/providers/visual-core.mjs` & shared frozen plan.

1. Freeze repository, Cortex generation, routes/screens, viewports, states, themes, locales,
   platforms, interactions, references, & acceptance criteria.
2. Create an explicit visual specification with expected matrix & capture artifacts; never invent evidence.
3. Run `node ../../audit-run.mjs <root> --visual-spec <visual-spec.json>`. For runtime captures,
   also supply `--url`, `--surfaces`, & optional `--visual-baselines`.
4. Read frozen `plan.json` before `visual.json`; `visual.core` must be selected before execution.
5. Missing captures, baselines, matrix cases, readable PNGs, runtime states, or required review are
   `UNPROVEN`; zero pixel findings is not a pass without complete coverage.
6. Finalize through shared report & SARIF pipeline. Do not emit an incompatible report shape.

Use `/designer` for implementation & `/audit` for full repository provider set.
