---
name: audit-visual
description: "Thin visual-audit entrypoint over the shared Audit visual provider. Use for /audit-visual, visual regressions, rendered-state coverage, or screenshot-baseline review."
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

`/audit-visual` does not maintain a second visual-audit engine. It is a thin entrypoint over
`tools/skills/audit/providers/visual-core.mjs` and the shared frozen provider plan.

1. Freeze repository root, Cortex generation, routes/screens, viewports, states, themes, locales, platforms, interactions, references, and acceptance criteria.
2. Create an explicit visual specification containing the expected matrix and capture artifacts. Existing screenshots may be supplied; this entrypoint never invents evidence.
3. Run:

   `node tools/skills/audit/audit-run.mjs <root> --visual-spec <visual-spec.json>`

   For runtime capture evidence, also supply `--url`, `--surfaces`, and optionally `--visual-baselines`.
4. Read the frozen `plan.json` before `visual.json`. `visual.core` must have been selected before execution began.
5. Missing captures, missing baselines, uncovered matrix cases, unreadable PNGs, runtime omissions, or review-required captures are `UNPROVEN`; zero pixel findings is not a pass unless coverage is complete.
6. Finalize through the shared Audit report and SARIF pipeline. Do not emit a separate incompatible report shape.

Use `/designer` for creation or implementation. Use `/audit` for the full repository provider set.
