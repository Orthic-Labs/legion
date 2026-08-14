---
name: audit-visual
description: "Review rendered UI through Legion's shared Audit visual provider. Use for /audit-visual, visual regressions, screenshot baselines, or rendered-state coverage."
metadata:
  legion:
    provenance: legion-authored-public-router
    licenseState: unresolved
    rightsReceipt: null
    publish: false
---

# Audit Visual

Route rendered-state diagnosis to Legion's shared visual Audit workflow at
`../../audit-visual/SKILL.md`. This entrypoint owns no visual engine, capture matrix, or
incompatible report format.

1. Freeze target routes or screens, states, viewports, themes, locales, platforms, interactions,
   references, & acceptance criteria.
2. Execute `audit-run.mjs` through shared `/audit` with its visual specification & evidence.
3. Keep missing captures, baselines, matrix cases, unreadable artifacts, & runtime omissions as
   `UNPROVEN`; zero pixel findings alone is not a pass.
4. Route visual creation or implementation to `/designer`; full repository health to `/audit`.

This package wrapper is unpublished: its source rights are unresolved & it has no rights receipt.
