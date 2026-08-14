---
name: audit-fix
description: "Apply bounded remediation from a frozen Legion Audit report, then rerun its same provider plan. Use only for /audit-fix after /audit evidence exists."
metadata:
  legion:
    provenance: legion-authored-public-router
    licenseState: unresolved
    rightsReceipt: null
    publish: false
---

# Audit Fix

Route only frozen-report remediation to Legion's shared Audit Fix workflow at
`../../audit-fix/SKILL.md`. This entrypoint owns no scanner selection, provider registry,
denominator, or report shape.

1. Require sealed `plan.json`, `facts.json`, `report.json`, & required security adjudication;
   stop on binding or plan drift.
2. Apply only unambiguous, bounded fixes permitted by that frozen plan.
3. Rerun exactly same shared Audit provider plan & finalize shared report/SARIF evidence.
4. Preserve any incomplete, skipped, or unadjudicated coverage as `UNPROVEN`; do not claim clean.

This package wrapper is unpublished: its source rights are unresolved & it has no rights receipt.
