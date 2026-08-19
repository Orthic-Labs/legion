---
name: audit-fix
description: "Apply bounded remediation from a frozen Legion Audit report, then rerun its same provider plan. Use only for /audit-fix after /audit evidence exists."
metadata:
  legion:
    provenance: legion-authored
    licenseState: licensed
    rightsReceipt: LICENSE
    publish: true
---

# Audit Fix

```text
MODE: IMPLEMENT
PRIMARY_DELIVERABLE: Bounded fixes plus reconciled rerun evidence.
DISCOVERY_PROFILE: D1_SCOPED_SOURCE
EFFECT_PROFILES: repo_write, audit_engine
SPECIALIST_REFS_MAX: 0
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Every applied fix is verified by the same frozen provider contract or remains explicitly UNPROVEN.
```

`/audit-fix` is a thin mutation loop over shared `/audit` provider architecture. It never selects
providers, creates a second scanner registry, or reinterprets original denominator.

1. Require prior `plan.json`, `facts.json`, `report.json`, & security adjudication result.
2. Verify plan seal, repository binding, Cortex generation, provider set, & denominators before
   editing. Stop on drift & create a new `/audit` plan.
3. Fix only unambiguous findings. Never auto-fix manual findings, unadjudicated security findings,
   or visual findings lacking acceptance evidence.
4. Do not install tools, fetch mutable rules, or alter provider selection.
5. After each bounded batch, rerun `node ../../tools/audit/audit-run.mjs <root>` with identical scope & evidence.
6. Cap loop at four batches; stop earlier on no progress, regression, drift, or new high/critical finding.
7. Return changed files, closed/open findings, regressions, rerun commands, & report/SARIF paths.
