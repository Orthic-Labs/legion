---
name: audit-fix
description: "Apply bounded remediation from a frozen Legion Audit report, then rerun its same provider plan. Use only for /audit-fix after /audit evidence exists."
kind: capability
capabilityClass: workflow
discoverability: public
domain: engineering
operations:
  - analyze
  - evaluate
  - execute
  - produce
effects:
  - source-read
  - repository-write
  - process-exec
metadata:
  legion:
    provenance: legion-authored
    licenseState: licensed
    rightsReceipt: LICENSE
    publish: true
---

# Audit Fix

```text
PRIMARY_DELIVERABLE: Bounded fixes plus reconciled rerun evidence.
SPECIALIST_REFS_MAX: 0
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Every applied fix is verified by the same frozen provider contract or remains explicitly UNPROVEN.
```

`/audit-fix` is a thin mutation loop over shared `/audit` provider architecture. It never selects
providers, creates a second scanner registry, or reinterprets original denominator.

**Standing:** Audit Fix is a workflow capability attached to a frozen Audit result. It is **not**
Oracle (it does not independently certify completion) and **not** Alchemist merely because it
writes (authority is not inferred from `repository-write`). Its actual effects remain
Arcane-gated.

1. Require prior `plan.json`, `facts.json`, `report.json`, & security adjudication result.
2. Verify plan seal, repository binding, Cortex generation, provider set, & denominators before
   editing. Stop on drift & create a new `/audit` plan.
3. Fix only unambiguous findings. Never auto-fix manual findings, unadjudicated security findings,
   or visual findings lacking acceptance evidence.
4. Do not install tools, fetch mutable rules, or alter provider selection.
5. After each bounded batch, rerun `node ../../tools/audit/audit-run.mjs <root>` with identical scope & evidence.
6. Cap loop at four batches; stop earlier on no progress, regression, drift, or new high/critical finding.
7. Return changed files, closed/open findings, regressions, rerun commands, & report/SARIF paths.
