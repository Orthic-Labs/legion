---
name: audit-fix
description: Apply bounded fixes from a frozen Audit report, then rerun the same provider plan. Use only after `/audit` has produced report.json and plan.json.
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

`/audit-fix` is a thin mutation loop over the shared `/audit` provider architecture. It does not
select providers, create a second scanner registry, or reinterpret the original denominator.

1. Require the prior run's `plan.json`, `facts.json`, `report.json`, and security adjudication result.
2. Verify the plan seal, repository revision/dirty binding, Cortex generation, provider set, and denominators before editing. Stop on drift and create a new `/audit` plan instead.
3. Fix only findings whose evidence and proposed change are unambiguous. Preserve functionality. Never auto-fix MANUAL findings, security findings lacking completed adjudication and variant analysis, or visual findings lacking acceptance evidence.
4. Do not install tools, call the network, fetch mutable rules, or alter provider selection.
5. After each bounded batch, rerun `node tools/skills/audit/audit-run.mjs <root>` with the same scope and evidence arguments, then finalize the report.
6. Cap the loop at four batches. Stop earlier on no progress, regression, plan drift, or a newly introduced high/critical finding.
7. Return the files changed, findings closed, findings still open, regressions, exact rerun commands, and the new report/SARIF paths. Never claim clean while any selected provider is skipped, unmeasured, incomplete, or unadjudicated.
