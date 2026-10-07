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

# Audit Fix

```text
PRIMARY_DELIVERABLE: Bounded fixes plus reconciled rerun evidence.
SPECIALIST_REFS_MAX: 0
CHILD_AGENTS_MAX: 16
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
Guard-gated.

1. Require prior `plan.json`, `facts.json`, `report.json`, & security adjudication result.
2. Verify repository binding, direct Membrane Blueprint evidence, provider set, & denominators
   before editing with `legion verify <run-dir>` (a plan whose `seal.authenticity` is `unsigned` stays
   `UNPROVEN`; see `doctrine/legion.md`). The provider uses resident Hub transport when available & a
   bounded one-shot for supplied root when Hub is off or resident access reports `project is not
   enrolled`; enrollment does not gate one-shot access. Stop on drift & create a new `/audit` plan.
3. Fix only unambiguous findings. Never auto-fix manual findings, unadjudicated security findings,
   or visual findings lacking acceptance evidence.
4. Do not install tools, fetch mutable rules, or alter provider selection.
5. After each bounded batch, rerun `legion audit <root> --out <run-dir>` with identical scope & evidence,
   then rerun the applicable reasoning lenses: read the new `<run-dir>/lens-packets/*.json`, fan out one
   fresh-context subagent per packet (at most `CHILD_AGENTS_MAX`), routed and tiered exactly as `/audit`
   does, with verbatim-anchored findings and the refutation rule applied. Lens results are
   skill-adjudicated and unauthenticated (the engine has no ingest path), so report them apart from
   engine findings: read the audit skill's
   `references/lens-routing.md` before every iteration. A fix is verified only when both the same
   frozen provider plan and the lenses that raised the finding come back clean for it; subagents read
   and report, only this skill edits.
6. Cap loop at four batches; stop earlier on no progress, regression, drift, or new high/critical finding.
7. Return changed files, closed/open findings, regressions, rerun commands, & report path.
   Include `report.sarif` from the rerun; `legion report <run-dir>/report.json --format md` renders the
   human report. `legion fix --plan <sealed-remediation-plan>` only validates a plan and applies nothing:
   this skill makes the edits.
