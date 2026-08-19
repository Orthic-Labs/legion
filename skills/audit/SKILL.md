---
name: audit
description: "Diagnose a whole repository through Legion's frozen Audit provider plan. Use for /audit or repository-wide read-only health, security, runtime, & evidence review."
metadata:
  legion:
    provenance: legion-authored-public-router
    licenseState: unresolved
    rightsReceipt: null
    publish: false
---

# Audit

```text
MODE: DIAGNOSE
PRIMARY_DELIVERABLE: Re-runnable audit report with bounded findings.
DISCOVERY_PROFILE: D1_SCOPED_SOURCE
EFFECT_PROFILES: audit_engine
SPECIALIST_REFS_MAX: 0
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Frozen provider plan reconciles to evidence or typed degradation.
```

[Execution contract](../../references/execution-contract.md) is normative; this summary never
overrides it.

1. Freeze repository root, scope, revision, dirty state, & requested mode.
2. Read [provider architecture](../../references/provider-architecture.md); discovery belongs to
   Cortex — never build a parallel registry.
3. Run `node ../../tools/audit/audit-run.mjs <root>`: fresh Cortex generation, signed `plan.json`, & exact
   frozen provider set; missing signing material is `UNPROVEN`.
4. Project-executing checks need trusted host network-sandbox receipt; without it they are
   `UNPROVEN`; file-only providers still run.
5. Read `plan.json` before `facts.json`; every contract-enumerated failure is `UNPROVEN` & keeps
   audit incomplete.
6. Read [engine interface](../../references/engine-interface.md) for scanner, report, & CLI contracts.
7. Read [lens routing](../../references/lens-routing.md); reason only inside frozen-plan providers.
8. Adjudicate each security candidate independently; no generator closes its own finding.
9. Deduplicate, then run `../../audit-finalize.mjs` to write `report.json` & `report.sarif`.
10. Reconcile every provider & denominator; incomplete coverage is never clean.

Return gate vector, coverage, findings with evidence loci, rerun commands, seal, signature, Cortex
generation, receipts, artifacts, & typed degradation; `quality_gate` stays separate.

Read [full manual](../../references/manual.md) only for complex runtime, migration, desktop/Tauri,
data-safety, or report-schema edges. Frozen provider order, executable registry truth, real
`file:line` evidence, secret redaction, full security-candidate challenge, & no mutable external
rulesets remain mandatory.
