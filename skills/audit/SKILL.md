---
name: audit
description: "Diagnose a whole repository through Legion's frozen Audit provider plan. Use for /audit or repository-wide read-only health, security, runtime, & evidence review."
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
  - process-exec
  - artifact-write
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

# Audit

```text
PRIMARY_DELIVERABLE: Re-runnable audit report with bounded findings.
SPECIALIST_REFS_MAX: 5
CHILD_AGENTS_MAX: 16
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: BLUEPRINT, ARCHITECT
TERMINAL: Frozen provider plan reconciles to evidence or typed degradation.
```

[Execution contract](references/execution-contract.md) is normative; this summary never
overrides it.

1. Freeze repository root, scope, revision, dirty state, & requested mode.
2. Read [provider architecture](references/provider-architecture.md); route repository discovery
   through public Blueprint/Membrane — never build a parallel registry.
   The provider uses resident Hub transport when available, otherwise a bounded one-shot for
   supplied root. Enrollment controls resident watcher operation only; `project is not enrolled`
   must fall through to one-shot.
3. Resolve packaged Legion root, then run
   `node <package-root>/tools/audit/audit-run.mjs <root> --out <run-dir>` so complete declarative
   provider registry, Blueprint generation, denominators, & reasoning contracts freeze together.
   `legion audit <root> --out <run-dir>` is acceptable only when its plan contains full selected
   provider set plus applicable reasoning lenses. `providers: []`, `lensesRan: []` when lenses were
   required, `native-provider-composition-partial`, or `fullAudit: false` is control-plane
   degradation — never Audit evidence & never “no findings.” Continue with package runner; if that
   runner is unavailable, execute deterministic scanners & applicable lenses directly, record
   `audit-runner-unavailable`, & keep result incomplete.
   If resident & one-shot paths both genuinely fail or are unavailable, record exact typed
   degradation & continue applicable providers; do not treat enrollment alone as unavailable.
4. Project-executing checks need trusted host network-sandbox receipt; without it they are
   `UNPROVEN`; file-only providers still run.
5. Read `plan.json` before `facts.json`; every contract-enumerated failure is `UNPROVEN` & keeps
   audit incomplete.
6. Read [engine interface](references/engine-interface.md) for scanner, report, & CLI contracts.
7. Read [lens routing](references/lens-routing.md); fan every applicable reasoning contract to one
   native subagent in one parallel wave. Inline execution is fallback only when seats are
   unavailable. Reason only inside frozen-plan providers.
8. Adjudicate each security candidate independently; no generator closes its own finding.
9. Deduplicate, then finalize through [execution contract](references/execution-contract.md) so
   `report.json`, `report.sarif`, & receipts reconcile against exact plan. Missing provider/lens
   coverage stays typed `incomplete`.
10. Reconcile every provider & denominator; incomplete coverage is never clean.

Return gate vector, coverage, findings with evidence loci, rerun commands, & receipts, artifacts, &
typed degradation; `quality_gate` stays separate. A zero-finding result is reportable only after
every planned provider, lens, candidate adjudication, denominator, & required qualification
reconciles complete.

Read [full manual](references/manual.md) only for complex runtime, migration, desktop/Tauri,
data-safety, or report-schema edges. Frozen provider order, executable registry truth, real
`file:line` evidence, secret redaction, full security-candidate challenge, & no mutable external
rulesets remain mandatory.
