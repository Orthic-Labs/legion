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
EXECUTION: Native staged reasoning runtime; no subagent fan-out.
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: BLUEPRINT, ARCHITECT, AUDIT-VISUAL
TERMINAL: Frozen provider plan reconciles to evidence or typed degradation.
```

[Execution contract](references/execution-contract.md) is normative; this summary never
overrides it.

1. Freeze repository root, scope, revision, dirty state, requested mode, & coverage mode (`auto`
   default, `exhaustive`, or `risk-sampled`; see [execution contract](references/execution-contract.md)
   Coverage modes).
2. Read [provider architecture](references/provider-architecture.md). When graph grounding is
   used, route it through the optional `blueprint-grounding` method in
   [route resources](references/route-resources.json); never build a parallel registry. Without
   that host capability, continue standalone-safe checks & leave graph-dependent claims unproven.
   The provider uses resident Hub transport when available, otherwise a bounded one-shot for
   supplied root. Enrollment controls resident watcher operation only; `project is not enrolled`
   must fall through to one-shot.
3. Run `legion audit <root> --out <run-dir>` (`<run-dir>` under `<root>/.audit/`) so complete declarative provider registry,
   Blueprint generation, denominators, & reasoning contracts freeze together. The native binary
   is the only runner; there is no Node or Python runner. `legion verify <run-dir>` re-checks the run
   and `legion report <run-dir>/report.json --format md` renders it.
   Its plan must contain the full provider set selected for this run plus applicable reasoning lenses.
   Filters are explicit partial scope: report the original applicable provider universe and excluded
   applicable providers. `planComplete` means the selected frozen plan reconciled; `fullScope` means
   no applicable provider was excluded. Providers with empty denominators or checked conditional
   triggers that did not fire are not omissions. `providers: []`, `lensesRan: []` when lenses were
   required, or `native-provider-composition-partial` is control-plane degradation — never Audit
   evidence & never “no findings.” Continue with the native runner; if it is
   unavailable, execute deterministic scanners & applicable lenses directly, record
   `audit-runner-unavailable`, & keep result incomplete.
   If resident & one-shot paths both genuinely fail or are unavailable, record exact typed
   degradation & continue applicable providers; do not treat enrollment alone as unavailable.
4. Project-executing checks need trusted host network-sandbox receipt; without it they are
   `UNPROVEN`; file-only providers still run.
   If the trusted host declares `AUDIT_OWNERSHIP_SCAN_CMD`, provider `governance.capability-ownership`
   runs it read-only; findings are advisory "duplicates RightKit owner" notes (listed under
   `advisoryFindings`, never blocking unless the host sets `AUDIT_OWNERSHIP_SCAN_REQUIRED=1`);
   an unset command is reported as the degradation note `ownership-scan-unavailable`, never clean.
5. Read `plan.json` before `facts.json`; every contract-enumerated failure is `UNPROVEN` & keeps
   audit incomplete.
6. Read [engine interface](references/engine-interface.md) for scanner, report, & CLI contracts.
7. Read [reasoning runtime](references/reasoning-runtime.md), [lens routing](references/lens-routing.md),
   [lens cues](references/lens-cues.md), and [pattern cards](references/pattern-cards.md). Run
   `legion audit run-reasoning --run <run-dir> [--claude <path>] [--model <id>] [--reasoning-effort <level>]`. Alchemist executes
   staged evidence gathering and review under frozen packets; a fresh verifier checks proposed findings.
   Calls use snapshot-only tools, record actual usage as known or unknown, ingest authenticated receipts,
   and recompute the report. Model tiers and stage budgets are defined in [lens routing](references/lens-routing.md).
   Missing prerequisites, exhausted budget, and unresolved evidence remain typed gaps. Cards sharpen
   existing lenses and are selected only when applicable; they do not create new domains.
   See [execution contract](references/execution-contract.md) for packet and ingest invariants.
8. Apply [semantic review](references/semantic-review.md) when a repository supplies explicit
   specifications or standards. Reuse `correctness` for SPEC fidelity & `ai-slop` for STANDARDS,
   with independent inputs, reports, & verdicts; missing inputs are typed `unproven` or
   `not-applicable` with a reason, never filled from invented standards.
9. Adjudicate each security candidate; no generator closes its own finding. Candidates are batched by
   cluster, but high-risk or uncertain dismissals go to individual review. Run variant analysis
   (follow-up plan) for every confirmed finding.
10. Deduplicate, then finalize through [execution contract](references/execution-contract.md) so
   `report.json`, `report.sarif`, & receipts reconcile against exact plan. Missing provider/lens
   coverage stays typed `incomplete`. Providers without a passing bench class or qualification record
   appear as non-blocking `unqualified:<provider>` coverage notes (`coverageNotes`) unless the registry
   marks them `requiredForCleanClaim`; report them, they do not block a clean verdict.
11. Reconcile every provider & denominator; incomplete coverage is never clean.

Return gate vector, coverage, findings with evidence loci, rerun commands, & receipts, artifacts, &
typed degradation; `quality_gate` stays separate, and `coverageMode` (`exhaustive` or `sampled`) is
reported apart from both. A risk-sampled run is labelled "whole-repository risk-sampled audit" and reports
`qualityGate: sampled`, never `proven`; its findings and missing evidence keep their own states. A zero-finding result is reportable only after
every planned provider, lens, candidate adjudication, denominator, & required qualification
reconciles complete.

Read [full manual](references/manual.md) only for complex runtime, migration, desktop/Tauri,
data-safety, or report-schema edges. Frozen provider order, executable registry truth, real
`file:line` evidence, secret redaction, full security-candidate challenge, & no mutable external
rulesets remain mandatory.
