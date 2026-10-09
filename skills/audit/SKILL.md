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
3. Run `legion audit <root> --out <run-dir>` (`<run-dir>` under `<root>/.audit/`) so complete declarative provider registry,
   Blueprint generation, denominators, & reasoning contracts freeze together. The native binary
   is the only runner; there is no Node or Python runner. `legion verify <run-dir>` re-checks the run
   and `legion report <run-dir>/report.json --format md` renders it.
   Its plan must contain full selected provider set plus applicable reasoning lenses. `providers: []`, `lensesRan: []` when lenses were
   required, `native-provider-composition-partial`, or `fullAudit: false` is control-plane
   degradation — never Audit evidence & never “no findings.” Continue with the native runner; if it is
   unavailable, execute deterministic scanners & applicable lenses directly, record
   `audit-runner-unavailable`, & keep result incomplete.
   If resident & one-shot paths both genuinely fail or are unavailable, record exact typed
   degradation & continue applicable providers; do not treat enrollment alone as unavailable.
4. Project-executing checks need trusted host network-sandbox receipt; without it they are
   `UNPROVEN`; file-only providers still run.
   If the trusted host declares `AUDIT_OWNERSHIP_SCAN_CMD`, provider `governance.capability-ownership`
   runs it read-only (findings non-blocking unless the host sets `AUDIT_OWNERSHIP_SCAN_REQUIRED=1`);
   undeclared means not-applicable, never clean.
5. Read `plan.json` before `facts.json`; every contract-enumerated failure is `UNPROVEN` & keeps
   audit incomplete.
6. Read [engine interface](references/engine-interface.md) for scanner, report, & CLI contracts.
7. Read [lens routing](references/lens-routing.md); fan every applicable reasoning contract to one
   native subagent in one parallel wave, tiered by lens kind (strongest for `security`, `architecture`,
   `correctness`; mid for other judgment lenses; lowest for mechanical lenses). Inline execution is
   fallback only when no native seat is available. Reason only inside frozen-plan providers.
   The engine has no in-process lens host: `legion audit --out <run-dir>` freezes a per-run epoch key
   and emits each reasoning lens as a `pending-host` packet at `<run-dir>/lens-packets/<provider>.json`,
   listed under `lensWork` / `reasoningLensesPending`; `reasoningLensesRan` counts a lens only after
   the CLI ingests its result. Read every packet, fan out one subagent per packet (at most
   `CHILD_AGENTS_MAX`) at the tier `lens-routing.md` assigns, and have each write a
   `legion-lens-result` JSON file whose every finding carries a verbatim code anchor
   (`anchor: {path, line, text}`; see the execution contract). Apply the refutation rule (a finding is
   withdrawn only by citing, as a `disproof` anchor, the line that disproves it). Then run
   `legion audit ingest --run <run-dir> --provider <id> --result <file>` once per lens, sequentially:
   the CLI is the trusted host, rejects any anchor that does not match the file bytes at the frozen
   revision, MACs the receipt, and rewrites `report.json` with the recomputed verdict. Finish with
   `legion verify <run-dir>`; it recomputes the verdict from the ingested receipts. A lens that is not
   ingested stays `pending-host` and keeps the audit non-clean.
8. Apply [semantic review](references/semantic-review.md) when a repository supplies explicit
   specifications or standards. Reuse `correctness` for SPEC fidelity & `ai-slop` for STANDARDS,
   with independent inputs, reports, & verdicts; missing inputs are typed `unproven` or
   `not-applicable` with a reason, never filled from invented standards.
9. Adjudicate each security candidate independently; no generator closes its own finding.
10. Deduplicate, then finalize through [execution contract](references/execution-contract.md) so
   `report.json`, `report.sarif`, & receipts reconcile against exact plan. Missing provider/lens
   coverage stays typed `incomplete`. Providers without a passing bench class or qualification record
   appear as non-blocking `unqualified:<provider>` coverage notes (`coverageNotes`) unless the registry
   marks them `requiredForCleanClaim`; report them, they do not block a clean verdict.
11. Reconcile every provider & denominator; incomplete coverage is never clean.

Return gate vector, coverage, findings with evidence loci, rerun commands, & receipts, artifacts, &
typed degradation; `quality_gate` stays separate. A zero-finding result is reportable only after
every planned provider, lens, candidate adjudication, denominator, & required qualification
reconciles complete.

Read [full manual](references/manual.md) only for complex runtime, migration, desktop/Tauri,
data-safety, or report-schema edges. Frozen provider order, executable registry truth, real
`file:line` evidence, secret redaction, full security-candidate challenge, & no mutable external
rulesets remain mandatory.
