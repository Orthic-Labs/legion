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
   evidence & never “no findings.” If the native runner is unavailable, record
   `audit-runner-unavailable`, preserve the frozen provider/lens denominator, & keep
   the result typed `incomplete`; do not run scanners or lenses through a direct fallback.
   If resident & one-shot paths both genuinely fail or are unavailable, record exact typed
   degradation & continue only providers available through native execution; do not treat enrollment
   alone as unavailable or use direct scanner/lens execution as a bypass.
4. Native external scanner/check/tool/version/snapshot execution requires native owner admission.
   Current CLI policy freezes `externalProcesses=owner-admission-required`,
   `admissionStatus=unavailable`, & `effectiveMode=deny-external`; requests are denied before
   executable resolution, version probing, or spawn with reason `native-owner-admission-unavailable`.
   Caller environment, declared ownership argv, & network flags cannot grant admission. Preserve
   typed denial receipts & gaps; do not bypass them. Project-executing checks also need trusted host
   network-sandbox receipt; without either prerequisite they are `UNPROVEN`; file-only providers
   still run. SDK in-process helpers with an explicit trusted owner authorizer are a separate path.
   If the trusted host declares `AUDIT_OWNERSHIP_SCAN_CMD`, provider `governance.capability-ownership`
   retains its full denominator & a typed admission-denied receipt; declaration alone cannot run
   the command. Findings, when supplied by an admitted run, are advisory "duplicates RightKit owner"
   notes under `advisoryFindings`; `AUDIT_OWNERSHIP_SCAN_REQUIRED=1` makes coverage required for a
   clean claim. An unset command remains a typed `ownership-scan-unavailable` gap, never clean.
5. Read `plan.json` before `facts.json`; every contract-enumerated failure is `UNPROVEN` & keeps
   audit incomplete.
6. Read [engine interface](references/engine-interface.md) for scanner, report, & CLI contracts.
7. Read [reasoning runtime](references/reasoning-runtime.md), [lens routing](references/lens-routing.md),
   [lens cues](references/lens-cues.md), and [pattern cards](references/pattern-cards.md). Run
   `legion audit run-reasoning --run <run-dir> [--claude <path>] [--model <id>] [--reasoning-effort <level>]`. Alchemist executes
   staged evidence gathering and review under frozen packets; a fresh verifier checks proposed findings.
   Calls use snapshot-only tools, record actual usage as known or unknown, ingest authenticated receipts,
   and recompute the report. For the requested bounded Ember run, freeze a 50,000-token total budget
   across input and output, a 10,000-token total per physical model call (including at most 2,500 output
   tokens), at most 5 calls, and width 1. These are run-scoped caps, not general CLI defaults. Reserve at
   least one call for fresh finding verification, so no more than four initial author calls are admitted.
   Deterministic host gathering uses zero model calls; optional cheap gathering is used only when needed
   and separately admitted. See [lens routing](references/lens-routing.md).
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
every selected provider, lens, candidate adjudication, denominator, & required qualification
reconciles. The frozen plan retains the full applicable provider/lens/path universe. If the bounded
selection defers mandatory paths, record their exact paths and digest as `mandatoryDeferred`, emit
explicit coverage gaps, and keep the run `incomplete`; never call deferred mandatory coverage clean
or convert it into confidence. Explicit `exhaustive` mode remains strict and refuses when it cannot fit.

## Production assurance profiles

Assurance profiles are strength-ordered: `pre-pr` < `repository` < `release`. They are frozen into
the plan before solving; a pass under a weaker profile never projects to a stronger one. The legacy
`--profile standard` behavior is unchanged. Details: [execution contract](references/execution-contract.md#production-assurance-profiles-target-cli).

- `--profile pre-pr|repository|release` selects the required evidence set for that claim.
- `--runtime-policy no-node-python` constrains Audit-owned execution only (no Node/Python launchers,
  plugins, TS-loaded configs, or child interpreters). Evidence produced by Node or Python in application
  CI and imported with authenticated provenance is allowed and discloses its upstream runtime.
- `--product-contract <json>` and repeatable `--artifact-manifest <json>` import the product obligations
  and authenticated artifact evidence. Imports never widen scope or substitute for missing evidence.
- Per-stack coverage is distinct and never borrowed: Kotlin source detekt is separate from typed detekt
  and needs no JVM contract for source-only checks; Android Lint runs per variant; Xcode/iOS targets need
  their own workspace/scheme/destination evidence and cannot reuse macOS SwiftPM results; native JS/TS lint
  (Oxlint/Biome) runs without Node; PostgreSQL, Nginx, dependency health, structure, domain contracts, and
  runtime journeys each keep their own denominators and gaps.
- Four separate claims, reported distinctly and never merged:
  - **implemented**: source integrated and relevant checks passed;
  - **fixture-qualified**: rule/provider exercised on broken and valid fixtures with recorded error rates;
  - **host-qualified**: trusted owner invocation, containment, and receipts on an exact host/toolchain;
  - **app-qualified**: exact repository set, artifacts, and required journeys satisfy the selected profile.
  A rule can be implemented but shadow-only; a complete audit can carry blocking findings; a
  fixture-qualified provider can leave release incomplete. Never state a claim that was not reached.
- Selectors over saved reports: `legion report <report.json> --report assurance|trend|debt [--format json|markdown]`.
  `assurance` projects the claims above, `trend` projects finding history over saved runs, and `debt`
  projects open debt. These are projections only; they add no scan.
- `legion audit gate --run <dir>` reports one outcome: `eligible`, `blocked-findings`, or `incomplete`,
  with reasons. It validates the frozen run and requirements; it adds no second policy engine. Anything
  other than `eligible` is not a release-ready claim.
- External tools (scanners, linters, build/type/test commands) need native owner admission. Without it,
  each tool stays an explicit typed gap (`native-owner-admission-unavailable`), never a clean result and
  never a direct fallback.
- CLI wiring for these flags, the gate, and the new selectors is root-integration work; until it is
  verified in a built binary, describe them as target behavior, not as runnable commands.

Read [full manual](references/manual.md) only for complex runtime, migration, desktop/Tauri,
data-safety, or report-schema edges. Frozen provider order, executable registry truth, real
`file:line` evidence, secret redaction, full security-candidate challenge, & no mutable external
rulesets remain mandatory.
