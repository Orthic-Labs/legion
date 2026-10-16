# Audit — execution contract (normative detail)

This text is normative; the SKILL body summarizes it and must agree with it.

## Canonical entrypoint (step 3 detail)

`legion audit <root> --out <run-dir>` is the one complete entrypoint. `<run-dir>` must sit under
`<root>/.audit/`. The native binary freezes one inventory generation, loads the declarative provider
registry, writes a SHA-256-sealed `plan.json` (HMAC-signed when `AUDIT_PLAN_SIGNING_KEY` is set), and
executes the exact frozen provider set. It writes `plan.json`, `facts.json`, `report.json`,
`report.sarif`, and `execution.json` to `<run-dir>`. Missing signing material is `UNPROVEN`
(`authenticity: unsigned`); it never degrades silently to an authenticity claim.

Flags: `--profile <name>`, `--only <provider>` / `--skip <provider>` (repeatable, resolved before the
plan freezes), `--type`/`--base`/`--base-commit`/`--dir` (diff scope, annotates facts and never
narrows the denominator), `--url`, `--surfaces`, `--runtime-interactions`, `--visual-spec`, `--visual-baselines`,
`--width`/`--height`, `--plan-only` (freeze and seal the plan without executing it),
`--provider-plan <plan.json>` with repeated `--provider-result <file>` (reconcile supplied results
against a frozen plan), and `--json`. `legion audit --help` is not supported; the flag list lives in
`engine/bins/legion/src/commands/audit.rs`.

Filtered runs preserve the applicable-provider universe computed from the same frozen inventory.
The report records `applicableProviders`, `selectedApplicableProviders`,
`excludedApplicableProviders`, and requested filters. `planComplete` describes reconciliation
within the selected plan; `fullScope` is true only when no applicable provider was excluded.
Providers with empty denominators and conditional lenses whose checked triggers did not fire are
not omissions. A complete filtered plan may therefore have `planComplete: true` and
`fullScope: false`.

Companions: `legion verify <run-dir>` re-checks the persisted facts against the frozen plan;
`legion report <run-dir>/report.json --format md|html|sarif|json [--out <file>]` renders a frozen report;
`legion fix --plan <sealed-remediation-plan>` validates a remediation plan and applies nothing.

## Coverage modes and quality outcome

`legion audit` implements frozen lens coverage planning with `--coverage auto|exhaustive|risk-sampled`
(`auto` by default). Coverage mode and review sets are sealed into the plan; deterministic providers
still cover their full inventory.

- `--coverage auto|exhaustive|risk-sampled` (default `auto`) is frozen into the plan with its review set.
- `exhaustive`: every denominator path of every reasoning lens is examined. It refuses up front when the
  run exceeds the run budget; it never freezes an incomplete run.
- `risk-sampled`: a frozen review set is examined. Its mandatory stratum (entrypoints, security-sensitive
  paths, files changed since the base commit, top churn files) is reviewed exhaustively. Its hotspot
  stratum is reviewed up to budget. Its remainder is a seeded sample ordered from the frozen plan seed,
  so it is reproducible and cannot be cherry-picked. The sample floor is a target bounded by budget;
  shortfall is recorded by `sampleFloorMet` with the remaining denominator in `declaredUnsampled`, and
  disables confidence claims.
  Paths outside the review set are recorded `declaredUnsampled`, not as gaps. A review-set path that was
  not examined stays a gap, and the run stays `incomplete`. The planner does not shrink mandatory coverage
  to satisfy optional sampling targets.
- `auto`: `exhaustive` when it fits the run budget, `risk-sampled` otherwise. The mode chosen is recorded.
- Deterministic providers always cover every inventory path. Coverage mode never changes them.
- Deterministic findings can promote files into the review set, never remove them.

Mandatory review is never reduced to meet an optional sample target. Planning refuses early if estimated
mandatory work, minimum bundle/gather calls, and verification reserve cannot fit the frozen run budget.
It adapts source chunks downward on whole-line boundaries to fit the rendered packet envelope; an
irreducible source line or metadata that exceeds the bound is a typed refusal. Snapshot metadata is
verified once per manifest during sizing, with digest checks retained on reads. Never increase budgets
or seat limits implicitly to force a plan to fit.

`next` reports `requiredInitialCalls` and `initialCallReservationTokens`; the reservation covers full
per-call admission for required author and gatherer calls plus verification/context capacity. Follow-up
work still needs its own admission. `max-total-seats` caps physical calls; `max-lens-seats` limits planned
seats per wave. Calls run sequentially. Estimated tokens are not actual usage or spend: receipts carry
host-reported actuals or `unknown`, and an overrun stops later calls.

Report `coverageMode` (`exhaustive` or `sampled`) separately from the quality outcome. `auditStatus` keeps
`pass | findings | incomplete`. `qualityGate` reads `proven` for an exhaustive clean run and `sampled` for a
clean risk-sampled run; `sampled` is never `proven`. Findings and missing evidence keep their failure and
incomplete states in either mode. Each reasoning lens reports `lensCoverage`:
`{mode, denominator, reviewSet, examined, strata: [{name, N, n, findings, confidence}]}`. Statistical
statements are defined in [coverage and trajectory](coverage-and-trajectory.md#whole-repository-coverage-statistics).

## Native reasoning runtime (step 7 detail)

The supported execution path is `legion audit run-reasoning --run <run-dir> [--claude <path>] [--model <id>] [--reasoning-effort <level>]`;
stages and tier routing are defined in [lens routing](lens-routing.md), while lifecycle, frozen scope,
host tools, verifier, usage, and prerequisites are defined in [reasoning runtime](reasoning-runtime.md).
The packet/result details below also describe the lower-level manual ingest interface. Do not dispatch
subagents as normal Stage 2 execution.

For each selected reasoning lens `legion audit --out <run-dir>` writes a `pending-host` work packet to
`<run-dir>/lens-packets/<provider>.json`, lists it under `lensWork` and `reasoningLensesPending`, and
generates a per-run epoch key at `<run-dir>/epoch.key` (mode 0600; only its digest appears in
`plan.json` `epoch.digest` and the report claim `reasoningEpochDigest`). Never read, copy, or print the
key. `run-reasoning` consumes selected frozen packets in the existing run and writes authenticated
delivery, runtime-call, verification, and ingest evidence. The lower-level result shape remains useful
for integrations that supply a result directly:

```json
{"schemaVersion": 1, "kind": "legion-lens-result", "provider": "reasoning.security",
 "packetDigest": "<canonical sha256 of packet.request.packet>", "planDigest": "<packet.request.planDigest>",
 "complete": true,
 "findings": [{"id": "...", "lens": "...", "severity": "...", "confidence": "...",
               "evidence": ["src/a.rs:12-18"], "failureScenario": "...", "action": "...", "verifyStatus": "...",
               "anchor": {"path": "src/a.rs", "line": 14, "text": "<verbatim source text starting on that line>"}}],
 "withdrawn": [{"id": "...", "reason": "...", "disproof": {"path": "...", "line": 1, "text": "<verbatim>"}}],
 "details": {"semanticReview": {}, "changeRisk": {}}}
```

`packetDigest` and `planDigest` are listed on each `lensWork` entry of the audit output (and are
`request.packet`'s canonical digest and `request.planDigest` in the packet file); `details` carries only the lens-specific `semanticReview` /
`changeRisk` objects when the lens schema requires them. Then, for each lens, sequentially:

```bash
legion audit ingest --run <run-dir> --provider <reasoning-provider-id> --result <result.json>
legion verify <run-dir>
```

`ingest` validates the result against the packet (provider id, packet digest, plan digest), requires
every finding to carry an anchor whose text appears verbatim at `path:line` in the file at the frozen
revision (and an `evidence` entry covering that line), requires every withdrawn finding to cite a
disproving anchor, rejects a working tree that drifted from the frozen revision, runs the lens report
schema, mints a receipt MACed with the epoch key, writes `<run-dir>/lens-receipts/<provider>.json`, and
rewrites `report.json` / `report.sarif` with the recomputed verdict. `legion verify` recomputes the
verdict from the execution plus the verified receipts and fails if `report.json` disagrees. A lens
counts in `reasoningLensesRan` only through an ingested receipt; unsigned plans cannot be ingested
(set `AUDIT_PLAN_SIGNING_KEY`). A rerun of `legion audit --out` replaces the epoch key and discards
older receipts.

### Packet fields that drive the result

- `excerptCoverage` (in `request.packet`): what the packet proves was examined. `basis:
  "bounded-excerpts"` lists `examinedPaths` (excerpt present and untruncated), `truncatedPaths` (cut at
  the per-file cap), and `omittedPaths` (no excerpt). Examined coverage is derived from this, never from
`complete: true`, which only attests that result producer finished. A denominator path that is truncated or
  omitted yields the gap `reasoning-excerpt-coverage:<provider>:<examined>/<expected> paths examined (...)`;
  the receipt is then `partial`, the lens does not count in `reasoningLensesRan`, and the report stays
  incomplete. Review truncated/omitted paths by reading the files, then rerun the audit; a packet with
  no recorded basis yields `excerpt-coverage-unrecorded:<provider>`.
- `scannerCandidates` (only `legacy.security.adjudication`): the scanner candidates to close, each
  `{findingId, provider, rule, severity, path, line, message, evidenceExcerpt}`. `null` means scanner
  results were unavailable (gap `scanner-candidates-unavailable:<provider>`; the lens stays uncovered).
- `candidateWorkItems` (only `legacy.security.adjudication`): `null` when `scannerCandidates` is
  `null`; otherwise `{parentPacketDigest, triage, clusters, batches, confirmations}`, replacing the
  earlier one-item-per-candidate shape. `parentPacketDigest` is the canonical digest of the batch packet
  with `candidateWorkItems` removed, avoiding a circular digest while binding every batch to the complete
  frozen evidence and invocation. `triage` lists candidates closed by a deterministic rule (see Security
  adjudication). `clusters` group candidates by rule and normalized sink/excerpt digest. `batches` group
  clusters by rule family, then file locality, with at most 25 clusters per batch inside the batch token
  budget. An empty `scannerCandidates` array has empty `triage`, `clusters`, `batches`, and `confirmations`,
  and remains distinct from unavailable candidates.
- `verdicts` (result array, adjudication only): exactly one aggregated entry per `scannerCandidates` item,
  `{candidateId, verdict, ...}`. `verdict` is `TRUE_POSITIVE`, `LIKELY_TRUE_POSITIVE`,
  `LIKELY_FALSE_POSITIVE`, `FALSE_POSITIVE`, `OUT_OF_SCOPE`, `HARDENING_GAP`, or `MISUSE_HAZARD`; every
  verdict also carries its `clusterId` and the canonical `workPacketDigest` of its batch. Every member of a
  cluster keeps its own verdict row, so no location is lost.
  The frozen plan groups candidates into bounded batches, then records separate confirmation and
  spot-check work. Each batch remains an aggregation boundary, not evidence that context isolation
  occurred. A claimed `contextId` alone is not trusted-host evidence; missing isolation attestation
  keeps adjudication incomplete with a typed gap. Previously saved packets without
  `candidateWorkItems` remain ingestible under their original compatibility behavior.
  A verdict needs `threatModel`, `reachability`,
  `impact`. A surviving verdict (`TRUE_POSITIVE` /
  `LIKELY_TRUE_POSITIVE`) also needs `severity`, `attackerControl` above `unproven`, `proof`,
  `evidenceStrength` above `possible`, and `devilsAdvocate`, plus an anchored finding with id
  `adjudicated:<candidateId>`. Missing, duplicate, or unknown candidate ids reject the ingest.

### Security adjudication batches

The native planner and ingest implement these stages. Context isolation remains a required evidence
condition: never treat a planned or self-reported fresh context as a completed attestation.

1. **Deterministic triage.** Only provable non-issues close here, each with verdict basis `deterministic`
   and a rule id: the candidate path is excluded from the lens denominators (generated, vendored, minified,
   or lock file); the value matches the existing placeholder detection; or the same fingerprint was already
   resolved by a native provider. Triage is reported as `autoTriaged` and is never counted as adjudicated.
   Test and fixture paths are not auto-closed, because real secrets leak there.
2. **Clustering.** Fingerprint = rule + normalized sink/excerpt digest. Each cluster gets one adjudicated
   representative. The duplicate-text check applies across clusters and allows expanded text within one.
3. **Batching.** Batches are bounded by token budget and cluster count, and every
   candidate gets a recorded evidence and disposition row.
4. **Confirmation.** Every surviving verdict (`TRUE_POSITIVE`, `LIKELY_TRUE_POSITIVE`, `HARDENING_GAP`,
   `MISUSE_HAZARD`) gets a second, single-candidate confirmation in a fresh context before it counts.
   High-risk or uncertain dismissals go directly to individual review.
5. **Spot-checks.** For each non-empty batch, `ceil(5% x false-positive candidates)` (at least one) is
   re-adjudicated alone in fresh contexts, chosen by seeded digest. Any disagreement voids the batch, and that
   batch reruns one candidate per context.
6. **Gates.** Confirmations and spot-checks are budgeted explicitly and ingested as work items.
   `security_adjudication: pass` requires that every batch, confirmation, and spot-check was ingested; until
   then it stays `unproven`. Context isolation must be host-attested. Echoed `contextId` or `workItemId`
   values never clear `adjudication-context-derived`.

### Variant-analysis follow-up

`legacy.security.variant-analysis` is selected by `confirmedSecurityFinding`, which is empty when the
parent plan freezes, so it cannot run inside the parent run. Each surviving verdict therefore leaves the
parent gap `security-variant-analysis-pending:<n> confirmed finding(s)` (also report claim
`securityVariantTrigger`) until a follow-up plan runs. No confirmed finding means no follow-up and no gap.

```bash
# After ingesting the adjudication result, the CLI plans the follow-up automatically
# (output key `followup`); to (re)plan explicitly:
legion audit ingest --run <run-dir> --followup
# Run the packet at <run-dir>/followup/lens-packets/legacy.security.variant-analysis.json, then:
legion audit ingest --run <run-dir> --followup --provider legacy.security.variant-analysis --result <variant.json>
legion verify <run-dir>
```

The follow-up is a second signed plan under `<run-dir>/followup/` (own `plan.json`, `frozen-plan.json`,
`epoch.key`, `lens-packets/`, `lens-receipts/`). Its only provider is variant analysis over a
deterministic scope inside the frozen inventory: confirmed files, source siblings in the same
directory, first-party source files with a lexical reference to a confirmed file's module stem, and
source files sharing non-ubiquitous identifiers from seed evidence. The signed plan records
`confirmedPaths` separately from `analysisPaths` and the reason each analysis path entered scope.
Findings and withdrawals must anchor inside `analysisPaths`; an
in-inventory file outside that set cannot bypass scope. The plan binds the parent plan digest and the
confirmed verdict digests. The
packet carries `variantSeeds`, one per confirmed finding (`rule`, `path`, `line`, `verdict`, `rationale`,
`threatModel`, `reachability`, `impact`, `parentFindingId`). Each variant finding is a normal lens
finding with a verbatim anchor plus `parentFindingId` (the seed's `adjudicated:<candidateId>`); zero
variants is a valid complete result (`findings: []`). The parent gap clears, and variant findings join
the parent report, only when the follow-up is complete and its chain verifies; a follow-up that does not
chain to the parent (`securityVariantFollowup.status: invalid`) keeps the gap and fails `legion verify`.

Qualification: a provider is qualified when its registry entry carries `benchmark.status: qualified`
with a `qualificationDigest` (the five bench-recall classes `secret`, `dependency_cve`, `dead_code`,
`duplication`, `type_error` carry a `benchmark.qualification` record citing the `bench` CI job). An
unqualified provider that completed is a non-blocking `unqualified:<provider>` entry in
`coverageNotes`; it blocks clean (`provider-unqualified:<provider>` gap) only when its registry entry
sets `benchmark.requiredForCleanClaim: true`. Clean requires every applicable required provider
complete and every required lens ingested.

## Network sandbox and runtime capture (step 4 detail)

Project-executing checks and runtime capture require a trusted host network sandbox. The host sets
`AUDIT_NETWORK_GUARD=active` only after network denial is actually enforced outside the audited
process. Without that receipt, build/type/lint/test/runtime commands are skipped as `UNPROVEN`;
file-only providers still run. Supply `--url <running-app-url>` for selected runtime providers,
`--surfaces <targets.json>` for button/card-driven views, `--visual-spec <spec.json>` for explicit
rendered evidence, or `--visual-baselines <map.json>` for baseline comparison.

`--runtime-interactions <descriptors.json>` freezes bounded declarative probe requests against
exact frozen loopback surfaces. Each descriptor binds a fixture source digest, probe action digest,
surface label/URL, and isolation-binding ID; these caller-supplied fields are claims, not proof of
fixture isolation. Only click/type/limited-key/selector assertions are accepted; scripts, eval,
navigation, and unknown action fields are rejected. Until a trusted host verifier proves isolated
target binding and scoped egress, no interaction action runs and each descriptor reports
`runtime-probe-isolation-not-configured`; ordinary baseline capture continues.

## Capability ownership (host-declared)

If the trusted host sets `AUDIT_OWNERSHIP_SCAN_CMD`, `governance.capability-ownership` runs that
read-only command and maps its findings (`line` optional; file-level when absent) into the report
as advisory "duplicates RightKit owner" notes under `advisoryFindings`. When unset it reports the
non-blocking coverage note `ownership-scan-unavailable:AUDIT_OWNERSHIP_SCAN_CMD unset`, never a
silent not-applicable. See `provider-architecture.md`.

## `UNPROVEN` conditions (step 5 detail)

Read `plan.json` before `facts.json`. A stale/missing Blueprint generation, plan-seal or signature
failure, binding drift, selected-provider omission, unsupported toolchain, absent network-sandbox
receipt, incomplete runtime/visual matrix, unmeasured rule pack, network-dependent check, or
unadjudicated security candidate is `UNPROVEN` and keeps the audit incomplete.

## Finalize and verify (steps 9 and 10 detail)

`legion audit` writes `report.json` and `report.sarif` itself; there is no separate finalize binary and
no `--candidates` / `--adjudication` flag. Security adjudication verdicts enter the run only through
`legion audit ingest` of the `legacy.security.adjudication` result (`verdicts`), and variant analysis
through the follow-up above. After the run:

```bash
legion verify <run-dir>
legion report <run-dir>/report.json --format md --out <run-dir>/report.md
```

`legion verify` checks the persisted artifacts against the frozen plan; a failing verify keeps the
audit incomplete. An unadjudicated security candidate stays `UNPROVEN` whatever the report says.

## Hard rules (full text)

- Order is freeze scope → deterministic Blueprint projection → deterministic provider plan → execute
  frozen plan → provider-bounded reasoning.
- The agent never selects, adds, removes, or narrows providers after execution begins.
- The declarative provider registry loaded by the native binary is the executable source of truth.
  Loaders may validate and merge registry data, but may not invent providers or qualifications.
- `plan.json` carries a SHA-256 integrity digest and an HMAC-SHA-256 authenticity signature bound
  to revision, dirty digest, Blueprint generation, registry digest, provider set, and denominators.
  An unsigned plan is valid only as an `UNPROVEN` artifact and cannot support a clean claim.
- Blueprint owns file, language, workspace, symbol, and graph discovery. Audit owns toolchain,
  manifest, build/test, runtime, visual, release, and adjudication evidence.
- Legacy scanner adapters receive their applicability from the frozen provider plan. Any internal
  stack-detection disagreement may only produce `UNPROVEN`; it may never narrow the frozen
  denominator or produce a clean result.
- Cite real `file:line` or scanner-log evidence for every finding.
- Redact secret values.
- Treat size as review trigger, never decomposition proof.
- A security pattern is a candidate until threat model, attacker control, reachability, impact,
  proof, and false-positive challenge are complete.
- Never install audit tools, fetch mutable rulesets, use external model APIs, or call the network during Audit, except dependency advisory checks in a host-explicit online run (see `provider-architecture.md` §Offline execution). Offline environment variables are defense in depth, not proof. Project-executing
  providers require the trusted host network-sandbox receipt; otherwise they stay `UNPROVEN`.
