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
narrows the denominator), `--url`, `--surfaces`, `--visual-spec`, `--visual-baselines`,
`--width`/`--height`, `--plan-only` (freeze and seal the plan without executing it),
`--provider-plan <plan.json>` with repeated `--provider-result <file>` (reconcile supplied results
against a frozen plan), and `--json`. `legion audit --help` is not supported; the flag list lives in
`engine/bins/legion/src/commands/audit.rs`.

Companions: `legion verify <run-dir>` re-checks the persisted facts against the frozen plan;
`legion report <run-dir>/report.json --format md|html|sarif|json [--out <file>]` renders a frozen report;
`legion fix --plan <sealed-remediation-plan>` validates a remediation plan and applies nothing.

## Reasoning lens packets (step 7 detail)

The engine has no in-process reasoning host; the CLI process is the trusted host for ingest. For each
selected reasoning lens `legion audit --out <run-dir>` writes a `pending-host` work packet to
`<run-dir>/lens-packets/<provider>.json`, lists it under `lensWork` and `reasoningLensesPending`, and
generates a random per-run epoch key at `<run-dir>/epoch.key` (mode 0600; only its digest appears in
`plan.json` `epoch.digest` and the report claim `reasoningEpochDigest`). Never read, copy, or print the
key. The session dispatches one fresh-context subagent per packet (up to `CHILD_AGENTS_MAX`) at the
tier `lens-routing.md` assigns. Each subagent writes a result file:

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

## `UNPROVEN` conditions (step 5 detail)

Read `plan.json` before `facts.json`. A stale/missing Blueprint generation, plan-seal or signature
failure, binding drift, selected-provider omission, unsupported toolchain, absent network-sandbox
receipt, incomplete runtime/visual matrix, unmeasured rule pack, network-dependent check, or
unadjudicated security candidate is `UNPROVEN` and keeps the audit incomplete.

## Finalize and verify (steps 9 and 10 detail)

`legion audit` writes `report.json` and `report.sarif` itself; there is no separate finalize binary and
no `--candidates` / `--adjudication` flag. Security adjudication verdicts are recorded by the main
session in its reconciliation notes and the final report; the native runner does not ingest them.
After the run:

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
- Never install audit tools, fetch mutable rulesets, use external model APIs, or call the network
  during Audit. Offline environment variables are defense in depth, not proof. Project-executing
  providers require the trusted host network-sandbox receipt; otherwise they stay `UNPROVEN`.
