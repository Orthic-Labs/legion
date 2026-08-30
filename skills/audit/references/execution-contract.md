# Audit — execution contract (normative detail)

Relocated verbatim from `SKILL.md` to meet the body token budget (2026-08-09). This text is
normative; the SKILL body summarizes it.

## Canonical entrypoint (step 3 detail)

`legion audit <root> --out <run-dir>` (implemented by `src/lib/core/audit.mjs`) is the canonical
entrypoint. It enriches audit-owned manifest/toolchain facts, loads the complete declarative
provider registry, writes `plan.json`, and executes the exact frozen provider set. `plan.json`'s
`seal` field is currently a stub (`{sealed:true}`, no cryptographic digest) and it carries no
HMAC `signature`; Blueprint `generationId` pinning is not wired into this path either. Treat seal,
signature, and generation pinning as `UNPROVEN` until `REPAIR_WIRE` lands (see `docs/canon/legion.md`
LEG-0xx). `AUDIT_PLAN_SIGNING_KEY` / real sealing logic exists only in the orphaned
`tools/audit/audit-run.mjs` and `tools/audit/audit-plan.mjs`, which are not reachable from the CLI
(only `scripts/self-test.mjs` and tests reference them) — do not invoke them as the entrypoint.

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

## Finalize invocation (step 9 detail)

`legion audit` reaches finalize through `src/lib/core/finalize-run.mjs`, which calls the exported
`finalizeAudit()` from `tools/audit/audit-finalize.mjs` — it does not run that file's own CLI
`main()`. Only `report.json` is written on this path; the SARIF writer lives solely inside
`audit-finalize.mjs`'s CLI `main()` and is never invoked by `legion audit`, so `report.sarif` is
not currently emitted. Execution results are recorded as `receipts.json` (not `execution.json` —
that name/shape does not exist on the reachable path).

## Hard rules (full text)

- Order is freeze scope → deterministic Blueprint projection → deterministic provider plan → execute
  frozen plan → provider-bounded reasoning.
- The agent never selects, adds, removes, or narrows providers after execution begins.
- `registry/providers.json` plus its declarative registry extensions are the executable source of
  truth. JavaScript loaders may validate and merge registry data, but may not invent providers or
  qualifications.
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
