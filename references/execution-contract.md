# Audit — execution contract (normative detail)

Relocated verbatim from `SKILL.md` to meet the body token budget (2026-08-09). This text is
normative; the SKILL body summarizes it.

## Canonical entrypoint (step 3 detail)

`node <audit-skill-dir>/audit-run.mjs <root>` is the canonical entrypoint. It pins one fresh
Cortex `generationId`, enriches only audit-owned manifest/toolchain facts, loads the complete
declarative provider registry, writes a SHA-256-sealed and HMAC-signed `plan.json`, and executes
the exact frozen provider set. Set `AUDIT_PLAN_SIGNING_KEY` through the trusted host environment.
Missing signing material is `UNPROVEN`; it never degrades silently to an authenticity claim.
`audit-complete.mjs` is an internal compatibility runner and is not a public entrypoint.

## Network sandbox and runtime capture (step 4 detail)

Project-executing checks and runtime capture require a trusted host network sandbox. The host sets
`AUDIT_NETWORK_GUARD=active` only after network denial is actually enforced outside the audited
process. Without that receipt, build/type/lint/test/runtime commands are skipped as `UNPROVEN`;
file-only providers still run. Supply `--url <running-app-url>` for selected runtime providers,
`--surfaces <targets.json>` for button/card-driven views, `--visual-spec <spec.json>` for explicit
rendered evidence, or `--visual-baselines <map.json>` for baseline comparison.

## `UNPROVEN` conditions (step 5 detail)

Read `plan.json` before `facts.json`. A stale/missing Cortex generation, plan-seal or signature
failure, binding drift, selected-provider omission, unsupported toolchain, absent network-sandbox
receipt, incomplete runtime/visual matrix, unmeasured rule pack, network-dependent check, or
unadjudicated security candidate is `UNPROVEN` and keeps the audit incomplete.

## Finalize invocation (step 9 detail)

```bash
node <audit-skill-dir>/audit-finalize.mjs --facts <facts.json> \
  --candidates <security-candidates.json> --adjudication <security-adjudication-result.json>
```

Writes both `report.json` and `report.sarif`.

## Hard rules (full text)

- Order is freeze scope → deterministic Cortex projection → deterministic provider plan → execute
  frozen plan → provider-bounded reasoning.
- The agent never selects, adds, removes, or narrows providers after execution begins.
- `registry/providers.json` plus its declarative registry extensions are the executable source of
  truth. JavaScript loaders may validate and merge registry data, but may not invent providers or
  qualifications.
- `plan.json` carries a SHA-256 integrity digest and an HMAC-SHA-256 authenticity signature bound
  to revision, dirty digest, Cortex generation, registry digest, provider set, and denominators.
  An unsigned plan is valid only as an `UNPROVEN` artifact and cannot support a clean claim.
- Cortex owns file, language, workspace, symbol, and graph discovery. Audit owns toolchain,
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
