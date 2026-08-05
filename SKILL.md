---
name: audit
description: Diagnose a whole repository through a frozen Cortex-backed provider plan, first-party language/framework/security/runtime/visual providers, and rerunnable JSON/SARIF evidence. Use `/audit` or `/audit-fix`; use `/commit` for one diff.
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

1. Freeze repository root, scope, revision, dirty state, and requested mode.
2. Read [provider architecture](references/provider-architecture.md). Discovery belongs to Cortex; Audit never builds a parallel language/file registry.
3. Run `node <audit-skill-dir>/audit-run.mjs <root>`. This is the canonical entrypoint. It pins one fresh Cortex `generationId`, enriches only audit-owned manifest/toolchain facts, loads the complete declarative provider registry, writes a SHA-256-sealed and HMAC-signed `plan.json`, and executes the exact frozen provider set. Set `AUDIT_PLAN_SIGNING_KEY` through the trusted host environment. Missing signing material is `UNPROVEN`; it never degrades silently to an authenticity claim. `audit-complete.mjs` is an internal compatibility runner and is not a public entrypoint.
4. Project-executing checks and runtime capture require a trusted host network sandbox. The host sets `AUDIT_NETWORK_GUARD=active` only after network denial is actually enforced outside the audited process. Without that receipt, build/type/lint/test/runtime commands are skipped as `UNPROVEN`; file-only providers still run. Supply `--url <running-app-url>` for selected runtime providers, `--surfaces <targets.json>` for button/card-driven views, `--visual-spec <spec.json>` for explicit rendered evidence, or `--visual-baselines <map.json>` for baseline comparison.
5. Read `plan.json` before `facts.json`. A stale/missing Cortex generation, plan-seal or signature failure, binding drift, selected-provider omission, unsupported toolchain, absent network-sandbox receipt, incomplete runtime/visual matrix, unmeasured rule pack, network-dependent check, or unadjudicated security candidate is `UNPROVEN` and keeps the audit incomplete.
6. Read [engine interface](references/engine-interface.md) for scanner, report, and CLI contracts.
7. Read [lens routing](references/lens-routing.md); reason only inside providers selected by the frozen plan. Candidate generation, adjudication, and variant analysis use separate providers and separate contexts.
8. Adjudicate every entry in `security-candidates.json` in its own fresh context. A candidate generator may not close its own candidate. Confirmed findings require repository-wide variant analysis.
9. Deduplicate findings, then run `node <audit-skill-dir>/audit-finalize.mjs --facts <facts.json> --candidates <security-candidates.json> --adjudication <security-adjudication-result.json>`. It writes both `report.json` and `report.sarif`.
10. Reconcile every selected provider and denominator against the final report. Skipped, absent, errored, stale, partial, unmeasured, unsigned, unsandboxed, or review-required coverage is never clean.

Return gate vector, provider and framework coverage, top findings, exact evidence loci, rerun commands,
plan seal and signature, Cortex generation, measured rule-pack qualification, network-policy receipt,
runtime/visual artifacts, and typed degradation. Keep `quality_gate` separate from overall audit status.

Read [full manual](references/manual.md) only for audit-fix, decomposition, best-shape claims,
complex runtime coverage, migrations, desktop/Tauri, data safety, or report-schema edge cases. Load
only matching specialist checklist for security, performance, accessibility, SQLite, migrations,
or desktop work.

Hard rules:

- Order is freeze scope → deterministic Cortex projection → deterministic provider plan → execute frozen plan → provider-bounded reasoning.
- The agent never selects, adds, removes, or narrows providers after execution begins.
- `registry/providers.json` plus its declarative registry extensions are the executable source of truth. JavaScript loaders may validate and merge registry data, but may not invent providers or qualifications.
- `plan.json` carries a SHA-256 integrity digest and an HMAC-SHA-256 authenticity signature bound to revision, dirty digest, Cortex generation, registry digest, provider set, and denominators. An unsigned plan is valid only as an `UNPROVEN` artifact and cannot support a clean claim.
- Cortex owns file, language, workspace, symbol, and graph discovery. Audit owns toolchain, manifest, build/test, runtime, visual, release, and adjudication evidence.
- Legacy scanner adapters receive their applicability from the frozen provider plan. Any internal stack-detection disagreement may only produce `UNPROVEN`; it may never narrow the frozen denominator or produce a clean result.
- Preserve functionality in audit-fix; restore behavior before cleanup or style work.
- Cite real `file:line` or scanner-log evidence for every finding.
- Redact secret values.
- Treat size as review trigger, never decomposition proof.
- A security pattern is a candidate until threat model, attacker control, reachability, impact, proof, and false-positive challenge are complete.
- Never install audit tools, fetch mutable rulesets, use external model APIs, or call the network during Audit. Offline environment variables are defense in depth, not proof. Project-executing providers require the trusted host network-sandbox receipt; otherwise they stay `UNPROVEN`.
