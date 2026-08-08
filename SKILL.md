---
name: audit
description: Diagnose a whole repository through a frozen Cortex-backed provider plan, first-party language/framework/security/runtime/visual providers, and rerunnable JSON/SARIF evidence. Use `/audit` for read-only diagnosis.
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

The [execution contract](references/execution-contract.md) is normative; this summary never
overrides it.

1. Freeze repository root, scope, revision, dirty state, and requested mode.
2. Read [provider architecture](references/provider-architecture.md); discovery belongs to
   Cortex — never build a parallel registry.
3. Run `node <audit-skill-dir>/audit-run.mjs <root>` (canonical entrypoint): fresh Cortex
   generation, sealed and signed `plan.json`, exact frozen provider set; missing signing
   material is `UNPROVEN`.
4. Project-executing checks need the trusted host network-sandbox receipt; without it they are
   `UNPROVEN`, file-only providers still run. Runtime/visual flags are in the contract.
5. Read `plan.json` before `facts.json`; every contract-enumerated failure is `UNPROVEN` and
   keeps the audit incomplete.
6. Read [engine interface](references/engine-interface.md) for scanner, report, and CLI contracts.
7. Read [lens routing](references/lens-routing.md); reason only inside frozen-plan providers;
   separate contexts for generation, adjudication, variant analysis.
8. Adjudicate each security candidate in a fresh context; no generator closes its own; confirmed
   findings get repository-wide variant analysis.
9. Deduplicate, then run `audit-finalize.mjs` (exact invocation in the contract) to write
   `report.json` and `report.sarif`.
10. Reconcile every provider and denominator; contract-enumerated incomplete coverage is never
    clean.

Return gate vector, coverage, findings with evidence loci, rerun commands, seal and signature,
Cortex generation, receipts, artifacts, typed degradation; `quality_gate` stays separate.

Read [full manual](references/manual.md) only for decomposition, best-shape claims, complex
runtime coverage, migrations, desktop/Tauri, data safety, or report-schema edges; load only the
matching specialist checklist.

Hard rules are normative in the contract: frozen provider order, registry as executable truth,
unsigned plan ⇒ `UNPROVEN` only, Cortex/Audit evidence ownership split, no denominator narrowing,
real `file:line` evidence, secret redaction, size ≠ decomposition proof, full security-candidate
challenge, and no installs, mutable rulesets, external model APIs, or network mid-audit.
