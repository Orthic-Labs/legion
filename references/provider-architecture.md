# Audit provider architecture

## Ownership

Cortex owns deterministic repository discovery: first-party files, generated/vendored boundaries,
language parsing, symbols, edges, confidence tiers, freshness, and generation identity. Audit reads
`cortex graph status --json`, `cortex graph manifest`, and `cortex graph export`; it does not maintain
a second provider-selection file/language signature registry.

Audit owns provider planning and execution: project-native build/type/lint/test commands, audit-only
toolchain/config facts, runtime evidence, visual evidence, release checks, security adjudication,
coverage reconciliation, and reports.

The legacy `collect-facts.mjs` implementation may inspect local stack details only to choose the
command for a check that was already selected by the frozen plan. It never selects applicability.
A disagreement between its local command adapter and the Cortex-backed plan produces `skipped` or
`UNPROVEN`; it cannot narrow the denominator or produce a clean result.

## Frozen order

```text
freeze scope + repository identity
  → pin fresh Cortex generation
  → project graph into audit facts
  → load declarative registry data
  → select additive providers deterministically
  → seal and sign plan.json
  → execute exact frozen plan
  → reason only inside selected contracts
  → reconcile report against plan
```

The plan carries two independent protections:

- a SHA-256 integrity digest over the unsigned plan body;
- an HMAC-SHA-256 authenticity signature using `AUDIT_PLAN_SIGNING_KEY` supplied by the trusted host.

Both bind the repository revision, dirty-tree digest, Cortex generation/manifest, registry digest,
provider set, and expected denominators. Missing signing material leaves a valid integrity artifact,
but adds an `unsigned-plan` coverage gap and keeps the audit `UNPROVEN`. A generation, dirty-tree,
registry, denominator, or signature change invalidates the experiment.

If Cortex is missing, stale, corrupt, incomplete, or changes generation during projection, Audit may
run only providers explicitly declared safe without Cortex. The audit remains `UNPROVEN`; it never
falls back to an agent-invented language inventory.

## Registry

The executable registry is declarative. `registry/providers.json` contains legacy/facts and
reasoning contracts; `registry/providers-runtime.json` contains runtime provider contracts and
coverage-family augmentations. `registry/provider-registry.mjs` is the sole authoritative loader: it
parses, merges, and validates both files for the planner, verifier, manifest generator, and tests.
`registry/provider-registry-complete.mjs` is only a compatibility re-export and contains no registry
logic.

`scripts/generate-manifest.mjs` renders the human/scanner compatibility manifest from that same
loader. Edit registry data, regenerate the manifest, and run `generate-manifest.mjs --check`; never
hand-maintain executable selection logic in `manifest.json`.

Selection is additive. Every matching language, framework, platform, security, runtime, and release
provider is selected. Provider capability declarations may be partial or unproven; those states are
coverage gaps, not implicit passes.

Every provider returns or is normalized to:

```text
applicable · required · status · complete · coverage · commands · receipts
inventory · candidates · findings · coverageGaps · artifacts · degradation
```

See `schemas/provider-result-v1.schema.json`.

## Offline execution

The canonical entrypoint is `audit-run.mjs`. Audit always sets defense-in-depth offline controls for
package managers and toolchains and excludes checks that inherently require remote advisory or
version services.

Environment variables alone do not prove network denial because audited project code can open its
own sockets. Therefore project-executing providers—build, type, lint, test, and runtime capture—run
only when the trusted host has already established an external network sandbox and sets
`AUDIT_NETWORK_GUARD=active`. Without that receipt, those providers return `UNPROVEN` and remain in
the frozen denominator. The receipt and skipped checks are recorded in `facts.network_policy`.
Audit never silently enables network to improve coverage.

## Security separation

Security detection is split into independently selected provider contracts:

- `security.credentials`
- `security.insecure-defaults`
- `security.misuse-resistance`
- `security.agentic-ci`
- `security.agent-skill-mcp`

The credential provider applies a three-stage filter: regex/known-format tiers, entropy and
placeholder analysis, then file-context qualification. The agentic-CI provider also emits explicit
agent-to-tool boundary candidates when untrusted prompt/request sources and tool/MCP sinks coexist;
validation, authorization, reachability, and impact are adjudicated separately. Every detector emits
candidates only.

A different provider adjudicates each candidate in its own fresh context through threat model,
attacker control, source-to-sink trace, reachability, primary controls, environmental mitigations,
real impact, proof, and false-positive challenge. Evidence strength, verdict, and severity remain
independent. Confirmed findings require a separate variant analysis before closure.

`adapters/security-adjudication.mjs` enforces provider/context separation and verdict invariants.
`security-pipeline.mjs` rejects context reuse across candidates.

## Measured rule packs

`bench/precision-recall.mjs` consumes labeled positive and negative samples and deterministic
detections. A provider is marked `measured` only when its own rule outputs—not merely provider
selection—have reproducible precision and recall artifacts. Rule packs without that evidence remain
`UNPROVEN` and prevent a clean claim. Numerical metrics are evidence metadata, not repository scores.

## Entry points and outputs

- `/audit` → `audit-run.mjs`, the complete shared provider runner.
- `/audit-fix` → a bounded mutation loop over the same frozen provider contract.
- `/audit-visual` → a thin route over `visual.core`, not a second visual engine.
- `plan.json` — frozen, integrity-sealed, authenticity-signed provider plan.
- `facts.json` — deterministic execution results plus plan/Cortex/network-policy reconciliation.
- `report.json` — normalized audit findings and gate vector.
- `report.sarif` — dependency-free SARIF 2.1.0 projection for code-scanning consumers.
