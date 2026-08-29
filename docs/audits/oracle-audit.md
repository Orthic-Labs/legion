# Oracle Subsystem Audit

Date: 2026-08-29. Method: read-only inspection of the Oracle definition chain, dispatch substrate, enforcement surfaces, packages, and tests, plus cross-cutting packaging/harness analysis.

## 1. What Oracle is, per canon

Independent assurance authority: read-only semantic Completion Validation before every successful final delivery. Reconstructs scope from raw user turns, distrusts implementer prose, returns `PASS` or `BLOCK` with violated requirement plus path/line, never runs tests, one repair + one recheck max. Model tier `frontier-judgment` (`opus`). Chain: `src/roster/oracle.md` → `doctrine/oracle.md` → `agents/oracle.md`.

## 2. Why Oracle *is* reliably dispatched (unlike Sage/Alchemist)

The mandatory trigger lives in the always-loaded constitution, five times over: `AGENTS.md:13` (invariant 7), `:44` (tier 5 runbook), `:46` ("say done only after PASS"), `:75` (package rules), plus SSOT:83 and `docs/agent-rules.md:17`, and canonical sources point to `doctrine/oracle.md`. The trigger is a concrete universal event ("before every successful final delivery"), not an abstract state. This asymmetry — not description quality — is the reason sessions dispatch Oracle and not the other two authorities.

## 3. Architecture documentation status

**Doctrine-only.** No architecture document specifies, in one place, the dispatch path, the input packet, the output contract, and the enforcement point:

- Packet format: prose only (`doctrine/oracle.md` and AGENTS.md list contents in natural language). No JSON/TS schema for the Completion Validation packet exists.
- Output contract: a prose text-block convention ("Scope reviewed: … / PASS" or "BLOCK\n- path:line — defect — violates requirement") — not a parseable artifact, receipt, or schema.
- Enforcement point: none (Finding 1).
- A machine-checked `oracle` packet branch *does* exist — but for the tier-4 contract-chain substrate, not ambient Completion Validation, and it is broken (Finding 3).

## 4. Findings

1. **[Critical] Nothing mechanically enforces Completion Validation.** The `Stop` hook — the only structural interception point for "final delivery" — classifies `Stop` as a lifecycle event and unconditionally allows it (`engine/bins/legion-hook/src/main.rs:28-30`, `protocol.rs:126-141`). No code anywhere reads an Oracle verdict. The closest gate, `src/packages/arcane/lib/stop-shape.mjs`, checks closing-message *prose shapes* only — a fabricated "Oracle returned PASS" sails through. Enforcement rests entirely on doctrine compliance. `README.md:57`'s fidelity table ("Oracle Completion Validation | yes | yes | yes") overstates this as a harness guarantee.
2. **[High] No machine-checkable PASS/BLOCK receipt.** No schema, no receipt file, no digest binding a verdict to a specific diff/artifact set (contrast Alchemist's sealed `EC-*` execution contracts). Nothing prevents "PASS" from being asserted without Oracle running, and nothing lets a later audit verify a delivery was validated.
3. **[High] The authority-dispatch Oracle branch is broken by naming drift.** `authority-dispatch-v1.schema.json:18` requires `packetType: "oracle"`, but `src/lib/dispatch-validator/validate-dispatch.py:494,514` recognizes only the retired `"seer"` (its own fixtures too, `test_validate_dispatch.py:1506`) — a schema-conformant packet is rejected. The naming contract (`tests/naming-contract.test.mjs:15-16`) says `seer` is fully retired. The contracts smoke test covers only the JSON schema, so the drift is uncaught.
4. **[Medium] Undocumented second duty.** `skills/dispatch/references/manual.md:154-166` assigns Oracle *pre-execution* adversarial packet review (allowlist completeness, lane disjointness, dependency validity, parallelism, closure) in Completion-Validation vocabulary. Doctrine says Oracle is "never a routine reviewer of ordinary work" and reviews only completed work. No canonical file reconciles the two, or states whether one-repair-one-recheck applies.
5. **[Medium] Package-name collision.** `src/packages/oracle/**` is a facade over the **Audit** core (inspect/plan/audit/verify/explain; findings/denominators/claimBoundary output), unrelated to Completion Validation, with **no consumer found anywhere** — yet it ships in the package lists and is the first thing a code search for "oracle" surfaces. Likely an abandoned migration artifact; actively misleading.
6. **[Low-Medium] The tier/trigger text migrated out of `doctrine/legion.md`** into AGENTS.md; the routing doc a reader would naturally consult contains no trigger rule.
7. **[Low] A known historical blind spot is unmitigated.** `docs/provenance/oracle-assurance-archived.md:296-306` records a real escape (machine-state poisoning outside the repo; Oracle diffs source, not runtime state) and prescribes `legion state snapshot/verify` — which does not exist in the current CLI.
8. **[Low] No golden-fixture test of the output format** — even the machine-checkable part of the contract (its text shape) is unverified by CI.
9. **[Medium, packaging] `agents/oracle.md`'s doctrine pointers are bare relative paths** (no `${CLAUDE_PLUGIN_ROOT}`), unreachable when the plugin is installed standalone; and no `tools:` allowlist enforces Oracle's read-only mandate structurally — it is prose-only.

## 5. Recommended fixes, in order

1. Define an `oracle-completion-validation-v1` packet + receipt schema (verdict, scope digest, diff digest, path/line findings), and have Legion require the receipt before reporting done — even before any hook enforcement exists, a typed artifact beats prose.
2. Make `Stop` enforceable: hook checks for a fresh Oracle receipt bound to the session's delivery claim (see `docs/audits/arcane-audit.md` — Stop is currently structurally unblockable).
3. Fix the `seer`→`oracle` drift in `validate-dispatch.py` and its fixtures.
4. Reconcile or re-home the dispatch-skill pre-execution review duty.
5. Rename, document, or remove `src/packages/oracle` (name collision).
6. Enforce read-only structurally: add a `tools:` allowlist (no Bash/Edit/Write) to `agents/oracle.md` frontmatter.
7. Add a golden-fixture output-format test; consider anchor-based rubrics and per-finding independent validation to reduce BLOCK false positives (see absorption catalog).
