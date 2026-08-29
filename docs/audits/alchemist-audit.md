# Alchemist Subsystem Audit

Date: 2026-08-29. Method: read-only inspection of the full Alchemist definition chain, skill package, contracts/governance layer, registry, CI wiring, and tests, plus cross-cutting packaging/harness/discoverability analysis.

## 1. What Alchemist is, per canon

Controlled transformation authority: applies an already-bounded contract, integrates exact artifacts, runs declared checks, mechanically repairs implementation failures. Model tier `balanced-executor` (`sonnet`). Chain: `src/roster/alchemist.md` → `doctrine/alchemist.md` → `agents/alchemist.md`, plus the `/alchemist` skill (`skills/alchemist/`, `discoverability: explicit`, aliases `/jfdi`, `/justdoit`) whose scripts are the OmniRoute cheap-worker adapter.

## 2. Architecture documentation status

**No single consolidated architecture document; the pieces are individually well specified.** Coverage is split across: SSOT §6/§9/§12/§14/§18 (boundary, tier), `doctrine/alchemist.md` (method), nine contract schemas (packet shape, schema-only), `GOALROUTE.md` (state binding, not cross-linked), `skills/alchemist/references/manual.md` (excellent, but scoped to the worker adapter and self-disclaimed as host-specific), the Arcane packages (receipts/grants, code-only), and `docs/host-integration-plan.md` §1.2/§2 (projection). Missing: one reader-facing trace of **dispatch → contract validation → capability grant → execution (ambient or OmniRoute) → receipt/event-ledger → completion gate**. Today that path must be assembled from five-plus files that never cross-reference each other; `doctrine/alchemist.md` never mentions the dispatch-validator or the Arcane capability-grant machinery that actually governs its effects.

## 3. Invocation surfaces

- `/alchemist` (+`/jfdi`, `/justdoit`) — explicit-only by design; excluded from natural-language classification (SSOT §9:312-313) and correctly absent from `routing/domains.json`.
- Task-tool subagent via `agents/alchemist.md` (minimal pointer card).
- `@alchemist` (AGENTS.md:50).
- One **mechanical** trigger: the dispatch validator requires a satisfied Alchemist gate when a packet's task semantics include `EXPERIMENT|BENCHMARK|PERFORMANCE|MODEL|RESEARCH|REPEATED_FAILURE` (`validate-dispatch.py:1891-1943, 2117-2147`).
- Codex projection `[agents.alchemist]` TOML, `allow_implicit_invocation: false`.

## 4. Why Alchemist is rarely dispatched

Reachable, but structurally dormant in practice:

1. **The constitution discourages it.** `AGENTS.md` declares ambient the default for mutations and repeats "`execute` does not imply Alchemist" three times as a pure anti-trigger, with no positive worked example. Canonical sources never point to `doctrine/alchemist.md`.
2. **Its precondition almost never becomes true.** The trigger is "policy, locking, explicit contracting, or risk requires a controlled boundary" — but the live hook gate is fail-open when unconfigured (see `docs/audits/arcane-audit.md`), no default policy ships, and so a policy-enforced lock structurally never arises in a stock install.
3. **Over-declared host requirement.** `src/registry/skills/index.json` declares `hostRequirements: ["omniroute"]` at the entrypoint level (degradation: exit 4, treat unavailable), though `skills/alchemist/SKILL.md:26` scopes omniroute to the worker-execution sub-path only. Probing logic can report the whole capability unavailable when only cheap delegation is.

## 5. Findings

1. **[High] The worker-runner test suite never runs.** `skills/alchemist/tests/test_windows_runner.py` (5 real cases driving `run-worker.ps1` through `powershell.exe` with a faked `omniroute.cmd`) is orphaned: `package.json:106` globs only `*.test.mjs`, and no pytest step exists in `.github/workflows/ci.yml` or `scripts/ci/right-git-ci.sh` despite a windows-2025 CI leg. A regression in the highest-risk component ships undetected.
2. **[Medium] Behavioral eval fixtures are unwired.** `skills/alchemist/evals/evals.json` and `legacy-jfdi.json` encode the safety-critical behaviors (never push, never print gateway secrets, worker claim ≠ proof, no-contract-no-effect) — no runner executes them (`run-architecture-evals.mjs` reads only `src/evals/architecture/*.jsonl`).
3. **[Medium] `run-worker.sh` has zero automated coverage** and known gaps (no isolated home/sandbox, `gtimeout` fallback).
4. **[Medium] Constitution asymmetry** (§4.1) — the primary reason Alchemist is never proactively selected.
5. **[Low-Medium] No end-to-end architecture doc** (§2).
6. **[Low] Three independently maintained description strings** (`agents/`, `src/roster/`, `doctrine/` frontmatter); the only automated check is a substring assertion (`roster/index.mjs:45` requires "Dispatch").
7. **[Low] Host-requirement over-declaration** (§4.3).
8. **[Info] Legacy `forge`/`sorcerer` shim is live** (`arcane/compatibility/forge/schema-map.json:156` still projects `ALCHEMIST_STATE` values) — intentional per SSOT §16, but must be retired deliberately, not mistaken for dead code.
9. **[Info] Governance-layer coverage is strong**: bind projection, naming contract, arcane stage tests (including sealer rejection of Alchemist self-certification, `contract-seal-store.test.mjs:36-39`), 1500+ lines of dispatch-validator pytest, goalroute binding tests all run in CI.

## 6. Recommended fixes, in order

1. Wire `test_windows_runner.py` (and a `run-worker.sh` equivalent) into CI; wire the eval fixtures into a runner.
2. Give Alchemist a worked-example block in `AGENTS.md` (the one concrete precondition it has: an explicit multi-file contract handed off from a Sage freeze with named acceptance IDs) and add `doctrine/alchemist.md` to canonical sources.
3. Decide the ambient-by-default question deliberately: either ship a minimal default locked-domain policy so Alchemist's trigger can occur in stock installs, or document Alchemist as dormant-until-opt-in.
4. Narrow the registry `hostRequirements` to the worker-delegation operation.
5. Write the end-to-end architecture trace document (§2) — this is the audit's "architecture document exists?" answer: only for the worker adapter; not for the authority as wired.
6. Add description-parity checking across the three definition files to `legion:check`.
7. Adopt a typed dispatch-return vocabulary (`fixed|rejected|deferred` + `structural: true` escalation; `DONE/DONE_WITH_CONCERNS/BLOCKED/NEEDS_CONTEXT`) — see absorption catalog.
