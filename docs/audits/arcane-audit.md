# Arcane Subsystem Audit

Date: 2026-08-29. Method: read-only inspection of hooks wiring, both Arcane implementations (Rust engine and JS package), policy/receipt schemas, MCP surface, CLI, docs, and tests.

## 1. Executive summary

Arcane exists as **two independent, non-communicating implementations** that both call themselves Arcane:

- **JS reference** (`src/packages/arcane/**`, 187 files, ~86 tests): deny-by-default policy (POL-1, `unclassifiedEffect: "deny"`), HMAC-signed hash-chained receipt store with `verifyChain()` and quarantine, host-event ingestion that rejects model self-reports, pre-effect correlation, completion gate, stop-shape, S01–S11 stage machinery, and its own Claude Code/Codex hook adapters. **Not wired to anything a host invokes.**
- **Rust engine** (`engine/` — `legion-hook`, `legion` MCP/CLI): the implementation `hooks/hooks.json` and `mcp.json` actually invoke. It is materially thinner than its documentation implies: **no receipt persistence at all**, and **fail-open by default** for every effect class.

The green JS test suite therefore gives false assurance about production behavior. No architecture document describes the live runtime; the SSOT (§3, line 108) names `src/packages/arcane/**` as the runtime enforcement owner — the wrong codebase.

Arcane is also the only authority with **no agent card, no doctrine file, and no skill** (`agents/arcane.md`, `doctrine/arcane.md`, `skills/arcane/` all absent); it is documented only as principle statements (SSOT §8) plus a stale plan.

## 2. Enforcement surfaces (live Rust path)

- 8 events wired to `legion-hook` (10s timeout). Lifecycle events — `SessionStart`, `SubagentStart`, `UserPromptSubmit`, `PostCompact`, **and `Stop`** — are unconditionally allowed before any policy runs (`main.rs:28-29`). `PostToolUse`/`PostToolUseFailure` are unconditionally allowed with no receipt written (`main.rs:31-32`).
- `PreToolUse` is the only policy-reaching event: two hardcoded hard-gates (destructive commands; unapproved force-push), then a heuristic `EffectRequest` → `authorize_effect`.
- **Default behavior is fail-open.** With `LEGION_NATIVE_APPLICATION_CONFIG` absent — the shipped state; nothing sets it — every effect class (`FILE_DELETE`, `CREDENTIAL_ACCESS`, `VCS_PUSH`, `PUBLISH`, …) is allowed as "ambient effect accepted", asserted by the binary's own test `absent_policy_allows_every_effect_class` (`main.rs:667-687`), and labeled `enforcement_health: "strong"` — misleading for a no-policy pass-through.
- Config present but unparseable → deny (fail-closed). Config wired to the shipped `arcane-m1-policy.json` (named `legion-installed-m1-deny-by-default`, but with **empty `effect_rules`**) → `CanonicalEffectPolicy` finds no matching rule → **denies everything** (`legion-application/src/lib.rs:1649-1652`). An undocumented behavioral cliff: unwired = allow-all, wired-to-shipped-policy = deny-all.
- The MCP surface is correctly **fail-closed** (`ReleaseBindingGate`; unloadable application → inert server) — asymmetric with the hook.

## 3. Receipt lifecycle

Five non-interoperating receipt/record schemas; the live enforcement path produces **none**:

1. Hook path: no receipt object exists; `authorize_effect` returns `Result<(), RuntimeError>` only.
2. `legion_m1_invoke`: `InvocationReceipt` built in-memory, returned in the MCP response, never persisted.
3. `legion-effects::ExecutionReceipt`: audit-provider executor only, unrelated to hooks.
4. `legion_contracts::EffectReceipt`: dead type, never constructed.
5. JS `ReceiptStore`: the only durable, verifiable implementation (`receipts.jsonl` + `chain-head.json`, HMAC, `verifyChain()`, quarantine) — reachable only through the JS CLI/adapters. The `.audit/arcane/**` state on disk comes from here, not from anything a host fires.

## 4. Findings

1. **[Critical] Default install is fail-open for all effect classes** (§2), contradicting every "Arcane gates classified effects" claim and the shipped policy's own deny-by-default name.
2. **[Critical] No receipt is produced or persisted by the live enforcement path.** "Records receipts silently" is true only of the unwired JS package. Nothing exists to audit after the fact.
3. **[Critical] MCP tools are entirely ungated.** Hook matchers (`hooks.json:52,64,76`) never match `mcp__*` — MCP write actions (email, Slack, DB writes, calendar, purchases) receive zero interception and zero receipt; the hook is never invoked. `EffectClass::ExternalSideEffect` exists in the model but `parse_effect_class` never emits it.
4. **[Critical] Event vocabulary likely mismatches Claude Code.** `SubagentStart`, `PostCompact`, `PostToolUseFailure` are registered; Claude Code's events are `SubagentStop`, `PreCompact`, and failures arriving as `PostToolUse`. If confirmed against the live host schema, three of eight registrations are silent no-ops and the real events are never registered. `Notification`/`SessionEnd`/`PermissionDecision`: zero references repo-wide, no non-goal record.
5. **[High] `Stop` cannot be blocked** despite registration — so neither Oracle-PASS gating nor open-contract gating at session end is possible today (see `docs/audits/oracle-audit.md`).
6. **[High] No PATH/health verification for the binaries.** Bare `"command": "legion-hook"`; the plugin ships no binary in `hooks/`; `legion doctor` checks declarations, never resolution; a missing binary degrades per host semantics to non-blocking — silently disabling even the hard gates. Compounded by an undeclared capability: neither `legion` nor `legion-hook` appears in `src/registry/capabilities.json`, and no public distribution channel currently ships them (`release/distribution-contract.json:13` nativeRelease blocked; npm private; homebrew/winget empty).
7. **[High] No architecture document for the live implementation**; SSOT misattributes ownership; `docs/host-integration-plan.md` is labeled "active implementation plan" while describing the retired JS hook, including an "ask" escalation the Rust binary cannot produce (`protocol.rs` emits only deny).
8. **[High] Incompatible policy schemas.** Three-to-four policy-pack shapes coexist; the hook's `CanonicalEffectPolicy` hard-fails any rule specifying `required_trust`/`required_enforcement` (`lib.rs:1663-1667`), so the richer semantics in `schemas/arcane-policy-pack.v1.schema.json` and the JS POL-1 cannot be enforced through the live hook even if wired.
9. **[Medium, bug] `MultiEdit` is matched but unclassified** (`main.rs:339-347` maps only `Write|Edit|NotebookEdit`) → every `MultiEdit` call is unconditionally denied `ARC_HOST_EVENT_INVALID`, regardless of configuration.
10. **[Medium] Windows destructive-command coverage is incomplete**: no `rd /s`, `rmdir /s /q`, `del /s /q`, `erase`, or PowerShell aliases (`ri`, `rd`, `del`) — native Windows recursive deletes fall through to ambient-allow.
11. **[Medium] Network egress never pre-blocked**: `WebFetch|WebSearch` appear only in PostToolUse matchers, and the post-effect branch allows unconditionally without consulting policy.
12. **[Medium] 10s timeout with O(n) ledger cost trend** (~317ms @ 774 records per the plan doc) — timeout = failed hook = fail-open.
13. **[Low] `legion run open/close` silently no-ops** with `status: "incomplete"` and exit 0 when unconfigured (`cli.rs:1954-1962`), masking the same missing-config condition behind Finding 1.
14. **[Low] Dead/near-miss types** (`EffectReceipt`; vocabulary-sharing `ExecutionReceipt`) invite future conflation; `qualification/evidence/lanes/E-ARCANE/` is unpopulated despite `INTERFACES.md` prescribing it.

## 5. Recommended fixes, in order

1. Decide fail-open vs fail-closed **deliberately** and make the artifacts agree: ship a minimal real default policy (non-empty `effect_rules`), or rename/document ambient-permissive as the intended stock posture. Fix the empty-policy deny-all cliff either way.
2. Persist receipts in the live path — port or bind the JS `ReceiptStore` chain (receipt-before-effect, content-free, hash-chained) into `legion-hook`.
3. Correct the event vocabulary against Claude Code's real hook schema; register `SubagentStop`/`PreCompact`; drop or remap the no-op names.
4. Add `mcp__*` category matchers and wire `ExternalSideEffect`; fix the `MultiEdit` bug; add cmd.exe/alias destructive verbs.
5. Declare `legion`/`legion-hook` as host capabilities with degradation behavior; add a doctor check that the binaries resolve; unblock a distribution channel that actually ships them.
6. Write `doctrine/arcane.md` + an architecture document for the live Rust pipeline (gate flow, policy schema, receipt schema, degradation table); mark `host-integration-plan.md` superseded; correct SSOT ownership.
7. Make `Stop` gateable (prerequisite for Oracle enforcement and open-contract gating).
8. Reconcile the policy schemas or explicitly version them; either implement trust/enforcement inputs in `CanonicalEffectPolicy` or remove those fields from the canonical schema.
