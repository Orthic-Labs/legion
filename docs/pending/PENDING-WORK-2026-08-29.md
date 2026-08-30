# Consolidated Pending Work — 2026-08-29 (rev 5; wave-A execution marked 2026-08-30)

Single tracker merging: the 2026-08-29 subsystem audits (`docs/audits/2026-08-29/`), the remediation
status after commits `24d52058`/`a188f799`, the two adopted architecture proposals in this folder,
and the Sol review corrections. Rev 3 records the converged resolutions of both formerly
owner-reserved decisions (P0.1 canonical default policy; P4.23 delete the fake Oracle package).
Fixed items are excluded. No owner-reserved decisions block execution (the Guard's final name
remains open but blocks nothing). Rev 4 adds the Bounded Falsification primitive, FILE_DELETE
discrimination, and the supervision-deferral disposition.

## P0 — Guard honesty and hardening (the deterministic effect layer)

1. **DONE (2026-08-30, in-flight): canonical default Guard policy shipped** as `canonical_default_policy_pack()` in `engine/crates/legion-contracts/src/policy.rs`, with `targets`/`operations` filtering for `FILE_DELETE` discrimination. Original: **RESOLVED (2026-08-29): ship a canonical default Guard policy.** Neither of the originally
   written options survives: not "ambient allow with advisory label," not a policy that can simply
   be absent. The normal installed state is a built-in default policy that is always present:
   ordinary reversible effects → ambient allow *as an explicit policy decision*; reserved/high-risk
   effects (credential access, publish, delete, push, …) → deny/approval. Optional user/project
   policy may tighten or extend the baseline. If the baseline itself cannot load or validate, that
   is a real Guard failure → **fail closed**. Ambient permission is a policy decision, not the
   absence of policy. (The current state asserts, in its own test, that every effect class is
   allowed with `enforcement_health = "strong"` when policy is absent — indefensible for a security
   subsystem.) **`FILE_DELETE` needs target/operation discrimination, not class-level approval:**
   ordinary bounded workspace deletion (recoverable, within scope) may be ambient-allowed by
   policy; destructive/recursive/broad/protected-target deletion is deny/approval. The policy
   schema filters by `targets` and operation; the effect class alone is too broad — otherwise every
   source-file removal in a refactor needs approval. Implement together with item 4 (policy-artifact
   reconciliation) so a second ambiguous historical policy never coexists with the new baseline.
   (arcane-audit gap 1)
2. **NOT DONE (2026-08-30):** build/deploy effect, deliberately left to the owner. The lockout was hit repeatedly during this session's work; the denial string is `engine/bins/legion-hook/src/main.rs:211` ("source revision is missing"), raised when the payload cwd has no resolvable `.git`. Workaround used throughout: keep the shell cwd at the repository root and wrap directory changes in a subshell. Original: Redeploy the installed binary — the committed subdirectory-resolution and MultiEdit fixes are not
   in the deployed `legion-hook.exe`; the lockout was reproduced live in-session on 2026-08-29.
3. **DONE (2026-08-30, lane-a1):** `engine/crates/legion-policy/tests/guard_property.rs`, 9 properties, `cargo test -p legion-policy` green. Original: Fuzz/property-test the Guard's input path **before** widening it to MCP/effects. Threat model:
   adversarial model- and tool-controlled payloads (the actual trust boundary), not just an outside
   attacker. Inputs: malformed/nested/huge JSON, odd Unicode, missing/null/wrong-type fields, shell
   quoting and nested `sh -c`/`cmd`/`powershell`, path oddities, MCP names/payloads, multi-target
   edits, unknown effect classes. Properties, not examples: never panic, never hang, bounded
   memory/time, denial never becomes fallback, known-dangerous variants stay denied, unknown
   classification never claims strong authorization, parser ambiguity is explicit. The crate
   currently has no fuzz/property dependency.
4. **DONE (2026-08-30, in-flight):** `src/packages/arcane/policy/README.md` marks the Node bundle historical; no rule content needed porting. Original: Reconcile the two policy artifacts: port `src/packages/arcane/policy/arcane-policy-v1.json` rules
   into the policy-pack schema `legion-application` consumes, or mark it historical. (gap 2)
5. **DONE (2026-08-30, lane-b7): triage written to `docs/pending/arcane-package-triage.md`** — all 235 files classified exactly once (68 PORT, 22 RESTORE, 207 MOVE, 20 RETIRE across per-portion SPLITs; 0 inferred from filename alone, 0 unresolved). `stop-shape.mjs` is recorded as a SPLIT per the tracker's own example, as are `host-runtime.mjs`, `hook-adapter-core.mjs`, and five others. **Execution of the dispositions is NOT done** — this item produced the disposition map only; moving/retiring the files remains.

    **Execution attempted and correctly refused (2026-08-30, lane-d2): the triage's RETIRE class is wrong.** A lane dispatched to delete the twelve RETIRE files stopped before mutating anything, because they are not dead ceremony — they have live production consumers. `lib/policy.mjs` and `lib/policy-compiler.mjs` back the shipped CLI (`src/lib/cli/commands/run.mjs`, `rules.mjs`) and `tests/cli.test.mjs`; `codex-escalation.mjs` is called by `host/hook-adapter-core.mjs`; `control-lifecycle.mjs` supplies `ENFORCEMENT_RANK` to `lib/completion-gate.mjs` and `assessControlRetirement` to `src/lib/cli/commands/governance/delivery.mjs`; the policy JSON/schema artifacts are resolved directly by `tests/cli.test.mjs`. Retiring them would break the CLI and the suite. The Rust canonical Guard policy supersedes these *in the engine*, but the Node CLI has not been migrated onto it, so the duplication is live, not dead.

    **What this means:** P0.5 execution cannot proceed from the current triage. RETIRE must be re-derived against actual consumers rather than against supersession-in-principle, and the 170 MOVE entries need the same test applied before anyone moves them. This is a re-triage, not a delete pass. Original: Triage `src/packages/arcane/` (234+ orphaned Node files, tests still green) per-module, not as
   one disposition:
   - PORT — deterministic mechanisms that belong to the Guard
   - RESTORE — original cognitive-Arcane pieces (Brief/Minimize injection payloads)
   - MOVE — machinery owned by Legion or another subsystem (completion-gate concepts → P2.16)
   - RETIRE — ceremony and dead architecture, with their tests

   Classification is **semantic, not "it was a hook, therefore Guard"**: stop-shape.mjs in
   particular splits — its effect/safety rules PORT to the Guard, while its ending-shape response
   discipline (anti-caveat, no-permission-endings) is cognitive-Arcane postflight and RESTOREs to
   the cognitive plane (delivered through the Guard's Stop event, owned by Arcane).

## P1 — Cognitive plane v0 + measurement (parallel with P0 except where Guard-dependent)

6. **PARTIALLY DONE (2026-08-30, in-flight + lane-c3): the trace SCHEMA is landed** — `engine/crates/legion-contracts/src/trace.rs` plus `schemas/route-outcome-trace.v1.schema.json` carry route, semanticRequirement, context sources/size, capabilities considered/selected, authority attached, compute posture, result, latency, token/cost (integer micro-USD), the four Arcane §30 challenge fields, and the four provenance digests. **Still open:** nothing EMITS these traces yet, and no derived metric (Sage dispatch rate, Oracle BLOCK->real-fix rate, `challenge_yield`, `avoidable_user_challenge_rate`, …) is computed anywhere. Emission is Guard/host work that sits behind the blocked P1.8/P2 items. Original: **Outcome telemetry (automatic, content-light — no agent-authored artifacts).** Structured trace
   per routed request: route (direct/deliberate/grounded), semanticRequirement, context sources+size,
   capabilities considered/selected, authority attached (sage/alchemist/oracle), compute
   (no-model/tiny/strong), result (success/repair/user-correction/blocked), latency, token/cost.
   Derived metrics: Sage dispatch rate, Oracle BLOCK rate and BLOCK→real-fix rate,
   false-block/override rate, context retrieved-vs-used, no-model execution rate, small-model
   escalation rate, cost per successful task — plus the challenge metrics: `challenge_yield`
   (passes that materially improved the answer / passes invoked) and
   `user_challenge_rate`, `reactive_challenge_yield`, and `avoidable_user_challenge_rate` — all
   with the mechanical definitions in Arcane §30 (every term is a recorded trace field:
   KEEP/NARROW/REVISE outcome, assumption-dependent-conclusion flag, evidence-availability at
   first answer; no human judgment at measurement time). This is the tuning substrate for the
   control plane; without it every routing decision is steered by anecdote. **Land the telemetry
   schema immediately before or in the same change as P1.12** — otherwise the first live
   falsification behavior produces exactly the learning data we want without capturing it.
7. **DONE (2026-08-30, lane-a9 + a9b): behavioral routing evals.** `scripts/run-skill-evals.mjs` scores all six dimensions deterministically (28 files / 346 cases PASS); live grading is opt-in and fails loudly without a grader; `tests/skill-routing-evals.test.mjs` covers the scorer. Original: **Behavioral routing evals.** `scripts/run-skill-evals.mjs` is structure-only; `--live` exits
   ("no live grader is wired") — description changes are currently deploy-and-hope (proven by
   `24d52058`, shipped with zero behavioral verification). Build a harness measuring: should-route /
   should-NOT-route, first-ranked capability, Sage/Alchemist/Oracle attachment, DIRECT vs machinery,
   semanticRequirement classification, context selection. Deterministic fixture validation in every
   CI; live model grading as periodic/candidate qualification (nondeterministic, costs tokens).
   Mandatory before any resident micro-router lands.
8. **BLOCKED (2026-08-30): not attempted.** Packaged as lane-c1 with P2.14/P2.15/P1.10; the dispatch of that lane was refused by this session's permission classifier because it edits the live effect gate (`engine/bins/legion-hook/src/main.rs`, `hooks/hooks.json`). Needs an explicit owner decision. Original: SessionStart `additionalContext` injection: Brief/Minimize policy + one-paragraph routing summary
   (restores the lost 2,295-char payload; fixes the bare-install orphan problem). *Guard-dependent:
   rides on the redeployed binary (P0.2).*
9. **NOT DONE (2026-08-30):** out of scope for this repository — the checkout targets the workspace repo and re-registers host configs, which this dispatch deliberately excluded. Original: Restore groundwork: `git checkout df1e09bf -- mcps/groundwork docs/GROUNDWORK.md` in the
   workspace repo; re-register in host configs; reference from the injection. *Not Guard-dependent —
   can land immediately.*
10. **BLOCKED (2026-08-30): not attempted** — same lane-c1 classifier refusal as item 8. The source-side analysis is done: lane-b7's triage records `stop-shape.mjs` as a SPLIT, with the effect/safety and laundering checks PORTing to the Guard and the anti-caveat / no-permission-ending / bounded ending judgement RESTOREing as Arcane postflight. Original: Restore the ending-shape discipline from `stop-shape.mjs` (anti-caveat family,
    no-permission-endings, ending-only judgment, real-failure exemption) as **Arcane-owned
    postflight, invoked through the host/Guard Stop event** — the Guard is the delivery vehicle,
    never the owner of cognitive response policy. Never-hang bounds: deterministic only, re-entry
    cap 2–3, forced clean exit. *Guard-dependent (P0.2, P0.3).*
11. **DONE (2026-08-30, in-flight + lane-a2):** `doctrine/arcane.md` and `doctrine/guard.md`. *Not Guard-dependent.*
12. **PARTIALLY DONE (2026-08-30, in-flight):** the doctrine half is complete — `doctrine/arcane.md` §'Bounded Falsification (Challenge Pass)' carries the primitive, the three levels (with Oracle as L2 only when independent completion assurance is genuinely required), the eight L1 triggers, the one-pass no-recursion bound, and the telemetry definitions; the trace fields exist in `trace.rs`. **Still open:** the SessionStart-injected posture rules, which are item 8 and therefore blocked. Original: **Bounded Falsification (Challenge Pass) — core cognitive primitive** (Arcane proposal §30).
    One evidence-directed self-challenge pass before committing to a materially
    assumption-dependent conclusion: identify the 1–3 material, cheaply-checkable assumptions,
    check them, end in KEEP/NARROW/REVISE. Three levels (L0 direct / L1 self-challenge / L2
    independent reviewer/challenger — Oracle is L2 only when independent completion assurance is
    actually required, never a generic second opinion); L1 triggers listed in §30; hard bound one
    pass, no recursion. Evidence-seeking: generic self-reflection is excluded by design because it
    creates unbounded prose-oriented review rather than evidence-directed falsification. v0 ships
    as doctrine + SessionStart-injected posture rules; the resident tiny model
    later classifies `challengeRequired` from traces. Distinct from Oracle (no independence claim,
    cannot BLOCK) and from Sage (not a decision authority). *Not Guard-dependent.*
13. **DONE (2026-08-30, lane-c3):** `arcaneProfileDigest` / `legionCanonDigest` / `skillCatalogDigest` / `guardPolicyDigest` added as optional fields to the route/outcome trace in `engine/crates/legion-contracts/src/trace.rs` and to `schemas/route-outcome-trace.v1.schema.json`, with round-trip and backward-compatible deserialization tests (`cargo test -p legion-contracts` 27/27; schemas in sync). Original: **Behavioral provenance via content-addressed digests, not doctrine versions.** Add
    `arcaneProfileDigest` / `legionCanonDigest` / `skillCatalogDigest` / `guardPolicyDigest`; a
    session pins its epoch and meaningful receipts/route traces record it automatically. Answers
    "which exact rules produced this route/verdict?" — including dirty trees, installed projections,
    and mid-session changes — without migration bureaucracy. (Some records already carry source
    revisions; the gap is precise behavioral-configuration identity.)

## P2 — Guard coverage

14. **BLOCKED (2026-08-30): not attempted** — lane-c1 classifier refusal (live effect gate). Original: Gate `mcp__*` tool effects: widen `hooks/hooks.json` matchers AND add `parse_effect_class` arms
    together (matcher alone fail-closes everything). Partly blocked on
    `legion_contracts::EffectClass` lacking an `ExternalSideEffect` variant. **Scope: MCP
    writes/sends/deletes only.** `Task`/`Agent` dispatch is an orchestration/compute action — Legion
    governs its budgets, authority, and executor semantics; the subagent's own effects are gated
    per-effect inside its session. Do not classify dispatch itself as an external effect.
15. **BLOCKED (2026-08-30): not attempted** — lane-c1 classifier refusal. Original: Add `SubagentStop` to `SUPPORTED_EVENT_TYPES` + hooks.json — as **observation/receipting** of
    authority dispatch outcomes, not gating.
16. **BLOCKED (2026-08-30): returned NEEDS_ORCHESTRATOR.** The dispatch packet's allowlist was wrong — it named `engine/crates/legion-application/src/lib.rs`, but the Stop gate actually lives in `engine/bins/legion-hook/src/main.rs`, the same classifier-refused file as item 14. No typed `verificationRequirement` and no Rust representation of `oracle-completion-validation-v1` exist yet; both need an ownership decision. Original: Verification-proportional Stop gate: the hard gate consults a typed `verificationRequirement`
    emitted by the Arcane route / Legion completion contract — **not** a "session touched files →
    Oracle mandatory" heuristic (a typo edit must not trigger frontier assurance because `Write`
    fired). Wiring the currently producer-less `oracle-completion-validation-v1` receipt is part of
    this item; the gate checks for the receipt only when the requirement demands one.
    (oracle-audit gaps 1–2, reconciled with proportional-verification architecture)

## P3 — Legion mechanism-aware work compilation (LEG-MR sequence, adopted)

17. **DONE (2026-08-30, lane-a3):** in `doctrine/legion.md`. Original: LEG-MR-0: doctrine sentence — least nondeterministic authorized executor; "mechanical" ≠ "cheap
    model". Ambient cheap/mechanical execution belongs to Legion's mechanism-aware host binding —
    not to Alchemist, which stays the controlled bounded-transformation authority.
18. **DONE (2026-08-30, lane-a4):** schema in the direct-packet asset, completeness / contradiction / denied-never-escalates checks in `validate-dispatch.py` (all four reject classes negative-tested; legacy `executor` packets still validate), EXECUTOR block in `skills/tasklist/SKILL.md`. Original: LEG-MR-1: `executorRequirement` in `skills/dispatch/assets/direct-packet.json` + validator
    checks (completeness, contradiction, escalation monotonicity — `denied` never escalates) in
    `validate-dispatch.py`; EXECUTOR block in `skills/tasklist/SKILL.md`.
19. **DONE (2026-08-30, lane-b1):** per-action executor requirements in `skills/alchemist/SKILL.md` (3 actions), `skills/commit/SKILL.md` (4), and `skills/qa/SKILL.md` (4), mixing `required`/`conditional`/`forbidden` with mechanical actions on `forbidden`; manifests refreshed.
20. **DONE (2026-08-30, lane-b2 + b8):** `ExecutorBindingReceiptV1` in `engine/crates/legion-contracts/src/receipt.rs` with typed binding, mechanism, escalation, verification, and failure-outcome types; the `unsupported` outcome is representable so a host that cannot satisfy `semanticRequirement: forbidden` reports it instead of substituting a semantic executor. Tested in-file (`cargo test -p legion-contracts` 26/26).
21. **DONE — Option B staging (2026-08-30, lane-b3 + b8):** additive `executor_requirements` map keyed by `NodeId` plus `ExecutionRequirementV1` in `engine/crates/legion-contracts/src/plan.rs`; `Plan::new` and `PlanNode` unchanged; a literal pre-change plan JSON with no `executor_requirements` key still deserializes and defaults to empty (tested). **Option A remains:** move requirements onto `PlanNode`, update producers and consumers, make the node field canonical, and keep or migrate the Option B map as a compatibility projection.
22. **DONE (2026-08-30, lane-b4):** `skills/dispatch/evals/executor-requirement.json` covers all four cases (deterministic-sufficient / semantic-required / conditional-escalation / denied-never-escalates); harness now PASSes 29 files / 350 cases with 0 issues.
    **Explicitly deferred, outside LEG-MR-0..5:** the fact-derived work-state/supervision
    architecture (Legion proposal §16.1 — typed observations, fact-derived node state, causal
    invalidation, executor rebinding). Valuable, but LEG-MR-0..5 is a coherent implementation
    slice; a later supervision extension must not inflate the first landing.

## P4 — Authority & packaging remainder

23. **DONE (2026-08-30, lane-a5 + a5b):** package and its packaging references deleted; nothing salvageable into `src/lib/core`; the naming contract's four package-existence assertions removed (Oracle ROLE assertions kept). Original: **RESOLVED (2026-08-29): delete `src/packages/oracle/`, do not rename.** Its own README
    establishes it is not Oracle, is a facade over Audit with no Oracle semantics, has no consumer
    outside its own tests, ships anyway, and actively misleads searches. Renaming an unused facade
    preserves dead architecture for no product reason. Before deletion: salvage any genuinely
    useful fixtures/regression tests into the real Audit owner (`src/lib/core` side); then the
    package — and its packaging references in `package.json`/`biome.json`/`MANIFEST.package.json` —
    goes. Do not create a new permanent package because the old one existed. (oracle-audit gap 3)
24. **DONE (2026-08-30, lane-a8):** `skills/oracle/SKILL.md` + `dependencies.json`; `/sage` documented as attach-only. Original: `/oracle` skill entrypoint packaging the ephemeral-packet procedure + input checklist; decide
    deliberately whether `/sage` gets one or is documented as attach-only.
25. **DONE (2026-08-30, lane-a7 + a3):** `agents/sage.md` has a read-only `tools:` grant and `doctrine/legion.md` shows the conditional Sage branch. Original: Sage structural enforcement (retained; Sol concurs — **not** ceremony): behavioral evals answer
    "when should Sage be selected?"; a `tools:` restriction answers "what may Sage physically do
    once selected?" — different controls. Give `agents/sage.md` a read-only `tools:` grant matching
    "never performs product-state effects" (Oracle already has this). Add the missing Sage branch
    to the routing diagram in `doctrine/legion.md` — **visibly conditional, never a mandatory
    stage**:

    ```text
    capability work
        │
        ├─ material unresolved decision? → Sage → settled work
        │
        └─────────────────────────────────────────┘
                                  ↓
                             execution
    ```

    The audit's checklist-trigger and affirmative ambient-Alchemist-cue proposals stay **dropped** —
    behavioral routing evals (P1.7) are the fix for discoverability, and ambient mechanical
    execution routes through mechanism-aware host binding (P3.17).
26. **DONE (2026-08-30, lane-a10):** `scripts/qualify-clean-environment.mjs` + tests, 6/6, rejecting private rescue env vars, reachable checkouts, pre-existing state even when empty, dev binaries on PATH, and copied/mismatched artifacts. Original: **Clean-environment product qualification** (reframed from "second-user testing"): CI already
    runs `native-installed-smoke.mjs` against an isolated install root — what's missing is a
    hermetic acceptance test where nothing from the operator environment can rescue Legion: fresh
    VM/container, no workspace files, no inherited private env, no rhook/OmniRoute/Membrane unless
    explicitly installed, no prior Legion state, release artifact only, harness installed normally.
27. **DONE (2026-08-30, lane-b5):** PATH-binary check class added to `scripts/verify-plugin-parity.mjs`; negative-tested with a stripped PATH, it fails with actionable bootstrap text naming both `legion` and `legion-hook`, and stays silent when the binaries are reachable. Populating homebrew/winget manifests remains open as a packaging task.
28. **DONE (2026-08-30, lane-b6):** `.codex-plugin` parity generated/verified by `scripts/generate-codex-skill-sidecars.mjs` (missing/stale/extra sidecars detected; `--check` contract preserved, no drift across 25), and `m1_status` in `engine/bins/legion-mcp/src/tools.rs` no longer fabricates `"complete"` — it reports observable state or a typed unknown/unavailable (`cargo test -p legion-mcp` 7/7).
29. **DONE (2026-08-30, lane-a6):** `cargo clippy -p legion-host --all-targets -- -D warnings` is clean. Original: Pre-existing clippy failures in `engine/crates/legion-host/src/setup_registry.rs`.

## P5 — Documentation separation (adopted direction)

30. **PARTIALLY DONE (2026-08-30, lane-c4 + lane-a2):** `docs/architecture/sage.md`, `docs/architecture/alchemist.md`, `docs/architecture/oracle.md` written, and the Guard (`doctrine/guard.md`) and Arcane cognitive-plane (`doctrine/arcane.md`) documents exist. **Still open:** per-skill docs following the manifest structure, and trimming the SSOT down to ownership tables and cross-role invariants only. Absorption backlog: `docs/audits/2026-08-29/absorption-by-subsystem.md`.

    **Contradiction found (lane-c4), RESOLVED (2026-08-30, lane-d1):** `docs/LEGION-CANONICAL-SSOT.md` §§2–3 and §8 named Arcane / `src/packages/arcane/**` as the deterministic effect-enforcement owner, contradicting `doctrine/arcane.md` and `doctrine/guard.md`. The owner decided to align the SSOT to the doctrine. §§2–3, 6, 7–8, 11–14 and 18 now assign deterministic effect enforcement, receipts and runtime ownership to the Guard, assign the cognitive plane to Arcane, state the Guard-as-delivery-vehicle distinction once, and replace per-role depth with pointers to `docs/architecture/*.md`. All `src/packages/arcane/**` enforcement references are gone. Canonical naming and portability both PASS.

    **Still open after lane-d1:** stale Arcane-gating wording remains in `doctrine/legion.md`, `doctrine/sage.md` and `doctrine/alchemist.md` — outside that lane's allowlist, not yet reconciled.

## Execution status — 2026-08-30

Executed through dispatch packet `docs/dispatch/2026-08-30-pending-work.json` (21 lanes over three
waves, plus five repair/follow-on lanes). Implementation by Luna (GPT-5.6 High) one-shots; every
check run by the integration owner. Nothing committed.

**Suite state at park:** `pnpm test` 1359/1359; `cargo test --workspace` green; canonical naming
PASS; schemas in sync; no catalog, manifest, host-projection, or sidecar drift.
`pnpm legion:check` fails on exactly one deliberate item: the plugin surface changed, so it wants a
version bump from 0.1.0 in `.claude-plugin/plugin.json` and `package.json`. That is release-affecting
and left for the owner. Note that running `scripts/verify-plugin-parity.mjs` WITHOUT `--check`
rewrites `src/registry/plugin-surface.json` and silently satisfies that gate — do not let that
count as resolving it.

**Owner decisions still open:**

1. Redeploy `legion-hook.exe` (item 2) — recurring lockouts throughout this session.
2. Plugin version bump (above).
3. Permission for the live-effect-gate lane covering items 8, 10, 14, 15, 16 — refused by the
   executing session's classifier and deliberately not worked around.
4. The SSOT-versus-doctrine Arcane ownership contradiction recorded under item 30.
5. Whether P0.5's dispositions get executed, and whether item 21 advances to Option A.

## Sequencing

Not strictly serial. Hard orderings only: P0.1–P0.3 before any claim of strong enforcement and
before Guard-dependent P1 items (8, 10) and P2; P1.7 before any resident micro-router; P3 schema
work (18) before P3 engine work (21). Everything else — groundwork (9), telemetry design (6),
evals (7), doctrine (11), falsification primitive (12), provenance (13), P4 — proceeds in
parallel. "Fix the Guard first" must not become a process blockade. The two formerly
owner-reserved items (1, 23) are resolved above; no owner-reserved decisions block execution.
