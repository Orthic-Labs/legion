# Consolidated Pending Work — 2026-08-29 (rev 4)

Single tracker merging: the 2026-08-29 subsystem audits (`docs/audits/2026-08-29/`), the remediation
status after commits `24d52058`/`a188f799`, the two adopted architecture proposals in this folder,
and the Sol review corrections. Rev 3 records the converged resolutions of both formerly
owner-reserved decisions (P0.1 canonical default policy; P4.23 delete the fake Oracle package).
Fixed items are excluded. No owner-reserved decisions block execution (the Guard's final name
remains open but blocks nothing). Rev 4 adds the Bounded Falsification primitive, FILE_DELETE
discrimination, and the supervision-deferral disposition.

## P0 — Guard honesty and hardening (the deterministic effect layer)

1. **RESOLVED (2026-08-29): ship a canonical default Guard policy.** Neither of the originally
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
2. Redeploy the installed binary — the committed subdirectory-resolution and MultiEdit fixes are not
   in the deployed `legion-hook.exe`; the lockout was reproduced live in-session on 2026-08-29.
3. Fuzz/property-test the Guard's input path **before** widening it to MCP/effects. Threat model:
   adversarial model- and tool-controlled payloads (the actual trust boundary), not just an outside
   attacker. Inputs: malformed/nested/huge JSON, odd Unicode, missing/null/wrong-type fields, shell
   quoting and nested `sh -c`/`cmd`/`powershell`, path oddities, MCP names/payloads, multi-target
   edits, unknown effect classes. Properties, not examples: never panic, never hang, bounded
   memory/time, denial never becomes fallback, known-dangerous variants stay denied, unknown
   classification never claims strong authorization, parser ambiguity is explicit. The crate
   currently has no fuzz/property dependency.
4. Reconcile the two policy artifacts: port `src/packages/arcane/policy/arcane-policy-v1.json` rules
   into the policy-pack schema `legion-application` consumes, or mark it historical. (gap 2)
5. Triage `src/packages/arcane/` (234+ orphaned Node files, tests still green) per-module, not as
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

6. **Outcome telemetry (automatic, content-light — no agent-authored artifacts).** Structured trace
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
7. **Behavioral routing evals.** `scripts/run-skill-evals.mjs` is structure-only; `--live` exits
   ("no live grader is wired") — description changes are currently deploy-and-hope (proven by
   `24d52058`, shipped with zero behavioral verification). Build a harness measuring: should-route /
   should-NOT-route, first-ranked capability, Sage/Alchemist/Oracle attachment, DIRECT vs machinery,
   semanticRequirement classification, context selection. Deterministic fixture validation in every
   CI; live model grading as periodic/candidate qualification (nondeterministic, costs tokens).
   Mandatory before any resident micro-router lands.
8. SessionStart `additionalContext` injection: Brief/Minimize policy + one-paragraph routing summary
   (restores the lost 2,295-char payload; fixes the bare-install orphan problem). *Guard-dependent:
   rides on the redeployed binary (P0.2).*
9. Restore groundwork: `git checkout df1e09bf -- mcps/groundwork docs/GROUNDWORK.md` in the
   workspace repo; re-register in host configs; reference from the injection. *Not Guard-dependent —
   can land immediately.*
10. Restore the ending-shape discipline from `stop-shape.mjs` (anti-caveat family,
    no-permission-endings, ending-only judgment, real-failure exemption) as **Arcane-owned
    postflight, invoked through the host/Guard Stop event** — the Guard is the delivery vehicle,
    never the owner of cognitive response policy. Never-hang bounds: deterministic only, re-entry
    cap 2–3, forced clean exit. *Guard-dependent (P0.2, P0.3).*
11. Write `doctrine/arcane.md` (cognitive plane) and a Guard architecture doc. *Not Guard-dependent.*
12. **Bounded Falsification (Challenge Pass) — core cognitive primitive** (Arcane proposal §30).
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
13. **Behavioral provenance via content-addressed digests, not doctrine versions.** Add
    `arcaneProfileDigest` / `legionCanonDigest` / `skillCatalogDigest` / `guardPolicyDigest`; a
    session pins its epoch and meaningful receipts/route traces record it automatically. Answers
    "which exact rules produced this route/verdict?" — including dirty trees, installed projections,
    and mid-session changes — without migration bureaucracy. (Some records already carry source
    revisions; the gap is precise behavioral-configuration identity.)

## P2 — Guard coverage

14. Gate `mcp__*` tool effects: widen `hooks/hooks.json` matchers AND add `parse_effect_class` arms
    together (matcher alone fail-closes everything). Partly blocked on
    `legion_contracts::EffectClass` lacking an `ExternalSideEffect` variant. **Scope: MCP
    writes/sends/deletes only.** `Task`/`Agent` dispatch is an orchestration/compute action — Legion
    governs its budgets, authority, and executor semantics; the subagent's own effects are gated
    per-effect inside its session. Do not classify dispatch itself as an external effect.
15. Add `SubagentStop` to `SUPPORTED_EVENT_TYPES` + hooks.json — as **observation/receipting** of
    authority dispatch outcomes, not gating.
16. Verification-proportional Stop gate: the hard gate consults a typed `verificationRequirement`
    emitted by the Arcane route / Legion completion contract — **not** a "session touched files →
    Oracle mandatory" heuristic (a typo edit must not trigger frontier assurance because `Write`
    fired). Wiring the currently producer-less `oracle-completion-validation-v1` receipt is part of
    this item; the gate checks for the receipt only when the requirement demands one.
    (oracle-audit gaps 1–2, reconciled with proportional-verification architecture)

## P3 — Legion mechanism-aware work compilation (LEG-MR sequence, adopted)

17. LEG-MR-0: doctrine sentence — least nondeterministic authorized executor; "mechanical" ≠ "cheap
    model". Ambient cheap/mechanical execution belongs to Legion's mechanism-aware host binding —
    not to Alchemist, which stays the controlled bounded-transformation authority.
18. LEG-MR-1: `executorRequirement` in `skills/dispatch/assets/direct-packet.json` + validator
    checks (completeness, contradiction, escalation monotonicity — `denied` never escalates) in
    `validate-dispatch.py`; EXECUTOR block in `skills/tasklist/SKILL.md`.
19. LEG-MR-2: per-lane/action executor requirements in skills; mechanical examples use `forbidden`.
20. LEG-MR-3: `ExecutorBindingReceiptV1` host-binding receipt shape.
21. LEG-MR-4: Rust `Plan` migration (Option B staging → Option A when canonical).
22. LEG-MR-5: eval fixtures (deterministic-sufficient / semantic-required / conditional-escalation /
    denied-never-escalates).
    **Explicitly deferred, outside LEG-MR-0..5:** the fact-derived work-state/supervision
    architecture (Legion proposal §16.1 — typed observations, fact-derived node state, causal
    invalidation, executor rebinding). Valuable, but LEG-MR-0..5 is a coherent implementation
    slice; a later supervision extension must not inflate the first landing.

## P4 — Authority & packaging remainder

23. **RESOLVED (2026-08-29): delete `src/packages/oracle/`, do not rename.** Its own README
    establishes it is not Oracle, is a facade over Audit with no Oracle semantics, has no consumer
    outside its own tests, ships anyway, and actively misleads searches. Renaming an unused facade
    preserves dead architecture for no product reason. Before deletion: salvage any genuinely
    useful fixtures/regression tests into the real Audit owner (`src/lib/core` side); then the
    package — and its packaging references in `package.json`/`biome.json`/`MANIFEST.package.json` —
    goes. Do not create a new permanent package because the old one existed. (oracle-audit gap 3)
24. `/oracle` skill entrypoint packaging the ephemeral-packet procedure + input checklist; decide
    deliberately whether `/sage` gets one or is documented as attach-only.
25. Sage structural enforcement (retained; Sol concurs — **not** ceremony): behavioral evals answer
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
26. **Clean-environment product qualification** (reframed from "second-user testing"): CI already
    runs `native-installed-smoke.mjs` against an isolated install root — what's missing is a
    hermetic acceptance test where nothing from the operator environment can rescue Legion: fresh
    VM/container, no workspace files, no inherited private env, no rhook/OmniRoute/Membrane unless
    explicitly installed, no prior Legion state, release artifact only, harness installed normally.
27. Binary distribution: populate homebrew/winget or gate plugin activation on a preflight naming
    the bootstrap; add a PATH-binary check class to `verify-plugin-parity.mjs`. (plugin-gaps §1.1–1.2)
28. `.codex-plugin` parity automation; MCP server documented as M1-scoped or given read-only
    discovery/status tools (`m1_status` hardcodes `"complete"`). (plugin-gaps §1.4, §2.4)
29. Pre-existing clippy failures in `engine/crates/legion-host/src/setup_registry.rs`.

## P5 — Documentation separation (adopted direction)

30. One architecture document per role (Sage, Alchemist, Oracle), one for the Guard, one for the
    Arcane cognitive plane; per-skill docs following the manifest structure; SSOT keeps ownership
    tables and cross-role invariants only. Absorption backlog:
    `docs/audits/2026-08-29/absorption-by-subsystem.md`.

## Sequencing

Not strictly serial. Hard orderings only: P0.1–P0.3 before any claim of strong enforcement and
before Guard-dependent P1 items (8, 10) and P2; P1.7 before any resident micro-router; P3 schema
work (18) before P3 engine work (21). Everything else — groundwork (9), telemetry design (6),
evals (7), doctrine (11), falsification primitive (12), provenance (13), P4 — proceeds in
parallel. "Fix the Guard first" must not become a process blockade. The two formerly
owner-reserved items (1, 23) are resolved above; no owner-reserved decisions block execution.
