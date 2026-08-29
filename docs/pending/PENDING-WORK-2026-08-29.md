# Consolidated Pending Work — 2026-08-29 (rev 2, post Sol review)

Single tracker merging: the 2026-08-29 subsystem audits (`docs/audits/2026-08-29/`), the remediation
status after commits `24d52058`/`a188f799`, the two adopted architecture proposals in this folder,
and the Sol review corrections (this revision). Fixed items are excluded. Owner-reserved decisions
are marked **[ADRIAN]**.

## P0 — Guard honesty and hardening (the deterministic effect layer)

1. **[ADRIAN]** Fail-open default: ship a default policy config loaded by `legion-hook` and fail
   closed when absent, or keep ambient-allow and label it `"advisory"` — never `"strong"`.
   One line in `authorize_effect`'s `None` branch + config shipping. (arcane-audit gap 1)
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
   - PORT — deterministic mechanisms that belong to the Guard (e.g. stop-shape ending detectors)
   - RESTORE — original cognitive-Arcane pieces (Brief/Minimize injection payloads)
   - MOVE — machinery owned by Legion or another subsystem (completion-gate concepts → P2.11)
   - RETIRE — ceremony and dead architecture, with their tests

## P1 — Cognitive plane v0 + measurement (parallel with P0 except where Guard-dependent)

6. **Outcome telemetry (automatic, content-light — no agent-authored artifacts).** Structured trace
   per routed request: route (direct/deliberate/grounded), semanticRequirement, context sources+size,
   capabilities considered/selected, authority attached (sage/alchemist/oracle), compute
   (no-model/tiny/strong), result (success/repair/user-correction/blocked), latency, token/cost.
   Derived metrics: Sage dispatch rate, Oracle BLOCK rate and BLOCK→real-fix rate,
   false-block/override rate, context retrieved-vs-used, no-model execution rate, small-model
   escalation rate, cost per successful task. This is the tuning substrate for the control plane;
   without it every routing decision is steered by anecdote.
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
10. Port the ending-shape Stop discipline from `stop-shape.mjs` (anti-caveat family,
    no-permission-endings, ending-only judgment, real-failure exemption) into the Guard's Stop
    branch with never-hang bounds: deterministic only, re-entry cap 2–3, forced clean exit.
    *Guard-dependent (P0.2, P0.3).*
11. Write `doctrine/arcane.md` (cognitive plane) and a Guard architecture doc. *Not Guard-dependent.*
12. **Behavioral provenance via content-addressed digests, not doctrine versions.** Add
    `arcaneProfileDigest` / `legionCanonDigest` / `skillCatalogDigest` / `guardPolicyDigest`; a
    session pins its epoch and meaningful receipts/route traces record it automatically. Answers
    "which exact rules produced this route/verdict?" — including dirty trees, installed projections,
    and mid-session changes — without migration bureaucracy. (Some records already carry source
    revisions; the gap is precise behavioral-configuration identity.)

## P2 — Guard coverage

13. Gate `mcp__*` tool effects: widen `hooks/hooks.json` matchers AND add `parse_effect_class` arms
    together (matcher alone fail-closes everything). Partly blocked on
    `legion_contracts::EffectClass` lacking an `ExternalSideEffect` variant. **Scope: MCP
    writes/sends/deletes only.** `Task`/`Agent` dispatch is an orchestration/compute action — Legion
    governs its budgets, authority, and executor semantics; the subagent's own effects are gated
    per-effect inside its session. Do not classify dispatch itself as an external effect.
14. Add `SubagentStop` to `SUPPORTED_EVENT_TYPES` + hooks.json — as **observation/receipting** of
    authority dispatch outcomes, not gating.
15. Verification-proportional Stop gate: the hard gate consults a typed `verificationRequirement`
    emitted by the Arcane route / Legion completion contract — **not** a "session touched files →
    Oracle mandatory" heuristic (a typo edit must not trigger frontier assurance because `Write`
    fired). Wiring the currently producer-less `oracle-completion-validation-v1` receipt is part of
    this item; the gate checks for the receipt only when the requirement demands one.
    (oracle-audit gaps 1–2, reconciled with proportional-verification architecture)

## P3 — Legion mechanism-aware work compilation (LEG-MR sequence, adopted)

16. LEG-MR-0: doctrine sentence — least nondeterministic authorized executor; "mechanical" ≠ "cheap
    model". Ambient cheap/mechanical execution belongs to Legion's mechanism-aware host binding —
    not to Alchemist, which stays the controlled bounded-transformation authority.
17. LEG-MR-1: `executorRequirement` in `skills/dispatch/assets/direct-packet.json` + validator
    checks (completeness, contradiction, escalation monotonicity — `denied` never escalates) in
    `validate-dispatch.py`; EXECUTOR block in `skills/tasklist/SKILL.md`.
18. LEG-MR-2: per-lane/action executor requirements in skills; mechanical examples use `forbidden`.
19. LEG-MR-3: `ExecutorBindingReceiptV1` host-binding receipt shape.
20. LEG-MR-4: Rust `Plan` migration (Option B staging → Option A when canonical).
21. LEG-MR-5: eval fixtures (deterministic-sufficient / semantic-required / conditional-escalation /
    denied-never-escalates).

## P4 — Authority & packaging remainder

22. **[ADRIAN]** `src/packages/oracle/` rename (`audit-facade`) or deletion — its own README defers
    the call. (oracle-audit gap 3)
23. `/oracle` skill entrypoint packaging the ephemeral-packet procedure + input checklist; decide
    deliberately whether `/sage` gets one or is documented as attach-only.
24. Sage structural enforcement (retained from the audit; **not** ceremony): add the missing Sage
    branch to the routing diagram in `doctrine/legion.md`, and give `agents/sage.md` a read-only
    `tools:` grant matching "never performs product-state effects" (Oracle already has this; it is
    harness enforcement, not process). The audit's checklist-trigger and affirmative
    ambient-Alchemist-cue proposals are **dropped** — behavioral routing evals (P1.7) are the
    correct fix for discoverability, and ambient mechanical execution now routes through
    mechanism-aware host binding (P3.16).
25. **Clean-environment product qualification** (reframed from "second-user testing"): CI already
    runs `native-installed-smoke.mjs` against an isolated install root — what's missing is a
    hermetic acceptance test where nothing from the operator environment can rescue Legion: fresh
    VM/container, no workspace files, no inherited private env, no rhook/OmniRoute/Membrane unless
    explicitly installed, no prior Legion state, release artifact only, harness installed normally.
26. Binary distribution: populate homebrew/winget or gate plugin activation on a preflight naming
    the bootstrap; add a PATH-binary check class to `verify-plugin-parity.mjs`. (plugin-gaps §1.1–1.2)
27. `.codex-plugin` parity automation; MCP server documented as M1-scoped or given read-only
    discovery/status tools (`m1_status` hardcodes `"complete"`). (plugin-gaps §1.4, §2.4)
28. Pre-existing clippy failures in `engine/crates/legion-host/src/setup_registry.rs`.

## P5 — Documentation separation (adopted direction)

29. One architecture document per role (Sage, Alchemist, Oracle), one for the Guard, one for the
    Arcane cognitive plane; per-skill docs following the manifest structure; SSOT keeps ownership
    tables and cross-role invariants only. Absorption backlog:
    `docs/audits/2026-08-29/absorption-by-subsystem.md`.

## Sequencing

Not strictly serial. Hard orderings only: P0.1–P0.3 before any claim of strong enforcement and
before Guard-dependent P1 items (8, 10) and P2; P1.7 before any resident micro-router; P3 schema
work (17) before P3 engine work (20). Everything else — groundwork (9), telemetry design (6),
evals (7), doctrine (11), provenance (12), P4 — proceeds in parallel. "Fix the Guard first" must
not become a process blockade. Items 1 and 22 need Adrian before any executor touches them.
