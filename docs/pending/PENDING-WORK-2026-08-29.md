# Consolidated Pending Work — 2026-08-29

Single tracker merging: the 2026-08-29 subsystem audits (`docs/audits/2026-08-29/`), the remediation
status after commits `24d52058`/`a188f799` (`docs/audits/remediation-status.md`), and the two adopted
architecture proposals in this folder (Arcane cognitive control plane; Legion mechanism-aware work
decomposition). Items already fixed are excluded. Owner-reserved decisions are marked **[ADRIAN]**.

## P0 — Guard honesty (the deterministic effect layer; prerequisite for everything)

1. **[ADRIAN]** Fail-open default: ship a default policy config loaded by `legion-hook` and fail
   closed when absent, or keep ambient-allow and label it `"advisory"` — never `"strong"`.
   One line in `authorize_effect`'s `None` branch + config shipping. (arcane-audit gap 1)
2. Redeploy the installed binary — the committed subdirectory-resolution and MultiEdit fixes are not
   in the deployed `legion-hook.exe`; the subdirectory lockout was reproduced live on 2026-08-29 in
   this session.
3. Reconcile the two policy artifacts: port `src/packages/arcane/policy/arcane-policy-v1.json` rules
   into the policy-pack schema `legion-application` consumes, or mark it historical. (gap 2)
4. Disposition `src/packages/arcane/` (234+ orphaned Node files whose tests still run): retain as
   reference with a header, or retire with tests. (gap 6)

## P1 — Cognitive plane v0 (Arcane restored, all deterministic; no resident model)

5. SessionStart `additionalContext` injection: Brief/Minimize policy + one-paragraph routing summary
   (restores the lost 2,295-char payload from the pre-cutover Node hook; also fixes the bare-install
   orphan problem, plugin-system-gaps §2.3).
6. Restore groundwork (sequential thinking + Context7): `git checkout df1e09bf -- mcps/groundwork
   docs/GROUNDWORK.md` in the workspace repo; re-register in `.claude.json` / Codex config; reference
   from the injection.
7. Port the ending-shape Stop discipline from `src/packages/arcane/lib/stop-shape.mjs`
   (anti-caveat regex family, no-permission-endings, ending-only judgment, real-failure exemption)
   into the Guard's Stop branch with never-hang bounds: deterministic only, re-entry cap 2–3,
   forced clean exit (non-zero exit disables all later hooks for the event).
8. Write `doctrine/arcane.md` (cognitive plane) and a Guard architecture doc — Arcane currently has
   no canonical document at all. (arcane-audit gap 3; adopted decision: Arcane stays separate)

## P2 — Guard coverage

9. Gate `mcp__*` tools and subagent dispatch: widen `hooks/hooks.json` matchers AND add
   `parse_effect_class` arms together (matcher alone fail-closes everything). Blocked in part on
   `legion_contracts::EffectClass` lacking an `ExternalSideEffect` variant. (plugin-gaps §2.1)
10. Add `SubagentStop` to `SUPPORTED_EVENT_TYPES` + hooks.json so authority dispatch outcomes are
    receipted. (plugin-gaps §2.2)
11. Stop gate for Oracle: once P0.1 lands, have Stop consult a per-session "oracle ran" marker for
    sessions that touched files, built on the now-registered `oracle-completion-validation-v1`
    receipt (which still has **no producer** — wiring it is part of this item). (oracle-audit gaps 1–2)

## P3 — Legion mechanism-aware work compilation (LEG-MR sequence, adopted)

12. LEG-MR-0: doctrine sentence — least nondeterministic authorized executor; "mechanical" ≠ "cheap
    model".
13. LEG-MR-1: `executorRequirement` (semanticRequirement/capabilities/effects/escalation/completion)
    in `skills/dispatch/assets/direct-packet.json` + validator checks (completeness, contradiction,
    escalation monotonicity — `denied` never escalates) in `validate-dispatch.py`; EXECUTOR block in
    `skills/tasklist/SKILL.md`.
14. LEG-MR-2: per-lane/action executor requirements in skills; mechanical examples use `forbidden`.
15. LEG-MR-3: `ExecutorBindingReceiptV1` host-binding receipt shape.
16. LEG-MR-4: Rust `Plan` migration (Option B staging → Option A when canonical).
17. LEG-MR-5: eval fixtures (deterministic-sufficient / semantic-required / conditional-escalation /
    denied-never-escalates).

## P4 — Authority & packaging remainder (from the audits, still open)

18. **[ADRIAN]** `src/packages/oracle/` rename (`audit-facade`) or deletion — its own README defers
    the call. (oracle-audit gap 3)
19. `/oracle` skill entrypoint packaging the ephemeral-packet procedure + input checklist; decide
    deliberately whether `/sage` gets one or is documented as attach-only. (oracle-audit gap 4,
    sage-audit gap 5)
20. Sage: checklist-level trigger + routing-diagram branch + `tools:` read-only grant; Alchemist:
    one affirmative ambient-tier routing cue for "cost-route the muscle" (or reword rule 5) —
    partially addressed by the symptom-first descriptions in `24d52058`, structural halves remain.
    (sage-audit gaps 1–3, alchemist-audit gap 1)
21. Binary distribution: populate homebrew/winget or gate plugin activation on a preflight that
    names the bootstrap; add a PATH-binary check class to `verify-plugin-parity.mjs`.
    (plugin-gaps §1.1–1.2)
22. `.codex-plugin` parity automation; MCP server either documented as M1-scoped or given read-only
    discovery/status tools (`m1_status` hardcodes `"complete"`). (plugin-gaps §1.4, §2.4)
23. Pre-existing clippy failures in `engine/crates/legion-host/src/setup_registry.rs` (not gating;
    real).

## P5 — Documentation separation (adopted direction)

24. One architecture document per role (Sage, Alchemist, Oracle), one for the Guard, one for the
    Arcane cognitive plane; per-skill docs following the manifest structure; SSOT keeps ownership
    tables and cross-role invariants only. Absorption backlog for external patterns:
    `docs/audits/2026-08-29/absorption-by-subsystem.md`.

## Sequencing note

P0 → P1 are strictly ordered (a redesign on a fail-open, mislabeled gate inherits its dishonesty;
v0 injection/Stop discipline ride on a redeployed Guard). P2 and P3 can proceed in parallel after
P0. P4 items are independent. Items 1 and 18 need Adrian before any executor touches them.
