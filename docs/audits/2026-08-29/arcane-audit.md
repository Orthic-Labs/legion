# Arcane Subsystem Audit — 2026-08-29

Fresh audit; prior documents in `docs/audits/` were not read. Evidence anchored to file:line at read time.

## 1. Inventory

**Enforcement path (currently wired, Rust/native):**
- `hooks/hooks.json` — bare command `legion-hook` on `SessionStart`, `SubagentStart`, `UserPromptSubmit`, `PostCompact`, `PreToolUse`, `PostToolUse`, `PostToolUseFailure`, `Stop`; `timeout: 10` everywhere.
- `engine/bins/legion-hook/src/main.rs` (~594 lines of logic) — the actual gate. Lifecycle events always allowed; post-effect events always allowed (observation only); pre-effect runs two hardcoded "hard gates" (destructive-command regex, forced-push approval) then delegates to `authorize_effect`.
- `engine/bins/legion-hook/src/protocol.rs` — envelope, `SUPPORTED_EVENT_TYPES`, lifecycle/pre/post classification.
- `engine/crates/legion-application/src/lib.rs` — only path that can load a real policy.
- `engine/crates/legion-policy-model/src/{effect,pack}.rs` — typed `EffectClass`, policy-pack schema.

**Policy artifacts (disconnected from each other):**
- `dist/native/.../share/legion/assets/policy/arcane-m1-policy.json` — only policy shipped beside native binaries; `effect_rules: []`, `unclassified_effect: "deny"` — an empty stub.
- `src/packages/arcane/policy/arcane-policy-v1.json` + `.rules` — a rich, well-commented policy (VCS_PUSH deny-by-default, CREDENTIAL_ACCESS deny, locked domains). Nothing in `legion-hook`/`legion-application` reads this path.
- `src/packages/arcane/schemas/arcane-decision-envelope-v1.schema.json`, `schemas/arcane-policy-pack.v1.schema.json`.

**Legacy/parallel Node implementation:** `src/packages/arcane/` (234+ files: ledger, contract-lifecycle, denial-circuit, completion-gate, stop-shape, etc.). Formerly driven by `hooks/arcane-hook.mjs`, deleted in commit `cae05d40` ("cut over Legion to native runtime"). `pnpm test` still runs its unit tests, but the code is unreachable from any live hook path.

**Runtime evidence:** `.audit/arcane/host-events/*.json` (200+ records) and `.audit/arcane/receipts/receipts.jsonl` — local, gitignored, genuinely written per event.

**No `arcane` agent, roster entry, or doctrine file** — `agents/`, `src/roster/`, `doctrine/` all lack an arcane file. "No model" matches design; no canonical doc does not.

## 2. Architecture docs status

`doctrine/` has legion/sage/alchemist/oracle/covenant-seat — **no `doctrine/arcane.md`**, no `src/roster/arcane.md`. The closest descriptions are `docs/host-integration-plan.md` (a status log, not a spec), inline Rust doc-comments, and comments inside the (unloaded) `arcane-policy-v1.json`. The native cutover (`cae05d40`) that replaced the Node hook with `legion-hook` was never recorded as a canonical enforcement contract. **Verdict: Arcane has no architecture document analogous to the other authorities' doctrine — a real gap, independent of the no-model design point.**

## 3. Packaging

- `package.json` is `"private": true` with **no `bin` field**; README states public package-manager installation "is not open yet."
- `.claude-plugin/plugin.json` declares `mcpServers.legion.command: "legion"` (bare); `hooks/hooks.json` calls bare `legion-hook` — both assume PATH.
- `dist/` and `engine/target/` are gitignored; compiled binaries are **not in the tree a marketplace plugin install clones** (`marketplace.json` → `source: "./"`).
- The only real distribution path is the signed PowerShell bootstrap (`packaging/channels.json`, `https://legion.orthiclabs.com/install.ps1`) pulling GitHub Release artifacts — entirely outside the plugin install flow. `packaging/homebrew` and `packaging/winget` are explicitly unpopulated placeholders.
- **Consequence:** a marketplace-only install gets hooks/agents/skills/MCP registration but no executables; every hook event fails with command-not-found and nothing warns the user. `legion doctor` only helps after `legion` is already on PATH. The MCP server additionally requires `LEGION_NATIVE_APPLICATION_CONFIG` to even start (`engine/bins/legion-mcp/src/main.rs:23`), which nothing outside Rust tests sets.

## 4. Harness

- **[Most severe] Policy is never loaded in real installs.** `main.rs:128-141` (`native_application()`) reads `LEGION_NATIVE_APPLICATION_CONFIG`; if unset, returns `Ok(None)` — not an error. `authorize_effect` (`main.rs:87-107`) then returns `HookResponse::allowed(..., "ambient effect accepted")`, which `protocol.rs:179-189` labels `enforcement_health: "strong"`. **No code path anywhere sets that env var for a real `legion-hook` process** — only Rust test harnesses do. In real installs, Arcane allows every effect except the two hardcoded gates, while self-reporting "strong" enforcement — exactly the false-strength claim the policy file's own comments forbid. The rich policy's `CREDENTIAL_ACCESS: deny`, `VCS_PUSH: approvalRequired`, locked domains: none of it is enforced by the shipping binary.
- **Matcher coverage:** PreToolUse matcher is `shell|shell_command|Bash|PowerShell|Write|Edit|MultiEdit|NotebookEdit|apply_patch`. `Task`/`Agent` dispatch was deliberately dropped ("no command, no pre-effect mapping" — `docs/host-integration-plan.md` §1.1), but that reasoning doesn't extend to **`mcp__*` tools, which are entirely ungated** — MCP sends, migrations, deletes bypass Arcane completely. Naively widening the matcher would fail-closed on everything (`parse_effect_class` has no arm for Task/mcp names → "effect class is missing or unsupported" → denied), so matcher + Rust classifier must change together.
- **`timeout: 10` / fail-open-vs-closed** on spawn failure is a host decision; the policy's declared `preEffectGateUnavailable: "fail-closed"` intent lives in the never-loaded policy file, so it's aspirational.
- **Hardcoded gates are narrow regexes** (`is_destructive_command`, `main.rs:421-463`: `rm -r*`, `Remove-Item -Recurse`, `git clean`, `dropdb`, `terraform apply/destroy`, `curl|sh`). Trivial bypasses exist (`shutil.rmtree`, `find -delete`); acceptable for a tripwire, not for a "strong"-labeled boundary.
- **Receipts** are genuinely written locally but gitignored, with no doctrine on retention, rotation, or how an agent should consult them.

## 5. Agent experience

- `SubagentStart` is lifecycle → always allowed, no policy content returned: a spawned agent gets zero typed signal about constraints; policy (when it loads) is discovered only reactively per-effect.
- When a hard gate **does** deny, the response is well-designed: typed JSON with `permissionDecision: "deny"`, human-readable reason, machine `code` (`ARC_EFFECT_CLASS_UNAUTHORIZED`, `ARC_APPROVAL_REQUIRED`) — genuinely actionable. But because real policy never loads, policy-driven denial codes are dead paths in normal operation. An agent today experiences Arcane as silent pass-through plus two regex trip-wires — the opposite of "gates every effect."
- No agent-facing doctrine explains any of this; discovering the ambient-allow reality requires reading Rust source.

## 6. Ranked gap list

1. **[Critical]** Policy never loads in real installs — Arcane enforces almost nothing beyond two regexes while labeling enforcement "strong." (`main.rs:128-141` → `92-106` → `protocol.rs:179-189`; env var set only in `engine/bins/legion/tests/*.rs`.) *Fix:* ship a default `LEGION_NATIVE_APPLICATION_CONFIG` via `legion setup`/plugin install and fail closed when missing; or, if ambient-allow is an intentional interim posture, label it `"advisory"`/`"unsupported"` (both already in the decision-envelope schema enum) instead of `"strong"`.
2. **[High]** Two disconnected policy artifacts; the shipped one is an empty stub. *Fix:* port `arcane-policy-v1.json` rules into the policy-pack schema `legion-application` consumes, or mark the Node-side policy historical.
3. **[High]** No canonical doctrine document for Arcane. *Fix:* write `doctrine/arcane.md` covering the decision envelope, hard-gate list, policy-loading contract, and the current ambient-by-default reality.
4. **[High]** Plugin install ↔ binary reachability gap (see §3). *Fix:* a plugin-surfaced preflight ("run the bootstrap first"), or a bundled Node shim fallback so marketplace-only installs degrade gracefully.
5. **[Medium]** MCP tools (and Task dispatch) ungated at PreToolUse. *Fix:* widen `hooks.json` matcher **and** add `parse_effect_class` arms mapping `mcp__*` names (send_/delete_/apply_ verbs) and subagent dispatch to effect classes.
6. **[Medium]** `src/packages/arcane/` (234+ files) is orphaned from live enforcement while its tests still run, implying coverage of behavior that no longer exists. *Fix:* mark retained-for-reference or retire with its tests.
7. **[Medium]** Destructive-command regex is a best-effort tripwire; doctrine should say so and stop letting it justify "strong" labels.
8. **[Low]** Arcane absent from `src/registry/capabilities.json` and `qualification/` — its own outward dependencies (native binary, env var, policy file) are unclassified, contrary to `docs/agent-rules.md`.
9. **[Low]** `SubagentStart` could surface an effective-policy summary once policy loading is fixed, so subagents learn constraints proactively.

## 7. Original-intent drift and restoration plan (added 2026-08-29, from workspace git history)

Arcane was originally conceived as sequential thinking + Context7 grounding + response discipline ("check before replying, facts before vibes, Brief"). Git archaeology in the parent workspace repository shows all three pieces existed and were lost separately:

| Piece | Where it lived | What happened | Recoverable from |
|---|---|---|---|
| Sequential thinking + Context7 | `mcps/groundwork/server.js` (423 lines, dependency-free MCP: sequential checkpoints + bounded Context7 retrieval), `docs/GROUNDWORK.md` | Built `dc8ab150` (Jul 21), renamed `df1e09bf`; later deleted from the tree and unregistered from `.claude.json` (only citadel-channel + membrane remain) | `git checkout df1e09bf -- mcps/groundwork docs/GROUNDWORK.md` |
| Brief + Minimize session injection | Node `hooks/arcane-hook.mjs` — verified in `3515f3db`'s commit message: SessionStart emitted **2,295 chars of Brief+Minimize policy** with `systemMessage MINIMIZE:ON`; six Python hooks (`enforce_brief.py` et al.) were retired *into* it | Legion's native cutover (`cae05d40` in the legion repo) deleted `arcane-hook.mjs`; the Rust `legion-hook` emits nothing on SessionStart (§4) | Payload logic survives in `src/packages/arcane/` (orphaned) |
| Anti-caveat / no-open-question Stop discipline | `src/packages/arcane/lib/stop-shape.mjs:145-159` — `unresolved-caveat` detector ("one caveat", "that said,", "keep in mind", "one last thing") + permission-seeking endings ("shall I…"), judging only the turn's ENDING and exempting caveats that report real failures | Orphaned by the same cutover; `legion-hook` unconditionally allows Stop, so it never runs | Regex family + instruction text intact in `stop-shape.mjs` |

**Verdict:** drifted. What ships neither slows models down (no Arcane-caused loops) nor helps them — it is inert plumbing plus receipts. The intended discipline layer exists in the repo but is disconnected from every live hook path.

### Restoration steps (exact, ordered; do NOT implement without explicit instruction)

1. **Port the Stop-shape ending detectors into `legion-hook`'s Stop branch** (`engine/bins/legion-hook/src/main.rs`, lifecycle short-circuit at :22-30). Carry over from `stop-shape.mjs`: the `unresolved-caveat` regex family (line 153), the open-question/permission-seeking family, the ending-only judgment rule (line 493), and the D-2 exemption (a caveat IS the outcome when reporting a real failure). Return `decision: "block"` with the existing instruction text ("Resolve the caveat yourself rather than reporting it."). Guard with ruflo-style never-hang discipline: bounded execution, a re-entry counter (max 2–3 blocks per session, matching gstack's bounded re-entry), and forced clean exit — a non-zero exit or hang disables all subsequent hooks for the event.
2. **Restore SessionStart injection**: emit `hookSpecificOutput.additionalContext` from the SessionStart branch carrying the Brief+Minimize policy text (source it from `src/packages/arcane`'s policy injector rather than re-authoring), plus a one-paragraph routing summary (fixes plugin-system-gaps.md §2.3 in the same change).
3. **Restore groundwork**: `git checkout df1e09bf -- mcps/groundwork docs/GROUNDWORK.md` in the workspace repo, re-register in `.claude.json` (and Codex `config.toml`), and reference it from the step-2 injection ("ground claims via groundwork before answering"). Pull-based MCP = zero loop risk; this is the facts-before-vibes half.
4. **Fix policy loading first or in parallel** (gap 1 above) — steps 1–2 gain teeth only if the binary stops mislabeling ambient-allow as "strong."
5. **Anti-ceremony guardrails** (the "stuck in loops for hours" concern): every new gate must be deterministic (regex/marker checks, never an LLM call inside the hook), bounded (fixed re-entry cap, then allow with a recorded `advisory` receipt), and ending-scoped (judge the last paragraph, not the whole turn). A gate that cannot decide in <100ms belongs in doctrine or an MCP tool, not in a hook.

Design rationale: prose alone was already tried (doctrine says plenty about Brief) and the tic persists — matching trailofbits' "put the check in a deterministic validator, not the prompt" and superpowers' pressure-test findings that models rationalize past prose. Hooks for the two deterministic disciplines (caveat/open-question endings, session injection); MCP for grounding; prose only for what regexes can't judge.

## Status update (same day, commit 24d52058)

Partially remediated by a parallel session — see plugin-system-gaps.md §4 and docs/audits/remediation-status.md for exactly which gaps above are closed vs still open.
