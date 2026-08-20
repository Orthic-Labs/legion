# Legion host-integration implementation plan

**Status:** active implementation plan
**Governed by:** `docs/LEGION-CANONICAL-SSOT-v2.md` §36 and invariants I-19 … I-23
**Scope:** how canonical Legion semantics reach Claude Code, Codex, Gemini CLI, and
AGENTS-only harnesses; how Arcane enforces effects on each; how failures are diagnosed.

This plan owns **implementation steps only**. It defines no semantics. Where it appears to
disagree with the SSOT, the SSOT wins (§0).

---

## 0. Problem statement

Legion's canonical content is host-neutral. Its delivery was not. Before this work:

- the plugin was disabled in the operator's settings, so **no** capability or agent was
  discovered by Claude Code, and every other symptom was downstream of that;
- the installed plugin was a copy taken at commit `52a83ca` with the pre-`src/` layout, while
  the working tree had moved to `src/packages/**`. The manifest in the tree pointed the MCP
  server at `src/integrations/mcp/server.mjs`; the installed copy had no `src/`. The version
  string was identical across both, so nothing signalled the drift;
- `legion bind` wrote `.claude/agents/**` while the plugin package shipped `agents/**` for the
  same three roles — two installers for one harness;
- **no** binder projected `skills/` at all. Outside Claude Code, Legion was three roles and zero
  capabilities;
- Arcane's effect gate registered for tools it could not classify (`Agent`, `spawn_agent`) and
  did not register for tools it could (`WebFetch`, `WebSearch` — both declared `NETWORK_EGRESS`
  in `EFFECT_TOOL_MAP`), so a declared gate was a silent no-op;
- two gates could not be satisfied by any action available to the operator (below).

## 1. Completed

### 1.1 Arcane correctness (SSOT I-22, I-23)

| Defect | Fix | Verified by |
|---|---|---|
| `git push --force` refused with `ARC_APPROVAL_REQUIRED` that no action could produce — `approvalStore` defaults to `null` and nothing wires one | refusal now escalates to the host's own operator prompt (`permissionDecision: 'ask'`) when the target ref is isolated; ambiguous targets still hard-deny; a wired store still consumes a target-bound approval and skips the prompt | live hook: `ask` for `git push --force origin main`, `deny` for bare `git push --force`, `deny` for `rm -rf` |
| ambient Stop refused for missing contract receipts it had no opportunity to create | a session with no run binding and no contract is ambient: contract certification does not apply, and the result is labelled `enforcementHealth: 'unsupported'` so nothing reads as a passed certification | live hook: bare `Stop` allows; 573 Arcane tests pass |
| every hook event paid two Node cold starts | `arcane-hook.mjs` imports the adapter in-process | ~400 ms → ~354 ms per malformed-payload event |
| ledger re-read and re-verified the full hash chain up to three times per event | `#verify()` returns the records it verified; `append`/`inspect` reuse them. Same full-chain walk, same strength, computed once | `readFileUtf8` 274 ms → 105 ms in CPU profile |
| effect gate registered for unclassifiable tools, unregistered for classifiable ones | `Agent`/`spawn_agent` dropped from PreToolUse; `WebFetch`/`WebSearch` added to PostToolUse. `Bash` retained — it is load-bearing for the destructive-command, VCS-rewrite, and escalation gates | `hooks/hooks.json`; regression cases above |

### 1.2 Canonical projection (SSOT 36.2)

`scripts/generate-host-projection.mjs` → `src/registry/host-projection.json`.

Derived from canonical owners only: `skills/*/SKILL.md`, `src/roster/*.md`,
`src/registry/capabilities.json`. Emits 21 domain capabilities, 2 role entrypoints, 3 roles,
16 host capabilities, the 4 reference classes, and a fidelity declaration per harness.
`--check` fails on drift.

`skills/alchemist` and `skills/covenant` project as `kind: role-entrypoint`,
`discoverability: internal` (SSOT 6.1) — they are compatibility entrypoints into an authority,
not domain capabilities.

### 1.3 Diagnosis (SSOT 36.9)

`legion doctor --json` gained a `host` section: installation identity (active source, enabled
state, installed vs source version, **layout match**, commit sha), discovery counts, MCP
entrypoint existence, hook registrations, duplicate-installation-path conflicts, declared
fidelity per harness, and Arcane key/adapter health.

On the machine where this was written it reports, unprompted:
`enabled: false | versionMatches: true | layoutMatchesSource: false` — which is exactly the
failure that took manual investigation to find.

## 2. Declared fidelity today

Derived from the adapter registry (`src/lib/host/registry.mjs`) — the single source of truth —
and projected into `host-projection.json`. Truthful, not aspirational (SSOT 36.5); never rounded
up. Instructions is the fifth surface the adapters carry (baseline context via AGENTS.md or a
native instructions file).

| Harness | Instructions | Skills | Agents | MCP | Enforcement |
|---|---|---|---|---|---|
| claude-code | strong (plugin) | strong (plugin) | strong (plugin) | strong (plugin) | strong (blocking hook) |
| codex | strong (AGENTS.md) | degraded (.agents/skills) | unsupported | strong (config.toml) | unsupported |
| cline | strong (.clinerules) | degraded (.agents/skills) | unsupported | unsupported | unsupported |
| command-code | strong (AGENTS.md) | degraded (.agents/skills) | unsupported | unsupported | unsupported |
| pi | strong (AGENTS.md) | degraded (.agents/skills) | unsupported | unsupported | unsupported |
| generic | strong (AGENTS.md) | degraded (.agents/skills) | unsupported | unsupported | unsupported |

`skills = degraded` for every non-Claude harness because none of them has native Agent Skills
discovery: Legion projects the canonical SKILL.md packages to `.agents/skills` (by symlink, never
forked) and points at that location from the instructions block, so the capability content reaches
the model but selection is instruction-driven rather than host-driven. That is the honest state,
not a claim of native support. Enforcement is `unsupported` wherever no blocking hook/permission mechanism exists;
Arcane's semantics stay host-neutral but the transport is host-specific, and a harness that cannot
block an effect is never labelled `strong`. `command-code`, `pi`, `agents`, and their `mcp` values
are `unsupported` where the native mechanism is not yet confirmed; correcting any of them is a
one-line edit to that harness's descriptor, which is the point of the data-driven seam.

Cline's `mcp` was corrected from `strong (.cline/mcp.json)` to `unsupported` (2026-08-20): Cline
reads its MCP registry from extension-managed storage (`cline_mcp_settings.json`) outside the
repository, so the previously declared project-local path registered nothing. A fidelity claim must
describe what Legion actually installs and verifies.

Detection uses harness-specific evidence only. `AGENTS.md` was removed as a Codex / Pi /
Command Code signal and `.vscode` as a Cline signal: those are cross-harness or cross-extension
conventions, and matching on them made one ordinary repository detect as three harnesses at once.
Two harnesses that genuinely coexist are still both reported — from their own evidence.

Gemini is intentionally absent — it is not built, because it is not used.

## 3. Remaining work

### 3.1 Development path — done

Develop against the live tree, never the installed cache: `npm run plugin:dev` proves the live
plugin surface resolves and prints the `claude --plugin-dir <legion-root>` + `/reload-plugins`
invocation. Keep the marketplace plugin **disabled** while developing so the two do not both own
the harness.

`scripts/verify-plugin-parity.mjs` records the plugin's discoverable surface (skills, agents, MCP,
hooks) and a structural digest in `src/registry/plugin-surface.json`. `--check` fails when that
digest changes without a version bump — the exact drift the installed cache suffered when a
pre-`src/` snapshot shared version `0.1.0-dev.0` with a restructured tree. It runs in
`legion:check` and `prepack`, and `legion doctor` reports the surface digest, counts, and whether
the installed copy's layout still matches its source.

### 3.2 Claude native projection — done

The plugin package is the single installation owner for Claude Code. Parity is proven by
`verify-plugin-parity` (23 skills, 4 agents, 1 MCP server, 8 hook events all resolve), so
`bind/claude-code.mjs` is retired: it detects nothing, writes nothing, and an explicit
`--harness claude-code` request returns a note pointing at the plugin. `legion bind` no longer
competes for the Claude harness (I-20).

### 3.3–3.5 Generic host adapter seam — done

The harness integration is now a data-driven adapter seam, not a per-harness reimplementation:

```
canonical Legion  →  host-projection.json  →  adapter descriptor (capabilities)  →  engine install/verify
```

- `src/lib/host/surfaces.mjs` — the closed vocabulary: five surfaces (instructions, skills,
  agents, mcp, hooks) each rated `strong` / `degraded` / `unsupported`.
- `src/lib/host/skill-projection.mjs` — projects canonical `skills/<id>` packages into a harness's
  skill location by **symlink** (byte-identical copy only as a fallback), and verifies byte-identity
  against the canonical source. This is the no-fork guarantee: `SKILL.md` is the common interchange
  format and is never rewritten.
- `src/lib/host/engine.mjs` — implements `detect / capabilities / install / verify / uninstall`
  **once**, parameterized by a descriptor. It moves and registers canonical content; it never
  decides what Legion contains.
- `src/lib/host/adapters/*.mjs` — one small descriptor per harness: `claude-code` (plugin-owned,
  defers install), `codex`, `cline`, `command-code`, `pi`, and `generic`.
- `src/lib/host/registry.mjs` — the adapter list and the data-driven interface; `legion harness`
  is the thin CLI over it.

Skills prefer the common `.agents/skills` surface; a harness that reads a native location declares
it as `path` in its descriptor and the same projection code handles it. Adding a harness requires **only a descriptor** when its surfaces can be expressed with the
mechanisms the engine already implements (`agents-md` / `native-file` instructions, `skills-dir`
projection, `json` or `toml` MCP registration, `blocking-hook` enforcement) — one descriptor file
plus one registry line, or no registry line at all if the harness declares itself as data through
`.agents/legion-harness.json` or `LEGION_HARNESS_DESCRIPTOR`. A harness with a genuinely new
transport or config format requires **one shared mechanism implementation** in the engine, added
once and available to every harness thereafter — but never a duplicated copy of Legion's semantics.
The earlier claim that an unknown harness "needs no code at all" was true only for harnesses whose
surfaces happened to match the existing mechanisms.

Conformance is locked by two suites. `tests/host-adapter-conformance.test.mjs`: the same canonical catalog
reaches every projecting harness, every projected `SKILL.md` is byte-identical to canonical,
discovery counts match the canonical projection, declared fidelity is structurally valid and
enforcement is never overclaimed, and no descriptor enumerates individual skills (so adding a skill
needs no per-harness edit). `tests/host-adapter-safety.test.mjs` adds the host-safety invariants:
internal capabilities never reach a discovery surface, install refuses to overwrite a user-owned
skill directory or a fork, malformed JSON/TOML is preserved rather than replaced, uninstall removes
only Legion-owned entries, one generic file never detects three harnesses, every declared mechanism
path is actually created by install, and only one installer is active per surface. A real
`codex mcp list` discovery smoke test is included but skips when the binary is absent, so no harness
binary is a mandatory CI dependency.

Relationship to `legion bind`: the adapter seam is the go-forward harness integration. The older
`bind/*` writers for surfaces the seam now owns are **quarantined** (2026-08-20): `claude-code` was
already retired, and `codex` and `agents-md` now return `false` from `detect()`, so
`legion bind --write` with no explicit `--harness` can never select them and never races the seam
for `.codex/config.toml` or `AGENTS.md`. They are quarantined rather than deleted because they still
carry legacy migration paths the seam does not have (prior-generation unmanaged-table migration,
duplicate-MCP cleanup); those run only when an operator names the harness explicitly. `gemini` is untouched — no
adapter claims that harness, so there is nothing for it to compete with.

### 3.6 Latency — investigated; the dominant cost is algorithmic, not process-lifecycle

The per-event `git rev-parse HEAD` subprocess is **removed**. `resolveSourceRevision` now reads
HEAD from the git directory directly (`src/packages/arcane/host/source-revision.mjs`), returning
exactly what git would for normal checkouts, packed-refs, detached HEAD, worktrees, and
submodules, and falling back to the subprocess only for a layout it does not recognize. Output is
identical, so no enforcement behaviour changes. CPU profile confirms `spawnSync` at 0 ms after the
change; unit tests assert the resolver matches `git rev-parse HEAD` across all five layouts.

Benchmarked against realistic history — the live workspace already carries **774 ledger events** —
the dominant remaining cost is `readFileUtf8` at ~317 ms for a single event: the ledger reads and
verifies its entire hash chain on every append, which is O(n) in history and the reason a single
hook event is slow once a workspace has been used for a while. The per-event `git` subprocess and
module loading are now minor beside it.

This means a resident Arcane daemon is **not** justified: the cost is algorithmic, and a daemon
would still verify the chain on append. The fix is the deferred, larger change below, which is
security-bearing and out of scope for this host/runtime pass:

> Replace full-chain re-verification with a signed verified-prefix checkpoint (verify only records
> after the checkpoint, then advance it). This preserves tamper detection over old records while
> making append O(new). It changes a security-bearing invariant and must be reviewed on its own,
> not folded into a performance pass. It is a candidate for the SSOT/Arcane owner, not this task.

### 3.7 Evals

Cross-harness discovery and enforcement evals: for each harness, assert the declared fidelity
matches observed behaviour. A fidelity table that drifts from reality is the failure mode this
whole section exists to prevent.

### 3.8 `skills/commit` — deferred to the SSOT/capability owner

Narrowing `skills/commit` touches capability semantics, so it is out of scope for the host/runtime
pass and belongs to the SSOT/capability migration owner. It already routes repository-wide
diagnosis to `/audit` rather than embedding it; the remaining question is whether
`references/manual.md` has accumulated an audit engine, and that is a semantic call.

## 4. Ordering

1. ~~SSOT host-projection invariants~~ — done (§36, I-19 … I-23)
2. ~~Claude live-plugin dev path + package/version lifecycle~~ — done (§3.1)
3. ~~Canonical projection IR~~ — done (§1.2)
4. ~~Claude native projection + retire competing bind path~~ — done (§3.2)
5. ~~Generic host adapter seam + the harnesses in use (Codex, Cline, Command Code, Pi) + generic custom harness~~ — done (§3.3–3.5)
6. Gemini — **not built**, not used (explicit non-goal)
7. ~~Arcane hook narrowing, Stop correction, double-spawn removal~~ — done (§1.1)
8. ~~Benchmark — per-event git subprocess removed; ledger O(n) identified as the dominant cost~~ — done (§3.6)
9. Resident Arcane decision — **not justified** by the measurements; the fix is algorithmic (§3.6)
10. ~~`legion doctor` host diagnosis + plugin surface identity + live adapter seam~~ — done (§1.3, §3.1, §3.3–3.5); ~~cross-harness conformance evals~~ — done (`tests/host-adapter-conformance.test.mjs`)

Host/runtime work is complete. The 2026-08-20 cleanup pass closed the remaining host-layer
correctness and safety gaps: projected skill membership now comes from the canonical capability
projection rather than a `skills/*` directory scan (internal role entrypoints no longer leak into
discovery), install and uninstall are collision-safe and surgically reversible, malformed config
fails closed, copy-fallback verification covers the whole package, detection is non-ambiguous, and
the superseded `bind/*` writers are quarantined. Those invariants are locked by
`tests/host-adapter-safety.test.mjs`.

What remains is either an explicit non-goal (Gemini) or semantic/security-bearing work owned by the
SSOT/capability and Arcane owners: the ledger verified-prefix checkpoint and `skills/commit`
narrowing.

Superseded paths are retired as their native equivalents land, not kept in parallel
(SSOT §26 retirement test, §32 non-goals).
