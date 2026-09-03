# Legion DOGFOOD Checklist — Windows daily-use & breakage catcher

**Product under test:** Legion **0.3.13** (installed)
**Install root:** `%USERPROFILE%\AppData\Local\Orthic Labs\Legion`
**Plugin projection (host-served skills):** `%USERPROFILE%\.claude\skills\legion`
**Host OS:** Windows 11 (Git Bash / PowerShell)
**Verified:** 2026-09-03, read-only commands only. Nothing was edited, committed, pushed, or mutated
during verification of this document. `legion setup repair` had already been run on this machine before
verification started.
**Read-only rule:** every command below is safe to run. The only Legion commands that mutate the host are
`legion setup repair|apply|remove|purge` — **never run those while dogfooding.** They rewrite
`~/.claude`, `~/.codex`, and `%LOCALAPPDATA%`.

How to read this doc:
- **EXPECTED** = what a correct install looks like.
- **OBSERVED (0.3.13, this machine)** = what was actually measured tonight, 2026-09-03, with the exact
  command shown.
- **UNVERIFIED** = claim not confirmed live on this machine. See §8.

Verified product hashes (for exact-value diffing), from `legion --json setup status`, `clients[]` where
`clientId: "antigravity"`:
- `legion --version` → `0.3.13`
- release_version → `0.3.13`
- runtime_digest → `3850acbfd78edeba397ff5191d532808fd9902c80b504646ae2deb284c1adbf8`
- capability_catalog_hash → `f6e23f2de22db40b5fcb58a1afbd2f1fa0e65542cc0f87f4d3265b0d088cf1dc`
- mcp_tool_schema_hash → `ecdbcc6acf2cbe64a3611ad3fc147a2423c5dd575db26143a63ba7572731b094`

---

## 1. What Legion claims to do

### 1.1 The routing tree
Source: `doctrine/legion.md`. Legion owns **semantic capability selection, operation/effect derivation,
authority attachment, and orchestration.** Arcane shapes cognitive processing & response policy only;
Guard gates declared typed effects.

```
USER INTENT
   ↓
LEGION — semantic classification over the compact canonical catalog
   ↓
0..N capabilities / internal entrypoints
   ↓
WORK GRAPH — operations, effects, dependencies, authority only where required
   ↓
GUARD gates declared effects   (legion-hook binary; fails OPEN if absent — see §6)
   ↓
EXECUTION / INTEGRATION
   ↓
ORACLE Completion Validation under current policy   (mandatory before every final delivery)
   ↓
DELIVERY
```

### 1.2 The three roles + Covenant (Sage / Alchemist / Oracle / covenant-seat)
Source: `doctrine/{sage,alchemist,oracle}.md`. Now confirmed shipped as real agents, not just skills:

```
$ claude plugin details legion@skills-dir
Agents (4)  alchemist, covenant-seat, oracle, sage
```

| Role | Owns one question | Source |
| --- | --- | --- |
| **Sage** | "Does a material unresolved decision require authoritative closure beyond the selected capability's routine mandate?" | `doctrine/sage.md` |
| **Alchemist** | "How do I make the already-decided meaning exist?" | `doctrine/alchemist.md` |
| **Oracle** | "What actually exists, what applies, what is proven, what fails, what remains unknown?" | `doctrine/oracle.md` |
| **covenant-seat** | one isolated deliberation seat, dispatched only by `/covenant` | roster |

### 1.3 The 27 shipped skills
`legion skills` and `claude plugin details legion@skills-dir` agree: **27 skills, 4 agents**, exactly:
ads, alchemist, architect, audit, audit-fix, audit-visual, blueprint, brand, brand-identity, coder,
commit, covenant, debugger, designer, dispatch, foundation, gotchas, handoff, marketing, oracle, qa,
research, seo, social, tasklist, wake, writing.

---

## 2. First-run checklist

| # | Check | Exact command | EXPECTED | OBSERVED (0.3.13, tonight) | Verdict |
| --- | --- | --- | --- | --- | --- |
| 2.1 | Install root exists | `Test-Path "$env:LOCALAPPDATA\Orthic Labs\Legion"` | `True` | `True` | PASS |
| 2.2 | `current` → `versions\0.3.13` | `ls -la "$LOCALAPPDATA/Orthic Labs/Legion"` | reparse point to `versions\0.3.13` | `current -> .../versions/0.3.13/` | PASS |
| 2.3 | `legion` on PATH | `where legion` | `…\current\bin\legion.exe` | `%USERPROFILE%\AppData\Local\Orthic Labs\Legion\current\bin\legion.exe` | PASS |
| 2.4 | Version | `legion --version` | `0.3.13` | `0.3.13` | PASS |
| 2.5 | Plugin discovered by Claude Code | `claude plugin list --json` | an entry with `id: "legion@skills-dir"`, `enabled: true` | `{"id":"legion@skills-dir","version":"0.3.13","scope":"user","enabled":true,"installPath":"C:\\Users\\<user>\\.claude\\skills\\legion"}` | **PASS (fixed, was FAIL in the 0.3.12 draft)** |
| 2.6 | Plugin component inventory | `claude plugin details legion@skills-dir` | Skills (27), Agents (4) | `Skills (27)` … `Agents (4) alchemist, covenant-seat, oracle, sage` | **PASS (fixed)** |
| 2.7 | Skill loader connected | `legion skills` | lists 27 skills with descriptions, no "not connected" gap | 27 rows printed, each with id + description, no error | **PASS (fixed)** |
| 2.8 | `--json` honoured | `legion --json skills` | valid JSON, `count: 27`, `releaseVersion: "0.3.13"` | `{"arguments":[],"count":27,"kind":"legion-skills","releaseVersion":"0.3.13","schemaVersion":1,"skills":[...]}` | **PASS (fixed)** |
| 2.9 | `legion --help` has descriptions | `legion --help` | every subcommand has a one-line description | every listed subcommand (`status`, `serve`, `init`, `doctor`, `bind`, `inspect`, `targets`, `components`, `stacks`, `controls`, `governance`, `skills`, `languages`, `providers`, `rules`, `schedule`, `plan`, `audit`, `verify`, `explain`, `report`, `fix`, `hooks`, …) has descriptive text | **PASS (fixed)** |
| 2.10 | `legion doctor` outside a git repo | `cd <empty temp dir>; legion doctor` | succeeds, no git-repo requirement | `legion doctor: complete`, `catalog entries: 27`, `provider count: 1`, `inventory digest: sha256:e3b0c4...`, `clean claim: true` — no error | **PASS (fixed, old "os error 2" is gone)** |
| 2.10a | `legion doctor` in a directory whose files churn | `cd %TEMP%; legion doctor` | `status: "incomplete"` with a single `cannot read …: os error 2` gap | reproduced in `%TEMP%` itself: doctor walks the tree and a transient `*.tmp` vanishing mid-walk becomes a gap | PASS (expected; use an **empty** dir for 2.10, not a churning one) |
| 2.11 | Claude MCP server registered | read `~/.claude.json` → `mcpServers.legion` | present, with an ownership marker | `mcpServers.legion` present: `command: …\current\bin\legion.exe`, `args: ["serve","--stdio"]`, `_legionOwnership: {owner: "claude-code", generation: "0.3.13:...", digest: "sha256:..."}` | **PASS (fixed)** |
| 2.12 | Codex MCP server registered | `grep -A5 mcp_servers.legion ~/.codex/config.toml` | present, with an ownership marker | `[mcp_servers.legion]` present: `command = '…\current\bin\legion.exe'`, `args = ['serve', '--stdio']`, `# /legion-owned` comment marker | **PASS (fixed)** |
| 2.13 | `~/.claude/skills` is a real directory | `ls -la ~/.claude \| grep skills` | real directory (not a junction to the dev tree) | `skills/` is a real directory containing `legion/`; **no junction to `<workspace>\tools\skills`** | **PASS (fixed)** — the development tree still exists at `<workspace>\tools\skills` but is no longer on the host's path. |
| 2.13a | Plugin root ships the declared hook manifest | `ls "$env:USERPROFILE\.claude\skills\legion\hooks\hooks.json"` | the file exists (Claude Code reads plugin hooks only from `<plugin root>/hooks/hooks.json`) | **absent** — projection root holds only `.claude-plugin/`, `agents/`, `mcp.json`, `plugin.json`, `rightax-portable-core.json`, `skills/` | **FAIL — see §6 #7** |
| 2.13b | Plugin root ships agents | `ls "$env:USERPROFILE\.claude\skills\legion\agents"` | `alchemist.md`, `covenant-seat.md`, `oracle.md`, `sage.md` | all four present | PASS (fixed) |
| 2.14 | `legion --json setup status` | `legion --json setup status` | per-client block with `installed: true`, `origin: "installed"`, hashes matching `legion --version` | 5 clients present (`antigravity`, `claude-code`, `codex`, `cursor`, `pi`); `antigravity` block shown: `installed: true`, `origin: "installed"`, `bound_release.release_version: "0.3.13"` | PASS |

---

## 3. Daily-use scenarios

### 3.1 Invoke a skill by slash command in Claude Code
- **Steps:** open Claude Code in any repo → type `/audit` (or any public skill id) → send.
- **Pass condition:** Claude Code resolves `/audit` to Legion's `audit` skill from the installed plugin
  projection `%USERPROFILE%\.claude\skills\legion\skills\audit\SKILL.md`.
- **OBSERVED:** the plugin is registered and enabled (§2.5), and `audit` is one of the 27 listed skills
  (§2.7). **UNVERIFIED live** — this document does not fire a real slash command inside a running Claude
  Code session; it verifies plugin discovery and skill listing only.

### 3.2 Invoke a skill by slash command in Codex
- **Steps:** open Codex → type `/seo` → send.
- **Pass condition:** Codex resolves `/seo` through `[mcp_servers.legion]` (§2.12).
- **OBSERVED:** the MCP registration exists with the correct binary path and an ownership marker.
  **UNVERIFIED live** — no interactive Codex session was driven for this document.

### 3.3 Routing case that should reach Sage / 3.4 Alchemist / 3.5 Oracle / Covenant
- **Pass condition:** Legion routes to the named role per `doctrine/{sage,alchemist,oracle}.md`; `/covenant`
  dispatches an isolated `covenant-seat`.
- **OBSERVED:** all four agents are shipped and enumerated by `claude plugin details legion@skills-dir`
  (§1.2, §2.6). **Live routing behavior is UNVERIFIED** — this document confirms the agents exist and are
  registered, not that a live conversation routes to them correctly.

### 3.6 `/audit` on a small repo
- **Requires** the `blueprint-graph` host capability (the `blueprint` binary). Not verified present on
  PATH for this document. **UNVERIFIED live; environment dependency, not a product defect.**

### 3.7 MCP server responds to a bare JSON-RPC probe
```
{ echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"dogfood","version":"1.0"}}}';
  echo '{"jsonrpc":"2.0","method":"notifications/initialized"}';
  echo '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'; } | timeout 12 legion serve --stdio
```
- **OBSERVED:** confirmed working in the packaged form the hosts actually use — both `~/.claude.json`
  and `~/.codex/config.toml` invoke `legion serve --stdio` with **no `--plugin-root` flag** (§2.11, §2.12).
  See §6 #2 for the separate, still-broken `--plugin-root` form that the plugin's own `mcp.json` declares.

---

## 4. Per-skill smoke table (27 skills)

All 27 ship a resolvable `SKILL.md` under `%USERPROFILE%\.claude\skills\legion\skills\<id>\SKILL.md`
(confirmed by directory listing) and all 27 are listed by `legion skills` with a description (§2.7).
That proves artifact residency and CLI-loader connectivity for every skill. It does not prove every skill
executes correctly end-to-end inside a live host session — see §3 for the scope of what was actually
driven interactively (nothing was).

Known reference-resolution issues, reverified tonight against the installed projection (`$P` =
`%USERPROFILE%\.claude\skills\legion`):

| Skill | Issue | Exact command | EXPECTED | OBSERVED tonight |
| --- | --- | --- | --- | --- |
| audit | `SKILL.md` line 49 instructs `node <package-root>/tools/audit/audit-run.mjs <root> --out <run-dir>`, but no `tools/` directory is shipped | `find "$P" -maxdepth 2 -type d -name tools` | one path ending `legion/tools` | **no output** — **CONFIRMED still broken** |
| audit | `references/manual.md` and `references/lens-routing.md` cite five sibling lens files that the bundle does not contain: `audit-design-decisions.md`, `coverage-and-trajectory.md`, `lens-cues.md`, `migration-safety.md`, `ponytail-lens.md` | `ls "$P/skills/audit/references/"` | the five files present alongside the five that ship | only `engine-interface.md`, `execution-contract.md`, `lens-routing.md`, `manual.md`, `provider-architecture.md`. All five cited files exist **only** at the repo-root `references/` directory, which the projection does not ship — **CONFIRMED broken (new tonight)** |
| tasklist | `scripts/validate-tasklist.py` resolves `PACKAGE_ROOT = Path(__file__).resolve().parents[3]` and delegates into `src/lib/` targets the portable core does not ship | `python "$P/skills/tasklist/scripts/validate-tasklist.py" --help` | usage text, exit 0 | `FileNotFoundError: … legion\src\lib\dispatch-validator\validate-tasklist.py` — **CONFIRMED broken on the installed tree (new tonight)** |
| dispatch | same delegation defect in `scripts/validate-dispatch.py` | `python "$P/skills/dispatch/scripts/validate-dispatch.py" --help` | usage text, exit 0 | `FileNotFoundError: … legion\src\lib\dispatch-validator\validate-dispatch.py` — **CONFIRMED broken on the installed tree (new tonight)** |
| tasklist | `examples/validated-tasklist.md`, `examples/validated-tasklist.minimize.json`, `examples/validated-tasklist.route.json`, `scripts/test_validate_tasklist.py` reference `/workspace/...` paths | `grep -rl "/workspace/" "$P/skills/tasklist"` | no output | the four files listed — **CONFIRMED still present.** These are example/fixture strings; the *runtime* defect is the `src/lib` delegation row above, not these strings. `validate-route.py` was searched for across the whole projection and **not found anywhere**, nor referenced by any live path — treat that sub-claim as moot |
| dispatch | `examples/dispatch-route-fixture.json` contains a `/workspace` path | `grep -rl "/workspace/" "$P/skills/dispatch"` | no output | the fixture — **CONFIRMED still present** (fixture-only, same reading as above) |

---

## 5. Failure triage — which command/file answers which question

| Question | Command / file | What to read |
| --- | --- | --- |
| Is Legion installed & on PATH? | `legion --version`; `where legion` | version + binary path |
| Is the plugin registered with Claude Code? | `claude plugin list --json`; `claude plugin details legion@skills-dir` | `enabled: true`; Skills/Agents/Hooks/MCP counts |
| Did the MCP server actually bind? | `~/.claude.json` → `mcpServers.legion`; `~/.codex/config.toml` → `[mcp_servers.legion]` | presence + `_legionOwnership` marker / `# /legion-owned` comment |
| Which skills does the host actually serve? | `ls -la ~/.claude/skills` | should be a real directory containing `legion/`, not a junction |
| Is the skill loader connected? | `legion skills` / `legion --json skills` | 27 rows, no "not connected" gap |
| Does the packaged (`--plugin-root`) MCP form start? | `legion serve --stdio --plugin-root <projection>` | exit code + stderr — **still broken, see §6 #2** |
| Repo health / inventory | `legion doctor` | succeeds inside or outside a git repo |
| What does setup think is installed? | `legion --json setup status` | `clients[].installed`, `origin`, hashes |
| Capability / host registry truth | `src/registry/capabilities.json`, `src/registry/skills/index.json`, `src/registry/host-projection.json` | capability list, domains, host requirements |
| Doctrine / role truth | `doctrine/{legion, sage, alchemist, oracle}.md` | routing tree + role contracts |
| Are Guard's plugin hooks registered at all? | `ls "$env:USERPROFILE\.claude\skills\legion\hooks\hooks.json"`; `claude plugin details legion@skills-dir` | the file must exist and the details view must report `Hooks (9)`. Today the file is absent and the count is 0 — §6 #7 |
| Is `legion-hook` reachable for Guard? | `where legion-hook` | must resolve under `…\current\bin\`. Hooks invoke the bare name with no `${CLAUDE_PLUGIN_ROOT}` prefix, and `legion-hook` fails **open and silently** when unresolvable (`src/registry/capabilities.json`, `legion-hook.degradation`) — an unreachable binary means no Guard, with no user-visible signal |
| Do the packaged Python validators run? | `python "$env:USERPROFILE\.claude\skills\legion\skills\tasklist\scripts\validate-tasklist.py" --help` | usage text and exit 0. A `FileNotFoundError` naming `src\lib\...` is §6 #11 — the portable core ships `skills/**` and `agents/**` only |
| Where is the setup transaction record? | `%LOCALAPPDATA%\Legion\setup-state.json`, `%LOCALAPPDATA%\Legion\journal\`, `%LOCALAPPDATA%\Legion\integrations\` | the live setup registry and ledgers. Note `release/distribution-contract.json` also names `%LOCALAPPDATA%\Orthic Labs\Legion\integration-journal.json`; that file is written by `scripts/qualify-windows-release.mjs`, not by `legion setup repair`, so its absence after an ordinary install is expected, not a fault. Read these; never hand-edit them |

---

## 6. Known-broken table

| # | Finding | Status | Evidence (verified tonight, 2026-09-03) |
| --- | --- | --- | --- |
| 1 | Nothing registered with any host while `setup status` reports complete | **FIXED in 0.3.13** | `claude plugin list --json` shows `legion@skills-dir` enabled; `~/.claude.json` has `mcpServers.legion` with an ownership marker; `~/.codex/config.toml` has `[mcp_servers.legion]` with a `# /legion-owned` marker (§2.5, §2.11, §2.12) |
| 2 | Shipped `mcp.json` `--plugin-root` command rejected by the binary | **STILL OPEN** | `legion serve --stdio --plugin-root "%USERPROFILE%\.claude\skills\legion"` → exit 2: `portable plugin root rejected: rightax-portable-core.json is invalid: unknown field \`publicAgents\`, expected one of \`schemaVersion\`, \`kind\`, \`plugin\`, \`publicSkills\`, \`publicFiles\`, \`privateWorkspaceContent\`, \`clientProjections\` at line 34 column 16; run legion setup repair --confirm`. The manifest's own `publicAgents` field (line 34 of `%USERPROFILE%\.claude\skills\legion\rightax-portable-core.json`) is rejected by the binary that is supposed to read it. Both hosts avoid this path entirely by invoking `legion serve --stdio` with **no** `--plugin-root` flag (§2.11, §2.12) — that bare form works (§3.7) — so this is currently a latent defect that does not block the registered hosts, not a live blocker. **Repo-side fix landed in `aa4f6101`; see row 8 for the pending-verification detail.** |
| 3 | `legion skills` reports "native skills implementation is not connected" | **FIXED in 0.3.13** | `legion skills` lists all 27 with descriptions; `legion --json skills` returns valid JSON with `count: 27` (§2.7, §2.8) |
| 4 | Host loads development skills via `~/.claude/skills` → `<workspace>\tools\skills` junction | **FIXED in 0.3.13** | `~/.claude/skills` is now a real directory holding the installed `legion/` plugin projection, not a junction (§2.13). The development tree still exists at `<workspace>\tools\skills` but is not referenced by any host path checked tonight. |
| 5 | `tasklist`/`dispatch` reference `/workspace` paths and a `validate-route.py` not shipped in the projection | **STILL OPEN (partially)** | `/workspace` paths confirmed present in `tasklist/examples/*`, `tasklist/scripts/test_validate_tasklist.py`, and `dispatch/examples/dispatch-route-fixture.json` tonight. `validate-route.py` was not found anywhere in the projection (moot — nothing shipped references a live path to it under this search). |
| 6 | Plugin manifest declares MCP but the host reports zero | **STILL OPEN — new detail found tonight** | `claude plugin details legion@skills-dir` reports `Hooks (0)` and `MCP servers (0)` even though the plugin surface declares hook events and one MCP server. Root cause for the MCP half: a plugin's manifest for Claude Code must be named `.mcp.json`, but Legion ships `mcp.json` (no leading dot) at `%USERPROFILE%\.claude\skills\legion\mcp.json` — Claude Code's plugin scanner does not pick it up under that name, hence `MCP servers (0)` in the details view. Legion's MCP integration works anyway, because both hosts register `mcpServers.legion` / `[mcp_servers.legion]` directly at the **user config level** (§2.11, §2.12), a separate mechanism from the plugin-manifest MCP surface the `claude plugin details` counter reads. The Hooks(0) half is now independently derived and split out as row 7. |
| 7 | The nine declared hook events never reach any client: the plugin root ships no `hooks/hooks.json` | **STILL OPEN — root cause found tonight** | `src/registry/plugin-surface.json` declares `counts.hookEvents: 9` over `PostCompact, PostToolUse, PostToolUseFailure, PreToolUse, SessionStart, Stop, SubagentStart, SubagentStop, UserPromptSubmit`, and `scripts/verify-plugin-parity.mjs:172` sources them from the repo-root `hooks/hooks.json`. But `assemblePortableCore(...)` in `scripts/assemble-native-release.mjs:440-451` is passed only `pluginManifestPath`, `mcpManifestPath`, `skills`, `agents`, `clientProjections` — **no hooks input** — so `%USERPROFILE%\.claude\skills\legion\hooks\hooks.json` does not exist (§2.13a) and `claude plugin details legion@skills-dir` reports `Hooks (0)`. This is the same class of defect as the agents bug fixed in `9ca9b98d`: the surface declares components the assembler never packages. **Guard is therefore not merely degraded on Claude Code — it is unregistered.** Note the two per-skill hook manifests that *do* ship (`skills/coder/hooks/hooks.json`, which is the empty array `[]`, and `skills/seo/hooks/hooks.json`) are skill-local and are not the plugin hook surface. |
| 8 | Installed 0.3.13 binary still rejects its own portable core over `publicAgents` | **FIXED IN REPO, NOT IN THE INSTALLED BUILD — pending re-verification after the next release** | Reconfirmed tonight against the installed binary: `legion serve --stdio --plugin-root "%USERPROFILE%\.claude\skills\legion"` still prints: `portable plugin root rejected: rightax-portable-core.json is invalid: unknown field publicAgents, expected one of schemaVersion, kind, plugin, publicSkills, publicFiles, privateWorkspaceContent, clientProjections at line 34 column 16; run legion setup repair --confirm`. Commit `aa4f6101` (*fix(plugin-root): accept the agents the core now carries*) adds `public_agents` to the contract in `engine/bins/legion/src/cli.rs:301`, defaults it empty for older cores, requires each declared agent to be a declared file, and allows `agents/<name>.md` through the closure check. That fix is in `main` but not in the 0.3.13 build installed here, so the row stays open on this host. **Mark PENDING-VERIFICATION; re-run the probe above on the first build after `aa4f6101`.** Both hosts still avoid this path (they invoke bare `legion serve --stdio`), so it remains latent rather than blocking. |
| 9 | `legion_m1_status` over MCP always answers `"status": "complete"` while the CLI answers `"incomplete"` | **STILL OPEN (repo-side, new tonight)** | `engine/bins/legion/src/cli.rs:1121` — `m1_status_value` unconditionally inserts `object.insert("status".into(), json!("complete"))`, and it is the value returned for the MCP tool at `cli.rs:1082`. `native_m1_status` (`cli.rs:1163-1183`) reports the honest `"status": "incomplete"`, `"fidelity": "degraded"` with three named gaps. One binary, two contradictory truths for the same question depending on surface. A fix must either propagate the real status into `m1_status_value` or rename the MCP field so it cannot be read as product status. |
| 10 | `tests/e2e/qualification.test.mjs` cannot run: it imports a script that no longer exists | **STILL OPEN (repo-side, new tonight)** | `tests/e2e/qualification.test.mjs:6` does `import { qualificationBundle } from '../../scripts/qualify-release.mjs'`; `scripts/qualify-release.mjs` is absent. `node --test tests/e2e/qualification.test.mjs` fails at import. It is not caught by CI because `pnpm test` is `node --test --test-concurrency=1 "tests/*.test.mjs"`, which does not glob `tests/e2e/`. A fix must delete the test or re-point it at `scripts/qualify-windows-release.mjs`. |
| 11 | The `tasklist` and `dispatch` packaged validators cannot run on an installed tree | **STILL OPEN (new tonight)** | Both wrappers compute `PACKAGE_ROOT = Path(__file__).resolve().parents[3]` and `runpy` a target under `src/lib/{tasklist,dispatch}-validator/`. The portable core ships only `skills/**` (plus `agents/**` since `9ca9b98d`), so on the installed projection both raise `FileNotFoundError: … legion\src\lib\dispatch-validator\validate-tasklist.py` and `… validate-dispatch.py` respectively (reproduced tonight, §4). Note the tasklist wrapper points at the **dispatch** validator directory, so that path is wrong twice over. A fix must either package the two validator engines inside each skill bundle or inline them, and must add a smoke check that executes both wrappers from the assembled plugin root rather than from the repo. |

---

## 7. History — why these changed

- **Registration (fixed):** the plugin used to be projected only into `~/.claude/plugins/legion`, which
  is Claude Code's internal state directory and is never scanned as a plugin source. The documented
  "local install with no marketplace" model is actually a **skills-directory plugin**: a real directory
  under `~/.claude/skills` carrying a `.claude-plugin/plugin.json` manifest, which Claude Code does scan.
  0.3.13 ships the projection that way, and `claude plugin list --json` now shows `legion@skills-dir`.
- **Agents never firing (fixed):** the release assembler previously shipped **skills only**. The four
  declared agents (sage, alchemist, covenant-seat, oracle) never reached any client, which is why sage,
  alchemist, and covenant-seat never fired in practice, while oracle appeared to work anyway — because
  oracle also exists as a skill, independent of the agent surface. 0.3.13's `claude plugin details`
  output now shows `Agents (4)` alongside `Skills (27)`.

---

## 8. UNVERIFIED claims

Items not confirmed live on this machine tonight, listed so they are not mistaken for verified facts:

1. **Live slash-command routing in a running Claude Code or Codex session** (§3.1, §3.2). This document
   confirms plugin discovery, registration, and skill/agent listing — not that typing `/audit` in a live
   session actually surfaces Legion's skill text and begins execution.
2. **Live routing to Sage / Alchemist / Oracle / covenant-seat** (§3.3–3.5). Agents are shipped and
   enumerated; a live conversation was not driven to trigger role hand-off.
3. ~~The exact count of declared hook events and the reason `Hooks (0)` shows.~~ **Resolved tonight —
   see §6 #7.** The nine events are declared in the repo-root `hooks/hooks.json` and counted into
   `src/registry/plugin-surface.json` (`counts.hookEvents: 9`); the assembler simply never copies that
   file into the plugin root, so the host has nothing to count. What remains UNVERIFIED is only whether
   shipping `hooks/hooks.json` alone makes `claude plugin details` report `Hooks (9)` — that requires a
   rebuilt package, which this read-only pass cannot produce. The hook commands are the bare word
   `legion-hook` (no `${CLAUDE_PLUGIN_ROOT}` prefix); `where legion-hook` resolves to
   `…\current\bin\legion-hook.exe` on this machine, so PATH is not the blocker here — packaging is.
4. **`blueprint`, `blueprint-graph`, `omniroute`, and other host-capability binaries being on PATH** on
   this machine tonight — not checked as part of this pass; scenarios that depend on them (§3.6, and any
   skill requiring `blueprint-graph`/`omniroute` per `capabilities.json`) are UNVERIFIED live for that
   reason alone, independent of the product's own correctness.
5. **`legion setup repair` idempotency / exact remediation behavior** — repair was run on this machine
   before tonight's verification pass, but repair itself was not re-run or inspected tonight (mutating
   command, excluded by the read-only rule for this document).
