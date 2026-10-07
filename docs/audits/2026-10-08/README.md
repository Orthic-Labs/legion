# Legion system audit — 2026-10-08

**Scope.** Everything that is or was Legion: the workspace lineage since 2026-06-10, the Legion repository since 2026-08-05, the 29 packaged skills, the governance documents, the Arcane/Guard runtime, the Rust engine and CLI, the host projections on this Mac, and the workspace rules that wrap it all.

**Method.** Read-only. Seven Sonnet subagents each owned one layer and wrote a report into `evidence/`; the lead verified the consequential claims directly (hook firing, duplicate MCP, stale goal hook, the Aug 3 rule cut, doctor output, skills diff). No repository, config, or installed file was changed. Nothing was built or tested locally (RightKit gates local Cargo); CI numbers come from `legion-ci` run 37684060947.

**Evidence.**

| File | Layer |
|---|---|
| `evidence/01-history-parent.md` | Workspace lineage 2026-06-10 → 08-10, original rules, 50-rule loss table |
| `evidence/02-history-legion.md` | Legion repo epochs, deletions vs replacements, drift symptoms |
| `evidence/03-skills-audit.md` | 29 skills: 4,474 references checked, per-skill table, ranked breakages |
| `evidence/04-doctrine-consistency.md` | 45 governance docs: ownership map, 20 contradictions, 19 dead references |
| `evidence/05-runtime.md` | Installed binaries, hooks, receipts, MCP, doctor, RightKit interference |
| `evidence/06-workspace-reality.md` | Workspace rules vs reality, Membrane/Cortex/rhook/Luna, skills fork, tools/ orphans |
| `evidence/07-engine.md` | Crates, LOC, tests, CLI surface, src residue, CI |

---

## 1. Verdict

The core is sound. The seams are not.

**Sound:** the Guard hook fires in every Claude Code session (about 6 ms per frame), 7,350 Rust tests pass in CI, all 29 skills project and load from the installed 0.3.21 plugin, and every manifest digest matches the bytes on disk.

**Not sound:** the written system and the running system have diverged. Four hand-maintained definitions of Legion disagree. The SSOT ranks stale documents above live ones. 78 deleted scripts are still taught as tools in 226 places. 144k lines of ported Rust are wired to nothing. Receipts are written but never read, and the advertised route trace has never been produced. A stale global hook has been injecting "do not ask the operator" into every session for a month.

**Root cause in one sentence.** The rules that made the original system good lived only in prose, were cut on 2026-08-03 without enforcement successors, and every subsequent rename and port deleted the previous form before the new one was proven, while the one gate that would have caught the fallout (the shipped-skill-paths check) was deleted in the same commit as the files it protected.

---

## 2. What it was

### 2.1 Lineage

| Date | Commit | Event |
|---|---|---|
| 2026-06-10 | `dc863dea` (workspace) | Import: 66 skills under `tools/skills`, 13 numbered rules, `tasks/lessons.md` |
| 06-19 | `4f2d6a26` | review → jury, review-self → council |
| 06-27 / 07-21 | `737f0400` / `4e305326` | Hooks tracked in git; Rust `rhook` runtime |
| 07-12 | `64217102` | Skills collapsed into routers (68 → 28) |
| 07-14 | `38eef902`, `b588f4b3` | Jury and council unified; Agent Room → Roundtable → Citadel (08-03) |
| 07-18 | `f5b27077` | Luna added as cheapest worker tier |
| 07-21 | `0da31e02` | Sequential thinking + Context7 fused into `groundwork` |
| 07-26 | | groundwork → reflect → Tether; RightContext → Membrane |
| 08-01 | `f9f1e5b4` | Tether → Sentinel; Blueprint → Cortex; MemRight → Crypt |
| **08-03** | **`2e6c7e7e`** | **Rule files cut from 70.8 KB to 8.2 KB in one commit** |
| 08-05 | `46eaa81d` (legion) | "Nemesis" audit engine created (depends on Cortex) |
| 08-05 | `d641bcab` | Sequential-thinking gate deleted |
| 08-06 | | Sentinel → Forge |
| 08-08 | `c1b5a618` | Canonical Legion doc set: Sage, Alchemist, Oracle, Arcane, Covenant |
| 08-09 | | Nemesis → Legion; nine engineering skills retired (restored 08-31) |
| 08-21 | | Cortex → Blueprint |
| 08-30 | `b81800da` | Guard split from Arcane |
| 08-31 | `ad3d27c6` | canon → foundation |
| 09-03 | `0cdf9d0d` | 58 test files found never to have run in CI; dead suites retired |
| 09-13..15 | `fc366b5b` | Native Rust CLI cutover |
| 09-23 | `31fa7209` | Membrane/Blueprint dependency removed from Legion |
| 09-25..26 | `ebb349ae`, `1908f4f6` | Rust port complete; 1,023 + 89 JS/Python files deleted |
| 10-05 | | Apple skills absorbed (37 commits); `tasks/lessons.md` deleted (`267bae38`) |
| 10-06 | `cb716706` / `3248d233` | SEO skill edited in two repos 14 s apart, both reverted within a minute |
| 10-08 | `6a87e641` | Handoff continuity restored (missing since the 09-24 port) |

Name chain for the grounding layer alone: sequential-thinking+Context7 → groundwork → reflect → Tether → Sentinel → Forge → Arcane → Arcane/Guard. Seven names in seven weeks.

### 2.2 What the original system enforced

From the 2026-06-10 and 07-31 rule sets (`git show 4530211c:CLAUDE.md`, `dc863dea:tools/skills/verification-before-completion/SKILL.md`):

- WebSearch-first grounding with at least two URLs and an explicit "unverified" label; Context7 lookup for library docs.
- Sequential-thinking gate before any change touching more than two files, architecture, or non-obvious debugging, with typed gap fields (`sourceChecked`, `assumptionsUnverified`, `needsContext`).
- Verify-before-propagate: read the source-of-truth file in the same turn and cite path and line before multi-file edits to names, versions, amounts.
- No completion claim without fresh evidence; "done without opening the artifact is a false claim".
- Mandatory `.verdict.json` ship gate with dual jurors and a cross-model quorum.
- Anti-sycophancy: lead with three weaknesses; "sycophant mode is a bug".
- Self-improvement ledger (`tasks/lessons.md`): save a memory before continuing after any durable correction.
- Karpathy surgical-change and code-simplicity rules.

### 2.3 What survived

Of 50 tracked rules and mechanisms: **8 preserved, 11 renamed, 13 weakened, 18 dropped.** Five of the eight preserved are hook- or script-backed. The dropped and weakened set is almost entirely epistemic discipline that lived only in prose: grounding, verify-before-propagate, fresh evidence, anti-sycophancy, lessons. That asymmetry is the central finding: **what was enforced survived; what was merely written did not.**

Today's Arcane default route is `grounding: none`. The `groundwork` MCP is back on disk since 08-30 but no rule references it. Oracle is optional. `GEMINI.md` still says to run Oracle before every delivery.

---

## 3. What it is now

| Layer | What exists | State |
|---|---|---|
| **Governance** | 45 docs, 36,095 words. Four hand-maintained Legion definitions (`AGENTS.md`, `docs/agent-rules.md`, parent `docs/agent-rules/legion.md`, the SessionStart text in `legion-hook`) plus 32 generated copies | 15 of 15 concepts defined in more than one place; 20 contradictions; 19 dead references. A Claude chat in `legion/` loads ~2,470 words and never sees `AGENTS.md`; a Codex chat loads only `AGENTS.md` and no workspace rules |
| **Roles** | Sage (opus), Oracle (opus), Alchemist (sonnet), Covenant seat (sonnet) as `agents/*.md`; each also defined in `doctrine/`, `src/roster/`, `docs/canon/`, `docs/architecture/`, and as a skill | Roster, agents, and `AGENTS.md` say Sage optional / Oracle optional / Alchemist ambient. SSOT, canon, architecture, README, plugin.json say Sage exceptional / Oracle before delivery / Alchemist needs a contract |
| **Skills** | 29 packaged, 29 manifests, 77 `legion script` entries | Manifests clean. 115 broken internal paths (70 are relocated files), 78 dead script names in 226 places, 53 eval files with no runner, 5 skills still demand `python-runtime`, `_shared/` used by 5 skills but declared nowhere. `tools/skills` in the workspace is a frozen 08-31 fork that nothing loads |
| **Arcane / Guard** | `legion-hook` 0.3.21 on nine Claude Code events | Fires and denies correctly. Always exits 0; denial is in JSON. 180 session-provenance receipts since Oct 5, scattered across 27 working directories. `skillCatalogDigest` is null in every one (symlink bug). No route-outcome trace has ever been written. False positives: `git clean -n`, `git restore .`, `rm -r ./build` |
| **Engine** | 21 crates + 4 bins + xtask, 424,500 LOC Rust, 7,350 tests | 70% of crate LOC is mechanical `wf_port`; ~144k LOC in 103 modules is named by nothing (heuristic). 9 of 11 `engine/tests` files never compile. 116 dead-code warnings, none fatal. clippy, deny, fmt unenforced |
| **CLI** | 32 advertised + 11 hidden commands | Root help is a hard-coded Node-era string. 5 of 32 have real help. `hooks`, `assurance`, `mcp install` are stubs; `fix` validates and never applies; `legion hooks` means git hooks |
| **Host projection** | Plugin at `~/.claude/skills/legion` (skills symlinked, agents/hooks/MCP static copies) | Not in `installed_plugins.json`. MCP server registered twice (user `~/.claude.json` and plugin `.mcp.json`): two `legion serve` processes per session, tool list doubled. Third copy in `~/.codex/plugins/legion`. `legion doctor` reports no Claude installation while everything is live, and has one permanent phantom gap |
| **Workspace rules** | 41 references in `workspace.md` + `legion.md` | 28 live, 5 stale, 5 dead. Membrane and Cortex are gone from this Mac; rhook is orphaned source; `status.py` exits on a missing manifest. 10 nested product repos carry a stale generated `AGENTS.md`. All 4 `.claude/commands` chain skills that do not exist. 20 `tools/` entries are orphaned |
| **User-level hooks** | RightKit build-control and ownership hooks; `goal-progress-guard.py` on every tool call | Goal guard has been `active: true, condition: "fix it all"` since Sep 4, spawns python on every tool call, and injects "do not stop to ask the operator" whenever heardright is dirty. Fired today. RightKit blocks benign commands by basename regex (`release-signing.md`, `echo cargo`, `PATH=`) |

---

## 4. How it was lost (six mechanisms)

1. **Prose rules cut without enforcement successors.** The 08-03 cut promised `docs/rules/conduct.md`; it was never created. The sequential-thinking gate was deleted two days later. Karpathy rules vanished two days after being added. None of these has a decision note.
2. **Renames without a single owner.** Seven names for the grounding layer, four live definitions of Legion, and an SSOT precedence ladder that ranks `docs/canon/*` (frozen Sep 2, citing 25 deleted files as "production consumer") above the current roster.
3. **Ports that drop modes and delete the oracle.** The Rust port was agent-generated in waves with the JS as reference, then the JS was deleted. Handoff continuity was missing for 14 days. Audit lost its lens fan-out three times (08-25, 08-31, 09-11). The dangling-path gate died in `ebb349ae` alongside the files it would have flagged.
4. **Gates that pass vacuously.** `bench_recall` skips uncovered classes green. `seo_closure` requires 19 deleted Python files, so the SEO completion gate can never pass. `doctor` once claimed a clean repo it never inspected. Manifest checks verify bytes, not whether a referenced tool exists.
5. **Agents working in the wrong place.** Personal skills swept into the package (08-14), private paths shipped (08-19, 09-03), SEO edited in two repos and double-reverted (10-06), a goal hook left global for a month.
6. **Governance nobody loads.** Only 6% of governance text is loaded in a session; the stale side of every contradiction sits in the other 94%, reachable through "Read X" pointers that the SSOT tells agents to trust.

---

## 5. Findings, ranked

Severity: **B** blocks correct operation today; **H** causes recurring breakage; **M** debt.

| # | Sev | Finding | Evidence |
|---|---|---|---|
| 1 | B | Stale global `goal-progress-guard.py` (`fix it all`, since Sep 4) runs on every tool call in every repo and injects a "never ask the operator" directive | 05 §7 |
| 2 | B | Legion MCP server registered twice (user scope + plugin); two processes, doubled tool list | 05 §5 |
| 3 | B | Role positions contradict across docs: Oracle optional vs mandatory, Alchemist ambient vs contract, Sage optional vs exceptional; SSOT precedence ranks stale canon above live roster | 04 §3 C1–C4 |
| 4 | B | 78 deleted scripts still documented as the interface (226 mentions); `audit` normative contract names deleted Node runners; 18 dead `auto-jury` blocks; 5 skills cite deleted `qa-shot.mjs` | 03 §2 S1, §7 1–4 |
| 5 | B | `legion script seo/seo_closure` cannot pass (needs 19 deleted `.py` files) and is SEO's completion gate | 03 §7.1, 02 §3 |
| 6 | H | No dangling-path / dead-tool gate exists; the one that did was deleted in `ebb349ae` | 02 §7, 03 §2 S6 |
| 7 | H | Receipts: written to process cwd (27 dirs), `skillCatalogDigest` null everywhere (symlink bug), route-outcome trace never produced, Oracle receipt never present | 05 §3 |
| 8 | H | Four divergent Legion definitions; Claude and Codex load different constitutions in the same directory; `docs/pending/README.md` ("sole index") generator deleted | 04 §5 |
| 9 | H | `tools/skills` is a dead fork of 26 skills; `.claude/skills/README.md` still calls it canonical; `/brand` has no pointer to `tools/legion-overlay/brand` where brand data lives | 06 §4 |
| 10 | H | `workspace.md` mandates Membrane packets, Cortex shims, rhook, `status.py`: none bound on this Mac | 06 §1–2, 04 §4D |
| 11 | H | 53 eval files have no runner; `covenant` and `commit` evals reference deleted proofs | 03 §7.9 |
| 12 | H | ~12 tools ported to Rust but not wired into `legion script`; docs call them "not ported" | 03 App. B, 02 §7 |
| 13 | H | `legion doctor` blind: reports no Claude installation, phantom `arcane@local-brief` gap, JS-era probe strings | 05 §4 |
| 14 | H | Guard false positives (`git clean -n`, `git restore .`, `rm -r ./build`); RightKit basename regex blocks `release-signing.md`, `echo cargo`, `PATH=`; `legion run --help` was blocked during this audit | 05 §3, §6 |
| 15 | M | ~144k LOC unwired `wf_port` modules; 1,400 dead lines in `cli.rs`; Node-parity shims and fake Node stack traces | 07 §1a, §2c |
| 16 | M | 9 of 11 `engine/tests` never compile, including the 41-test no-Node/no-Python guard | 07 §5a |
| 17 | M | CLI: 5 of 32 commands have real help, 11 working commands hidden, `hooks`/`assurance`/`mcp install` stubs, `fix` never applies | 07 §2 |
| 18 | M | 70 relocated links (seo 18, marketing 19, ios/macos 12 each); ios/macos are a 548 KB byte-identical fork | 03 §2 S2, §7.11 |
| 19 | M | 5 skills declare `python-runtime`; `_shared/` and banana/dataforseo/firecrawl/Ahrefs MCPs undeclared; `ads` ships 10 unregistered agents and contradicts its own `CHILD_AGENTS_MAX: 0` | 03 §2 S3–S5 |
| 20 | M | `action.yml` runs deleted `tools/audit/audit-run.mjs`; `seo/hooks/hooks.json` runs deleted `validate-schema.py`; `providers.json` lists 29 deleted `.mjs` paths | 02 §3 |
| 21 | M | Workspace: 10 stale nested `AGENTS.md`, 4 dead `.claude/commands`, 20 orphaned `tools/` entries, uncommitted rule edits, Windows path in `.codex/config.toml` | 06 §3, §5, §6 |
| 22 | M | `CLAUDE_CODE_SUBAGENT_MODEL=sonnet` set at user and workspace scope while Sage/Oracle declare opus; a memory note says it must stay unset | 04 §3 C10 (unverified) |

---

## 6. Recovery plan

Ordered by leverage. Each phase is independently valuable; none requires the next.

### Phase 0 — Stop the bleeding (minutes, no build)

1. Set `active: false` in `~/.claude/active-goal.json`, or unregister `goal-progress-guard.py` from `~/.claude/settings.json`. Also remove the orphaned `~/.claude/hooks/turn-discipline.py` and `~/.claude/bin/rhook`.
2. Remove the `legion` entry from `~/.claude.json` `mcpServers` (keep the plugin's). One owner.
3. Add a `> STALE: cites deleted code (2026-09-25 port). Not authoritative.` banner to `docs/canon/*`, `docs/pending/README.md`, `docs/architecture/host-integration-plan.md`, `docs/product.md`, `docs/architecture.md`.
4. Decide the three role positions once (recommended: the current roster side, since it is what the agents and hooks implement): Sage optional design/adjudication, Oracle optional, Alchemist ambient unless governed.

### Phase 1 — One owner per thing (docs, one sitting)

5. Pick one source for the Legion identity text and generate the rest from it: `AGENTS.md`, `docs/agent-rules.md`, the parent `docs/agent-rules/legion.md`, and `SESSION_START_CONTEXT` in `engine/bins/legion-hook/src/main.rs`. Make Claude and Codex load the same words in the same directory.
6. Rewrite the SSOT precedence ladder so `docs/canon/*` is below the roster or absent. Sweep the 20 contradictions listed in `evidence/04` §3 to the decided side.
7. `workspace.md`: delete the Membrane, Cortex-shim, rhook, and `status.py` bullets; fix Node/pnpm/Luna numbers; move the Windows-only Package Rules commands out of the always-loaded file. Run `manage.py sync` and `check`, then resync the 10 stale nested `AGENTS.md`.
8. Delete `tools/skills` (keep `content` if wanted, as its own thing). Fix `.claude/skills/README.md`. Give `/brand` an explicit pointer to `tools/legion-overlay/brand`. Remove the 4 dead `.claude/commands`.
9. Move `docs/canon/*` and `docs/pending/` to `docs/provenance/` or regenerate them from Rust; today they cannot be regenerated.

### Phase 2 — Make dead references impossible (gates, one PR)

10. Restore a shipped-paths gate in `legion-dev`: every relative link in `skills/**/*.md` resolves; every `legion script <name>` in prose exists in the dispatch table; every `scripts/*.py|mjs|sh` mention is a leak; every `hostRequirements` entry is used; `_shared/` is a declared bundle. Run it in `legion:check`.
11. Wire the 9 orphaned `engine/tests` files into the workspace (or delete them). Make dead-code warnings fatal for the bins. Enforce `cargo fmt --check` and clippy in CI.
12. Either port the eval runner to Rust or delete the 53 eval files; dead evals are worse than none.
13. Add a retirement ledger (`docs/provenance/retirements.md`) and a check: any path deleted under `skills/`, `scripts/`, `hooks/`, or any rule removed from `docs/agent-rules/*` must have a row naming its successor or "intentionally dropped". This is the rule that would have prevented most of §4.

### Phase 3 — Skills repair (mechanical, parallelizable)

14. Rewrite the 70 relocated links (`evidence/03` Appendix C has every one).
15. Replace or remove the 78 dead script names: `legion script` where a port exists, delete the instruction where it does not. Priority: `audit/references/execution-contract.md`, the 18 `auto-jury` blocks, the 5 `qa-shot.mjs` citations.
16. Wire the ~12 ported-but-unwired tools into `legion script` (`coverage`, `ai_visibility_import`, `checklist_compiler`, SEO `validate-schema`, designer `add-music`/`convert-formats`, coder cheap-review routing, goal-route validator).
17. Fix `seo_closure` to check the Rust entries, not deleted `.py` files. Drop `python-runtime` from the five skills and the registry. Declare `_shared/` and the MCP host capabilities. Register or remove the 10 `ads` agents. Collapse ios/macos shared files into one bundle.
18. Fix `action.yml`, `seo/hooks/hooks.json`, `providers.json`.

### Phase 4 — Runtime truth (engine, two or three focused PRs)

19. Receipts: set a single `LEGION_STATE_ROOT` (installed-product state dir) and use the payload `cwd` for repo keying. Resolve `current_exe()` through the symlink so `skillCatalogDigest` is populated. Either derive a route-outcome trace from Claude frames or remove the metric claims from `doctrine/arcane.md`.
20. `hooks.json`: absolute path to the installed `legion-hook`, or have the hook self-report absence at SessionStart so a missing binary cannot fail open silently.
21. `doctor`: detect the skills-dir projection, drop the `arcane@local-brief` gap, replace JS-era probe strings and the `node scripts/generate-host-projection.mjs` drift check.
22. Narrow the destructive classifier (`git clean -n`, `git restore .`, `rm -r <relative>` are not destructive) and ask RightKit to classify by `remote.origin.url` and argument, not basename regex (the Sep 4 gotchas entry already states this rule).
23. CLI: real clap help for every command; show the 11 hidden commands; delete the Node-parity shims and the 1,400 superseded handler lines; implement or remove `hooks`, `assurance`, `mcp install`, `fix`.

### Phase 5 — Restore the lost discipline as enforcement, not prose

This is the part that answers "bring it back to good shape". Each item restores one of the §2.2 rules in the form that survived everywhere else: a hook or a typed field.

24. **Grounding.** Add a `grounding: required` trigger to the Arcane default route for external facts, library APIs, versions, and prices; route it to WebSearch and the `groundwork` MCP that is already on disk. Emit `sourceChecked` and `assumptionsUnverified` in the route trace.
25. **Fresh evidence before "done".** Make the Stop hook check, when files changed this session, that the final message carries an evidence pointer (test output, command output, or opened artifact). Today Stop returns "lifecycle observation accepted" unconditionally.
26. **Verify-before-propagate.** Add a Bounded Falsification trigger for multi-file edits to names, versions, amounts: cite the source file and line in the same turn.
27. **Anti-sycophancy.** Put "lead with weaknesses" into the Oracle and Covenant seat prompts and into the Brief style; it currently lives only in a convened Covenant seat.
28. **Lessons.** Restore a lessons ledger (`gotchas.md` already exists; drop the "user-confirmed recurring only" restriction so first-occurrence corrections are captured).

### Phase 6 — Shrink (after Phases 2 and 4)

29. Delete the ~144k LOC of unwired `wf_port` modules once a reachability proof (not the heuristic) confirms it. Delete `src/lenses`, `src/recipes`, `src/internal`, 37 of 39 `src/evals`, 107 of 118 `src/schemas`, `bench/`, `migration/`, root `manifest.json`, 15 of 17 root `schemas/`. Stop shipping `src/lib`, `src/packages/contracts`, `src/schemas` in `package.json` `files`.
30. Retire the 20 orphaned `tools/` entries and the untracked `tools/bin`, `council`, `jury`.

---

## 7. Not verified

- Whether `CLAUDE_CODE_SUBAGENT_MODEL=sonnet` overrides the explicit `model: opus` in `agents/sage.md` and `agents/oracle.md`. Check one subagent transcript.
- Whether a missing `legion-hook` on PATH makes Claude Code fail open. Inferred from hook-exit semantics.
- Membrane state on the Windows host.
- The 103-module `wf_port` reachability count is a name-match heuristic.
- No local build or test ran; CI figures are from the latest green `legion-ci` run.
- The parent workspace has uncommitted edits to `AGENTS.md`, `workspace.md`, the lock file, and RightKit crates that predate this audit and were not examined.

---

## Addendum (same day): SEO, the audit skill, and two external sources

Three further questions were asked after the main audit. Evidence: `evidence/08-seo-lineage.md`, `evidence/09-audit-depth.md`, `evidence/10-external-review-sources.md`.

### A. SEO: nothing is lost everywhere, but Legion holds a lagging copy

The standalone repository is **github.com/bogusyogi/SEO** (public, branch `master`, head `9f313f2` on 2026-10-06). It was extracted from Legion commit `a4eaaa2` on 2026-09-16, and that tree is identical to the Legion peak. It is a standalone Python plugin with 242 files, 70 scripts, 28 test files, and CI on Windows, macOS, and Linux. It has no `legion script`, Membrane, or Rust dependency.

| | Peak in Legion (`f1d1847b`, 09-11) | Legion today | SEO repo |
|---|---|---|---|
| Files | 146 | 97 tracked (+21 stale `.pyc`) | all 146 present, 91 byte-identical, 55 edited, +96 new |
| Executables | 34 scripts, 7 banana, 2 hooks | 25 live via `legion script seo/*`, 5 wired but unrouted, 13 ported with no entry point | all present |
| Tests | 6 files (39 functions), 14 fixtures | 0 test files, 14 fixtures nothing reads | all present |

Lost from Legion but alive in the SEO repo: the six test suites (governance, kernel, replay, assurance), 8 fixtures, the `seo_closure` gate (61+ errors as ported), `validate-schema.py` (still named by `skills/seo/hooks/hooks.json`), `pre-commit-seo-check.sh`, and the ported-but-unreachable libraries `coverage`, `contracts`, `ai_visibility_import`, `checklist_compiler`, `page_engine`, `source_freshness`, `analyze_visual`, `capture_screenshot`, and the banana `batch`/`setup_mcp`/`validate_setup` tools.

The workspace ops folder `/Volumes/D/claude/SEO` is a per-site deployment layer for the SEO repo, not a Legion route: its PowerShell runners call `D:\Claude\standalone-seo`, `agent-routes.json` cites three report files that do not exist, and its recorded rightsites head is 286 commits behind. `tools/skills/seo` is an older subset and should be deleted.

**Decision for Adrian.** Make `bogusyogi/SEO` canonical and reduce Legion's `seo` skill to a thin router that declares the external repo as a `HOST_CAPABILITY`, or keep Legion canonical and re-import the 96 new files plus the tests. The first option is recommended; it conflicts with the Package Rule "Legion is the canonical source for every skill it ships", so that rule needs one amendment allowing a declared external canonical repository.

### B. The audit skill: the numbers did not shrink, the run is hollow

| | Best (2026-07-15) | Now |
|---|---|---|
| Deterministic checks | 23 | 78 providers in the registry (32 external-tool, 29 native, 17 lens contracts) |
| Reasoning lenses | 15, one subagent each, in parallel, with a verify pass | 15 defined; **0 run** |
| Audit-fix | re-ran everything each iteration | `CHILD_AGENTS_MAX: 0` still in `skills/audit-fix` |
| Last real run (viewright, 2026-10-03) | | 39 of 78 providers cancelled, 5 completed, 0 lenses; 192 findings, 187 from the accessibility suite |

Why it feels weaker (each verified in source by the subagent; the first two confirmed by the lead):

1. **No signing key, no audit.** `AUDIT_PLAN_SIGNING_KEY` is set by nothing, so every plan is "integrity digest only; authenticity unproven" (`legion-audit/src/p12_pipeline/mod.rs:164`). On an unsigned plan, `legion-audit/src/execution.rs:150-158` marks every provider that is not a source-only diagnostic as failed with the gap `unsigned-source-diagnostic-only` / `unsigned-plan-provider-not-executed`, which takes out all external scanners and all 15 lens providers. The behaviour is deliberate fail-closed design; the defect is that the installed product never supplies a key, so the closed state is the only state.
2. **No lens host.** The Rust runner has no production `ReasoningHost`, so zero reasoning lenses run regardless of the key. `lensesRan` counts lens *tags* on deterministic providers, so it reads 6 or 8 when none ran: a false signal.
3. **Lowest tier.** Commit `d72c46ae` (2026-09-19) routed all audit lenses to the lowest model tier.
4. **Empty inputs.** Inventory `dependencies` and `symbols` are always empty, so 8 architecture and 7 security providers receive nothing and return empty or failed; `anyDependency` selectors can never fire.
5. **Unreachable clean.** Every provider is planned `required` and all 78 are unqualified, so 73 of 78 end incomplete and a clean verdict is impossible by construction.
6. **Hard-coded doctor.** `commands/doctor.rs:152` and `commands/languages.rs:20-21` return `framework.react`, `framework.tauri` and empty `selected`/`blocked`/`missingTools` for every repository. The "misdetection" seen in §3 is a constant.
7. **Vacuous bench.** `bench_recall.rs` prints SKIP and passes for uncovered and tool-missing classes; the drift class is always skipped; the corpus is the same 13 fixtures since 07-26; no CI step installs the scanner tools. The drift detector is confirmed removed; `docs.contract` reads `docClaims` that nothing produces.
8. **Missing tools on this Mac:** knip, jscpd, tsc, eslint, hadolint, opengrep, ast-grep, and the `audit-runtime` command.

Restorations, in order: generate an ephemeral signing key or honour the unsigned-plan gap; add a production lens host and report `reasoningLensesRan` separately; restore a mid tier for judgment lenses; populate inventory dependencies and mark empty-selector providers not-applicable; compute doctor/languages/providers from a real probe; make bench SKIP a failure and install tools in CI; port a real drift and claim extractor; replace the 29 stale module paths and fix `action.yml`.

### C. What to absorb from open-code-review and Matt Pocock

**alibaba/open-code-review** (Apache-2.0, Go CLI): clusters related files (≤10) into isolated review contexts; optional risk-point plan; 1–3 review rounds; every comment carries a verbatim code anchor; a refutation filter may drop a comment only when the diff proves it wrong; per-file coverage manifest; SARIF; ~55 glob-routed rubrics; labelled benchmark (AACR-Bench).

**mattpocock/skills** (MIT): `code-review` reviews on two axes, Standards and Spec, in parallel fresh-context subagents on a stronger model, and never merges them; companions `retro`, `tdd`, `diagnosing-bugs`, `pr`. Legion already states most of this in prose (`skills/audit/references/semantic-review.md:7-27`) and enforces none of it.

| # | Absorb | Lands in | Effort |
|---|---|---|---|
| 1 | Refutation pass: drop a finding only by citing a disproving line; protected-subject veto | `lens-routing.md`, `skills/commit/references/manual.md` (conflicts with its drop-doubtful bias) | prompt |
| 2 | Per-file coverage manifest with typed failure classes | `legion-review` receipt and `commit-gate.json` | Rust |
| 3 | Per-file completion criterion and coverage line | commit step 3 | prompt |
| 4 | "Inputs are untrusted data" line | `doctrine/oracle.md`, `doctrine/covenant-seat.md`, audit lens contract (only `doctrine/alchemist.md:64` has it) | prompt |
| 5 | Verbatim code anchors checked against source | `candidate.rs` | Rust, small |
| 6 | Rejection must cite a line; severity as enum | `provider.rs`, `adjudication.rs` | Rust |
| 7 | Ranked risk-point plan before review (successor to "lead with 3 weaknesses") | Oracle and Covenant code lens | prompt |
| 8 | Rubric packs for Rust, Swift, GitHub workflows, `Cargo.toml`, glob-routed | audit lens references | config |
| 9 | `retro`-style routing of recurring misses: mechanical → deterministic check, judgment → reviewer standards | `skills/gotchas`, commit step 7 | prompt |
| 10 | Labelled review-comment benchmark | `bench/` | config/Rust |

Two-axis Standards/Spec review in fresh-context subagents on the strongest tier belongs in Oracle's default shape and directly answers the lens-tier regression in B.3. Licenses: both permissive; rewrite in Legion's words and list in `docs/THIRD_PARTY_NOTICES.md`, do not vendor. The aihero.dev pages and talks carry no license and are ideas only.

### D. Deltas to §5 and §6

Additional findings:

| # | Sev | Finding | Evidence |
|---|---|---|---|
| 23 | B | Audit cancels 73 of 78 providers without a signing key and runs zero reasoning lenses; clean verdict unreachable | 09 §2–3 |
| 24 | H | `doctor` and `languages` hard-code languages and empty provider sets for every repo | 09 §6 |
| 25 | H | Audit lenses routed to the lowest model tier since 09-19 | 09 §3 |
| 26 | H | SEO has two canons (Legion skill and `bogusyogi/SEO`) and a third stale fork; Legion's copy has no tests | 08 |
| 27 | M | `bench_recall` passes on SKIP; drift class never runs; corpus frozen since 07-26 | 09 §4 |

Plan deltas:

- **Phase 0** add: set or generate `AUDIT_PLAN_SIGNING_KEY` in the installed product, or ship the unsigned-plan gap, so `/audit` runs its providers again today.
- **Phase 1** add: decide the SEO canon (A above) and amend the Package Rule accordingly; delete `tools/skills/seo`.
- **Phase 4** add: the eight audit restorations in B, starting with the lens host and the real doctor probe.
- **Phase 5** add: items 1, 4, 7 from C into Oracle and Covenant prompts; two-axis review on the strongest tier as Oracle's default shape; items 2, 5, 6 into `legion-review`.
- **Phase 6** add: bench becomes a hard gate with tools installed in CI; retire or revive the dead `evidence-gauntlet` eval.
