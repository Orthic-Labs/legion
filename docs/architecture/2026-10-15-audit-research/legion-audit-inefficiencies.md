I found no persistent index or cache anywhere in the audit pipeline. Every run walks and SHA-256-hashes the repo three times, compiles the plan three times, and builds every lens packet twice. Each of the 15 lens packets also carries a full copy of the repo inventory. Several working-tree files were being edited while I read (`execution.rs`, `inventory.rs`, `legacy_checks/{mod,registry,runtime_capture}.rs`, `reasoning/{excerpts,ingest,lens_plan,mod}.rs`), so line numbers are as of the read.

All engine paths are under `/Volumes/D/claude/legion/engine/`.

## Ranked by cost (biggest first)

**1. Every lens packet embeds the whole repo inventory, and each lens re-reads the same files.**
- `reasoning/mod.rs:620` serialises the full inventory as `projection`. Line 715 puts it into part 1 of every lens packet.
- Measured on `rightkit/.audit/fresh-2026-10-11/lens-packets/`: 16 packets, 69 MB in total, about 4.5 MB each.
  - `projection.entries` is 2.67 MB, identical in all 15 `reasoning.*` packets (10,023 entries, including `.DS_Store`).
  - The excerpts themselves are only about 0.6 MB per packet.
- Each lens builds its excerpts separately (`mod.rs:569-590` calls `partition_excerpts_scoped` / `partition_review_set`, which reads files at `excerpts.rs:860`). With 11 lenses on `sourceFilesAtLeast`, each source file is read, redacted and excerpted about 11 times per build.
- **Cheapest fix:** drop `projection` from packets, or replace it with the inventory digest plus a path to one shared `inventory.json`. Then build an excerpt cache keyed by `(path digest, mode, hunks)` once per run and have packets reference it.

**2. Seats are not actually bundled in the engine.**
- SKILL.md step 7 and `lens-routing.md` say one seat "reads its excerpts once" using `lens-dispatch.json`. Nothing in the engine writes that file yet (grep finds no hits). The design doc `docs/architecture/2026-10-15-scaled-audit-design.md:135` still lists it as planned.
- Packets are still written one per provider (`ingest.rs` `write_lens_packets`), so seat J1 would load three packets with overlapping excerpts.
- `skills/audit-fix/SKILL.md` step 5 still says "fan out one fresh-context subagent per packet", which contradicts the bundled-seat routing.
- Every packet keeps a pretty-printed request (`to_vec_pretty`): about 1 MB of whitespace per packet on top of the 3.5 MB request.
- **Fix:** emit one packet per bundle with a shared excerpt set and per-lens questions, write compact JSON, and align audit-fix with the bundles.

**3. Providers run one at a time, and the declared parallel and cache settings are ignored.**
- `execution.rs:534` runs `for provider in plan.providers()` and awaits each provider in turn. The same body is duplicated as a sync path at `:346`.
- The registry (`src/registry/providers.json`, 87 providers) marks nearly every provider `scheduleClass: parallel-safe` and `cachePolicy: content-addressed`. Nothing in `crates/` or `bins/` reads `scheduleClass`, `cachePolicy` or `maxParallelism`.
- **Fix:** run providers in dependency-ordered waves with bounded concurrency (only `legacy.quality.test` is `serial`). Key cached results by `(provider version, tool version, ruleset digest, denominator digest)`.

**4. Every Rust audit starts from a cold build.**
- `legacy_checks/mod.rs:1448` points `CARGO_TARGET_DIR` at the per-run scratch directory, which is deleted on drop (`:375-383`, `audit.rs:3109`).
- One run then does `cargo check` plus `clippy` (`code.rust`, `code/tools.rs:24-26`), `clippy -D warnings` again (`legacy.quality.lint`), `cargo build` (`legacy.quality.build`), `cargo geiger` (full compile), and `cargo test` in a separate copy.
- ESLint and ruff run with `--no-cache` (`code/tools.rs:410`, `:497`).
- **Fix:** use one persistent target and cache directory per repo under `.legion-cache/` (already excluded at `inventory.rs:547`). Run clippy once and let `code.rust` and `legacy.quality.lint` share the result.

**5. Scanners overlap.**
- Secrets: gitleaks runs twice — `git .` over full history (`registry.rs:344-366`) and `dir .` (`security/producer.rs:885-900`).
- SAST: `semgrep --config auto` (`registry.rs:317`) and `opengrep/semgrep scan .` (`producer.rs:536-558`).
- Dependency advisories: npm/pip/cargo-audit, plus `dependency.osv`, plus `cargo deny` (which also checks advisories).
- **Fix:** pick one owner per class, or reuse one tool's output across providers.

**6. Diff scope never reaches the external tools.** See Scope modes below. Every tool scans `.` (`code/tools.rs:414`, `:497`, `:564`; `producer.rs:557`, `:700`, `:790`, `:890`), and gitleaks walks all of history even on a one-file diff.
- **Fix:** pass the changed-file list where the tool accepts paths (semgrep/opengrep, eslint, ruff, gitleaks `--log-opts=<range>`). Skip whole-project tools when no manifest or lockfile changed.

**7. Work repeated within one run.**
- **Inventory walk plus full read and SHA-256 of every file, three times:**
  - `freeze_lens_basis` (`audit.rs:1010`)
  - `plan_inventory` (`legion-application/src/lib.rs:2175`)
  - `execution_inventory` (`:2182`)
  - Plan-only runs also do three: lens basis, the Plan op, and `native_inventory_binding` (`audit.rs:348`, `:1206`).
- **`compile_with_root` three times:** lens basis, the provider universe (`plan.rs:494` via `audit.rs:2263`), and the executed plan. The comment at `plan.rs:130` admits they "compile independently". Each compile:
  - re-reads files for triggers (`triggers.rs:47`, which reads the whole file and then caps at 64 KB);
  - runs `git log --numstat -n 2000` (`coverage_plan.rs:317`);
  - stats every file (`:356`).
- **Packets built twice:** the size gate (`audit.rs:1039`) builds them, then `lens_work_items` (`:1117`) builds them again. Triggers are re-evaluated per packet (`mod.rs:605`).
- **Scope git calls run twice:** `--name-only` (`audit.rs:2525`) and `-U0` (`:2695`), plus `rev-parse` and `@{u}` again in `review_context` (`:2772-2790`).
- **Fix:** build the inventory and plan once and pass them through `NativeOperation::Audit`. Reuse the size-gate packets. Memoise triggers and churn.

**8. Test runs copy the entire inventory.** `disposable_copy.rs:376-470` reads each file, hashes it (`:150`), writes it, re-reads it and hashes it again (`:455`). It then walks the copy again (`:2416`).
- On a diff-scoped run the inventory contains only the changed files, so the copy is probably incomplete for building — worth a check.
- **Fix:** compare the inventory digest instead of re-hashing, and use reflink/hardlink copies where available.

**9. Ingest loop and artifact sizes.**
- Each `legion audit ingest` calls `recompute_run` twice: once in `plan_followup` (`audit.rs:891`) and once in `ingest_command`. Follow-up ingests call it three times.
- Each call re-reads `execution.json` and `report.json` and rewrites the report and SARIF.
- The skill requires ingests to run sequentially, one per lens.
- On the rightkit run: `report.json` 16 MB, `execution.json` 15 MB, `report.sarif` 12 MB, `facts.json` 5 MB. Findings are copied into all four, and `plan.json` and `facts.json` embed the plan again (`audit.rs:575-614`, `1262-1281`).
- **Fix:** batch ingest (`--result` repeated), recompute once, and reference findings by ID instead of copying them.

**10. Audit-fix reruns everything.** Up to 4 batches × a full `legion audit` (all 87 providers, including tests and builds) plus all lenses (`audit-fix/SKILL.md` steps 5-6).
- **Fix:** rerun only the providers and lenses whose findings were touched, scoped to the edited files.

**11. `legion verify` rebuilds instead of checking.** It re-walks and re-hashes, recompiles the plan (`legion-application/src/lib.rs:2150-2152`), and runs `recompute_run` (`verify.rs:258`). That is cheap compared with execution, but it would disappear once a persisted index digest exists.

## Missing persistent index or cache

Nothing is reused across runs:
- Inventory digests are computed and thrown away.
- Scratch is deleted every run.
- `symbols` is always empty (`inventory.rs:146`).
- Fan-in only counts manifest dependencies and is "usually 0" — the comment at `coverage_plan.rs:350-354` says a Blueprint graph "would be the better source; none is available".
- `commands/mod.rs:75-77` says the engine has no external context engine.
- `worktree.rs` (`create`/`cleanup`) exists but nothing calls it.

**What an index-first step would need to store** (in `.legion-cache/index/`, keyed by git object IDs plus a dirty-file digest, updated incrementally from `git diff`):
- the file list with digest, size, language, source/test/generated class and git status;
- manifests, dependencies and package scripts;
- symbols, imports and a reverse import (fan-in) graph;
- churn and ownership (`git log`/`blame`);
- trigger signatures;
- skeleton/region/raw excerpt cache, keyed by digest;
- provider results keyed by (tool version, ruleset digest, file digest).

**Consumers it would serve:**
- inventory and plan binding (one walk);
- `triggers.rs`;
- `gather_facts` (churn and fan-in);
- `excerpts.rs` (shared across lenses);
- the packet `projection` (becomes a reference);
- disposable copy and native secrets (digest already known);
- `verify` (compare digests);
- audit-fix (find what changed).

## Scope modes today (`audit.rs:2525-2637`)

| Flag | What it does now |
|---|---|
| `--type all` | Default. Whole repo. |
| `--type local` | `git diff HEAD`, plus untracked files, plus `@{u}..HEAD`. Drops vendor and generated paths. |
| `--type uncommitted` | Plain `git diff`: unstaged changes only. Staged and untracked files are excluded, although the docs describe it as "working tree only". |
| `--type committed` | `HEAD~1..HEAD` only. |
| `--base B` | `B...HEAD` (from the merge base). |
| `--base-commit X` | `git diff X`, i.e. X compared with the working tree, dirty changes included. It is not an A..B range. |
| `--dir` | Only filters the changed-file list. It never narrows the inventory on its own (`:2401-2404`). |

**Gaps:**
- No PR mode (PR number → base/head).
- No `A..B` range mode and no `--head`.
- No single-commit mode other than `HEAD~1`.
- No staged-only mode.
- The bytes audited are always the working tree, so a range or PR can't be audited without checking it out (the unused `worktree.rs` could materialise the head).
- `--dir` can't narrow a whole-repo audit.
- Tools ignore the scope (item 6).
- The docs say on purpose that the scope flags do not turn /audit into single-PR review (`engine-interface.md:8`, `manual.md:165`).

## CodeRabbit and Ponytail mentions

**CodeRabbit** has no mode or flag. It is documentation only:
- `skills/audit/references/lens-cues.md:1-25` — an "absorption" table mapping CodeRabbit's review categories to lenses, says there is "no separate CodeRabbit round", and calls CodeRabbit "retired" as an external reviewer.
- `engine-interface.md:6` and `manual.md:162` — "CodeRabbit-inspired" CLI flags, meaning the scope flags above.
- `manual.md:261` — `correctness` is labelled the "coderabbit fold".
- Competitor matrices in `a workspace competitor-matrix plan doc` (e.g. `03-COMPETITIVE-FEATURE-MATRIX.md:91`, `:138`) and other docs.

**Ponytail** exists as the `minimize` lens:
- Its full prompt is `references/ponytail-lens.md` and `skills/audit/references/ponytail-lens.md`, with tags `delete`/`stdlib`/`native`/`yagni`/`shrink`.
- `audit-design-decisions.md` D5/D6 record it as folded into the audit.
- The `debt_markers` scanner greps for `ponytail:` (`registry.rs:96`).
- `/Volumes/D/claude/docs/plans/2026-07-28-first-party-minimize-enforcement.md` cites github.com/DietrichGebert/ponytail and rejects recreating its modes.

## Cheapest wins, in order
1. Remove `projection` from the packets.
2. Reuse the size-gate packets and the lens-basis inventory and plan, instead of building them again.
3. Keep a persistent cargo, ESLint and ruff cache.
4. Run providers in parallel waves.
5. Remove the duplicate gitleaks, semgrep and advisory scanners.
6. Add `--head`/`--range`/`--pr`/`--staged`, and pass the scoped file list to the tools.
7. Batch ingest so `recompute_run` runs once.