# Audit v2 design: index first, scoped runs, CodeRabbit- and Ponytail-style reviews

**Charter result:** significant. This is D2 (system-level, crosses boundaries, involves a migration) with the objective `optimize` on two axes, efficiency and review fidelity. Rigor is standard. Current state comes from the working tree as of 2026-10-15:
- Lane B, lane C and part of lane A are uncommitted.
- `coverage_plan.rs` is 1,225 lines.
- `lens-dispatch` is referenced in `ingest.rs` and `audit.rs`.

`blueprint` is not on PATH on this Mac, so Ember gets no Blueprint graph.

## 1. Frame

**Outcome.** One `/audit` engine that:
1. builds or refreshes a persistent index first, then reads every input from it;
2. runs on any scope (repo, PR, range, commit, branch, staged, uncommitted, local, since-last), with an optional path filter;
3. renders honest audit, CodeRabbit-style and Ponytail-style reports from one finding schema;
4. completes a whole-repo audit of Ember, and a PR-mode run, on an installed build.

**Quality drivers.**

| ID | Scenario |
|---|---|
| Q1 Efficiency | On a warm rerun, Ember (1,071 files) does no repeat walk or hash of unchanged files and builds no packet twice. Every repo file is read at most once per run, plus cache misses. |
| Q2 Honesty | A missing stage, unresolved edge, failed anchor or unrun tool shows up as a gap or `incomplete`, never as clean. |
| Q3 Determinism | Running with or without `.legion-cache/` gives the same plan digest and the same findings. |
| Q4 Scope fidelity | The bytes audited are the scoped revision's bytes, and external tools see the same scope. |
| Q5 Cost | Judgment-tier tokens go only to bundles, adjudication and the walkthrough. Mechanical work runs on Haiku/Luna. |
| Q6 Portability | Works identically on Mac and Windows. Snapshot creation uses only git plumbing. |

**RightKit reuse decisions** (from `rightkit owns`):

| Need | Owner | Decision |
|---|---|---|
| Blob, excerpt and provider-result cache | `disk-cache` → rightkit-cache 0.1.0 (hard size cap, LRU, atomic writes, group invalidation) | **Reuse.** Group invalidation maps onto tool/ruleset digests. Its API must be checked against the facts below at the start of P1. If it doesn't fit, **extend** it; don't build a second cache. |
| Repo file index | `file-index` → rightkit-fsindex | **Reject, with a recorded reason.** It is a whole-disk getattrlistbulk/FSEvents crawler. It is not git-aware, keyed by content or cross-platform for repo trees. Git plumbing (`ls-files -s`, `status -z`) already gives blob OIDs for free. |
| Symbol search | `search` → rightkit-search | Not needed in this design. Revisit if seats get an index query tool with free-text search. |
| Code graph | No RightKit owner. Blueprint `blueprint-graph` is Legion's optional host capability. | Use Blueprint when it is present. Otherwise a lexical file-level floor (decision C2). |
| SQLite (`rightkit-db`) | Not needed | A snapshot manifest plus content-addressed objects is enough. |

**Where dependencies go.**
- A new crate, `engine/crates/legion-index/`, holds all new dependencies in its own `Cargo.toml` (rightkit-cache, plus `sha2`/`serde` from the workspace). It is also added as a workspace member in `engine/Cargo.toml`.
- `legion-audit` gains exactly one line, `legion-index = { path = … }`, in its owner-held `Cargo.toml`. That line lands after the owner commits their current `rightkit-browser` change, or the owner adds it.
- `runtime_capture.rs` is not touched.
- No tree-sitter.

## 2. Decisions

### ADR-1 — Index first, as a content-addressed cache owned by Legion

**Decision.** Step 1 of every audit, including plan-only runs, is `IndexRefresh`. It runs once in `legion-application` and produces an `IndexSnapshot`. That snapshot is passed through `NativeOperation::Audit` to the lens basis, the plan compile, the provider universe, execution, packets, verify and audit-fix. This removes the three walk/hash passes (`audit.rs:1010`, `legion-application/src/lib.rs:2175`, `:2182`) and the three `compile_with_root` calls. The plan is compiled once and the size-gate packets are reused.

**Layout of `.legion-cache/index/`** (the directory is already excluded at `inventory.rs:547`):
- **`snapshots/<key>.json`**, where the key is the HEAD tree OID, the dirty-set digest, the index schema version and the exclusion-config digest. It holds, per path:
  - blob OID, sha256 (today's digest algorithm, so plan digests don't change), size;
  - language, class (source / test / generated / vendor / lock / minified), git status;
  - a pointer to the path's facts object.
- **`objects/`**, held in rightkit-cache and keyed by `(sha256, extractor version)`:
  - signature symbols (reusing the excerpt skeleton extractor);
  - lexical imports;
  - trigger matches per trigger-set digest (removes the whole-file read at `triggers.rs:47`);
  - manifest dependencies and scripts.
- **`graph/<snapshot>.json`**, the reverse import graph.
  - Each edge has a confidence of `certain`, `likely` or `possible`, and a source of `lexical` or `blueprint`.
  - `unknowns[]` lists dynamic imports, macros, glob re-exports and unresolved aliases, each with its cause.
  - Fan-in is derived from this graph, replacing today's "usually 0" (`coverage_plan.rs:350`).
- **`history/commits/<oid>.json`**, immutable per-commit numstat and author records.
  - Churn and ownership are computed by summing over the window.
  - Refresh fetches only commits it hasn't seen, replacing a full `git log -n 2000` on every compile.
  - Author identities stay local and never enter packets.
- **`excerpts/`**, keyed by `(sha256, mode, regions-digest, redaction-ruleset version)`. One excerpt set per run is shared by every lens.
- **`results/`**, provider results keyed by `(providerId, providerVersion, toolVersion, rulesetDigest, inputDenominatorDigest, scopeDigest)`. Used only for `cachePolicy: content-addressed` providers (decision C1).
- **`audited.json`**, the last audited `{scopeKey → headOid, planDigest, reportDigest}`. This powers `--scope since-last`.

**Invalidation.**
- Clean tracked files use their blob OID from `git ls-files -s`. Git handles racy files.
- Dirty and untracked files are always re-hashed. There are few of them.
- A new extractor version re-extracts lazily.
- No decision ever rests on mtime alone.
- If Blueprint is fresh at the same revision, its edges replace the lexical edges for that snapshot.

**Alternatives rejected.**
- SQLite index: more machinery than 10k-entry snapshots need.
- Tree-sitter parsers: new dependencies and build cost. The lexical floor plus Blueprint covers ranking and blast radius. Revisit only if benchmark recall shows a need.
- Requiring Blueprint: it is optional and absent on this host.

**What it removes.**
- The triple walk and compile, and the double packet build.
- The full inventory `projection` in every packet. It is replaced by `{inventoryDigest, snapshotRef}`, which saves about 2.67 MB per packet.
- About 11 re-reads of each file to build excerpts.
- `disposable_copy` re-hashing, because the digest is already known.
- The re-walk in `legion verify`, which becomes a snapshot-key comparison plus a re-hash of dirty files only.

### ADR-2 — One `ScopeSpec`, with bytes taken from the scoped revision

**Grammar.** `--scope repo | pr:<n|url> | range:A..B | commit:<sha> | branch[:<base>] | staged | uncommitted | local | since-last`, plus a repeatable `--path <glob>`.

**Old flags stay as aliases:**

| Old flag | New scope |
|---|---|
| `all` | `repo` |
| `committed` | `commit:HEAD` |
| `--base B` | `branch:B` |
| `--base-commit X` | `range:X..WORKTREE` |

`uncommitted` is fixed to mean staged + unstaged + untracked, with `--no-untracked` to drop untracked files. This matches the docs and CodeRabbit (decision C6).

**Resolution.** Each scope resolves to `{baseOid?, head: Worktree | Index | Commit(oid), changedSet, hunks}`.
- **PR mode** uses `gh pr view --json baseRefOid,headRefOid,…`. When the head isn't local, it runs `git fetch --no-write-fetch-head origin pull/<n>/head`. That writes objects only and no refs, and is a declared effect Guard gates.
- **`since-last`** uses `audited.json`. If the last audited OID is not an ancestor (rebase or force-push), it falls back to a full merge-base review of the branch and says so.

**Materialization.** Bytes come from the head:
- `Worktree`: audit in place.
- `Index` or `Commit`: build a snapshot directory at `.legion-cache/snapshots/<tree>/` with `GIT_INDEX_FILE=<tmp> git read-tree <oid>` and then `checkout-index -a --prefix=`.

That method is pure git, works on Windows, and never touches the real index, HEAD or refs. It also avoids the workspace's no-worktree rule, so the unused `worktree.rs` stays unwired.

Whole-project providers (build, test) run in the snapshot with persistent caches. Dependency directories are linked from the working tree only when the head's lockfiles are byte-identical to the working tree's. Otherwise the provider records `unavailable:scope-materialization` and the run is `incomplete`; `--install` opts into installing them.

**Scope reaches the tools** through `ToolScope {paths, gitRange, manifestsChanged}`:
- Path-capable tools (semgrep/opengrep, eslint, ruff) receive the changed files.
- gitleaks runs `git --log-opts=<base>..<head>`, plus `dir` over dirty and untracked files only.
- Advisory tools run only when a manifest or lockfile changed. In diff modes they are otherwise recorded as `not-in-scope`, not as a gap.
- Whole-crate tools (clippy) run whole, and their diagnostics are bucketed into `changed-line`, `touched-file pre-existing` and `out-of-scope`. The diff verdict counts only the first bucket (decision C5).

**Path filter.** `--path` now narrows the inventory and the denominators in every mode. The report labels the scope and never says "whole repository".

### ADR-3 — `legion audit next`: a host-side driver for resumable waves

Lane A's static `lens-dispatch.json` stays as the **frozen plan**. A new command, `legion audit next --run <dir>`, reads the plan plus everything ingested so far and returns the next ready wave: seats, tiers, packet paths and the expected result paths. It returns `done` or `incomplete:<reasons>` when nothing is left.

The skill loop becomes: `next` → dispatch the wave (at most 16 seats in parallel) → one batch `ingest --result …` → repeat.

Adjudication rounds use the same driver:
1. batches;
2. confirmations and seeded spot-checks;
3. a per-candidate rerun of any voided batch, plus high-risk dismissals routed to individual review.

That satisfies Astra's conditions on resumable waves and on budgeting confirmation, spot-check and fallback work. Each seat's result must carry the host-attested context receipt; echoed context IDs never clear a gap.

Alternative rejected: SKILL prose orchestrating the rounds. That is the missing driver the inventory flagged.

### ADR-4 — One finding schema, three renderers, two new passes

**New passes.** No new lenses. Correctness stays the CodeRabbit fold and minimize stays the Ponytail lens.

**P-pos (deterministic positioning, the Alibaba approach).**
- Every anchor must resolve to a line range in the scoped file's bytes, with a hash of the line content.
- In diff modes the anchor is tagged `in-diff`, or `beyond-diff` when it is read-beyond-diff context.
- A failed anchor (line 0, out of range, hash mismatch) is downgraded to `possible` with a reason `position-failed`. It is never dropped silently.

**P-reflect (verifier).**
- Lens findings at medium severity or above, from the deep bundles, are re-checked against the code by a fresh context that is not the author. It runs batched, like adjudication.
- Tier: specialist (Sonnet/Sol 6.1), because a wrong "upheld" still compiles. Security findings keep lane B's judgment-tier adjudication.
- Outcomes:
  - upheld with a concrete failing input or situation (the Ponytail evidence rule) → **proven**;
  - upheld without one → **likely**;
  - disputed → **possible**.
- Deterministic tool findings with a verified anchor are **proven**.

**Confidence tiers (decision C4).**
- `auditStatus: findings` is driven by proven and likely findings.
- Possible findings are listed in their own section and as an `unresolvedPossible` count. High and critical possible findings route to adjudication; they don't stay parked.
- Graph-derived claims follow OpenQodex's floor semantics. In particular, "Zero callers never means unused."

**Blast-radius brief** (from the index; no model call).
- Per changed symbol or file: importers and 1–2 hop dependents, implementers where Blueprint has them, tests that import the file, and unknowns.
- Capped at 40 per list, with the cap stated.
- Included in every diff-mode bundle packet. This gives read-beyond-diff without each seat re-reading the repo.

**Renderers** (`--report audit|review|ponytail`), all from `report.json`:

| Report | Contents |
|---|---|
| **review** (CodeRabbit-style) | Walkthrough header: change summary, a mermaid sequence diagram only when the brief shows flow across 2 or more modules, and a deterministic effort estimate from changed lines, files and fan-in. Line-anchored comments with category, severity (Critical…Info) and a suggested fix. Pre-merge check table. `--format github-review` writes a review JSON file; posting it is a separate, user-authorized effect. |
| **ponytail** | Exact template: "What this change does:"; Must fix / Should fix / Nice to have, numbered; four parts per finding; verdict; "Lean: -N lines possible"; "Not checked:" (filled from the coverage ledger). Categories map to Bug / Risk / Scale / Missing test / Speed / Lean. The minimize tag set is aligned to delete / reuse / stdlib / native / yagni / merge / split / shrink. |
| **audit** | Today's report, plus the confidence tiers and the coverage ledger. |

**Repository config: `.legion/audit.yaml`** (created only on request).
- Noise profile `quiet | chill | assertive`. Ponytail intensity lite/full/ultra maps onto these.
- `path_filters`, and `path_instructions` (glob → text, injected into matching bundle packets).
- `pre_merge`: PR title and description, linked issue, docstring threshold and custom command checks, each `off | warning | error`. `error` produces a blocking finding.
- `learnings.scope`.
- Debt markers, default `shortcut:` and `ponytail:` (the second is unverified, so both are matched). The `debt_markers` scanner feeds a debt ledger section.

**Learnings.** `legion audit learn <findingId> --note … | --dismiss-reason …` appends to `.legion/audit-learnings.jsonl`, with scope recorded. Learnings are injected into path-matched packets. They may annotate or lower presentation severity, but never suppress security or safety findings or change `auditStatus` (invariant I5).

**Honest naming.** A checklist test (`claims_coderabbit_style`, `claims_ponytail_style`) asserts the research thresholds:
- CodeRabbit-style needs items 1, 2, 4, 5 and 7, plus pre-merge checks.
- Ponytail-style needs items 2, 3 and 4 and the exact template.

The renderer prints "inspired by" until that test passes on the installed build.

### ADR-5 — What to take from Alibaba open-code-review and OpenQodex

**Adopt:**

| Idea | Why |
|---|---|
| Deterministic front end (select, exclude generated/vendor, bundle, bind rules) | Lane A's bundles plus index classes already do this. Add review units that pair interface with implementation and i18n pairs, using index edges. |
| Reflection and positioning | ADR-4. |
| Blast-radius brief with confidence tags, named unknowns and caps | ADR-1 and ADR-4. |
| Coverage ledger and hard incomplete | Every planned stage ran. In diff modes every changed hunk appears in at least one seat packet (checked deterministically). Every scanner candidate is dispositioned (lane B). `incomplete` exits with code 2 and writes the unchecked items. |
| Separating proven, likely and possible | ADR-4. |
| Scanner findings filtered to changed lines in diff modes | ADR-2 buckets. |
| Toolset pruning | Read-beyond-diff seats get `legion index query importers|dependents|excerpt` with a call budget instead of free grep. Prune further from benchmark traces. |
| Benchmark suite with an A/A noise twin | ADR-6. |

**Reject:**

| Idea | Why |
|---|---|
| Single configured model | Legion routes by tier. |
| Trading recall for precision in the engine | Audit keeps recall. Noise profiles only control what is shown. |
| Session-only resume | The `next` driver plus content caches go further. |
| OpenTelemetry and an MCP server | Legion lifecycle events already cover this. An index MCP server can come later. |
| Auto-posting sticky CI comments | Publication needs the user's authorization. |
| Separate reviewer-process copy of the repo | The snapshot dir already serves this purpose. |

### ADR-6 — Benchmark gate

`legion/evals/audit-bench/` holds:
- small fixture repos as git bundles;
- 40+ planted-bug PRs (security, correctness, perf, lean) and 20+ clean changes;
- 3 repeats and an A/A twin.

It reports:
- recall and location recall;
- precision as a lower and upper bound;
- clean rate;
- tokens per tier;
- wall-clock time.

Un-ruled rows are never scored. A phase that touches reasoning must not drop recall below `baseline − A/A band`, and it must report its cost delta.

## 3. Inefficiency fixes, ranked by payoff

| # | Fix | Where | Phase |
|---|---|---|---|
| 1 | Drop `projection` from packets; one compact-JSON packet per bundle; excerpts built once from the shared cache | `mod.rs:620/715`, `ingest.rs write_lens_packets` | P0 (lane A) |
| 2 | Build plan and inventory once and reuse the size-gate packets | `audit.rs:1010/1039/1117`, `plan.rs:130/494` | P0 |
| 3 | Persistent build caches: per-repo `CARGO_TARGET_DIR` and ESLint/ruff caches under `.legion-cache/build/<toolchain-digest>/`; cargo runs through the host's RightKit cargo wrapper when declared; clippy runs once and is shared by `code.rust` and `legacy.quality.lint` | `legacy_checks/mod.rs:1448`, `code/tools.rs` | P2 |
| 4 | Parallel provider waves: dependency-ordered waves, bounded by `maxParallelism` (default min(cores/2, 8)); `serial` runs alone; one lock per target dir for compile-heavy providers; sync and async paths merged | `execution.rs:346/534` | P2 |
| 5 | Index-first walk, hashing via blob OIDs, cached triggers and churn | ADR-1 | P1 |
| 6 | Scope reaches the tools, plus snapshot materialization | ADR-2 | P3 |
| 7 | Scanner de-duplication, one owner per class: secrets = gitleaks (history range, plus `dir` on dirty files only); SAST = opengrep/semgrep, one provider; advisories = one per ecosystem (cargo-deny stays per decisions.md) with OSV merged by advisory-ID fingerprint at ingest | `registry.rs:317/344`, `producer.rs:536/885` | P2 |
| 8 | Batch ingest (`--result` repeated or `--dir`), `recompute_run` once, findings referenced by ID across report, execution, facts and SARIF | `audit.rs:891`, ingest | P0 |
| 9 | Host-side driver for adjudication confirmation and spot-check rounds | ADR-3 | P0 |
| 10 | Provider-result cache, honoring `cachePolicy` | ADR-1, C1 | P2 |
| 11 | Scoped audit-fix reruns: rerun = `range:<pre-fix snapshot>..WORKTREE`, limited to the providers and lenses whose findings were touched plus anything triggered by the edited files; unaffected results are reused by cache key; `skills/audit-fix` step 5 aligned with bundles | audit-fix SKILL | P3 |
| 12 | Disposable copy uses known digests, reflink/hardlink copies, and the full snapshot (not just the diff inventory) | `disposable_copy.rs:376-470` | P1 |
| 13 | `verify` against index digests | `verify.rs:258`, `lib.rs:2150` | P1 |

## 4. Invariants

- **I1.** The index is a cache. Deleting `.legion-cache/` changes nothing in the plan digest, the findings or `auditStatus`; only timing and cache-hit metadata differ. This is tested as a cold-versus-warm equivalence test.
- **I2. No false clean.** Unknowns, failed anchors, skipped stages, unavailable materialization and unrun advisory tools are gaps. Zero importers never means unused.
- **I3.** The report binds `scopeSpec`, base OID, head (OID, tree, or worktree digest), the snapshot key and the index schema version.
- **I4.** Whole-repo deterministic scanning and all security-candidate dispositions stay exhaustive (Astra D2). Diff modes label their scope and never claim to cover the whole repository.
- **I5.** Noise profiles and learnings affect presentation only. They never suppress safety or security findings or flip status to pass.
- **I6.** Audit doesn't modify the repo. There are no HEAD, index or ref writes. A PR fetch writes objects only, under Guard.
- **I7.** Packet bytes are a pure function of frozen inputs. A cache hit and a cold build produce the same packet digest.

## 5. Reconciliation with the scaled design and lanes A, B and C

**Stays as is:**
- risk-sampled coverage;
- strata, seed, `qualityGate: sampled` / `coverageMode`;
- bundles J1/J2/S1/S2/M1;
- lane B batched adjudication with Astra's conditions;
- lane C scanner capability classes;
- decisions.md's excerpt-mode overrides (architecture, doc-drift and minimize stay raw).

**Changes:**
- Coverage facts come from the index rather than recomputation.
- In diff and since-last modes the mandatory stratum is the changed set plus the blast-radius importers (capped).
- Lane B's clusters reuse index excerpt digests for their normalized sink digest.

**Lane A should adjust these before it finishes** (all small; none needs new dependencies):
1. Turn `gather_facts` into a seam that takes precomputed `churn` / `fan_in` / `size` maps (a `FactsSource`). Its current internal `git log` and `stat` calls become the fallback implementation.
2. Bundle packets carry `{inventoryDigest, snapshotRef}`, never `projection`.
3. Write compact JSON.
4. Build packets once and reuse the size-gate packets in `lens_work_items`.
5. Give every seat entry in `lens-dispatch.json` a stable `seatId` and `wave`, and add `state`-free ingest expectations, so `next` (ADR-3) can drive it without a schema change.
6. Put the content-digest excerpt dedup behind a function `excerpt_for(digest, mode, regions)` so the P1 cache can replace its body.
7. Align `skills/audit-fix/SKILL.md` step 5 with the bundles.

## 6. Delivery plan

Each phase ships and is checked on the installed Mac build. The Windows lead proves Windows separately.

**P0 — Lane A finish plus quick wins** (fixes 1, 2, 8 and 9, and the `next` driver).
- Tests: packet byte-equality before and after projection removal (except the projection field); batch ingest equals sequential ingest; the `next` state machine runs over synthetic adjudication with a voided-batch fallback.
- **Gate: the full Ember audit completes.** Status is honest (`sampled` or `exhaustive`), and seats, tokens and wall-clock are recorded as the baseline.

**P1 — The index** (ADR-1, fixes 5, 12 and 13), in parallel with the **benchmark corpus** (ADR-6).
- Tests: I1 cold-versus-warm equivalence; dirty, untracked and racy cases; extractor-version invalidation; a lexical-edge fixture per language (Rust, TS/JS, Python, Swift, Go) with expected confidence and unknowns; Blueprint-replacement fixture.
- Gate: warm Ember rerun with zero full-file re-reads of unchanged files (asserted by an I/O counter), an identical report digest, and benchmark A/A baseline recorded.

**P2 — Execution** (fixes 3, 4, 7 and 10).
- Tests: parallel-versus-serial report equivalence; a serial provider never overlaps another; cache keys change with tool version; dedupe keeps every location.
- Gate: Ember wall-clock against the P0 baseline; benchmark recall within the A/A band.

**P3 — Scope modes** (ADR-2, fix 11).
- Tests on fixture repos for every mode: changed set, bytes from the snapshot (a file differing between worktree and head), gitleaks range, `since-last` after a rebase, `--path` narrowing, `uncommitted` including staged and untracked; plus a Windows snapshot test.
- **Gate: a PR-mode run on an installed build** against a real Ember PR, or a `range:` run if Ember has no open PR; plus an audit-fix scoped rerun.

**P4 — Review profiles** (ADR-4 and ADR-5).
- Tests: positioning rejects line 0 and out-of-range anchors; reflection downgrades are never dropped; renderer golden files; learnings cannot suppress security findings; honest-claim checklist tests.
- Gate: benchmark precision lower bound improves with no recall loss beyond A/A; Ember PR run rendered in review and ponytail formats.

**Critical path:** P0 → P1 → P2 and P3 in parallel → P4. The benchmark runs alongside P1.

## 7. Decisions for Council/Astra

| ID | Decision | My recommendation |
|---|---|---|
| C1 | Cached provider results count as run evidence | Yes, for `content-addressed` providers only. The full key (ADR-1) is recorded as `reused:{fromRun,key}`, and `--fresh` forces reruns. Test/build providers are never reused. Release qualification uses `--fresh`. |
| C2 | A Legion-built lexical import graph, given Blueprint's rule "never substitute ad-hoc grep for graph evidence" | Allowed as ranking and brief **signals** labelled `source: lexical` with confidence. Never presented as Blueprint graph evidence. Blueprint edges win when fresh. |
| C3 | `/audit` takes over PR/diff review and the profile names | Reverse `engine-interface.md:8` and `manual.md:165`. One engine and one skill, no separate `/review`. The style names are gated by checklist tests. |
| C4 | Confidence tiers in the report contract | Proven and likely drive `findings`. Possible is listed separately. High and critical possible findings route to adjudication. Report schema version bump. |
| C5 | Diff-mode verdict and completeness | Measured against the changed scope. Pre-existing touched-file findings are reported but not counted. `since-last` carries prior findings forward, re-anchored by line hash. |
| C6 | `uncommitted` semantics | Fix to staged + unstaged + untracked, with `--no-untracked`. |
| C7 | Repo-committed `.legion/audit.yaml` and the learnings file | Created only on user request. Their scope is visible in the report. I5 holds. |

I could not establish:
- whether `legion-contracts` holds a versioned report schema (this affects how C4 bumps the version);
- whether rightkit-cache's API supports content keys without hidden TTLs (checked at P1 start);
- whether Ember has an open PR for the P3 gate;
- how the RightKit cargo wrapper handles an audit-owned `CARGO_TARGET_DIR` (read `docs/rules/rightkit.md` before P2).

Files read for this design:
- `docs/architecture/2026-10-15-scaled-audit-design.md`
- `docs/architecture/2026-10-15-audit-research/{alibaba-openqodex,coderabbit-ponytail,legion-audit-inefficiencies}.md`
- `engine/crates/legion-audit/src/native_providers/reasoning/coverage_plan.rs`
- `skills/architect/doctrine/architecture/{00-charter-significance-tailoring.md,methods/add.md,workflow/01-frame.md}`
- `<workspace>/decisions.md`