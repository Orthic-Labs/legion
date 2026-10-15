# Audit v2 design, amended (rev 2): index first, scoped runs, CodeRabbit- and Ponytail-style reviews

**Status (rev 2).** This is a significant D2 design, with the objective `optimize` on efficiency and review fidelity. It applies the binding Council adjudication `2026-10-15-audit-v2-council.md` (verdict REVISE, rulings C1–C8). Astra approved those rulings under Adrian's delegated-decision rule (`decisions.md:9-11`).

**Current state (rev 2).** It is read from the checkout at `265794df`. The rev-1 statements about uncommitted lanes no longer hold.
- Scaled-design lanes A, B and C are committed in `1b802f52..265794df`.
- `blueprint` is not on PATH on this Mac.
- The report contract validates version 1 only (`legion-contracts/src/report.rs:34,48`).
- `Finding` uses `deny_unknown_fields`.

## 0. How each ruling is applied (rev 2)

| Ruling | Applied in |
|---|---|
| C1 approve with changes | ADR-1 result identity and provenance, invariant I1, phase 5 |
| C2 approve with changes | ADR-1 graph identity, ADR-7 coverage-respecting replacement |
| C3 approve | ADR-4 behavioural acceptance; doctrine update in phase 3 |
| C4 approve with changes | ADR-4 status rules, ADR-8 report v2; phases 2 and 4 |
| C5 rejected and replaced | ADR-2 attribution, merge-base and baselines |
| C6 approve | ADR-2 scopes, including partially staged tests |
| C7 approve with changes | ADR-9 trust boundary |
| C8 approve with changes | ADR-7 Blueprint integration contract |

## 1. Frame (rev 2)

**Outcome.** One `/audit` engine that:
1. builds or refreshes a persistent index first;
2. runs on any scope, with an optional path filter;
3. renders audit, review and ponytail reports from one finding schema;
4. completes a whole-repo Ember audit, and a PR-mode run, on an installed build with truthful coverage.

**Quality drivers (rev 2).**

| ID | Scenario |
|---|---|
| Q1 Efficiency | On a warm rerun, Legion's index and excerpt layer reads no unchanged file and builds no packet twice. Provider I/O (scanners and builds re-read files) is measured and reported separately. It is not gated to zero. |
| Q2 Honesty | These are gaps, never clean: a missing stage, an unresolved edge, a failed required anchor, an unresolved material dispute, an unrun tool, unavailable isolation, an ambiguous merge-base. Some of them force `incomplete` (ADR-4). |
| Q3 Determinism | With or without `.legion-cache/`, the deterministic artifacts are byte-equal when their inputs are frozen. Those artifacts are the plan digest, inventory digest, packet digests, executed deterministic provider findings and the gap set. Model outputs are not required to be identical. |
| Q4 Scope fidelity | The bytes audited are the scoped revision's bytes. Tools see the same scope. |
| Q5 Cost | Each run has a total reasoning budget covering lenses, adjudication, reflection and walkthrough. Mechanical work runs on Haiku or Luna. |
| Q6 Portability | Mac and Windows are proven separately in phase 3. Git is the only snapshot mechanism. |

**T3 answer (rev 2).** Audit does not use RightKit fsearch, rightkit-fsindex or rightkit-search, now or in v2. The engine has no reference to any of them (grep of `engine/`). rightkit-fsindex incorporates fsearch code, but it is a whole-disk crawler: not git-aware, not content-addressed, not portable for repo trees. The Audit index uses git plumbing for enumeration and blob OIDs, plus rightkit-cache for content-addressed storage.

**RightKit reuse (rev 2).**

| Need | Owner | Decision |
|---|---|---|
| Object, excerpt and result storage | rightkit-cache **0.2.0** (size cap, LRU, pinning, atomic writes, `clear_group`, dead-PID temp sweep) | **Reuse.** It allows one writable cache per directory per process (`disk.rs:15`). Cross-process writes need a writer lease; see ADR-1 concurrency. **Extend the owner** with that lease rather than build a second lock. Phase 3 opens with an API-fit test: content keys, no hidden TTL, `pin`/`unpin` for live runs. |
| File index | rightkit-fsindex | **Rejected** (see T3). |
| Search | rightkit-search | Not used. |
| Code graph | Blueprint, an external pinned core/CLI | Optional input under the ADR-7 contract. Otherwise the labelled lexical floor. |
| Process sandbox (Windows) | Unknown | Run `rightkit owns process-sandbox` at the start of phase 3. Until an owner exists, Windows PR-code execution is `unavailable:isolation`. |

**Dependencies.**
- New crate `engine/crates/legion-index/` holds rightkit-cache, `sha2` and `serde`.
- `legion-audit` gains one path dependency.
- No tree-sitter, no SQLite. `runtime_capture.rs` is untouched.

**Storage location (rev 2).**
- The cache root is configurable: `--cache-dir`, env `LEGION_AUDIT_CACHE_DIR`, or `audit.cacheDir` in user config. The default is `<root>/.legion-cache/`, which is on `/Volumes/D` for workspace repos.
- If the resolved root is on the Mac internal volume, or on Windows `C:`, the engine emits a `cache.location.warning` lifecycle event and asks for an explicit root (`docs/rules/disk-hygiene.md`).

## 2. Decisions

### ADR-1 — Index first: a content-addressed cache with complete identities (rev 2)

**Decision (unchanged).** `IndexRefresh` runs once in `legion-application`. It produces an `IndexSnapshot` that is threaded through `NativeOperation::Audit` to the plan, providers, packets, verify and audit-fix. This removes the three walk/hash passes (`audit.rs:1010`, `legion-application/src/lib.rs:2175,2182`) and the three `compile_with_root` calls.

**Identities (rev 2).** Every key is the digest of a canonical record.

| Artifact | Key fields |
|---|---|
| `snapshots/<key>.json` | `headKind` (worktree / index / commit); head tree OID; dirty-set digest (path plus sha256 of every dirty or untracked byte stream); index schema version; exclusion config digest; path-filter digest; git version; platform record (OS, arch, case sensitivity, eol/filter attributes digest) |
| `objects/` (signatures, lexical imports, trigger matches, manifests) | `(sha256, extractorId, extractorVersion, extractorConfigDigest)`; trigger matches also carry the trigger-set digest |
| `graph/<key>.json` | snapshot key; extractor-set digest; resolver config digest (tsconfig paths, Cargo workspace, package maps); Blueprint provenance `{version, contractVersion, scopedBytesDigest, coveredFilesDigest}` when used |
| `history/` | Per-commit numstat only. The window is fixed and digested in the plan: first-parent from head, at most 2,000 commits or 365 days, whichever is smaller. Author records are deferred (an optional item). |
| `excerpts/` | `(sha256, mode, regionsDigest, redactionRulesetVersion)`. Only redacted bytes are stored. |
| `results/` (C1) | `providerId`, `providerVersion`, tool binary digest and version, **resolved rules digest** (rule files actually loaded after config resolution), resolved tool config digest, **advisory DB digest plus fetch time**, platform record, env allowlist digest (toolchain versions and relevant env vars), input denominator digest (exact files consumed), scope digest |

**Result reuse (C1).**
- Eligible results come only from deterministic providers with `cachePolicy: content-addressed`.
- Never reused: test, build or network-live providers, and any advisory result whose DB is older than 24 h.
- Every stored result carries provenance: producing run ID, execution-receipt digest, Legion binary digest and the result content digest. That record is written to durable run state, outside the cache. On reuse the cached bytes must match the recorded digest, or the entry counts as a miss.
- Reports list `executed` and `reused{fromRun,key}` separately in the header and the coverage ledger.
- `--fresh` forces every provider to run. Release qualification always uses `--fresh`.

**Durable run state (rev 2).**
- `audited.json` leaves the cache. It becomes `<root>/.audit/state/audited.jsonl`, under the existing run directory root from `skills/audit/SKILL.md:51`.
- It is append-only. Each entry is `{scopeKey, headOid, mergeBaseOid?, planDigest, reportDigest, reportPath, findingFingerprints[], prevEntryDigest}`.
- Deleting `.legion-cache/` never changes `since-last` resolution.

**Worktree cleanliness (rev 2).** `git ls-files -s` alone does not establish cleanliness, so these rules apply:
- **Change set.** Computed with `git status --porcelain=v2 -z --untracked-files=all`, with optional locks off (ADR-2).
- **Re-hashed every run** with `git hash-object --no-filters --stdin-paths` (no `-w`):
  - paths with `assume-unchanged` or `skip-worktree` bits (`ls-files -v`);
  - racy entries, where the file mtime is at or after the index mtime;
  - paths with smudge, eol or filter attributes. Worktree sha256 is computed over the worktree bytes.
- **fsmonitor** is disabled (`-c core.fsmonitor=false`).
- **Special entries:**
  - submodules are recorded as `submodule` and are not traversed (gap);
  - LFS pointers are audited as pointer bytes (gap `lfs-pointer`);
  - symlinks are recorded by target and never followed.

**Concurrency and crash recovery (rev 2).**
- One writer per cache root. It holds `.legion-cache/LOCK`, an OS advisory lock (flock or LockFileEx) recording PID, host and start time.
- Readers open with `DiskCache::open_read_only`.
- A second audit waits at most 30 s. It then runs in **read-only cache mode**: misses are computed in memory and not persisted, and the report records this.
- A lease held by a dead PID is broken.
- Snapshot manifests and graphs are written to a temp path, fsynced, then renamed. Each manifest embeds its own digest. A manifest that fails verification is discarded and rebuilt, which is safe because the index is a cache.
- Until rightkit-cache ships the lease, Legion holds the lock in `legion-index/src/lock.rs` behind a trait.

**Storage caps, eviction and retention (rev 2).**

| Class | Default cap | Policy |
|---|---|---|
| objects, excerpts, results | 2 GiB | LRU |
| snapshots | 10 GiB | LRU |
| build caches (phase 5) | 20 GiB | LRU |

- Entries used by a live run are pinned.
- Changing the redaction ruleset clears the old ruleset's excerpt group at once.
- Excerpt groups unused for 14 days are cleared at open.
- `legion audit cache status|prune` reports bytes, hits, misses and evictions per class. Each run records the same metrics in its execution record.

**Invalidation (unchanged).** Changes come from blob OIDs plus the rules above. Mtime is never the sole test. New extractor versions re-extract lazily.

### ADR-2 — One `ScopeSpec`: scoped bytes, merge-base and attribution (rev 2)

**Grammar and aliases (unchanged).**
- Scopes: `repo | pr:<n|url> | range:A..B | commit:<sha> | branch[:<base>] | staged | uncommitted | local | since-last`, plus `--path <glob>`.
- Aliases: `all`→`repo`, `committed`→`commit:HEAD`, `--base B`→`branch:B`, `--base-commit X`→`range:X..WORKTREE`.

**`uncommitted` (C6).**
- It means staged, unstaged and untracked. This is a deliberate behaviour change: CodeRabbit excludes untracked files by default.
- `--no-untracked` drops untracked files.
- There is no unstaged-only scope; use `--path` or `staged`.
- The behaviour change is documented in phase 3.

**Staged resolution (rev 2).**
- Bytes come from stage-0 entries of `git ls-files -s -z`, streamed with `git cat-file --batch`. There is no `write-tree` and no object writes.
- Unmerged entries (stages 1–3) give `incomplete:unmerged-index`.
- Intent-to-add entries count as untracked, not staged.
- **Partially staged files:**

| Scope | Bytes | Hunks |
|---|---|---|
| `staged` | the index blob | `diff --cached` |
| `uncommitted` | the worktree bytes | `diff HEAD` |

  Tests cover each combination of staged, unstaged and untracked states for one path.

**PR resolution and merge-base (rev 2).**
- Run `gh pr view --json baseRefOid,headRefOid,baseRefName,isCrossRepository`.
- The review base is `git merge-base baseRefOid headRefOid`, which is GitHub's three-dot diff, not the base branch tip.
- The report records both `baseRefOid` and `mergeBaseOid`.
- More than one merge base (`--all`) gives `incomplete:ambiguous-merge-base`, unless the user passes `--base-oid`.
- The head is captured once. The report binds that OID, and a later head change is reported as stale, never silently followed.

**PR acquisition failures (rev 2).** All of these give `blocked` (the existing `ReportStatus::Blocked`), with cause and exit code 3:
- `gh` missing or unauthenticated;
- network failure;
- head unreachable (for example a deleted fork);
- OIDs not obtainable.

The engine never falls back to a local branch or another scope on its own.

**Git controls (rev 2).** Every git call goes through `legion-index::git::GitRunner`, which sets:
- `GIT_OPTIONAL_LOCKS=0` and `--no-optional-locks`;
- `GIT_TERMINAL_PROMPT=0`;
- `-c core.fsmonitor=false` and `-c gc.auto=0`.

PR fetch is `git fetch --no-tags --no-write-fetch-head --refmap= --no-recurse-submodules --no-auto-maintenance origin pull/<n>/head`. It has no destination refspec, so no ref or tag is updated. Guard gates it as an object-only declared effect, and the fetched OID is used directly.

A test asserts that refs, packed-refs, `HEAD`, `FETCH_HEAD` and the index digest are byte-identical before and after every scope. Flag availability is checked against the installed git (`git fetch -h`) at phase-3 start; this item is unverified until then.

**Materialization and snapshot lifecycle (rev 2).**

| Head kind | Bytes |
|---|---|
| Worktree | audited in place |
| Index or commit | streamed with `cat-file --batch` into `.legion-cache/snapshots/<treeOid>/` |

- No temp index, no `read-tree`, no worktree.
- Snapshots are built in `.tmp-<pid>-<seq>/`, renamed atomically, and made read-only (0444, or the Windows read-only attribute).
- Each snapshot is held by the run's lease. Unleased snapshots are LRU-evicted under the cap. Temp dirs with dead owners are swept at open.
- **No hardlinks or writable links into the source tree, ever.** Dependency directories are offered only as copy-on-write clones (APFS `clonefile`, ReFS block clone), and only when lockfiles are byte-identical. Otherwise the provider records `unavailable:scope-materialization` and the run is `incomplete`.
- `--install` is allowed only inside isolated execution (ADR-9). Install is never automatic.

**Tool scope (unchanged).** `ToolScope {paths, gitRange, manifestsChanged}` works as in rev 1:
- gitleaks uses the history range plus `dir` over dirty files only;
- advisory tools run when a manifest or lockfile changed, and are otherwise `not-in-scope`.

**Diff-mode attribution (rev 2; replaces C5).** The diff verdict counts every finding caused by the change, including findings at unchanged locations. Each finding gets an `attribution`:

| Attribution | When | Counted in verdict? |
|---|---|---|
| `introduced` | Anchored on a changed line | Yes |
| `regressed-elsewhere` | At an unchanged location, but either absent from the base-side result of the same provider and rule at `mergeBaseOid` (deterministic providers run on both sides; whole-crate tools like clippy run on both snapshots), or tied by a seat to a changed symbol through the blast-radius brief (callers, implementers, tests) | Yes |
| `pre-existing` | Fingerprint matched in base-side evidence | No; reported in its own section |
| `unresolved` | Base evidence unavailable, or re-anchoring `ambiguous` or `lost` | Yes; never silently excluded |

A finding is excluded only when it is established as pre-existing.

**Re-anchoring states.** `matched`, `moved` (same line-hash window, new range), `ambiguous` (more than one candidate) and `lost`. Carry-forward for `since-last` (phase 5) uses these states and the durable baseline in `audited.jsonl`.

**`since-last` (rev 2).**
- It resolves to `range:<last headOid>..WORKTREE` from durable state.
- If that OID is not an ancestor, it falls back to a merge-base review of the branch and says so.

### ADR-3 — `legion audit next` driver with termination (rev 2)

- `next --run <dir>` is a pure function of the frozen plan plus ingested results. Repeated calls return the same wave until results arrive.
- Each wave issues seat leases. A seat with no result when its lease expires (default 20 min) is reissued, and that counts as an attempt.

**Limits.**

| Item | Limit |
|---|---|
| Seat attempts | 2 |
| Adjudication rounds | 3 (batches; confirmations and seeded spot-checks; per-candidate rerun of voided batches plus high-risk dismissals) |
| Voided-batch reruns | 1 per candidate |
| Total `next` issuances | `2×seats + 3×adjudicationCandidates` |

Hitting any limit ends the run as `incomplete:retry-exhausted`, listing the items. `next` returns `done`, `incomplete:<reasons>` or `budget-exhausted`. The host-attested context receipt is still required.

**Reasoning budget (rev 2).**
- The plan freezes `reasoningBudget {judgment, specialist, mechanical, maxSeats}` covering lens bundles, adjudication, reflection and walkthrough.
- Reflection may use at most 25% of the specialist budget. Candidates are ordered security first, then severity.
- Findings that are never reflected stay `likely` and add the gap `reflection:budget`.
- Exhausting the adjudication budget with unresolved material disputes forces `incomplete`.

### ADR-4 — One finding schema, three renderers, two passes, honest status (rev 2)

**P-pos (positioning).**
- Every anchor resolves to a line range in the scoped bytes, with a line-content hash.
- Diff modes tag anchors `in-diff` or `beyond-diff`.
- A failed anchor (line 0, out of range, or hash mismatch) is marked `position-failed`.

**P-reflect (verification).**
- A fresh, non-author specialist context (Sonnet / Sol 6.1) re-checks findings from deep bundles at medium severity or above.
- Security findings keep lane B's judgment-tier adjudication.

**Confidence (C4).**

| Tier | Requires |
|---|---|
| `proven` | A semantic justification: either reflection upheld the finding with a concrete failing input or situation (Ponytail's evidence rule), or the provider declares `exactness: exact` for that rule class (compiler error, exact advisory version match, verified secret) and the anchor is verified |
| `likely` | An anchored tool hit without exactness, or reflection upheld without a concrete case |
| `possible` | Disputed, or `position-failed` |

An anchored tool hit is never `proven` on location alone.

**Status rules (C4; rev 2).**
- `incomplete` is forced when any of these holds:
  - a **required anchor** failed (any finding at medium or above, or any security finding);
  - a **material dispute** is unresolved (a high or critical finding disputed by reflection or adjudication and not closed within the round limits);
  - any coverage-ledger gap is mandatory.
- Otherwise, `findings` is driven by `proven` plus `likely`.
- `possible` findings appear in their own section and in the `unresolvedPossible` count. High and critical possibles route to adjudication.
- Reflection can lower confidence only by recording its evidence. It can never remove a finding's weight without resolving it.
- Graph claims follow floor semantics: zero callers never means unused.

**Blast-radius brief (unchanged).** It covers importers, 1–2 hop dependents, implementers, tests and unknowns, capped at 40 per list with the cap stated. It is included in diff-mode bundle packets and feeds `regressed-elsewhere`.

**Renderers (`--report audit|review|ponytail`).** These are as in rev 1:
- **review:** walkthrough with conditional mermaid diagram, deterministic effort estimate, line comments with fixes, pre-merge table, and `--format github-review` as a file (posting it is a separate, user-authorized effect);
- **ponytail:** the exact template, with "Not checked:" filled from the ledger; both marker conventions are recognized;
- **audit:** today's report plus confidence tiers and the coverage ledger.

**Behavioural acceptance (C3; rev 2).** Renderer goldens are necessary but not sufficient. A style name is printed only after both its benchmark gate and its checklist test (`claims_coderabbit_style`, `claims_ponytail_style`) pass on the installed build. Until then the renderer prints "inspired by".

| Style | Benchmark gate |
|---|---|
| CodeRabbit-style | Detects planted regressions in unchanged callers (read-beyond-diff), produces walkthrough and pre-merge checks, and line comments carry fixes |
| Ponytail-style | Reviews connected code, and every must-fix carries a concrete case |

### ADR-5 — Adopt and reject from Alibaba open-code-review and OpenQodex (unchanged)

The adopt and reject lists are as in rev 1. The coverage ledger now includes `reused` versus `executed`, attribution, and isolation gaps.

### ADR-6 — Benchmark gate, baselines and A/A (rev 2)

- **Location.** `legion/evals/audit-bench/` holds fixtures as git bundles. Each reasoning-touching gate uses 3 repeats plus an A/A twin.
- **Corpus size.** Calibrated, not fixed. The seed holds planted regressions, including caller regressions in unchanged files, plus clean changes. It grows until the A/A recall band half-width is 10 percentage points or less.
- **Baseline.** The baseline is the phase-1 engine at `265794df`, measured before any change.
- **Pass rule.** Recall must stay at or above `baseline − A/A band`, and the cost delta per tier is reported.
- **Exclusions.** Un-ruled rows are never scored.

### ADR-7 — Blueprint integration contract (C8; new in rev 2)

**Ownership.**
- Blueprint is extracted as one versioned core and CLI. Membrane pins it.
- Legion declares the optional host capability `blueprint-graph`, with a compatible version range in `src/registry/capabilities.json`. Its degradation is the labelled lexical floor.
- A resident transport is not a prerequisite.
- The extraction runs as its own track, owned by the Membrane/Blueprint owner, and does not gate any Audit phase.

**Invocation.** `blueprint graph export --contract legion-graph/1 --root <dir> --scoped-bytes <manifest.json> --out <file>`. The manifest maps each path to its sha256, taken from Legion's snapshot.

**Output contract (`legion-graph/1`).**
- `contractVersion`, `blueprintVersion`, `scopedBytesDigest` (echoed);
- `coverage {files[], languages[], unsupported[{path,cause}]}`;
- `nodes[{id, kind: file|symbol|test, path, range}]`;
- `edges[{from, to, kind: imports|calls|implements|tests, confidence: certain|likely|possible, evidence}]`;
- `unknowns[{location, cause}]`.

Exit codes: 0 ok, 2 partial (coverage lists the gaps), anything else unavailable.

**Freshness and use.**
- The output is accepted only when its `scopedBytesDigest` equals Legion's digest over the covered files.
- Otherwise Legion records gap `blueprint-stale` and uses the lexical floor.
- Blueprint edges replace lexical edges **only for files in `coverage.files`**.
- Every edge keeps its `source: blueprint|lexical` label.
- Graph-dependent claims ("unused", "no callers", "safe to delete") stay `possible` or unproven unless `certain` edges cover the whole relevant set.

### ADR-8 — Report schema v2 and compatible readers (C4; new in rev 2)

- **New types.** `legion-contracts/src/report.rs` gains `ReportV2` and `FindingV2`. Additions:
  - per finding: `confidence`, `confidenceBasis`, `anchor {path, range, lineHash, state}`, `attribution`, `disposition: executed|reused`;
  - per report: `scope {spec, baseRefOid?, mergeBaseOid?, head, snapshotKey, indexSchemaVersion}`, `unresolvedPossible`, `reasoningBudgetUsed`.
- **Writers** emit v2 from phase 2.
- **Readers.** `deserialize_schema_version_1_or_2` and `Report::read_any` read v1 as a v2 view: confidence `legacy-unknown`, attribution `legacy`, status preserved. Audit-fix, verify and SARIF export move to `read_any`.
- **v1 compatibility.** `--report-schema 1` writes a v1 projection for consumers pinned to v1. Because `Finding` denies unknown fields, the v2-only fields go under `finding.evidence` keys, which is allowed because it is a `BTreeMap`. Status is identical in both.
- **Tests.**
  - a golden v1 fixture parses through `read_any`;
  - a v2 report written as v1 passes the v1 `validate()`;
  - a v2 report written as v1 and read back through `read_any` gives the same digest for its v2-only fields.

### ADR-9 — Trust boundary for configuration and code execution (C7; new in rev 2)

- **Request-driven files.** `.legion/audit.yaml` and `.legion/audit-learnings.jsonl` are created only on user request.
- **Config source.** Executable config is read from **trusted policy**: user-level config plus the config at `mergeBaseOid`. PR-head config is data only. Path instructions and noise profile are validated (at most 32 entries, 4 KB each) and injected into packets as quoted, labelled data. Neither can change severity, status or authority.
- **Custom commands.** PR-controlled config **never grants execution authority**. `pre_merge` custom commands come only from trusted policy, run under Guard, and run isolated whenever the scoped bytes are not the user's own worktree.
- **PR code execution.** For `pr`, and for `range` or `commit` heads not reachable from a local branch, every provider that executes code is a PR-code execution. That includes build, test, clippy (`build.rs`, proc macros), installs and package scripts. These run only inside isolated execution:
  - **Mac:** the existing audit sandbox profile (`.legion-cache/audit-sandbox/profile.sb`, created at `inventory.rs:1226`), extended with no network except the declared registry for `--install`, no writes outside the snapshot and build cache, and no credential env;
  - **Windows:** no isolation exists yet, so these providers are `unavailable:isolation` and the run is `incomplete`.
- **Not allowed:** dependency installs outside isolation, automatic installs, and writable hardlinks into the source tree.
- **Learnings** may annotate or lower presentation only. They preserve the original severity and status and never touch security or safety findings (I5).
- **Config size (phase 5).** v2 ships the minimal config: noise profile, path filters and instructions, `pre_merge` off/warning/error. The debt ledger is optional.

## 3. Inefficiency fixes, by phase (rev 2)

| # | Fix | Where | Phase |
|---|---|---|---|
| 1 | Drop `projection`; one compact-JSON packet per bundle; excerpts built once | `mod.rs:620/715`, `ingest.rs write_lens_packets` | 2 |
| 2 | Build plan and inventory once; reuse size-gate packets | `audit.rs:1010/1039/1117`, `plan.rs:130/494` | 2 |
| 8 | Batch ingest; `recompute_run` once | `audit.rs:891`, ingest | 2 |
| 9 | `next` driver, including adjudication rounds | ADR-3 | 2 |
| 5 | Index-first walk; blob-OID hashing; cached triggers and churn | ADR-1 | 3 |
| 6 | Scope reaches the tools; materialization | ADR-2 | 3 |
| 13 | `verify` against index digests | `verify.rs:258`, `lib.rs:2150` | 3 |
| 3 | Persistent build caches through the RightKit cargo wrapper | `legacy_checks/mod.rs:1448`, `code/tools.rs` | 5 |
| 4 | Parallel provider waves | `execution.rs:346/534` | 5 |
| 7 | Scanner de-duplication | `registry.rs:317/344`, `producer.rs:536/885` | 5 |
| 10 | Provider-result cache (C1) | ADR-1 | 5 |
| 11 | Selective audit-fix reruns | audit-fix SKILL | 5 |
| 12 | Disposable copy from known digests, copy-on-write only (no hardlinks) | `disposable_copy.rs:376-470` | 5 |

## 4. Invariants (rev 2)

- **I1.** Deleting `.legion-cache/` leaves every Q3 deterministic artifact byte-equal and leaves durable state untouched. The cold-versus-warm test compares deterministic artifacts only, with frozen inputs and `--fresh` for providers.
- **I2.** No false clean. The Q2 conditions are gaps. Failed required anchors and unresolved material disputes force `incomplete`. Zero importers never means unused.
- **I3.** Reports bind the scope spec, `baseRefOid`, `mergeBaseOid`, head, snapshot key, index schema, and the executed-versus-reused split.
- **I4.** Whole-repo deterministic scanning and security dispositions stay exhaustive. Diff modes label their scope.
- **I5.** Noise profiles, config and learnings affect presentation only.
- **I6.** No HEAD, index, ref, tag or `FETCH_HEAD` writes. The PR fetch writes objects only, under Guard. All git calls run with optional locks off. No writable links into the source.
- **I7.** Packet bytes are a pure function of frozen inputs.
- **I8.** PR-controlled code and config never execute outside isolation, and never grant authority.
- **I9.** Incremental baselines live in durable run state and are digest-chained.

## 5. Reconciliation with the scaled design (rev 2)

These carry over unchanged from lanes A, B and C (`1b802f52..265794df`):
- risk-sampled coverage with its labelled sampling approval (`decisions.md:25`);
- strata and seed;
- bundles J1/J2/S1/S2/M1;
- lane B batched adjudication;
- lane C capability classes;
- the excerpt-mode overrides.

The rev-1 "lane A should adjust" items are now phase-2 work:
- a `FactsSource` seam;
- `{inventoryDigest, snapshotRef}` in packets;
- compact JSON;
- packets built once;
- `seatId` and `wave` in `lens-dispatch.json`;
- `excerpt_for(digest, mode, regions)`;
- audit-fix step 5 aligned with bundles.

In diff modes, the mandatory stratum is the changed set plus capped blast-radius importers. The cap is stated, and capped-out importers become a gap.

## 6. Delivery plan (rev 2)

Every gate is proven on the installed Mac build. Phase 3 also requires Windows proof from the Windows lead, by `win`. Haiku means `legion:alchemist`; Sonnet means `legion:alchemist-specialist`, with the reason stated.

### Phase 1 — Freeze, baseline evidence, benchmark seed

**Work.**
- Commit this rev-2 design; C1–C8 are already recorded at `decisions.md:9`.
- **Baseline.** Run the Ember audit on the installed build at `265794df` and capture:
  - wall-clock, seat count, and tokens per tier;
  - packet bytes;
  - Legion process I/O (rightkit-child-process `ProcessUsage`);
  - walk/hash pass count, from a temporary trace;
  - whether it completes, as the pre-change reproduction.
- **Benchmark seed.** Create `evals/audit-bench/`: fixture bundles, a runner (`legion-dev audit-bench`), A/A twin scoring, and recall and precision bounds.

**Who.** Haiku: baseline capture, fixture packaging, runner plumbing. Sonnet: authoring planted bugs, including caller regressions; a wrong plant passes silently.

**Gate.** Baseline numbers recorded in the run evidence. A/A band computed on the seed corpus.

### Phase 2 — P0 closure plus installed Ember completion

**Work.**
- Fixes 1, 2, 8 and 9.
- New `legion-audit/src/next.rs`, with the CLI in `legion-application`.
- `seatId` and `wave` in `lens-dispatch.json`.
- Report v2 (ADR-8) in `legion-contracts/src/report.rs` and `lib.rs`, plus the v1 projection writer.
- Deterministic anchor-range validation, with the required-anchor and material-dispute status rules (ADR-4).
- `reasoningBudget` in the plan.

**Tests.**
- Packet bytes are equal before and after projection removal, apart from that field.
- Batch ingest equals sequential ingest.
- `next` state machine: idempotence, lease expiry, the two-attempt limit, voided-batch fallback, `retry-exhausted`, `budget-exhausted`.
- The ADR-8 compatibility tests.
- A failed medium anchor never yields `clean` or `findings`.

**Who.** Haiku: projection removal, compact JSON, batch ingest, single build. Sonnet: the `next` state machine (concurrency, termination) and the report v2 migration (spec-bound contract).

**Gate.** The full Ember audit completes on the installed build with honest status and coverage ledger. Deltas against the phase-1 baseline are reported.

### Phase 3 — Minimal persistent index plus core scopes, Mac and Windows

**Work.**
- `legion-index`: `git.rs` (GitRunner), `snapshot.rs`, `objects.rs`, `graph.rs` (lexical), `history.rs`, `lock.rs`, `store.rs`.
- Scope handling in `legion-audit`: `scope.rs` (resolution, merge-base, PR acquisition), `materialize.rs`, `ToolScope`, base-side runs for attribution.
- Durable state `.audit/state/audited.jsonl`; `since-last` without carry-forward.
- Fixes 5, 6 and 13.
- Doctrine updates for C3: `engine-interface.md:8` and `manual.md:165`. Document the C6 behaviour change.
- The rightkit-cache API-fit test. File a writer-lease extension request to RightKit.

**Tests.**
- Cold-versus-warm equality of deterministic artifacts.
- Racy, assume-unchanged, filtered and LFS paths.
- Partially staged files in `staged` versus `uncommitted`.
- Unmerged index gives `incomplete`.
- Ambiguous merge-base gives `incomplete`.
- PR acquisition failures give `blocked` with exit 3.
- Refs, index and `FETCH_HEAD` byte-identical after every scope.
- Concurrent writers: second process goes read-only; stale lease broken.
- Crash mid-snapshot recovers.
- Eviction under the cap.
- Cache deletion keeps `since-last`.
- `regressed-elsewhere` fixture; `unresolved` counted.
- Per-language lexical edges with unknowns.
- Isolation absent on Windows gives `unavailable:isolation`.

**Who.** Haiku: snapshot and objects plumbing, history, fixture repos, Windows test runs. Sonnet: GitRunner and fetch controls, the lock and crash recovery, attribution and merge-base (each would compile while wrong).

**Gate.** All mode fixtures pass on Mac and on Windows. A warm Ember rerun shows zero index/excerpt re-reads of unchanged files, measured by an I/O counter, with provider I/O reported separately.

### Phase 4 — Semantic verification, renderers, installed PR acceptance

**Work.**
- P-pos line-hash positioning and P-reflect, with budgets.
- Confidence tiers under the C4 rules.
- Blast-radius brief.
- The review and ponytail renderers, with style gating.

**Tests.**
- Positioning rejects line 0, out-of-range and hash-mismatch anchors.
- Disputed high findings force `incomplete` when unresolved.
- An anchored hit without exactness is `likely`.
- Renderer goldens.
- Honest-claim checklist tests.
- Behavioural benchmark gates (ADR-4).

**Who.** Sonnet: reflection prompts and verdict mapping, positioning. Haiku: renderers and goldens.

**Gate.**
- Benchmark recall stays within the A/A band of baseline, and the precision lower bound improves.
- A real Ember PR (or `range:` if Ember has none) runs on the installed build and renders as audit, review and ponytail.
- Style names are printed only if the behavioural gates passed.

### Phase 5 — Measured execution optimisations and optional surface

**Work.**
- Fixes 3, 4, 7, 10, 11 and 12.
- C1 result reuse with provenance.
- Minimal `.legion/audit.yaml` and learnings (ADR-9).
- `since-last` carry-forward with re-anchoring states.

**Before starting.** Read `docs/rules/rightkit.md` for the cargo wrapper and `CARGO_TARGET_DIR`.

**Tests.**
- Parallel and serial runs give equal deterministic artifacts.
- A serial provider never overlaps another.
- Cache keys change with tool version, rules, DB age and platform.
- A reused result is labelled; `--fresh` reruns it.
- PR-head config cannot run commands.
- Learnings cannot suppress or change status.

**Who.** Haiku: waves, dedupe, config parsing. Sonnet: result-cache identity and provenance, isolation profile.

**Gate.** Ember wall-clock and tokens improve against the phase-2 numbers, with recall within the A/A band. Each optimisation keeps its measured gain or is reverted.

**Critical path.** 1 → 2 → 3 → 4 → 5. Phase-3 index and scope work may start as soon as the snapshot and `ToolScope` contracts are settled during phase 2. The Blueprint extraction track runs separately against ADR-7.

## 7. Open items (rev 2)

| Item | Unknown | Where it is settled |
|---|---|---|
| Windows isolation owner | Unknown; `unavailable:isolation` until resolved | Phase 3, `rightkit owns process-sandbox` |
| rightkit-cache cross-process writer lease | Must be extended in RightKit | Phase 3 |
| Ember open PR | Unknown | Phase 4 gate |
| RightKit cargo wrapper with an audit-owned target dir | Unknown | Phase 5 |
| Fetch flags (`--no-auto-maintenance`, `--refmap=`) on installed git, Mac and Windows | Unverified | Phase-3 start |