# Scaled full-repo audit design (Sage, 2026-10-15)

> **Superseded execution proposal.** The limits and selection details below record the original design,
> not current runtime behavior. Current Audit preserves the full applicable provider/lens/path universe,
> selects a bounded risk-sampled subset, records deferred mandatory paths as explicit incomplete gaps,
> and keeps explicit exhaustive mode strict. For the requested bounded Ember run, reasoning admission
> is capped at 50,000 total tokens across input and output, 10,000 total tokens per physical model call
> (including at most 2,500 output tokens), at most five calls, and width one, with at most four author
> calls and at least one reserved fresh verification call. These are run-scoped caps, not general CLI
> defaults. Deterministic gathering has no model-call floor; optional cheap gathering is admitted only
> when needed. See
> [`skills/audit/references/execution-contract.md`](../../skills/audit/references/execution-contract.md)
> and [`skills/audit/references/lens-routing.md`](../../skills/audit/references/lens-routing.md) for
> normative behavior.

Approved with changes by Astra under Adrian's delegated-decision rule; see workspace `decisions.md` (D1 batched adjudication, D2 risk-sampled coverage). Astra's conditions override the design where they differ.

## Diagnosis

- **Why the packet count explodes.** Every reasoning lens partitions its entire denominator into 512 KiB parts (`excerpts.rs` `MAX_TOTAL_EXCERPT_BYTES`, `partition_excerpts_scoped`, part ceiling `DEFAULT_MAX_PARTS=400`). Each part becomes one seat. Twelve raw lenses each re-read about 14.5 MiB of the same text, which is roughly 3.6M tokens per lens.
- **Why it can never close.** `lens_size_report` (`ingest.rs:2063`) only refuses when a single part exceeds the per-seat budget. It never caps total seats or total tokens, so a 280-seat plan freezes.
- **Why a subset can't count.** `merge_parts` (`ingest.rs:1381`) holds coverage incomplete until every part covers the whole denominator.
- **Security adjudication.** `adjudication_work_items` (`security_adjudication.rs:825`) creates one child packet per candidate. The docs (`execution-contract.md` ~L89, `provider-architecture.md` ~L117) require one fresh Oracle context per child.

There is no bounded "complete" anywhere in this design. The fix is to freeze a bounded coverage plan up front and judge completeness against that plan.

## 1. Lens coverage contract

**What "full audit" means.**
- **Deterministic providers:** every inventory path, with no change to today's behaviour.
- **Breadth lens:** every source path once, at a cheap tier, on skeleton excerpts.
- **Deep lenses:** a frozen review set chosen by risk, plus a seeded random sample of the rest.
- A run is `complete` when every unit of that frozen plan was ingested. It never claims that every lens judged every line.

**The review set**, frozen into each lens provider's plan configuration and covered by the plan digest:
1. **Mandatory stratum, reviewed exhaustively.** Entrypoints (bins, `main`, route/handler/command registries, the Tauri/IPC surface), security-sensitive paths (auth, crypto, IPC, deserialization, network, shell exec, signing), files changed since the base commit, and the top-N files by churn (from read-only `git log --numstat`).
2. **Hotspot stratum, reviewed exhaustively up to the budget.** Files ranked by a score: churn, plus fan-in, plus size, plus the density of findings from the deterministic providers.
3. **Remainder stratum, sampled.** The sample is ordered by `sha256(planDigest ‖ path)` so it is reproducible and can't be cherry-picked. Its size is whatever budget is left, with a floor of `min(30, |stratum|)`.

**Findings density.** Deterministic findings exist before packets are built, because packets are built after execution (`scanner_candidates_from_execution`). They can only promote files into the review set, never remove them. Packets record that promotion bound to the execution-report digest.

**Excerpt compression.**
- Add a third excerpt mode, `Regions`, next to Raw and Skeleton. It reuses `hunk_windows` (`excerpts.rs:53`) to produce the file's signature skeleton plus raw windows (±20 lines) around:
  - deterministic findings,
  - changed hunks,
  - entrypoint and sink symbols.
- Deep lenses use Raw only for the mandatory stratum and Regions for everything else.
- Files with identical content are excerpted once, and coverage is credited to every path that shares that digest.
- Generated, vendored, lock and minified files are left out of lens denominators. They stay in the deterministic denominators.

**Per-lens budgets.** Each lens gets a share of the run's token budget (section 2) instead of the single global constant.

**Status semantics.**
- `merge_parts` and `packet_coverage` compute `expected` against the review set. Paths outside it are recorded as `declaredUnsampled`, not as gaps.
- A review-set path that wasn't examined is still a gap, and the run is still `incomplete`.
- New report claim `lensCoverage`, per lens: `{mode: "exhaustive"|"risk-sampled", denominator, reviewSet, examined, strata:[{name, N, n, findings, confidence}]}`.
- `auditStatus` keeps its three values (`pass|findings|incomplete`).
- `qualityGate` gains `sampled`. A clean sampled run reports `qualityGate: "sampled"`, never `proven`.
- **Confidence statement** for each sampled stratum: with zero findings at high severity or above in n reviewed files, the 95% upper bound on the share of affected files is 3/n (the rule of three). When there are findings, report the Clopper-Pearson interval.
- `--coverage exhaustive` is still available. It fails the size gate up front when it can't fit, instead of freezing an incomplete run.
- Default is `--coverage auto`: exhaustive if it fits, risk-sampled otherwise.

Alternative considered: a single-stage uniform random sample. It's simpler, but it spends the budget on low-risk files.

## 2. Seat budgeting

**Bundled seats.** One seat reads one excerpt part once and answers several lenses that share an excerpt mode. It writes one result file per provider, so ingest, receipts and packet digests don't change. A new `lens-dispatch.json` lists, per seat: bundle id, packet files, tier, and wave.

| Bundle | Lenses | Excerpts | Tier |
|---|---|---|---|
| J1 | security, correctness, schema/contract drift | Raw/Regions | judgment (Opus/Sol) |
| J2 | architecture, doc-drift | Skeleton, whole denominator | judgment |
| S1 | performance, resilience, data-safety, minimize | Regions | specialist (Sonnet/Sol 6.1) |
| S2 | ai-slop + standards | Regions | specialist |
| M1 | breadth triage, naming, dead-file | Skeleton, every path | mechanical (Haiku/Luna) |

- Conditional lenses (a11y, platform-parity, release-readiness) join S1 or S2 when their trigger fires.
- `lens_plan.rs` `ModelTier` gains `Specialist`. Each `LensPlan` records its tier and bundle id, and both appear in `lensPlan` and `lens-dispatch.json`.

**Defaults.**

| Setting | Value |
|---|---|
| Seat token budget | 150k estimated input tokens |
| Run budget | 6M estimated input tokens, at most 48 seats |
| Wave width | `CHILD_AGENTS_MAX` = 16 |
| Waves | `ceil(seats / 16)`, judgment seats scheduled first |

**Budget split.** 15% breadth, 55% judgment bundles, 20% specialist bundles, 10% security adjudication. Unused share flows into the hotspot strata.

**Size gate.** It refuses when the plan exceeds the run budget, not only the per-seat budget, and prints how far over it is per bundle.

**Rough estimate for Ember** (not measured): mandatory plus hotspot plus sample comes to about 210 files at about 8 KB in Regions mode, roughly 0.45M tokens per bundle. Total is about 35 seats across 3 waves.

Alternative considered: one seat per lens with a shared excerpt cache. Every lens still re-reads the same text, so it saves bytes but not model tokens.

## 3. Security adjudication at 1.4k candidates

1. **Deterministic triage.** It closes only provable non-issues, each with a new verdict basis `deterministic` and a rule id:
   - the candidate's path is excluded from the lens denominators (generated, vendored, minified or lock file),
   - the value matches the existing placeholder detection,
   - the same fingerprint was already resolved by a native provider.

   These are reported separately as `autoTriaged` and never counted as adjudicated. Test and fixture paths are **not** auto-closed, because real secrets do leak there.
2. **Clustering.** Fingerprint = rule + normalized sink/excerpt digest. Each cluster gets one adjudicated representative. Every member keeps its own verdict row with `clusterId`, so locations are never lost.
3. **Batching.** Group clusters by rule family, then by file locality, with at most 25 clusters per batch within the seat budget. Each batch runs in one fresh Oracle context, separate from any generator context. Adjudication stays on the judgment tier, so `oracle.md` L37 doesn't change.
4. **Keeping the assurance.**
   - Every surviving verdict (TRUE_POSITIVE, LIKELY_TRUE_POSITIVE, HARDENING_GAP, MISUSE_HAZARD) gets a second, single-candidate fresh-context confirmation before it counts. Full per-candidate rigor stays where findings are confirmed.
   - From each batch, the larger of 1 or 5% of false-positive verdicts is re-adjudicated alone, selected by digest seed. Any disagreement voids the batch and reruns it one candidate per context.
   - The duplicate-text check in `adjudicate_scanner_candidates_isolated` applies across clusters but allows the expanded text within a cluster.
   - `security_adjudication: pass` (`wf064/finalize.rs:531`) requires that every batch, confirmation and spot-check was ingested.

## 4. Missing scanners

Legion should not provision them. They should be declared optional host capabilities with typed degradation, recorded in `skills/audit/dependencies.json` and frozen into each provider's host declaration at plan time:

| Class | Tools | When absent |
|---|---|---|
| Substitutable (a native provider or lens covers the domain) | gitleaks → `security.credentials`; semgrep → native security detectors and the security lens; jscpd, knip, cargo-machete → the minimize and dead-file lenses; swiftlint, actionlint → `security.agentic-ci`, ai-slop | Note `capability-absent:<tool>`. The clean claim names the domain as covered only by the native substitute. The run is not blocked. |
| Advisory, no native substitute | cargo-audit (`Cargo.lock` present), pip-audit (Python lock or requirements present), cargo-deny (advisories part) | Gap `unavailable:host-capability:<tool>`, so the run is `incomplete`. A known-vulnerable dependency is a safety finding no lens can reproduce. |
| Informational | cargo-geiger, cargo-outdated, license-checker, cargo-deny (licenses part) | Note only. |

Getting these tools onto a host belongs to the workspace setup tooling (`tools/setup-workspace.py` / RightKit), not to Legion.

Alternative considered: gating status on every tool. Ember's status would then depend on what happens to be installed, not on what the code needs.

## 5. Implementation plan (one build)

New and changed files, under `engine/crates/legion-audit/src/native_providers/reasoning/` unless a path is given:

- **New `coverage_plan.rs`.** Risk signals, strata, seeded sampling, budget split, promotion from deterministic findings, confidence math. Pure and deterministic, using the existing `canonical_digest` and sha256, so no new crates and **no `Cargo.toml` change**.
- **`lens_plan.rs`.** Add `ModelTier::Specialist`, a per-lens `tier` / `bundle` / `budget_share` table, and serialize them in `to_packet_value`.
- **`excerpts.rs`.**
  - `ExcerptMode::Regions`.
  - `partition_excerpts_scoped` takes a budget argument and a set of flagged regions.
  - Content-digest dedup, with coverage credited to aliased paths.
  - `MAX_TOTAL_EXCERPT_BYTES` stays as the per-part cap only.
- **`engine/crates/legion-audit/src/plan.rs`** (reasoning-provider compile, around L330–365). Freeze `configuration.coverage = {mode, reviewSet, reviewSetDigest, strata, seed}`. The review set gets its own digest; the full denominator binding is unchanged.
- **`mod.rs`.**
  - `build_invocations` partitions only the review set.
  - `excerpt_coverage_value` adds `reviewSetDigest` and `declaredUnsampled`.
  - The adjudicator packet replaces per-candidate `candidateWorkItems` with `{parentPacketDigest, triage, clusters, batches, confirmations}`.
- **`ingest.rs`.**
  - `packet_coverage` and `merge_parts` compute `expected` against the review set.
  - The `lensCoverage` claim.
  - `lens_size_report` becomes `lens_dispatch_plan`: bundles, waves, tiers, total-budget violations.
  - `recompute_run` emits `qualityGate: "sampled"`.
  - `write_lens_packets` also writes `lens-dispatch.json`.
- **`security_adjudication.rs`.**
  - New: `triage_candidates`, `cluster_candidates`, `adjudication_batches`, `confirmation_items`, `spot_check_items`.
  - `adjudicate_scanner_candidates_isolated` accepts batch-scoped contexts and cluster expansion.
  - `ContextPolicy` labels contexts per batch.
- **`engine/crates/legion-audit/src/wf_port/wf064/finalize.rs`.** New pass condition for adjudication.
- **`engine/crates/legion-audit/src/native_providers/legacy_checks/registry.rs`** and the plan's host-declaration resolution. Add a capability class to each tool spec. The `unavailable:` gap applies only to the advisory class.
- **`engine/bins/legion/src/commands/audit.rs`.**
  - `lens_size_gate` uses the dispatch plan.
  - New flags: `--coverage auto|exhaustive|risk-sampled`, `--run-token-budget`, `--max-total-seats`.
  - The output lists `lensWork` by bundle and wave.
- **Docs.** `skills/audit/SKILL.md`, `references/execution-contract.md`, `lens-routing.md`, `provider-architecture.md`, `manual.md`, `coverage-and-trajectory.md`, `dependencies.json`, `src/roster/oracle.md`.
- **Not touched:** `Cargo.toml`, `legacy_checks/runtime_capture.rs`.

**Tests.**
- `coverage_plan`: the same inputs give the same review set; findings promotion only ever adds files; changing the review set changes the plan digest.
- A synthetic 1,100-file fixture produces a plan within 48 seats / 6M tokens; `--coverage exhaustive` refuses on the same fixture.
- Ingest: a sampled lens is `complete` once its review set is ingested; a missing review-set path still yields a gap.
- Status: a clean sampled run gives `qualityGate: "sampled"`, never `proven`.
- Regions excerpts: anchors resolve and redaction still applies.
- Adjudication with 1,400 synthetic candidates:
  - batch count stays within the bound;
  - auto-triage verdicts are typed `deterministic`;
  - an unconfirmed survivor leaves `security_adjudication` at `unproven`;
  - a spot-check disagreement voids the batch;
  - cluster expansion keeps every location.
- Scanner capabilities: a missing substitutable tool doesn't block, and cargo-audit with `Cargo.lock` present does.

**Order of work.** Steps 1, 2 and 3 can run in parallel; step 4 needs all three, and step 5 comes last.
1. `lens_plan` tiers and bundles, then `coverage_plan.rs`, then `plan.rs` freeze.
2. `excerpts.rs` Regions mode and dedup.
3. Security triage, clustering, batches and confirmations, plus `finalize.rs`.
4. `mod.rs` packets, `ingest.rs` coverage and dispatch plan, CLI flags.
5. Scanner capability classes, docs, the full test suite, then one installed-build run on Ember as acceptance.

## What this changes in contracts and doctrine

- **Audit report contract:** new `qualityGate: "sampled"`; new claims `lensCoverage`, `autoTriaged` and `lens-dispatch.json`; `excerptCoverage.reviewSetDigest` / `declaredUnsampled`; `candidateWorkItems` changes shape. If `legion-contracts` holds a JSON schema for the report, it needs a schema-version bump. I didn't check whether one exists.
- **Oracle and audit doctrine:** "one fresh context per candidate" becomes "one fresh context per homogeneous batch, plus single-candidate confirmation of every surviving verdict and seeded spot-checks". This changes `provider-architecture.md`, `execution-contract.md` and `oracle.md`, so it needs explicit sign-off from you. The judgment tier for adjudication stays the same.
- **Audit skill doctrine:** `manual.md` L170 ("one fresh subagent per lens, all in ONE wave") becomes bundled seats dispatched in waves.

Some things are unknown from what I could see: how Ember's 1,392 candidates spread across scanners, which tools are absent on the Dell, and whether `legion-contracts` holds a versioned report schema. They don't change the design, only the Ember-specific estimates above.

**Two decisions are yours before this goes to implementation:**
- **Batched adjudication.** It replaces the per-candidate fresh-context rule in Oracle and audit doctrine. The design compensates with single-candidate confirmation of every surviving verdict and seeded spot-checks.
- **Sampled runs.** Risk-sampled runs can report `complete`, with the new `qualityGate: "sampled"`, which never reads `proven`. This changes the report contract.
## Astra's binding conditions (2026-10-15)

D1 batched adjudication:
- Bound batch tokens and cluster membership; record evidence and a disposition for every candidate.
- Independently recheck ceil(5% × false-positive candidates) per non-empty batch in fresh contexts; any disagreement triggers a full per-candidate rerun of that batch.
- Route high-risk or uncertain dismissals directly to individual review; keep variant analysis for confirmed findings.
- Require host-attested context isolation; echoed context IDs cannot clear existing assurance gaps.
- Replace any lifetime seat limit with bounded concurrency and resumable waves; budget confirmations, spot-checks and fallback work explicitly.

D2 risk-sampled coverage:
- Keep `auto` fallback and explicit `exhaustive`; keep whole-inventory deterministic scanning and all security-candidate dispositions exhaustive.
- Freeze strata, seed, sampling units, per-lens denominators and budgets; mandatory coverage never shrinks to fit.
- Limit statistical claims to random-stratum detectable findings under stated assumptions; rule-of-three only with zero observations; Clopper–Pearson only with justified binomial assumptions.
- Report `coverageMode: sampled` separately from the quality outcome; findings and missing evidence keep their failure/incomplete states.
- Label the run "whole-repository risk-sampled audit" prominently.
