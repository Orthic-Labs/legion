# Legion vs External Practice Corpus — Detailed Comparison & Recommendations

**Date:** 2026-08-13
**Author:** Legion (primary) — evidence-mined from 18 cloned repositories
**Status:** advisory recommendations for next iteration of the final architecture book
**Sources cloned at:** `/tmp/legion-practices-sources.GtrSei` (18 repos; see §1)
**Baseline documents:**

- `docs/agent-rules/legion.md` (operational doctrine, 64 lines)
- `tools/skills/legion/docs/research/2026-08-12-legion-architecture-book-final.md` v-final + control-closure amendment G-A19…G-A27 (2 206 lines) — hereafter "Final Book"
- Workspace rules `AGENTS.md` / `docs/agent-rules/workspace.md`

**Reading rule for this document:** every recommendation is grounded in a file you can open at the path cited. No practice is merged wholesale; each is reduced to a concrete control, test, or interaction pattern and then judged against Legion's existing controls. Catalog repos (VoltAgent, EricGrill, Arabela) are discovery cross-checks only.


---

## 0. Executive Summary — What to Do With the Final Book

**Do not rewrite the Final Book.** It is the right chassis. The 18-repo corpus confirms its core bets — bounded deliberation with a hard third-revision ceiling, `OBJECTIVE × DEPTH × RIGOR` routing, frozen acceptance ledger (G-A19), reviewer non-expansion (G-A20), representative-workload-before-hardening (G-A21), stop-precedence (G-A22), lineage budgets (G-A23), one-integration-owner (G-A24), acceptance-surface completion (G-A25), seal reachability (G-A26), and machinery-defect isolation (G-A27) — are stronger than anything found outside. No external repo combines all of those in one system.

**Three verb-forms for the next iteration:**

1. **KEEP** — 60–70% of the Final Book is already best-in-class. Do not dilute it with catalog noise.
2. **IMPLEMENT** — ~20% of the Final Book is specified but not yet mechanically enforced in Legion code (`legion.md`/`workspace.md`/Arcane/harness). Close that gap before adding anything new.
3. **ADD** — ~15 genuinely useful controls are missing. They cluster in seven families: (a) fresh-verification-before-claim, (b) root-cause-before-fix, (c) dismissal-first security triage, (d) cross-agent shared memory & debt propagation, (e) risk-proportional QA routing, (f) throwaway-prototype discipline, (g) graceful degradation with explicit debt. Each is small, isolated, and fits inside existing G-A* controls without adding a new global ceremony.

**Explicitly DO NOT add:** broad external-search mandates, multi-tool agent scaffolds, framework-index expansions (Lambdatest's 40-framework matrix, Playwright's 50-guide surface as requirements), or catalog-driven skill bloat. The Final Book's restraint on `BEST_SHAPE`-gated external search is correct; the minimalist harness lesson from `mini-swe-agent` is to keep the ambient path at ~100 lines of enforceable logic.

**One-line answer to the three requested questions:**

1. *Already implemented?* Bounded convergence, lineage budgets, acceptance ledger & surface proof, seal reachability, integration-owner serialization, consumptive review, and evidence provenance — all stronger than the corpus.
2. *In Final Book but not yet implemented?* Epoch-bound cancellation, cross-ID lineage counters, representative-workload gate, seal-reachability compiler, machinery-defect isolation, and split-fingerprint enforcement — doctrine exists, harness enforcement lags.
3. *Missing & should be added?* 15 controls listed in §4 (fresh-verification gate, systematic-debugging phases, FP-check dismissal-first, exploitation-chain check, adaptive review depth, debt propagation, knowledge propagation, prototype lifecycle, glossary sharpening, evidence decay waivers, severity-gated autonomous fix loop, and hierarchical escalation with replanning). §6 gives exact `ADD / CHANGE / REMOVE` proposals with file-level placement.

---

## 1. How This Comparison Was Produced

### 1.1 Source inventory

All 18 repos were cloned under `/tmp/legion-practices-sources.GtrSei`:

| # | Repo | Local dir | Corpus role per brief |
|---|---|---|---|
| 1 | `addyosmani/agent-skills` | `addy-agent-skills` | Core skill system |
| 2 | `obra/superpowers` | `obra-superpowers` | Core skill system |
| 3 | `garrytan/gstack` | `garrytan-gstack` | Core skill system |
| 4 | `mattpocock/skills` | `mattpocock-skills` | Core skill system |
| 5 | `NeoLabHQ/context-engineering-kit` | `neolab-context-engineering-kit` | Core skill system |
| 6 | `instructa/agent-skills` | `instructa-agent-skills` | Core skill system |
| 7 | `trailofbits/skills` | `trailofbits-skills` | Security & review |
| 8 | `coderabbitai/skills` | `coderabbitai-skills` | Security & review |
| 9 | `testdino-hq/playwright-skill` | `testdino-playwright-skill` | Testing & QA |
| 10 | `LambdaTest/agent-skills` | `lambdatest-agent-skills` | Testing & QA |
| 11 | `VoltAgent/awesome-agent-skills` | `voltagent-awesome-agent-skills` | Discovery catalog |
| 12 | `EricGrill/agents-skills-plugins` | `ericgrill-agents-skills-plugins` | Discovery catalog |
| 13 | `ArabelaTso/Coding-Skills-Collection` | `arabelatso-coding-skills-collection` | Discovery catalog |
| 14 | `SWE-agent/mini-swe-agent` | `swe-agent-mini` | Agent harness |
| 15 | `swe-agent/swe-agent` | `swe-agent` | Agent harness |
| 16 | `Agent-Field/SWE-AF` | `agent-field-swe-af` | Agent harness |
| 17 | `Agent-Field/agentfield` | `agent-field-agentfield` | Agent harness |
| 18 | `anthropics/claude-code` | `anthropics-claude-code` | Official reference |

`agent-field-swe-af-snapshot` is an extra snapshot of #16 and was not treated as a separate source.

### 1.2 Method

For each repo: enumerate `skills/**/SKILL.md`, read `README.md`, `SKILL.md`, and representative sub-guides (`references/`, `docs/`, `methodology.md`, etc.), then reduce each skill to its *enforceable control* (what it forbids, what it requires, what it measures). Catalog repos were scanned for taxonomy gaps, not mined for controls. Every claim below cites a local file path.

### 1.3 Legion baseline used for comparison

The comparison tests each external control against:

- the 27 canonical global doctrines G-A1…G-A27 (Final Book Part III, §0.5)
- the `OBJECTIVE × DEPTH × RIGOR` router (Part IV)
- the canonical state `architecture_state` v2 (Part V) plus `acceptance_ledger`, `evidence_reachability`, `representative_workload`, `integration`, and `machinery_defects` blocks
- the four consumptive-review and seal requirements (G-A13, G-A23, G-A26, G-A19)
- the live `legion.md` scope rule (tiers 1–5) and workspace integration-owner rule

A control is scored **COVERED** if Legion already enforces it mechanically, **SPECIFIED-NOT-ENFORCED** if the Final Book defines it but `legion.md`/Arcane does not yet enforce it, **MISSING-USEFUL** if it would strengthen Legion without violating boundedness, and **REJECT** if it would add ceremony, scope creep, or unverifiable work.

---

## 2. What Legion Already Does Stronger Than the Corpus

This is the "do not touch" list. Each item is already enforced or specified more rigorously in Legion than in any external repo.

### 2.1 Bounded deliberation and lineage budgets — no external equal

- **G-A7 bounded deliberation** (`≤1` revision D1, `≤2` D2, absolute ceiling 3 → `DECIDE_WITH_DEBT | SPIKE | ESCALATE`) and **G-A23 hard time/round boundaries** (`OBJECTIVE × DEPTH × RIGOR` wall/active-time plus `DSV4 ≤1, Covenant ≤1, Oracle ≤1+scoped re-audit, contract_versions ≤2` per objective lineage). No external repo has lineage-scoped counters that survive packet/contract/session ID changes.
- Closest analogs are weaker: `obra/superpowers` `skills/writing-plans/SKILL.md:66` ("Bite-Sized Task Granularity") and `adda-agent-skills/skills/planning-and-task-breakdown/SKILL.md` both right-size tasks but never cap revisions or wall-clock. `gstack` `lib/conductor-env-shim.ts` hermetic env is a different concern (reproducibility, not anti-loop). `SWE-AF` `docs/ARCHITECTURE.md:execution engine` has `max_coding_iterations=5` and `max_advisor_invocations=2` but resets per issue/DAG — not lineage-scoped. **Verdict: COVERED, do not weaken.**

### 2.2 Frozen acceptance ledger and reviewer non-expansion — strongest in corpus

- **G-A19 frozen acceptance ledger** (`REQUIRED | DEFERRED | OUT_OF_SCOPE` with `acceptance_fingerprint` bound to review packets/contracts/milestones) and **G-A20 review cannot create requirements** (block only on `FAILED_ACCEPTANCE | FAILED_INVARIANT | SAFETY_BLOCK` with named ID + minimum correction). No external repo has a fingerprint-bound ledger.
- `obra/superpowers` `skills/writing-plans/SKILL.md:36-66` (Global Constraints + Task Structure) comes closest: it copies exact values verbatim from spec into every task, but has no frozen fingerprint or scope-expansion guard. `trailofbits/skills` `plugins/differential-review` is risk-first but still allows reviewers to invent "should have" criteria. `coderabbitai/skills` groups by `Critical/Warning/Info` but does not enforce a scope rule. **Verdict: COVERED.**

### 2.3 Representative workload before hardening + acceptance-surface completion

- **G-A21** ("one representative end-to-end workload through the actual requested workflow and acceptance surface before theoretical hardening") and **G-A25** ("milestones/proxy/unit checks are `CANDIDATE`; only observed evidence at declared surface mints `COMPLETE`"). `obra/superpowers` `skills/verification-before-completion/SKILL.md:18-48` says "NO COMPLETION CLAIMS WITHOUT FRESH VERIFICATION EVIDENCE" and enumerates the `IDENTIFY → RUN → READ → VERIFY` gate, but Legion's forward-workload gate is more specific (actual user workflow, not just "run tests"). **Verdict: COVERED and complementary — worth adding obra's explicit gate function phrasing (see §4.1).**

### 2.4 One integration owner, one shared-state writer

- **G-A24** (one HEAD/index/receipt/parent-pin owner per repo; one writer per shared contract) plus Legion `How dispatch works:646` ("Worker output is untrusted until Legion verifies it in the primary checkout"). External parallels exist but are narrower: `SWE-AF` `docs/ARCHITECTURE.md:Agent Isolation with Semantic Reconciliation` gives each issue a git worktree and a Merger agent with semantic reconciliation — excellent, but still issue-level, not repository-level lineage enforcement. `obra/superpowers` `skills/subagent-driven-development/SKILL.md` dispatches fresh implementer per task with two-stage review but leaves integration to the human. **Verdict: COVERED; consider borrowing SWE-AF's semantic merger pattern as an optional Alchemist aid (see §4.9).**

### 2.5 Seal-time evidence reachability

- **G-A26** (`real producer → durable output → authenticated persistence → verifier → completion consumer → close path`, plus substitution/replay rejection and independently reachable recovery). Nothing in the 18-repo corpus has an equivalent compile-time seal check. `instructa/agent-skills` `skills/hard-cut/SKILL.md` has a hard-cut reachability rule for canonical shape, but for API payloads, not for evidence lifecycles. **Verdict: COVERED, unique to Legion.**

### 2.6 Stop precedence and machinery-defect isolation

- **G-A22** (`STOP/PAUSE/REVOKE` increments `intent_epoch`, marks `execution_cancelled`, invalidates continuation tokens, cancels active dispatch/monitor/wait) and **G-A27** (`OUT_OF_SCOPE_MACHINERY_DEFECT` with sanctioned degradation, out-of-band authenticated recovery). `anthropics/claude-code` `plugins/ralph-wiggum` and `hooks` have stop hooks but no epoch-bound cancellation model. `gstack` `scripts/gen-skill-docs.ts` and `lib/` have no cancellation token concept. **Verdict: COVERED.**

### 2.7 Decision hygiene — dominance, failure story, minimum-sufficient selection

- **G-A16 failure story** (mandatory per candidate), **G-A17 dominance before weights**, **G-A18 minimum-sufficient selection algorithm**, and **G-A10 hard gates before preference scores**. The corpus has fragments: `mattpocock/skills` `skills/engineering/triage` has a state machine but not dominance; `neolab-context-engineering-kit` `skills/analyse-problem` has hypothesis trees but not the evidence-strength scale A→E. No external repo sequences `feasibility → thresholds → evidence → dominance → weighted comparison → selection of least lifecycle-complex sufficient candidate` as one canonical algorithm. **Verdict: COVERED; keep the algorithm verbatim.**

### 2.8 Evidence provenance and authority separation

- **G-A4 provenance types** (`REQUIREMENT | CONSTRAINT | MEASURED_FACT | … | UNKNOWN`) with separate strength grade A→E, and **G-A14 authority never inferred** (five authority classes). `addy/skills/source-driven-development` and `neolab/skills/context-engineering` talk about evidence but collapse provenance and strength into one score. `trailofbits/skills` is the only external source that approaches Legion's rigor here, with its provenance-sensitive false-positive checks. **Verdict: COVERED.**

### 2.9 Validated good fragments Legion already mirrors

| External fragment | Legion equivalent | Assessment |
|---|---|---|
| `superpowers:executing-plans` "Load plan, review critically, execute all tasks" | Legions' Sage→Alchemist handoff with frozen ledger | Legion more bounded |
| `superpowers:dispatching-parallel-agents` "precisely crafted instructions, isolated context" | Legion "Worker output is untrusted… content-addressed patch" | Legion adds verification |
| `superpowers:subagent-driven-development` per-task review + whole-branch review | Legion per-round `BLOCKER/REQUIRED_THIS_SLICE` re-review only changed evidence (G-A13) | Legion more precise |
| `neolab:do-in-parallel` / `swe-af:structured concurrency` | Legion "Parallelize implementation, serialize delivery" | Parity |
| `gstack leas learnings.jsonl` | Legion `reopen_triggers`, `debt_ledger` | Legion needs cross-agent variant (see §4.8) |
| `instructa:architecture-ownership` "canonical owner" | Legion G-A24 + G-A1 significance test | Legion adds fingerprint enforcement |

**Net: the Final Book's scope-control cluster (G-A19…G-A27) is the corpus's strongest system. Do not regress it to accommodate any external workflow.**

---

## 3. In the Final Book but Not Yet Enforced — Implementation Gaps

These controls are normatively defined in the Final Book but have no corresponding mechanical enforcement in the current `legion.md` / `workspace.md` / Arcane / harness as observed in this workspace. They are higher priority than any new external addition.

### 3.1 Epoch-bound cancellation (G-A22 / Part V `convergence` + Part IX §31)

- **What doctrine says:** every dispatch/wait/monitor/tool-batch/goal-wakeup binds `intent_epoch + continuation_epoch`; `STOP/PAUSE/REVOKE/narrowing` increments `intent_epoch`, marks `execution_cancelled=true`, invalidates tokens, cancels active work where safe, suppresses auto-resume.
- **Current enforcement:** `AGENTS.md:68-79` (authority & conduct) says "Obey live user intent" but no epoch field is defined in any runtime state observed here; `tools/skills/legion/` has no cancellation token implementation.
- **Required implementation:** add `intent_epoch`, `continuation_epoch`, `execution_cancelled` to `architecture_state.convergence` (already in Part V template) and enforce in Arcane dispatch guard. Add eval 30 (persisted goal after stop). **Priority: P0 — safety-relevant.**

### 3.2 Cross-ID lineage budgets (G-A23 / §31)

- **What doctrine says:** one objective lineage carries budgets across packet IDs, contract IDs, agents, sessions, resumptions; a new identifier never resets a ceiling; `UNBOUNDED`/`AS_NEEDED`/omitted duration is invalid.
- **Current enforcement:** no lineage counter observed in `legion.md:52-64` dispatch section; `maxContractVersions=2` and `revision_ceiling=3` are stated but not enforced across sessions.
- **Required implementation:** `objective_lineage_id` + counters `dsv4_rounds`, `covenant_rounds`, `oracle_rounds`, `contract_versions`, `wall_clock_budget_ms`, `active_time_budget_ms` with Arcane guard `non-ambient dispatch lacks exact cap → reject`. Eval 31 covers this. **Priority: P0.**

### 3.3 Representative-workload gate (G-A21 / §28B)

- **What doctrine says:** after smallest complete slice, run one representative end-to-end workload through actual acceptance surface before theoretical hardening; unit/synthetic/proxy checks do not substitute.
- **Current enforcement:** no forward-test gate observed in any local hook or Alchemist contract.
- **Required implementation:** `execution.smallest_complete_slice` + `representative_workload` + `forward_test_result` in state; Arcane guard `theoretical hardening before one workload result → reject`. Eval 29. **Priority: P0.**

### 3.4 Seal-time reachability compiler (G-A26 / Part XIII §52)

- **What doctrine says:** every required evidence class proves `real producer → durable output → authenticated persistence → verifier → completion consumer → close path`; seal exercises positive lifecycle + substitution + replay rejection; recovery stays reachable when ordinary path fails.
- **Current enforcement:** "Before sealing, prove every required evidence field has a reachable authenticated producer" (`legion.md:44` Contract chain) is stated but without a reachability graph compiler or substitution/replay tests.
- **Required implementation:** `evidence_reachability` block in state + `evidence-reachability.v1` contract + Arcane seal compiler. Eval 33. **Priority: P0.**

### 3.5 Acceptance-surface completion (G-A25 / §53)

- **What doctrine says:** milestones/internal flags/unit tests/patches are `CANDIDATE`; `COMPLETE` requires observed evidence for every frozen `REQUIRED` at its declared surface from exact integrated state with `integration_owner` identity.
- **Current enforcement:** `AGENTS.md:51` "Report `produced → verified → committed → parent-pinned → pushed → deployed` precisely" is close but not gated on surface-specific observation.
- **Required implementation:** `acceptance-surface-proof.v1` + Arcane guard `COMPLETE without observed evidence for every REQUIRED at declared surface → reject`. Eval 34. **Priority: P1.**

### 3.6 Split fingerprints and unchanged-review denial

- **What doctrine says:** three fingerprints `decision_fingerprint`, `evidence_fingerprint`, `last_reviewed_packet_fingerprint` (Part 0 conflict 7); equivalent fingerprint + no material delta = no new pass (G-A6 progress invariant); unchanged-packet review dispatch is rejected (Part IX §31).
- **Current enforcement:** single "reasoning fingerprint" language lingers in older Legion text; no split enforcement observed.
- **Required implementation:** state fields `decision_fingerprint`, `evidence_fingerprint`, `last_reviewed_packet_fingerprint` + Arcane guards `same decision fingerprint twice without new evidence → terminate` and `review of unchanged packet without new scoped question → reject`. Evals 7, 22. **Priority: P1.**

### 3.7 Machinery-defect isolation (G-A27 / §28F)

- **What doctrine says:** gate failure → separate `OUT_OF_SCOPE_MACHINERY_DEFECT` with impact + sanctioned path + separate owner; delivery continues unless required evidence or safety is invalidated; recovery is narrow, authenticated, independent of failing control plane.
- **Current enforcement:** `legion.md:35` "Assurance defects enter the current contract only when they invalidate safety or evidence… record every other machinery defect separately" — stated but no `machinery_defects.out_of_scope` state or out-of-band recovery path.
- **Required implementation:** state block + Arcane guard `gate failure absorbed into product scope without required-evidence/safety impact → record defect and continue`. Evals 35–36. **Priority: P1.**

### 3.8 Explicit revision ceiling enforcement at dispatch

- **What doctrine says:** `D1 ≤1, D2 ≤2, absolute ceiling 3` with forced `DECIDE_WITH_DEBT | SPIKE | ESCALATE` (G-A7, Part 0 §0.4). Counter binds at dispatch, not at seal.
- **Current enforcement:** budgets mentioned but not bound at dispatch time in observed code.
- **Required implementation:** dispatch-time budget binding per §31 guard `third revision reached → require terminal choice before further pass`. Eval 11. **Priority: P1.**

---

## 4. Missing & Should Be Added — 15 Controls the Final Book Should Absorb

Each entry: **WHAT** (control), **WHERE IT CAME FROM** (file:line), **WHY LEGION NEEDS IT** (gap it closes), **HOW TO ADD IT** (exact placement in Final Book / `architecture_state` / Arcane), and **COST** (scope/ceremony impact).

### 4.1 Fresh-Verification-Before-Claim gate (from `obra/superpowers`)

- **Source:** `obra-superpowers/skills/verification-before-completion/SKILL.md:14-48` — `NO COMPLETION CLAIMS WITHOUT FRESH VERIFICATION EVIDENCE` with a five-step gate function `IDENTIFY → RUN → READ → VERIFY → CLAIM` and a table mapping claims to required fresh command output.
- **Gap in Legion:** Legion has G-A25 (surface proof) and "Evidence before claims" (constitutional §59) but no per-claim fresh-run rule. An agent can still claim "tests pass" from a previous run, or "bug fixed" from code inspection without re-running the original symptom.
- **Why add:** this is the highest-ROI anti-hallucination control in the corpus. It turns "evidence before claims" from a slogan into a checkable gate. It also prevents the common failure where Alchemist trusts worker success reports instead of verifying in the primary checkout.
- **Proposal — ADD to Final Book:**
  - **New sub-rule under G-A25 / §28E:** `G-A25b — Fresh Verification Gate.` Before any `PASS / COMPLETE / FIXED / CLEAN` claim the agent must (1) name the exact verification command/surface, (2) run it fresh in this turn, (3) read full output + exit code + failure count, (4) decide whether output confirms the claim. Skipping any step invalidates the claim. Agent success reports and stale runs (previous turn/session) are not verification.
  - **Evidence card field:** add `fresh_verification_proof` to `Evidence Card` §45 and `Representative Workload Contract` §51 with `{command, surface, run_id, exit_code, failure_count, timestamp, claim_verdict}`.
  - **Arcane guard:** `claim PASS/COMPLETE without fresh run output in same turn → reject claim` (does not block delivery, just blocks the claim).
- **Cost:** trivial — one paragraph + one table; no new state except a run-id timestamp. Verbatim phrase to adopt: obra's claim→requires→not-sufficient table.

### 4.2 Systematic Debugging — Four Phases, Iron Law "NO FIXES WITHOUT ROOT CAUSE" (from `obra/superpowers`)

- **Source:** `obra-superpowers/skills/systematic-debugging/SKILL.md:9-55` — Iron Law + 4 phases (1 Root Cause Investigation, 2 Pattern Analysis, 3 Hypothesis+Testing, 4 Fix+Verify) with multi-component diagnostic instrumentation (log entry/exit per boundary) and explicit "do not skip when issue seems simple / in a hurry."
- **Gap in Legion:** Final Book covers risk (Phase 5) and falsification but has no Alchemist-level debugging protocol. Ad-hoc fixes can enter via Alchemist's `CANDIDATE` path without tracing data flow to source.
- **Why add:** Alchemist currently returns "execution receipts, observed results, failed checks, contradictions" (Part VIII §26) but with no prescribed isolation of failing component. The multi-boundary instrumentation pattern is directly reusable for Legion's `invalidation_cause` tracing.
- **Proposal — ADD:**
  - **New module** `doctrine/architecture/methods/systematic-debugging.md` (progressively loaded, not always-on) encoding the 4 phases + the "log what enters/exits each component boundary, run once, then analyze where it breaks" pattern as the prescribed Alchemist debugging sequence.
  - **Amend Alchemist contract** (Part VIII §26): on `FAILED` status Alchemist must report `{phase: root_cause_investigation | pattern_analysis | hypothesis_test | fix_verify, failing_component, data_flow_trace, hypothesis, evidence}` before proposing a fix.
  - **Add to architecture hypothesis form** (§15): `invalidated_when` already exists — add `falsification_run_id` so the lineage from hypothesis to verification-before-completion (§4.1) is traceable.
- **Cost:** one conditional module + one amendment; no new runtime budget.

### 4.3 Dismissal-First Security Triage & False-Positive Check (from `trailofbits/skills`)

- **Source:** `trailofbits-skills/plugins/fp-check/skills/fp-check/SKILL.md:6-120` — `When to Use / When NOT to Use`, rationalizations table, Step 0 "restate the claim in your own words" (half of FPs collapse here), Standard vs Deep routing, generic phases vs task-tracked deep verification. Plus `plugins/differential-review/skills/differential-review/SKILL.md:5-60` — risk-first, codebase-size adaptive (SMALL/MEDIUM/LARGE), blast-radius calculation, honest coverage limits.
- **Gap in Legion:** Final Book's security coverage is spread across lens modules but has no explicit "dismissal-first" calibration. Reviewers are assumed to find bugs; bias toward overrating severity is not countered.
- **Why add:** Legion's G-A13 classifies findings by `kind`/`severity` but does not force a false-positive budget check. Trailofbits' `Step 0 restatement` and `Standard vs Deep` routing are lightweight and directly prevent wasted `BLOCKER` findings. The `differential-review` adaptive depth (deep/focused/surgical by codebase size) maps cleanly to Legion's `OBJECTIVE × DEPTH × RIGOR` depth governance.
- **Proposal — ADD:**
  - **Amend G-A13 / §20 ASSURE:** add a `DISMISSAL-FIRST` preamble: every `BLOCKER` security finding must first pass a 30-second Step 0 restatement; classify as `STANDARD` (single-component, well-understood bug class, straightforward source→sink, no concurrency) vs `DEEP` (cross-component, race/TOCTOU, logic-without-spec) and route accordingly. Record `coverage_limits` and `confidence` in the finding.
  - **Amend finding schema** (§48) with optional fields `triage_path: standard | deep`, `blast_radius: {files, transitive_callers}`, `confidence: high | medium | low`, `coverage_limits: string`.
  - **Reference** `trailofbits` `fp-check/references/bug-class-verification.md` as a specialist extension (link, do not inline).
- **Cost:** one paragraph + three optional finding fields; reduces review cost by filtering FPs early.

### 4.4 Exploit-Chain Check After Batch Triage (from `trailofbits/skills`)

- **Source:** `trailofbits-skills/plugins/fp-check/skills/fp-check/SKILL.md:88-96` — "After all bugs are verified, check for exploit chains — findings that individually failed gate review may combine to form a viable attack."
- **Gap in Legion:** G-A10 hard gates and G-A17 dominance eliminate candidates individually; no synthesis step checks whether multiple `ADVISORY`/`NIT` findings combine into a `BLOCKER`.
- **Why add:** defense-in-depth. Legitimately non-blocking findings can be jointly exploitable (e.g., information disclosure + authorization bypass). No other corpus source covers this.
- **Proposal — ADD to ASSURE phase gate (§20):** after per-finding triage, add a one-line exploit-chain scan: "Do any two or more `FOLLOW_UP/ADVISORY/NIT` findings compose into a safety/security violation? If yes, synthesize a single `BLOCKER` with combined evidence and `affected_decision_ids`." Bound to one scan per assurance round; not a new review round.
- **Cost:** one checklist line.

### 4.5 Risk-First Adaptive Review Depth by Codebase Size (from `trailofbits/skills`)

- **Source:** `trailofbits-skills/plugins/differential-review/skills/differential-review/SKILL.md:24-45` — `Codebase Size Strategy: SMALL <20 files → DEEP, MEDIUM 20-200 → FOCUSED, LARGE 200+ → SURGICAL` + `Risk Level Triggers: HIGH auth/crypto/external calls/value transfer, MEDIUM business logic/new public APIs, LOW comments/tests/UI/logging`.
- **Gap in Legion:** Legion gates assurance by `RIGOR` (Lite/Standard/Critical) but not by codebase size or blast-radius-aware scoping. Large repos risk over-review; small repos risk under-review.
- **Why add:** ties assurance cost to bounded effort. Prevents "run all lenses deeply on a 3-file helper" waste while ensuring small high-risk services get deep treatment.
- **Proposal — AMEND Part IV §7 and Part VIII §20:** add a normative sentence: "Within a given `RIGOR`, assurance depth scales to codebase size and blast radius per the SMALL/MEDIUM/LARGE strategy; a small high-risk change is not 'Lite' by virtue of being small." Add to the `Architecture Review Finding` a `blast_radius` hint so Alchemist can scope the fix.
- **Cost:** one sentence + reference table.

### 4.6 Evidence Decay — `valid_until`, Waivers, and Freshness Report (from `neolab/context-engineering-kit`)

- **Source:** `neolab-context-engineering-kit/skills/decay/SKILL.md:6-95` — every evidence item has `valid_until`; stale/expired classification; three actions `refresh / deprecate / waive` with explicit waiver deadline; freshness report with `FRESH | STALE | EXPIRED | WAIVED` buckets.
- **Gap in Legion:** Legion has `Evidence Card` §45 field `Expiry / review trigger` and G-A15 "trigger-based governance is not open-ended reconsideration" requiring observable triggers, but no freshness reporting or waiver semantics. `evidence_fingerprint` can go stale without detection.
- **Why add:** closes the loop on G-A15 and G-A8 (decision finality + expiry triggers). Explicit `waive_until` prevents "slightly expired but probably still valid" from becoming an implicit reopen.
- **Proposal — CHANGE:**
  - **Amend `Evidence Card` §45** — make `valid_until` required (not optional) for `MEASURED_FACT` provenance; add `waived_until` + `waiver_rationale` + `waiver_authority` optional fields.
  - **Add to `architecture_state.evidence`** (§8) fields `freshness_report_due` and `waived_items: []`.
  - **Add a one-page SOP** `doctrine/architecture/methods/evidence-decay.md` with the three actions and a markdown freshness report template (copy neolab's table verbatim, adapted to Legion evidence IDs).
  - **Arcane hint (not guard):** surface `EXPIRED` evidence in convergence receipt `gaps` (informational until a trigger fires).
- **Cost:** one SOP + two card fields; waivers are bounded and explicit, so no unbounded deferral.

### 4.7 Context Budgeting and Attention Decay (from `neolab/context-engineering-kit`)

- **Source:** `neolab-context-engineering-kit/skills/context-engineering/SKILL.md:36-95` — attention budget `n^2`, progressive disclosure, quality-over-quantity, context as finite resource, hybrid pre-load + JIT, compaction triggers, "place critical info at attention-favored positions."
- **Gap in Legion:** Final Book Part X §34 has progressive disclosure ("load only the root router + current phase + material lenses") and Part XVI adoption step 3 mentions it, but no explicit context-budget concept or compaction trigger.
- **Why add:** Legion sessions already hit context limits (Sage planning + Cortex maps). Unbounded agent history is a real cost driver.
- **Proposal — ADD to Part X §34:**
  - Normative sentence: "Treat context as a finite attention budget. Every engagement declares an explicit context budget alongside wall-clock/active-time budgets; monitor `tool-output tokens / total tokens` and trigger compaction when tool outputs exceed 70% of budget."
  - Reference `neolab` context-anatomy (system prompts, tool definitions, retrieved docs, message history, tool outputs — tool outputs dominate at ~84%).
  - Keep progressive disclosure as the load-time strategy; add compaction as the run-time strategy. No new global state — just a per-engagement budget field `context_budget_tokens` in `architecture_state.task`.
- **Cost:** one paragraph + one state field.

### 4.8 Cross-Agent Shared Memory — Conventions, Failure Patterns, Interfaces (from `SWE-AF` + `gstack`)

- **Source:** `agent-field-swe-af/docs/ARCHITECTURE.md:Cross-Agent Knowledge Propagation` — `codebase_conventions | failure_patterns (last 10) | bug_patterns (last 20) | interfaces/{issue_name} | build_health` key-value store injected into every coding iteration. `gstack` `~/.gstack/projects/{slug}/learnings.jsonl` + `~/.gstack/sessions/` provides a project-level learning log.
- **Gap in Legion:** Legion has per-packet `reopen_triggers` and `debt_ledger` but no cross-agent shared memory that propagates discoveries from agent 1 to agent 15 within the same objective lineage. Failure patterns are re-discovered.
- **Why add:** measurable efficiency gain in SWE-AF for 400–500+ agent builds; for Legion's smaller lineage it prevents re-doing the same convention discovery per worktree/task. Also enables "first successful coder discovers camelCase, all downstream coders inherit it" without adding coordination overhead.
- **Proposal — ADD to `architecture_state`:**
  - New block `shared_memory` (optional, enabled when `enable_learning=true`):
    ```yaml
    shared_memory:
      codebase_conventions: string   # discovered naming/patterns/structure
      failure_patterns: []           # last 10 {pattern, issue, workaround}
      bug_patterns: []               # last 20 {bug_type, frequency, modules}
      interfaces: map                # per-completed-issue {files, exports, test_status}
      build_health: {passing_modules, failing_modules, debt_count}
    ```
  - **Writer rules:** conventions written once by first successful coder; failures/bugs appended synchronously at level barriers; interfaces written on issue completion; all injected into next issue's prompt.
  - **Keep it simple:** key-value with schemas, not a vector DB. Update only at known lifecycle points (barrier sync). Do not add embedding retrieval.
- **Cost:** one optional state block + barrier-time writes; no extra agent calls.

### 4.9 Debt Propagation to Downstream Issues (from `SWE-AF`)

- **Source:** `agent-field-swe-af/docs/ARCHITECTURE.md:Graceful Degradation with Explicit Incompleteness` — `RETRY_MODIFIED` relaxes criteria, `ACCEPT_WITH_DEBT` records typed debt `{type, criterion, issue_name, severity, justification}` in `DAGState.accumulated_debt`; downstream issues receive `debt_notes` + `failure_notes` so they work around gaps rather than building on missing assumptions.
- **Gap in Legion:** Legion has `debt_ledger` and `residual_risks` but no downstream propagation mechanism. A downstream Alchemist task can silently build on an upstream `ACCEPT_WITH_DEBT` without seeing the `debt_notes`.
- **Why add:** prevents cascading rework. The Final Book's G-A11 (HOLD SCOPE) and G-A27 (machinery-defect isolation) both benefit from explicit gap accounting.
- **Proposal — CHANGE to Part V state + Part VIII §28B:**
  - Add to `architecture_state.decision`: `accumulated_debt: []` (typed, severity-rated) distinct from `debt_ledger` (advisory polish).
  - Add to execution handoff contract: every implementation step receives `upstream_debt_notes` and `upstream_failure_notes` as additional context; each downstream step must acknowledge them or explicitly route around them.
  - **Arcane informational (not blocking):** surface `accumulated_debt` in convergence receipt `residual_dispositions`.
- **Cost:** one state field + one handoff injection; no new budgets.

### 4.10 Risk-Proportional QA Routing — 2-Call vs 4-Call Path (from `SWE-AF`)

- **Source:** `agent-field-swe-af/docs/ARCHITECTURE.md:Risk-Proportional Resource Allocation` — `IssueGuidance.needs_deeper_qa` flag routes `default path (Coder → Reviewer, 2 calls)` vs `flagged path (Coder → QA + Reviewer parallel → Synthesizer, 4 calls)` with `risk_rationale` audit trail.
- **Gap in Legion:** Legion's QA path is uniform per `RIGOR`; there is no per-issue risk routing inside a `STANDARD` engagement. Every issue pays the same QA tax.
- **Why add:** proportional rigor (G-A2) applied at issue granularity. Cheapest-strong optimization without adding ceremony — lean where safe, thorough where risky.
- **Proposal — ADD to Sprint Planner / issue authoring and `architecture_state`:**
  - Add per-planned-issue field `needs_deeper_qa: bool` + `risk_rationale: string` + `testing_guidance` (from SWE-AF's `IssueGuidance`).
  - **Routing rule:** `STANDARD` rigor + `needs_deeper_qa=false` → default path; `needs_deeper_qa=true` (touches interfaces, large scope, unfamiliar territory, auth/crypto/payment) → flagged path with parallel QA+Reviewer and Synthesizer.
  - `LITE` always default; `CRITICAL` always flagged (or specialist evaluation where material).
  - Keep synthesizer lightweight: LLM-only merge of two signals, stuck-loop detection included.
- **Cost:** three per-issue fields + one routing decision; saves cost on lean issues, spends it where the book already says to.

### 4.11 Throwaway Prototype Branch — Logic vs UI, Clearly Marked, Trivial to Run (from `mattpocock/skills`)

- **Source:** `mattpocock-skills/skills/engineering/prototype/SKILL.md:6-42` — two branches `LOGIC` ("does this state model feel right?" → single shareable HTML with free-play + guided walkthroughs) vs `UI` ("what should this look like?" → multiple variations switchable by URL param + floating bar); rules `throwaway from day one, trivial to run, no persistence by default, skip polish, surface the state, capture as primary-source branch out of main`.
- **Gap in Legion:** Legion has `SPIKE` (G-A12 / Phase 6) but does not distinguish prototype shape by question type or prescribe the "throwaway branch out of main with context pointer" lifecycle.
- **Why add:** prevents spikes from becoming accidental production code — a known Legion anti-pattern. Explicit branching by question type avoids wasting a whole prototype on the wrong artifact.
- **Proposal — ADD to G-A12 / §11 TAILOR alternative and §45 Tracer/Spike Contract:**
  - Add to spike contract fields: `prototype_branch: logic | ui | none` + `shareability: single-file | single-route` + `disposal_policy: throwaway_branch_with_pointer | promotable` with rule "throwaway branch stays out of main; only validated decision merges."
  - Reference `mattpocock` branch-selection rule verbatim: logic question → HTML state-machine demo; UI question → route with variant switcher.
  - **Normative:** prototype located close to usage so context is obvious, but named as prototype and skippable to run (`pnpm <name>` or double-click HTML).
- **Cost:** three spike-contract fields + one paragraph in G-A12.

### 4.12 Triage State Machine Before Significance Test (from `mattpocock/skills`)

- **Source:** `mattpocock-skills/skills/engineering/triage/SKILL.md:14-95` — two category roles `bug | enhancement`, five state roles `needs-triage → needs-info | ready-for-agent | ready-for-human | wontfix`; rules: redundancy search + prior-rejection KB (`.out-of-scope/`), reproduction verification, grill-then-brief for `ready-for-agent`, quick state override with maintainer trust.
- **Gap in Legion:** Legion has G-A1 significance test ("consequence, not category") but no intake triage. New issues enter Sage without a `needs-triage` gate, so significance is judged before verification or redundancy check.
- **Why add:** reduces `FROZEN`→`REOPEN` churn from misclassified intake. The `.out-of-scope/` KB (`mattpocock` `OUT-OF-SCOPE.md`) complements Legion's `out_of_scope` ledger — durable rejection reasons with revisit triggers (G-A8).
- **Proposal — ADD as pre-tailor intake (Part VI Phase 0 preamble, not a new phase):**
  - Before `TAILOR` significance test, run triage: `needs-triage` → (redundancy search + `.out-of-scope/` lookup + claim reproduction) → `ready-for-agent | ready-for-human | needs-info | wontfix`. Only `ready-for-agent` enters Sage routing.
  - `ready-for-agent` issues carry an agent brief (per `mattpocock` `AGENT-BRIEF.md` pattern) that cites where redundancy was checked and what reproduction showed.
  - **Guard:** do not apply triage to `D0 ambient` single-file helpers — they bypass it entirely (consistent with triage doc: "single-file single-function not triaged").
- **Cost:** one preamble section; no new runtime beyond a label lookup.

### 4.13 Glossary Sharpening — `CONTEXT.md` + ADRs Sparingly (from `mattpocock/skills`)

- **Source:** `mattpocock-skills/skills/engineering/domain-modeling/SKILL.md:10-75` — single-context `CONTEXT.md` vs multi-context `CONTEXT-MAP.md`; challenge against glossary immediately when term conflicts; sharpen fuzzy language ("account = Customer or User?"); invented edge-case scenarios; inline `CONTEXT.md` updates as decisions land (glossary only, no implementation details); ADRs sparingly (three tests: hard to reverse, surprising without context, real trade-off).
- **Gap in Legion:** Legion has ADR dual-status (§47) but no glossary discipline. Fuzzy domain language leaks into quality scenarios (G-A5) without a correction mechanism.
- **Why add:** G-A5 "Scenarios Before Quality Labels" requires precise scenario language; without a glossary that language drifts per writer. The three ADR tests tighten Legion's existing lifecycle-governance (G-A15) against over-documentation.
- **Proposal — CHANGE to Part XIII §47 + add to Part X:**
  - **Add** `CONTEXT.md` (or `CONTEXT-MAP.md` for multi-context repos) as the canonical location for ubiquitous language, with rule "update inline whenever a term is resolved — do not batch."
  - **Tighten ADR gate:** replicate the three Sparingly tests verbatim as the ADR creation gate; otherwise record in `CONTEXT.md` or `debt_ledger`.
  - Keep ADRs named `ADR-*.md` with dual `decision_status | realization_status` (already in §47) — no format change.
- **Cost:** one glossary file + three-test gate; replaces some future ADRs, so net docs shrink.

### 4.14 Hard-Cut Canonical Shape with Exception Isolation (from `instructa/agent-skills`)

- **Source:** `instructa-agent-skills/skills/hard-cut/SKILL.md:6-80` — keep one canonical implementation, delete compat/fallback/adapter/coercion/dual-shape code; 10 hard rules (no fallback, no compat branches, no shims, no fail-fast legacy guards, no legacy-rejection tests, delete old-shape helpers); trace every producer/consumer; fixtures/builders/snapshots updated to canonical only; exception only for concrete persisted external/user data / on-disk state / wire format / documented public contract with exact file/function named.
- **Gap in Legion:** Legion has canonical-owner intent (G-A1 significance, G-A11 HOLD SCOPE) but no hard-cut rule for schemas/contracts/state/flags/enum sets. Dual-shape code accumulates after migrations.
- **Why add:** directly supports G-A25 outcome closure (one shape, one surface proof) and G-A26 seal reachability (one producer path to verify). Preserved compat branches double the cases that need seal proofs.
- **Proposal — ADD as a conditional module:**
  - New conditional module `methods/hard-cut.md` with the 10 hard rules copied verbatim, triggered whenever a change touches `schema | contract | persisted state | routing | config | feature flag | enum/value set | architecture boundary`.
  - **Review checklist addition** (§48 finding `kind`): `DUAL_SHAPE_LEGACY` as a `FOLLOW_UP` finding that never blocks current delivery but enters `debt_ledger` with explicit exception if a real external boundary exists.
  - **Execution workflow** 7 steps (§Execution workflow in hard-cut SKILL.md) as the Alchemist migration checklist for this class of change.
- **Cost:** one conditional module; saves coverage cost by deleting branches.

### 4.15 Architecture Ownership — Runtime vs First-Fix vs Canonical Long-Term (from `instructa/agent-skills`)

- **Source:** `instructa-agent-skills/skills/architecture-ownership/SKILL.md:7-78` — required discovery (docs + ADRs + top-level structure), required output separating `Runtime owner | First fix owner | Canonical long-term owner | Competing owners that are wrong | Cleanup direction`, decision order (identify runtime concern → name layer where bug happens → decide first-fix vs canonical), 6-layer map (`UI | Platform shell | Runtime orchestration | Domain/Application | Shared core | Adapter/Integration`), hard-cut rules for reusable domain policy.
- **Gap in Legion:** G-A1 and G-A24 give one canonical owner per decision, but Legion conflates "where to patch now" with "where it should live long-term." Real ownership questions need both answers (e.g., "patch in runtime runner now, move policy to domain package next slice").
- **Why add:** without the split, quick patches either pollute the runtime orchestration layer or block on a larger refactor. The three-owner split is exactly what G-A12 spikes and G-A24 writer leases need to avoid owning the wrong long-term boundary.
- **Proposal — CHANGE to `architecture_state.architecture` + ASSURE:**
  - Add per-responsibility fields `runtime_owner`, `first_fix_owner`, `canonical_owner`, `wrong_owners: []`, `cleanup_direction: string` to the responsibility/contract modeling output (§14 Phase 4).
  - **Normative translation step:** every ownership answer must map generic layers to repo's actual module/package/crate/service names before recommendation.
  - **Guard:** reusable domain policy may not remain in runtime orchestration; pure validation/normalization/capability logic may not remain there when shared-core/domain fits.
- **Cost:** five fields per responsibility, written only when ownership is material.

---

## 5. Repo-by-Repo Deep Dive — What Each Source Actually Says, and What Legion Should Do With It

### 5.1 `addyosmani/agent-skills` — Strong product-engineering process discipline, weak on scope/lineage

**What's inside:** 23 skills covering `api-and-interface-design`, `browser-testing-with-devtools`, `ci-cd-and-automation`, `code-review-and-quality`, `code-simplification`, `context-engineering`, `debugging-and-error-recovery`, `deprecation-and-migration`, `documentation-and-adrs`, `doubt-driven-development`, `frontend-ui-engineering`, `git-workflow-and-versioning`, `idea-refine`, `incremental-implementation`, `interview-me`, `observability-and-instrumentation`, `performance-optimization`, `planning-and-task-breakdown`, `security-and-hardening`, `shipping-and-launch`, `source-driven-development`, `spec-driven-development`, `test-driven-development`, `using-agent-skills`. Plus `references/` checklists and `hooks/`.

**Strong practices Legion should absorb:**

- `skills/incremental-implementation/SKILL.md` — thin vertical slices (DB+API+basic UI as one slice), implement→test→verify→commit per slice, three slicing strategies (vertical, contract-first, risk-first), `Rule 0: Simplicity First` and `Rule 0.5: Scope Discipline` ("touch only what task requires"). **Action:** copy its `SIMPLICITY CHECK` anti-examples into Legion MINIMIZE §18 as illustrative examples; add `slicing_strategy: vertical | contract_first | risk_first` to `architecture_state.execution.smallest_complete_slice`.
- `skills/documentation-and-adrs/SKILL.md` — ADRs as durable decision records with status. Complements Legion §47 dual-status; no conflict.
- `skills/doubt-driven-development/SKILL.md` — doubt as a typed driver, not as paralysis. Maps to Legion `uncertainty` block.

**What NOT to absorb:** generic skill packaging (`plugin.json`, `skill-anatomy.md`) — Legion's skill is a packaged content directory already; maturer.

**Score:** 70% already covered by Legion (phases 0–11 mirror addy's skill set), 30% incremental slice discipline worth borrowing as guidance inside existing steps.

### 5.2 `obra/superpowers` — Most disciplined lifecycle in the corpus; source of §4.1–§4.2

**What's inside:** `brainstorming`, `writing-plans`, `executing-plans`, `subagent-driven-development`, `dispatching-parallel-agents`, `test-driven-development`, `systematic-debugging`, `verification-before-completion`, `requesting-code-review`, `receiving-code-review`, `finishing-a-development-branch`, `using-git-worktrees`, `writing-skills`, `using-superpowers`.

**Strong practices:**

- `verification-before-completion` — adopted verbatim in §4.1.
- `systematic-debugging` — adopted in §4.2.
- `writing-plans` — "assumes engineer has zero context + questionable taste; files exact paths, interfaces consumes/produces, bite-sized steps 2–5 min, no placeholders (TBD/TODO/'handle edge cases'), self-review for spec coverage + placeholder scan + type consistency, checkbox syntax" — excellent, but Legion's `planning-and-task-breakdown` + `architecture_state` already cover this at architecture level; worth referencing as an Alchemist execution-planning template, not adding to Sage.
- `receiving-code-review` — "verify before implementing, ask before assuming, push back with technical reasoning if wrong, YAGNI check for 'professional' features (grep for actual usage), forbidden performative responses" — complements G-A20. **Action:** add its `YAGNI check: grep codebase for actual usage → if unused remove, don't improve` as a pre-review filter before G-A20 classification.
- `dispatching-parallel-agents` — "precisely crafted instructions, isolated context, never inherit session history" — Legion already requires this (worker output untrusted); worth keeping as a one-line dispatch instruction template.
- `subagent-driven-development` — "fresh subagent per task + two-stage review (task review + whole-branch review)" — Legion's per-round re-review of only changed evidence is more precise; whole-branch review is redundant if per-round gates are sound.

**What NOT to absorb:** `finishing-a-development-branch` branch→PR→cleanup flow (Legion uses trunk + integration owner, not long-lived branches) and `using-git-worktrees` as default (Legion serializes at integration-owner level, not via per-task worktrees — see §4.9 for the narrower adoption).

**Score:** highest signal-to-ceremony ratio in the corpus. Two mandatory adds (§4.1, §4.2), one filter (§5.2 `receiving-code-review`), one reference.

### 5.3 `garrytan/gstack` — Opinionated engineering workflow with persistence and stuck-loop detection

**What's inside:** a full plugin suite (`spec`, `plan`, `autoplan`, `conductor`, `guard`, `ship`, `land-and-deploy`, `review`, `qa`, `careful`, `learn`, `health`, `sync-gbrain`, etc.) plus `lib/` hermetic env, `hosts/` typed configs, `scripts/gen-skill-docs.ts` templated SKILL.md generation, evolving `CLAUDE.md` per repo.

**Strong practices:**

- **Project learnings** `~/.gstack/projects/{slug}/learnings.jsonl` with `gstack-learnings-search --limit 3` injected per session — same family as SWE-AF shared memory (§4.8) but at project lifetime scope rather than objective-lineage scope. **Action:** consider a persistent `learnings.jsonl` as a second tier above lineage-scoped `shared_memory`; keep injection limit at 3 to bound context.
- **Hermetic E2E** `test/helpers/hermetic-env.ts` — allowlist-scrubbed env, fresh `CLAUDE_CONFIG_DIR`, temp `GSTACK_HOME`, `--strict-mcp-config`, diff-based test selection via `touchfiles.ts` — excellent reproducibility practice, but at test-infra layer, not architecture doctrine. Reference, do not doctrine-ize.
- **Template-driven SKILL.md** (`SKILL.md.tmpl` → `SKILL.md` via `gen:skill-docs`) — keeps preamble tier, version, allowed-tools consistent. Legion already needs `manage.py sync` check each turn; no new doctrine.
- **Bounded review exposure** (`plan-eng-review`, `plan-devex-review`, `plan-design-review`) — similar to Legion's RIGOR-gated review; no new control.

**What NOT to absorb:** vendored gstack detection, proactive/ telemetry prompting, first-task detection — operational gstack concerns, not Legion doctrine.

**Score:** good as a reference implementation for learnings + hermetic testing; no new global doctrine beyond §4.8's second tier.

### 5.4 `mattpocock/skills` — High-quality reasoning skills; source of §4.11–§4.13

**What's inside:** `engineering/{triage, prototype, domain-modeling, codebase-design, improve-codebase-architecture, implementing, diagnosing-bugs, tdd, to-spec, to-tickets, grill-with-docs, research, wayfinder, wizard}`, plus `productivity/{grill-me, grilling, handoff, teach, wait-what}` and `in-progress/{loop-me, writing-shape, claude-handoff}`.

**Strong practices:**

- `triage` state machine, `.out-of-scope/` KB, redundancy check, reproduction-before-grill — adopted in §4.12.
- `prototype` logic-vs-UI branching with throwaway-branch lifecycle — adopted in §4.11.
- `domain-modeling` `CONTEXT.md` + ADR sparingly three tests — adopted in §4.13.
- `diagnosing-bugs` + `triage` + `research` together form a disciplined diagnostic chain that complements obra's `systematic-debugging` (broader root-cause tracing).
- `grill-with-docs` / `grilling` — "grilling" as concise adversarial questioning; Legion already has Covenant as the structured adversarial chamber, so do not add a second.

**Score:** three adds (§4.11–§4.13), one reference (diagnostic chain). Maintain the "only offer ADRs when hard to reverse + surprising without context + real trade-off" threshold verbatim.

### 5.5 `NeoLabHQ/context-engineering-kit` — Context lifecycle, decay, and judgment patterns; source of §4.6–§4.7

**What's inside:** ~50 skills: `context-engineering`, `create-agent`, `create-command`, `create-hook`, `create-skill`, `decay`, `judge`, `judge-with-debate`, `multi-agent-patterns`, `do-in-parallel`, `do-in-steps`, `test-driven-development`, `do-and-judge`, `analyse-problem`, `critique`, `reflect`, `thought-based-reasoning`, `tree-of-thoughts`, `why`, `attach-review-to-pr`, `plan-do-check-act`, `kaizen`, `cause-and-effect`, `root-cause-tracing`, etc.

**Strong practices:**

- `decay` — adopted in §4.6.
- `context-engineering` fundamentals (anatomy, attention `n²`, progressive disclosure, budgeting, hybrid pre-load + JIT, compaction) — adopted in §4.7.
- `judge` + `meta-judge → judge with isolated context` — meta-judge generates tailored rubric before judge scores with evidence citations; prevents confirmation bias from accumulated session state. **Action:** reference as Oracle evaluation pattern: when Oracle audits, first generate a tailored rubric (meta-judge phase) then score with isolated context and mandatory citations (file:line). Do not add a separate skill — add one paragraph to `doctrine/oracle.md` describing the two-phase pattern.
- `plan-do-check-act` / `kaizen` — continuous improvement loops; Legion already has Progress Invariant (G-A6) and convergence metrics (Part XV); no new control.

**What NOT to absorb:** the sheer breadth of reasoning skills (tree-of-thoughts, why, thought-based-reasoning) as separate doctrine — they are LLM reasoning tactics, not architectural controls.

**Score:** two adds (§4.6–§4.7) + one Oracle improvement; one of the more signal-dense kits after obra.

### 5.6 `instructa/agent-skills` — Ownership and hard-cut transitions; source of §4.14–§4.15

**What's inside:** `architecture-ownership`, `hard-cut`, `consolidate-test-suites`, `debug-lldb`, `electron-live-test`, `find-duplicate-ownership`, `gh-repo-bootstrap`, `git-safe-workflow`, `gitwhat`, `go-local-health`, `no-mistakes`, `package-security-check`, `redesign-my-landingpage`, `root-cause-finder`, `search-context`, `secleak-check`, `shellck`, `stage-review`.

**Strong practices:**

- `architecture-ownership` 6-layer map + 3-owner split — adopted in §4.15.
- `hard-cut` 10 rules + 7-step execution workflow — adopted in §4.14.
- `consolidate-test-suites` — "one canonical test owner" — useful as a special case of hard-cut for test ownership; do not add separately.

**Score:** two adds; the layer-map + hard-cut pair is the cleanest ownership/complexity control in the corpus.

### 5.7 `trailofbits/skills` — Dismissal-first security and adaptive differential review; source of §4.3–§4.5

**What's inside:** 40 plugins: `fp-check` (false-positive check), `differential-review`, `audit-context-building`, `building-secure-contracts`, `c-review`/`rust-review`/`dwarf-expert`, `constant-time-analysis`, `variant-analysis`, `semgrep-rule-creator`, `entry-point-analyzer`, `supply-chain-risk-auditor`, `sharp-edges`, `let-fate-decide`, `trailmark`, etc.

**Strong practices:**

- `fp-check` Step 0 restatement, Standard vs Deep routing, rationalizations table, exploit-chain synthesis — adopted in §4.3–§4.4.
- `differential-review` risk-first + adaptive depth (SMALL/MEDIUM/LARGE) + blast-radius + coverage honesty — adopted in §4.5.
- `audit-context-building` — building baseline context before audit (read docs, map trust boundaries) — mirrors Legion Phase 2/4; no new control.
- `property-based-testing`, `mutation-testing`, `dimensional-analysis` — assurance tactics; Legion already covers them under assurance lenses (progressively loaded), no new global.

**What NOT to absorb:** the 40-plugin breadth as Legion requirements — Legions inherits specialist lenses on demand, not as always-on plugins. Reference `references/architecture/canonical-bibliography.md` and `spec-to-code-compliance` as appropriate lens extensions.

**Score:** highest security-calibration value. Two gate-level adds + one checklist line.

### 5.8 `coderabbitai/skills` — Automated review severity and autonomous fix loop

**What's inside:** `code-review` (autofix variant) + `autofix` skill; CLI `coderabbit review --agent` with severity grouping and `--base/--dir/--agent` scope flags; fix-until-clean loop.

**Strong practices:**

- **Severity thresholds** `Critical (security/data loss/crash) > Warning (bug/performance/anti-pattern) > Info (style/suggestion)` with rule "fix Critical+Warning systematically, re-run review, repeat until clean or only Info remains." **Action:** reconcile with Legion's `BLOCKER | REQUIRED_THIS_SLICE | FOLLOW_UP | ADVISORY | NIT` — mapping: `Critical→BLOCKER, Warning→REQUIRED_THIS_SLICE, Info→FOLLOW_UP/ADVISORY/NIT`. Adopt the "repeat autonomous review until only ADVISORY/NIT remains" as the bounded autonomous fix loop for Alchemist pre-Oracle self-review (one loop, not unbounded).
- **Agent-readable review output** (`--agent` flag) — useful for Oracle/Covenant packet structure; reference, do not doctrine-ize.
- **Prerequisite + data-handling guard** (check for secrets in diff, narrowest token, verified install) — operational safety; keep in workspace rules, not in doctrine.

**What NOT to absorb:** CLI-specific flags as doctrine.

**Score:** severity → Legion severity mapping + one bounded autonomous fix loop; otherwise operational.

### 5.9 `testdino-hq/playwright-skill` — Production-tested browser testing; largest single-skill quality

**What's inside:** `SKILL.md` + 50+ reference guides: `locators.md`, `assertions-and-waiting.md`, `test-organization.md`, `page-object-model.md`, `fixtures-and-hooks.md`, `visual-regression.md`, `accessibility.md`, `network-mocking.md`, `api-testing.md`, plus `playwright-cli/` and `ci/` guides.

**Strong practices:**

- **10 Golden Rules** (especially `getByRole() over CSS/XPath`, never `waitForTimeout`, web-first assertions `expect(locator)` auto-retry, isolate every test, `baseURL` in config, `retries 2 CI / 0 local`, `traces on-first-retry`, fixtures over globals, one behavior per test, mock third-party only) — best end-to-end hygiene in the corpus. **Action:** adopt as a one-page appendix `references/testing/playwright-golden-rules.md` referenced from G-A21 representative workload and G-A25 surface proof; do not gate seal/complete on full 50-guide coverage.
- **Trace analysis** `trace-analysis.md` (`npx playwright trace` CLI, HAR + trace debugging) — aligns with Legion's evidence reachability recovery path; reference as diagnostic pattern.
- **Agent-native concerns** (on-demand HAR inside tracing, locators strategy, storage-state updates) — useful for Alchemist representative workload on web surfaces.

**What NOT to absorb:** full 50-guide matrix as required gate — that would violate Legion's "acceptance-criteria-met is done; polish beyond criteria is optional recorded debt" (G-A18 satisficing).

**Score:** one reference appendix; highest quality-per-page skill in the corpus for web acceptance surfaces.

### 5.10 `LambdaTest/agent-skills` — Broad but shallow testing matrix; cross-browser/Device/Accessibility value

**What's inside:** 40+ skills (`playwright-skill`, `cypress-skill`, `selenium-skill`, `appium-skill`, `jest-skill`, `pytest-skill`, etc.) + `hyperexecute-skill`, `smartui-skill` (visual), `accessibility-skill`, `api-skill`; `shared/` patterns.

**Strong practices:**

- **Environment matrix definition** (browser × device × accessibility × remote) — useful for Legion's `representative_workload` environment declaration. **Action:** add `representative_environment` fields `browser_matrix`, `device_matrix`, `a11y_surface` as optional extensions to `representative-workload.v1` §51 when the frozen acceptance surface is a web/mobile surface.
- **Typed test evidence** (test framework → artifact type) — maps to Legion evidence provenance `MEASURED_FACT` grading.

**What NOT to absorb:** 40-framework skill list as doctrine. Lambdatest's value is breadth; Legion's is bounded depth. Treat as an environment reference, not a required skill index.

**Score:** one small schema extension for web/mobile workloads; otherwise catalog reference.

### 5.11–5.13 `VoltAgent/awesome-agent-skills`, `EricGrill/agents-skills-plugins`, `ArabelaTso/Coding-Skills-Collection` — Discovery catalogs

**What's inside:** curated indices: VoltAgent (curated hundreds), EricGrill (67 plugins / 78 agents / 950+ skills index, `plugins-index.json`, category catalog Core & Workflows / Documents / Languages / AI & LLM / Code Quality / Frontend / DevOps / Data / Specialized), Arabela (compact index).

**Strong practices:**

- **Taxonomy cross-check** — use to verify Legion hasn't missed a capability family. After this 18-repo sweep, no omitted capability family was found that survives Legion's significance test (G-A1). The only families catalogs surface that Legion intentionally excludes are ephemeral trends (`mcp-*` sprawl, SEO/content marketing skills).

**What NOT to absorb:** any catalog entry as a required Legion skill. Catalog entries are leads, not implementation evidence, per brief.

**Score:** useful for discovery completeness confirmation; zero doctrine additions.

### 5.14 `SWE-agent/mini-swe-agent` — Minimal harness lesson (~100 lines)

**What's inside:** `src/minisweagent/agents/default.py` (DefaultAgent `AgentConfig` with `system_template`, `instance_template`, `step_limit`, `cost_limit=3.0`, `wall_time_limit_seconds`, `max_consecutive_format_errors=3`, linear `messages` history, `subprocess.run` per action, no tool-calling required, `trajectory` persistence), `environments/local.py`, `models/litellm_model.py`, benchmark harness `ProgramBench`, docs.

**Strong practices:**

- **Linear history + bash-only minimalism** — proves a capable agent needs ~100 lines + `subprocess.run`, not a multi-tool scaffold. **Action for Legion:** keep ambient path radically simple. Treat `legion.md` tiers 1–2 (answer/ambient) as mini-swe equivalents — no multi-tool ceremony. Validate that the ambient tier can complete with a budget comparable to `cost_limit + wall_time_limit + step_limit` without loading Sage phases.
- **Explicit limits** `step_limit / cost_limit / wall_time_limit_seconds / max_consecutive_format_errors` — already mirrored in Legion `wall_clock_budget_ms / active_time_budget_ms / pass_budget` but mini shows they can be four simple fields on the agent config, not a workflow phase. **Action:** ensure ambient dispatch has these four as the cheapest bounded loop (no lineage counters needed there).
- **Stateless per-action `subprocess.run`** — each action independent, trivially sandboxed. Reinforces Legion's content-addressed patch isolation, not shared shell state.

**What NOT to absorb:** the anti-tool-calling stance for contracted work — Legion's Alchemist legitimately needs `READ/WRITE/EDIT/BASH/GLOB/GREP`; mini's minimalism applies to ambient/default, not to D1/D2 contracted complexity.

**Score:** one architectural proof point: keep ambient minimal; do not let contracted ceremony leak into tier 2.

### 5.15 `swe-agent/swe-agent` — Mature harness with terminal statuses and yaml governance

**What's inside:** `sweagent/agent/`, `environment/`, `tools/`, `inspector/`, `run/`, `trajectories/`, `config/` single-yaml governance, benchmark batch mode, tool + history-processor experiments.

**Strong practices:**

- **Single-yaml governance** (`config/` drives tools, model, history handling) — parallels Legion's canonical `architecture_state` + `management/constitution.md` pattern; validates the single-state-object approach.
- **Terminal statuses** + trajectory browser — Legion already has five terminal states (Part VII §24); trajectory persistence mirrors Legion's receipts.

**What NOT to absorb:** tool-set experimentation as Legion doctrine — keep Legion tool guidance in `tool_guidance` within context, not as configurable per-engagement tool lists.

**Score:** validating, not additive. Confirms Legion's single-state + terminal-state design.

### 5.16 `Agent-Field/SWE-AF` — Full autonomous factory; source of §4.8–§4.10 plus escalation/concurrency/recovery patterns

**What's inside:** `docs/ARCHITECTURE.md` 8 architectural patterns; Issue DAG planning chain (Product Manager → Architect → Tech Lead bounded loop → Sprint Planner → Issue Writers → Kahn levels + file-conflict scan); execution engine with three loops, structured concurrency with 10-step barrier gate, worktree isolation, graceful degradation, runtime DAG mutation, durable checkpoints, risk-proportional allocation, cross-agent knowledge propagation; DID/VC governance; 22 agents.

**Strong practices — three already adopted in §4.8–§4.10:**

- **Hierarchical Escalation Control** (Inner 2/4-call → Middle Issue Advisor 5 actions `RETRY_MODIFIED | RETRY_APPROACH | SPLIT | ACCEPT_WITH_DEBT | ESCALATE_TO_REPLAN` → Outer Replanner 4 actions `CONTINUE | MODIFY_DAG | REDUCE_SCOPE | ABORT`; crash fallback `CONTINUE` not `ABORT`) — Legion has bounded deliberation per decision but not per-issue escalation inside execution. **Additional adoption for Legion (beyond §4.8–§4.10):** add middle-loop advisor as Alchemist's bounded recovery for a failed acceptance item: `max_advisor_invocations=2` per item, final invocation warns "last chance → bias ACCEPT_WITH_DEBT or ESCALATE_TO_REPLAN." Outer replanner maps to Legion Sage replanning via `MODIFY_DAG` on remaining DAG (already in Legion via cause+scope local invalidation, but SWE-AF's explicit `apply_replan()` 5 steps give a concrete implementation for it).
- **Structured Concurrency with Barrier Synchronization** (asyncio.gather per level → result classification → Merge gate → Integration Test gate → Debt gate → Split gate → Replan gate → Checkpoint → Advance) — Legion has "parallelize implementation, serialize delivery" but leaves barrier steps implicit. **Action:** codify Alchemist's level barrier as an ordered gate list in `doctrine/alchemist.md` (reference SWE-AF's 10-step gate, trimmed to Legion's needs: worktree/isolate → parallel execute → classify → merge → debt/split → replan → checkpoint).
- **Agent Isolation with Semantic Reconciliation** (per-issue git worktree + Merger reading PRD/architecture/conflict annotations) — extends G-A24 from repository-owner serialization to semantic worktree isolation. **Action:** adopt as an optional pattern when Alchemist parallelizes within a level; keep G-A24's rule ("workers return disjoint patches or reachable commits; they do not integrate/pin/push concurrently") as the invariant, add worktree+merger as the recommended implementation.
- **Graceful Degradation** and **Risk-Proportional Allocation** — already in §4.9–§4.10.
- **Runtime Plan Mutation** (`apply_replan` 5 steps: filter → remove → skip → update → add → recompute levels via Kahn) — gives Legion's local invalidation (G-A9 cause+scope) a concrete runtime mutation procedure. **Action:** add to `doctrine/alchemist.md` as the prescribed `MODIFY_DAG` implementation.
- **Durable Execution & Checkpoint Recovery** (`.artifacts/execution/checkpoint.json` at 5 boundaries, `DAGState` + `resume_build()`) — Legion has `architecture_state` persistence but not a specified checkpoint boundary list or resume contract. **Action:** add checkpoint boundaries (after DAG setup, before/after each level, after split, after replan, on completion) and a `resume_from_checkpoint` path that loads state and skips completed levels.
- **Sprint Planner `IssueGuidance` + Kahn levels + `_validate_file_conflicts`** — Legion's planning → decomposition already does levels; add `needs_deeper_qa` + `estimated_scope` + `testing_guidance` + `review_focus` as per-issue guidance (already in §4.10) and `_validate_file_conflicts` as a pre-execution file-touch scan per level.

**What NOT to absorb:** DID/VC governance chain for Legion's local workspace (overkill for single-repo, single-owner delivery), 22-agent catalog as required staffing, or the PM→Architect→Tech Lead bounded loop as an extra review cycle outside Legion's existing `strategy → staffing` (G-A23 caps still apply).

**Score:** single richest source; seven concrete patterns, three already covered in §4, four additional refinements listed here.

### 5.17 `Agent-Field/agentfield` — Broader orchestration/runtime platform

**What's inside:** control plane, SDK, `coverage-baseline.json`, `test-infra/`, `desktop/`, `control-plane/`, broader orchestration patterns.

**Assessment:** largely the runtime behind SWE-AF. Its value for Legion is as a control-plane contrast: AgentField's DID/VC + `af call` async execution vs Legion's Arcane/Membrane + local dispatch. Legion intentionally keeps control local and model-free (Arcane has no model) for single-workspace operation. No new doctrine; reference for future multi-repo / multi-operator Legion evolution only.

### 5.18 `anthropics/claude-code` — Official reference; baseline for native lifecycle

**What's inside:** `plugins/{agent-sdk-dev, claude-opus-4-5-migration, code-review, commit-commands, explanatory-output-style, feature-dev, frontend-design, hookify, pr-review-toolkit, ralph-wiggum, security-guidance, ...}`, hooks examples, `feed.xml`, plugin marketplace.

**Strong practices:**

- **Hook lifecycle** (`hookify` plugin, session-start hooks) — Legion Arcane hooks already cover this; validate that stop hooks propagate to cancellation tokens (ties to §3.1 gap).
- **Confidence-gated review** pattern in `pr-review-toolkit` — aligns with Legion's severity-gated review (G-A13).
- **Ralph Wiggum** autonomous loop pattern — bounded iteration with explicit exit; confirms Legion's loop-termination design.
- **Plugin packaging** — confirms Legion's "skill is only a packaged content directory with a manifest" rule; no conflict.

**Score:** baseline confirmation; no new doctrine beyond hook-stop propagation already noted.

---

## 6. Concrete Proposals — ADD / CHANGE / REMOVE

Each proposal names the target file/section, the exact change, and the implementation order. `ADD` = new control. `CHANGE` = tightening an existing one. `REMOVE` = deleting a harmful or redundant prescription.

### 6.1 Priority order

**Phase A — Close Final Book implementation gaps first (before new adds):**

| # | Proposal | Target | Type |
|---|---|---|---|
| A1 | Epoch-bound cancellation | `architecture_state.convergence` + Arcane dispatch guard | IMPLEMENT (G-A22) |
| A2 | Cross-ID lineage budgets | same + Arcane | IMPLEMENT (G-A23) |
| A3 | Representative-workload gate | `architecture_state.execution` + Arcane | IMPLEMENT (G-A21) |
| A4 | Seal-reachability compiler | `evidence_reachability` + Arcane seal path | IMPLEMENT (G-A26) |
| A5 | Acceptance-surface proof gate | convergence receipt | IMPLEMENT (G-A25) |
| A6 | Split fingerprints + unchanged-review denial | `convergence` state + Arcane | IMPLEMENT (G-A6/A13) |

**Phase B — Highest-ROI adds from corpus (all fit inside existing G-A* without new lineage budgets):**

| # | Proposal | Target | Type | Source |
|---|---|---|---|---|
| B1 | Fresh-verification-before-claim gate | G-A25 / §28E + Evidence Card + Arcane claim guard | ADD | obra |
| B2 | Systematic debugging 4 phases | New conditional module + Alchemist `FAILED` contract | ADD | obra |
| B3 | Dismissal-first FP check + Standard/Deep routing | G-A13 / §20 | ADD | trailofbits |
| B4 | Exploit-chain synthesis scan per assurance round | §20 gate checklist | ADD | trailofbits |
| B5 | Risk-first adaptive review depth (SMALL/MEDIUM/LARGE) | Part IV §7 + §20 | ADD | trailofbits |
| B6 | Evidence decay `valid_until` + `waived_until` + freshness SOP | Evidence Card §45 + `architecture_state.evidence` | CHANGE | neolab |
| B7 | Context budgeting + compaction trigger | Part X §34 + `architecture_state.task.context_budget_tokens` | ADD | neolab |
| B8 | Cross-agent shared memory (conventions/failure patterns/interfaces) | `architecture_state.shared_memory` + barrier writes | ADD | SWE-AF/gstack |
| B9 | Debt propagation (`debt_notes`/`failure_notes` downstream) | `architecture_state.decision.accumulated_debt` + handoff | CHANGE | SWE-AF |
| B10 | Risk-proportional QA routing (`needs_deeper_qa` 2-call vs 4-call) | Sprint planner guidance + `architecture_state` | ADD | SWE-AF |
| B11 | Throwaway prototype branching (logic vs UI) + disposal policy | G-A12 / Spike contract | ADD | mattpocock |
| B12 | Intake triage state machine before significance test | Part VI Phase 0 preamble | ADD | mattpocock |
| B13 | Glossary `CONTEXT.md` + ADR sparingly 3 tests | Part X + Part XIII §47 | CHANGE | mattpocock |
| B14 | Hard-cut 10 rules conditional module | New conditional module | ADD | instructa |
| B15 | Ownership 3-way split (runtime/first-fix/canonical) + layer map | Phase 4 modeling output | CHANGE | instructa |

**Phase C — Refinements from harnesses (only if Phase B proves stable):**

| # | Proposal | Target | Type | Source |
|---|---|---|---|---|
| C1 | Hierarchical escalation (Issue Advisor 5 actions + Replanner 4 actions, middle `max_advisor=2`) | `doctrine/alchemist.md` recovery section | ADD | SWE-AF |
| C2 | Barrier gate sequence (10-step ordered list, trimmed) | `doctrine/alchemist.md` level barrier | ADD | SWE-AF |
| C3 | Semantic worktree + Merger implementation of G-A24 | `doctrine/alchemist.md` optional pattern | ADD | SWE-AF |
| C4 | Durable checkpoint boundaries + `resume_from_checkpoint` contract | `architecture_state` + Arcane | ADD | SWE-AF |
| C5 | File-touch conflict scan per level (`_validate_file_conflicts`) | Planning → execution bridge | ADD | SWE-AF |
| C6 | Severity → Legion severity mapping + bounded autonomous fix loop (fix Critical/Warning until only Info remains, one loop) | `doctrine/alchemist.md` self-review | CHANGE | coderabbit |
| C7 | Playwright Golden Rules appendix (10 rules) + trace analysis reference | `references/testing/` | ADD | testdino |
| C8 | Environment matrix fields (`browser_matrix/device_matrix/a11y_surface`) on `representative-workload.v1` | §51 schema optional extension | CHANGE | lambdatest/testdino |

### 6.2 What to REMOVE or explicitly NOT adopt

| # | Current text / proposed external | Action | Rationale |
|---|---|---|---|
| R1 | Any reading that the 21-lens catalogue is a checklist to run deeply every time | REMOVE (clarify) | Final Book already says "omission scan, not mandatory deep analysis" (§13, §39). Re-state in `doctrine/legion.md` constitutional block to prevent misread. |
| R2 | Full 50-guide Playwright surface or 40-framework Lambdatest matrix as a required gate | REJECT | Violates G-A2 proportional rigor and G-A18 satisficing. Keep as reference appendices, not gates. |
| R3 | 40-plugin trailofbits scope as always-on Legion requirement | REJECT | Specialist lenses are progressively loaded, not always-on. Reference, not requirement. |
| R4 | Catalog-driven skill sprawl (VoltAgent/EricGrill 950+ skills) as Legion requirements | REJECT | Catalogs are discovery leads; implementing them would recreate the loop the Final Book was built to end. |
| R5 | Mini's tool-less / history-less stance for contracted D1/D2 work | REJECT for contracted tier | Keep for ambient tier only (§5.14). |
| R6 | DID/VC governance chain for local workspace | REJECT (defer) | Overkill for single-owner, single-repo delivery. Revisit only if Legion evolves to multi-operator remote execution. |
| R7 | Second whole-branch review after Alchemist per-round consumptive reviews | REMOVE | Redundant if G-A13 per-round "re-review only prior blockers" is correctly implemented. Keep per-task review; skip the extra whole-branch ceremony. |
| R8 | Auto-generated hard-cut rejection tests for legacy shapes (`instructa` rule 5) | REJECT | `instructa` explicitly says "do not add tests asserting rejection of old shapes." Kept as-is. |
| R9 | Any phrase that lets a reviewer propose "valuable hardening" without a frozen acceptance/invariant ID or safety block to reopen scope | REMOVE (already removed by G-A20) | Ensure G-A20's exact wording uses `force DEFERRED | OUT_OF_SCOPE; reject reopen` not a softer "consider." |

### 6.3 Detailed change specifications for the most load-bearing B-items

**B1 — Fresh-verification gate.** Insert into Part III after G-A27 as `G-A25b` (or as a §28E subsection):

> "Before any `PASS | COMPLETE | FIXED | CLEAN` claim the agent must (1) name the exact verification command or acceptance surface, (2) run it fresh in this turn, (3) read the full output including exit code and failure count, and (4) state whether the output confirms the claim. A claim without a fresh run in its own turn is not verification. Agent success reports and previous-turn outputs are not verification."

Add mapping table (obra's `Common Failures` style):

| Claim | Requires fresh | Not sufficient |
|---|---|---|
| Tests pass | `pnpm exec vitest run` output: 0 failures this turn | Previous run, "should pass" |
| Build succeeds | `pnpm exec tsc --noEmit` / `workspace-doctor` exit 0 this turn | Linter passing |
| Bug fixed | Original symptom reproduction now passes this turn | Code changed, assumed fixed |
| Requirements met | Line-by-line ledger check with evidence citations | Tests passing alone |

**B3 — Dismissal-first routing.** Amend G-A13 preamble:

> "Every `BLOCKER` security finding must first pass Step 0: restate the claim precisely (vuln class, root cause line, trigger, impact, threat model). Classify as `STANDARD` (single-component, well-understood bug class, straight source→sink, no concurrency) for linear verification, or `DEEP` (cross-component, race/TOCTOU, logic-without-spec, prior inconclusive) for task-tracked deep verification. Standard has two escalation checkpoints to Deep."

Add rationalizations table from `fp-check/SKILL.md` (no partial analysis, pattern recognition ≠ analysis, familiarity ≠ coverage).

**B6 — Evidence decay.** Amend Evidence Card §45: make `valid_until: YYYY-MM-DD` required when `provenance ∈ {MEASURED_FACT, DOCUMENTED_FACT}`. Add `waived_until`, `waiver_rationale`, `waiver_authority` as optional. New SOP `methods/evidence-decay.md` with three actions and the `FRESH | STALE | EXPIRED | WAIVED` freshness report table from `neolab/decay`.

**B8 — Shared memory.** Add to `architecture_state` (Part V):

```yaml
shared_memory:        # optional; enabled when enable_learning or level ≥2
  enabled: bool
  codebase_conventions: string   # written once by first successful coder
  failure_patterns: []           # last 10, each {pattern, issue, workaround}
  bug_patterns: []               # last 20, each {type, frequency, modules}
  interfaces: map<string, {files, exports, test_status}>  # per completed issue
  build_health: {passing_modules, failing_modules, debt_count}
```

Writes only at barrier boundaries; reads injected into next issue's prompt. Keep `gstack` `learnings.jsonl` as a second, project-lifetime tier only if artifact size justifies it (bounded to last 3 entries injected).

**B12 — Intake triage.** Insert as Part VI Phase 0 preamble (before TAILOR), titled `0a. TRIAGE`:

> "Classify intake as `bug | enhancement`. Run redundancy search (domain concept, not just wording) + `.out-of-scope/*.md` prior-rejection lookup + claim reproduction (checkout diff, run relevant tests/commands). State recommendation `needs-triage → needs-info | ready-for-agent (with brief) | ready-for-human | wontfix (with `.out-of-scope/` write for rejected enhancements)`. Bypass triage for `D0` single-file helpers. Only `ready-for-agent` enters Sage routing."

**B14 — Hard-cut.** New conditional module `methods/hard-cut.md` carrying instructa's 10 hard rules verbatim (ordered), the 7-step execution workflow, and the exception rule "only when removing would break persisted external/user data / on-disk state / wire format / documented public contract with exact file:line named."

---

## 7. What to Keep Absolutely Stable — Anti-Regression Checklist

After any future change to the Final Book, verify none of these is weakened. If a diff touches one of them, stop and re-derive with evidence.

1. **Bounded deliberation** D1≤1, D2≤2, ceiling 3, forced `DECIDE_WITH_DEBT|SPIKE|ESCALATE` — do not lift.
2. **Lineage budgets survive ID changes** — no new packet/contract/session resets them.
3. **Frozen acceptance ledger** with fingerprint binding reviews/contracts/milestones/completion.
4. **Reviewer non-expansion** `BLOCKER` requires `FAILED_ACCEPTANCE | FAILED_INVARIANT | SAFETY_BLOCK`.
5. **Representative workload before hardening** — unit/synthetic/proxy cannot substitute.
6. **Stop precedence** — latest intent cancels persisted work; stored objective never grants authority.
7. **One integration owner / one shared-state writer** — workers never integrate/pin/push concurrently.
8. **Acceptance-surface completion** — `COMPLETE` only with observed evidence per `REQUIRED` at declared surface from exact integrated state.
9. **Seal reachability** — every required evidence class proves full lifecycle + substitution/replay rejection + independently reachable recovery.
10. **Machinery-defect isolation** — gate failure becomes `OUT_OF_SCOPE_MACHINERY_DEFECT` with sanctioned path; delivery continues unless required evidence or safety blocked.
11. **Failure story mandatory per candidate at STANDARD+** — no story, no freeze.
12. **Dominance before weights, weighted scoring only over non-dominated set with sensitivity.**
13. **Minimum-sufficient selection** (G-A18) as the canonical algorithm — least lifecycle-complex sufficient candidate wins.
14. **Evidence provenance + strength kept separate fields** — unlabelled score is not evidence.
15. **Authority never inferred** — five classes distinct; `ACCEPTED_RISK` requires named accepting authority.

---

## 8. How to Evolve Legally — Adoption Sequence (mirrors Final Book Part XVI but with corpus insertions)

1. **Phases A1–A6 first** — without them, no new corpus addition can be trusted (seal, surface, stop, budgets, workload).
2. **Phases B1–B7 next** — all fit inside existing G-A* and state fields; each is ≤1 paragraph + ≤3 optional fields; implement in the order listed (fresh-verification before debugging before FP-check).
3. **Phases B8–B15 after** — deal with cross-agent state (memory, debt, QA routing, ownership) once B1–B7 have been calibrated on one live representative workload.
4. **Phases C1–C8 only after B proves stable** — harness-level refinements (hierarchical escalation, barrier sequence, worktree+merger, checkpoints) are heavier and must be earned with evidence.
5. **Run one live representative workload end-to-end before any further hardening** (Part XVI step 12) — optimize for `time_to_representative_workload`, observed `required_acceptance_pass_rate`, and `stop_to_effect_quiescence_ms`, never for document similarity or control count.

---

## 9. Open Questions Left by the Corpus (Not Added — Decide With Evidence)

- Should `learnings.jsonl` be project-lifetime persistent (gstack model) or purely objective-lineage scoped (SWE-AF model)? Provisional answer: both tiers can coexist, but measure injection cost before enabling the persistent tier.
- Should Legion adopt SWE-AF's Kahn-level DAG + per-issue `estimated_scope trivial|small|medium|large` for display/budgeting? Likely yes — but keep it as UI over existing decomposition, not as a required planning gate.
- Should Oracle use the neolab `meta-judge → judge with isolation + citations` pipeline for every audit, or only for `CRITICAL` rigor? Recommend `CRITICAL` always, `STANDARD` when material.
- Should Legion expose a `BEST_SHAPE` external-search scoping rule `top-2 mechanism classes × 2 approaches each, timeboxed` (Part IV §7 OPTIMIZE modifier) as a hard budget vs a guideline? Recommend hard budget — the SWE-AF experience shows "timeboxed broad search" drifts without it.

---

## 10. File-Level Traceability — Every External File That Mattered

| File (opened at `/tmp/legion-practices-sources.GtrSei`) | Legion impact |
|---|---|
| `obra-superpowers/skills/verification-before-completion/SKILL.md` | §4.1 `G-A25b` fresh-verification gate — adopt gate function + table |
| `obra-superpowers/skills/systematic-debugging/SKILL.md` | §4.2 systematic-debugging module + Alchemist `FAILED` contract |
| `obra-superpowers/skills/receiving-code-review/SKILL.md` | §5.2 YAGNI grep-before-improve filter before G-A20 |
| `obra-superpowers/skills/writing-plans/SKILL.md` | Reference for Alchemist execution planning; self-review checklist |
| `obra-superpowers/skills/dispatching-parallel-agents/SKILL.md` | Dispatch isolation phrasing |
| `neolab-context-engineering-kit/skills/decay/SKILL.md` | §4.6 evidence decay SOP + freshness report |
| `neolab-context-engineering-kit/skills/context-engineering/SKILL.md` | §4.7 context budgeting + progressive disclosure compaction |
| `neolab-context-engineering-kit/skills/judge/SKILL.md` | Oracle two-phase meta-judge → judge with isolation |
| `mattpocock-skills/skills/engineering/triage/SKILL.md` | §4.12 intake triage state machine + `.out-of-scope/` KB |
| `mattpocock-skills/skills/engineering/prototype/SKILL.md` | §4.11 logic-vs-UI prototype branching + disposal |
| `mattpocock-skills/skills/engineering/domain-modeling/SKILL.md` | §4.13 `CONTEXT.md` + ADR sparingly 3 tests |
| `instructa-agent-skills/skills/architecture-ownership/SKILL.md` | §4.15 3-way ownership split + 6-layer map |
| `instructa-agent-skills/skills/hard-cut/SKILL.md` | §4.14 hard-cut 10 rules + 7-step workflow |
| `trailofbits-skills/plugins/fp-check/skills/fp-check/SKILL.md` | §4.3 dismissal-first + Standard/Deep + exploit-chain scan |
| `trailofbits-skills/plugins/differential-review/skills/differential-review/SKILL.md` | §4.5 adaptive review depth SMALL/MEDIUM/LARGE |
| `coderabbitai-skills/skills/code-review/SKILL.md` | §6 C6 severity mapping + bounded autonomous fix loop |
| `testdino-playwright-skill/SKILL.md` (+ `core/locators.md` etc.) | §6 C7 Golden Rules appendix + trace analysis |
| `lambdatest-agent-skills/README.md` + `shared/` | §6 C8 environment matrix schema extension |
| `swe-agent-mini/src/minisweagent/agents/default.py` | §5.14 minimal harness proof — keep ambient path at ~100 lines |
| `swe-agent/sweagent/agent/` | Validating single-yaml + terminal-state design |
| `agent-field-swe-af/docs/ARCHITECTURE.md` | §4.8 shared memory, §4.9 debt propagation, §4.10 risk-proportional QA, + §6 C1–C5 escalation/barrier/worktree/checkpoint |
| `agent-field-agentfield/` | Control-plane contrast; defer DID/VC |
| `anthropics-claude-code/plugins/` | Baseline confirmation; hook-stop propagation |
| `addy-agent-skills/skills/incremental-implementation/SKILL.md` | Vertical/contract-first/risk-first slicing + simplicity checks for MINIMIZE |
| `garrytan-gstack/SKILL.md` + `hosts/` + `test/helpers/hermetic-env.ts` | Project learnings as second tier + hermetic E2E reference |
| `voltagent-awesome-agent-skills/README.md` | Taxonomy completeness check — no missing family |
| `ericgrill-agents-skills-plugins/README.md` + `plugins-index.json` | Same — confirms 950+ catalog is discovery only |
| `arabelatso-coding-skills-collection/README.md` | Same — third cross-check |

Unlisted `SKILL.md` files were scanned and found redundant with the files above or out-of-scope for architecture doctrine (e.g., `browser-skills/`, `ios-fix`, `redesign-my-landingpage`, `lambdatest/jest-skill` individual framework guides).

---

## 11. How to Use This Document Next

1. **Read §3** and confirm the six implementation gaps are accepted as P0/P1.
2. **Read §6.1 Phase B** in order; for each `B1…B15`, apply the exact target/placement listed. Each is small enough to be one commit. Do not batch them — one control per commit, verify with its named eval (30/31/33/etc.) or fresh manual check.
3. **After Phase B, run one live representative workload** and measure `time_to_representative_workload`, `required_acceptance_pass_rate`, `stop_to_effect_quiescence_ms`, and `dominated_candidate_selection_rate`. Optimize for those, not for document length.
4. **Then consider Phase C** only where Phase B evidence shows a gap that C would close. Default stance: defer Phase C.
5. Archive this document as `2026-08-13-legion-external-practices-comparison.md` alongside the Final Book — it is rationale, not doctrine. Doctrine lives only in `doctrine/*.md` and `doctrine/architecture/**` per Part XII.

---

*End — Legion external-practice comparison 2026-08-13.*
