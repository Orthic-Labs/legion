# Sage — Architect route bundle

**What this is:** the recovered method manual for Sage's Architect route (the "what should this
mean, what should the system become" route named in `doctrine/sage.md`'s three internal routes).
Recovered verbatim from git history — deleted at workspace commit `d810d827` (claimed "absorbed"
into the new agent definitions; it was not — only the 36-line constitution survived). Source:
`git show d810d827^:tools/skills/architect/references/manual.md` (292 lines). Loaded by: Sage,
when the task requires resolving what should exist (interfaces, invariants, acceptance semantics,
non-goals) or compiling settled decisions into an executable contract.

**Read `doctrine/sage.md` first.** This bundle is the craft underneath that constitution, not a
replacement for it. Where this manual's routing language conflicts with current doctrine, a
`> **Superseded:**` note marks the change inline; everything else is preserved as originally
written, including its own internal skill name (`architect`) and file paths from its era.

---

# Architect — design + plan a coding task

```text
MODE: OUTPUT_ONLY
PRIMARY_DELIVERABLE: Named design decision plus requested ADR or plan fields.
DISCOVERY_PROFILE: D1_SCOPED_SOURCE
EFFECT_PROFILES: source_read
SPECIALIST_REFS_MAX: 0
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Named design decision plus requested plan fields are populated.
```

Default is output-only: no web research, child agents, execution, plan-file write, or sidecar unless frozen manifest grants it.

Produces a plan, not code. Execution is a separate step (native fan-out or inline).

> **Superseded:** "Execution is a separate step (native fan-out or inline)" now means Alchemist —
> Sage authors the contract, Alchemist executes it. There is no standalone `/architect` skill to
> hand off to; this manual IS Sage's Architect route.

**Assessment-only boundary.** If the user only asks whether the current architecture is best-shaped,
what it is missing, or what to absorb from another tool, Phase 2's evidence-backed decision matrix +
verdict is the deliverable. Do not create a plan file or mutate the repo unless the user also asks to
plan, change, build, or action the result. When they do, continue through Phase 3 normally.

**Default gate = evidence-backed inline self-review. External review is explicit opt-in.** Explore,
design, challenge the ADR against code/tests/logs, then proceed without waiting for Adrian. Run the
named `/covenant` workflow only when Adrian explicitly asks for Council, a jury, or external review.
Escalate only for a hard blocker (missing secret/credential, irreversible production mutation,
legal/safety risk, or a decision he explicitly reserved).

> **Superseded:** `/council` → `/covenant`, as above throughout this document. Covenant's seats are
> packet-only and advisory; the disposition remains Sage's per G12.

**Substantive (risk + blast radius, with hard triggers):** A design is substantive if it changes
schema/data migration · auth/permissions/security · money/billing · a public API · an exported or
public contract · IPC · persistence · concurrency · irreversible state · an external dependency;
crosses subsystem boundaries; or changes more than three implementation files. Companion tests,
docs, and generated files do not count toward the file threshold. **A single file can be
substantive** when many consumers depend on it (shared utility, stylesheet, API client, central
config, exported symbol). Trivial means small in both scope and impact, with known local consumers.
If blast radius is uncertain, treat it as substantive. File count is a signal, not the decision
mechanism.

## When to use / not

Use to design AND plan an engineering task: a feature, refactor, schema change, library choice, ADR.

Do **not** use for:
- mapping the CURRENT architecture → `cortex`
- diagnosing repo health → `/audit`
- marketing / content / launch / SEO planning → `/marketing`

## Protocol — 3 phases (read-only until the plan doc is written)

### Phase 1 — Explore (ground in real code first)
**Consume Cortex's current-repository evidence before any ad-hoc reading.** Run
`cortex doctor --json`, then `cortex graph status`. Trust generated artifacts when doctor is
`ready`, or when doctor is `degraded` while the graph is explicitly fresh and doctor reports no
blocker/error; preserve every degradation warning as a design constraint or coverage limitation.
A `missing|stale|broken|corrupt` state, a stale graph, or any blocker/error means rebuild/repair,
not read around it. When a usable graph generation exists, use the bounded graph surfaces before lexical fallback:
`graph architecture --budget 2000` for the bounded component/dependency base, `graph search` + `graph resolve` for symbols,
`graph neighbors --budget 2000` for local context, `graph path --budget 2000` for flows, and `graph impact --budget 2000` for callers/consumers.
Structural query results are ranked reference rows, freshness-stamped, and tabular by default; add
`--json` for machine parsing and use the returned continuation cursor for another narrow hop.
Run `cortex brief --task "<task>"` for the graph-first task brief; use `graph candidates` when a
bounded machine-readable `ContextCandidateSet v1` helps select lens inputs. These candidates are
Cortex evidence, not final admitted agent context.

Read the tracked portable contract at `<repo>/.blueprint/manifest.json` plus the
`coverage.json` / `contradictions.json` companions; the machine-local `.agent/map.json`,
`understanding.json`, and `verdicts.json` artifacts remain the document/claim layer where present,
treating every `contradicted`/`stale` verdict as a trap. For completeness work,
`cortex graph flows --complete` is the primary flow inventory;
`understanding.json.architecture.coverageGaps` is the secondary synthesized queue. Do not let a
`partial|missing|undetermined` flow disappear because the implemented portion is healthy. If no
usable graph exists, run `cortex`/`cortex build`; if Cortex remains unavailable, state
`graph-unavailable` and fall back to root docs plus targeted Glob/Grep/Read. Follow established
conventions. Consume applicable open Audit findings and evidence-backed constraints for the active
commit/surfaces; reverify stale reports rather than inheriting them as fact. Consume durable decisions,
rules, and lessons from Crypt as planning context, but current code and executable evidence win
every conflict. Architect does not remap the repo or issue a health verdict.
**Survey broadly with `skel <file>` (tree-sitter skeletons, ~78% fewer tokens) to map structure
cheaply; read FULL only the files you will actually change — never skeletonize a file whose exact
logic you must verify or edit.** Output a short "what exists / what this touches" map. No code edits.

> **Membrane status (post-G3/G4/G5).** Membrane (formerly RightContext) is the umbrella architecture;
> Crypt is its durable-memory subsystem. **Now live in `main`:** the typed Architect decision
> store at `<repo>/.audit/architect/decisions.jsonl` (G5 Lane A) with the provider at
> `tools/skills/architect/decision_provider.py`; the typed Audit finding store (G4) plus its
> provider; `ContextPacket` / `ContextReceipt` v2; the local Rust federation gateway. Lifecycle
> semantics enforced fail-closed: `proposed → accepted → implemented → superseded`. Planner
> admissions only consider `accepted` / `implemented` siblings for a stable id — a `proposed`
> version is **never** admitted as current when an accepted sibling exists for the same logical
> decision, and a `superseded` record is never admitted when a current record exists. An
> `implemented` record must carry non-empty `implementationRefs`; surface the gap as a
> `ProviderWarning`, do not silently admit. The federating planner/gateway, `ScopeGrant`
> enforcement at runtime, and the three cross-client adapters (Claude / Codex / MCP) are wired
> but proceed against frozen G1 schemas until G2 (Mac portability) and G6 (benefit acceptance)
> produce evidence. Honest caveat: **G2 remains BLOCKED on real Mac operator evidence**; do not
> claim cross-machine parity until the G2 evidence manifest exists under
> `rightcontext-evidence/g2/`. Current runtime truth: `membrane/docs/MEMBRANE-STATE.md`; historical
> provenance: `docs/plans/2026-07-12-rightcontext-unified-architecture-dispatch.md`.

> **Superseded:** `tools/skills/architect/decision_provider.py` was the skill-era provider path.
> Verify current location before relying on it — if the skill directory no longer exists (the
> `architect` skill was retired along with `dispatch`/`debugger`/`qa`), treat this as a stale
> pointer and locate the current Membrane decision-store provider before use, or note the gap.

### Phase 2 — Design (options → decision)
Run the **Embedded design lenses** as a divergence-then-converge builder pass (synthesize the
result; show role notes only when they help the user compare):
- **User Advocate** — who benefits, the job, what they notice first.
- **Simplifier** — what to remove/defer; the laziest thing that works.
- **Systems Thinker** — dependencies, boundaries, failure modes, second-order effects.
- **Creative Provocateur** — sharper / less-obvious options.
- **Operator** — buildable, maintainable, easy to validate.

These are same-context perspectives, not independent reviewers and not the named `/covenant` skill.
Their job is cheap option improvement before the ADR. Flag real divergence instead of forcing
agreement, but do not spawn one agent per role by default. When Adrian explicitly opts into
`/covenant`, its advisory, revision, and Jury verdict run later. For unusually wide or irreversible
option spaces, independent exploration workstreams may gather alternatives and evidence; they do
not issue the verdict.

Then:
0. **Search the solution space.** This is mandatory when the decision touches external tech, a
   library/tool/version choice, a known-hard problem, an uncovered flow, competitor/tool absorption,
   or any claim that the result is the "best shape", architecturally complete, or current
   best-in-class. Search the current web for primary sources and implementations using the client's
   search tool (Claude: WebSearch; `mm`/claudemm sessions: `mmx search --q "<query>" --output json`,
   since MiniMax lacks the hosted WebSearch path); use the `reflect` MCP
   (`resolve-library-id` then `query-docs`) for current library/API docs and exact versions. For a best-shape/completeness review,
   inspect at least 2–3 credible external approaches for each material mechanism class represented by
   the coverage gaps—not merely the first tool the user supplied. Cite ≥2 primary sources for each
   external recommendation. Check code and benchmarks where available, plus license, security/privacy,
   operational maturity, and whether claimed gains are independently measured. Bring the strongest
   external option into the comparison; never design only from repo conventions or training memory.
   A search can end in `reject`—the obligation is to look and decide, not to import novelty.
0b. **Emit a prior-art decision matrix when step 0 is mandatory.** One row per material gap or
   mechanism: current local behavior + evidence · external approach + source · claimed advantage ·
   verified limitation/risk · `adopt|morph|reject|defer` · validation gate. `defer` names the evidence
   needed and remains an open architectural gap. Concepts may be clean-room inspiration; do not copy
   code until license compatibility is verified.
1. Propose **2-3 approaches when meaningful trade-offs exist**; lead with a recommendation + why.
   If only one option is viable, explain why the apparent alternatives are dominated instead of
   inventing fake choice.
2. **Challenge the request** when the evidence says so — don't add a service / dependency /
   abstraction the task doesn't need; recommend the simpler path (new service when an existing
   one would do, big-bang migration over strangler-fig, Kafka with no throughput sizing → flag).
2b. **Never downgrade; name the ceiling.** If a working solution / library / version / pattern
   already exists (per cortex's map), the design must not propose something strictly worse on
   capability, performance, security, or maintainability — and when it does propose a change, prove
   it's a net improvement on a named axis. Beyond just meeting the request, state what the
   best-in-class version of this would look like and what it would cost, so the user picks the
   ceiling instead of silently inheriting the floor.
3. Emit the **ADR decision block**:
   - Product outcome (who it helps · success signal · non-goals)
   - Context / forced trade-offs
   - Decision (one sentence)
   - Alternatives considered (why rejected, including externally researched options when step 0 fired)
   - Riskiest assumption (if wrong, the plan collapses) + smallest test that validates it
   - Blast radius · Reversibility / rollback · Hidden coupling

   When a fresh Cortex graph exists, Blast radius and Hidden coupling must cite `cortex graph
   impact` plus relevant `neighbors|path` evidence. If graph coverage is unsupported for the language
   or unavailable, say `graph-unavailable` and document the manual caller/consumer search used instead.

**Gate = inline evidence review by default.** Proceed to Phase 3 after the ADR survives the embedded
lenses and evidence checks. `/covenant` is an explicit opt-in external review, never an automatic
condition of planning or execution. Stop only for a hard blocker.

### Minimize decision gate

Before GoalRoute or task decomposition, compile a sibling `minimize-decision.v1` sidecar through
`$LEGION/bin/legion.mjs minimize decision`. Test rungs in canonical order, select first safe rung, record
evidence rejecting every earlier rung, declare allowed new files/dependencies, and write exact-byte
receipt. Keep this internal authority out of user-facing plan prose. Any semantic correction,
undeclared file/dependency, or changed policy invalidates decision plus all downstream route work.

### GoalRoute v2 — implementation strategy gate

After ADR selects target design and before Phase 3 decomposes tasks, compile GoalRoute through the
internal engine to compare complete
implementation strategies to that same target. Write `<plan-name>.route.json` plus receipt beside plan.

- A = current verified repo/system state.
- B = ADR outcome with executable acceptance proof.
- Constraints preserve authority, safety, scope, quality/behavior, compatibility, rollback, and cost.
- Candidate routes include characterization/migration/rewiring/verification dependencies, nominal
  critical path, retry probability, terminal-failure rework, cost, risk, and rework.
- Winner minimizes expected time to verified B, not happy-path wall time or smallest patch.

Validate through `tools/lib/goalroute/scripts/validate-route.py`. Phase-3 file map and tasks must bind
one-to-one to selected route DAG and dependency order. Independent route lanes may fan out; shared
state/hot files serialize. Architect owns target design and route. Dispatch may package it and Script
may optimize execution, but neither may silently redesign it. Semantic correction or changed
constraints invalidate route from root and require a new receipt.

> **Superseded:** "Dispatch may package it" — the retired `dispatch` skill's packaging role is now
> Legion's worker-capsule/relay doctrine (`doctrine/bundles/legion-worker-capsule.md`) when the
> executor is a cheap worker, or Alchemist directly when the executor is a native subagent.

### Phase 3 — Implementation plan (only when planning/change was requested)
Write the taskable plan assuming the worker has zero context for this codebase and questionable
taste — spell everything out. Save to `docs/plans/YYYY-MM-DD-<feature>.md`. **MANDATORY OKF emit (Skill Output Contract):** then `skill-emit report <plan.md> --type design --repo <repo>` makes the design/ADR plan recallable OKF knowledge in the memory engine.
This is the human-recall path. **Federated decision records (G5 Lane A):** the typed Architect
decision store at `<repo>/.audit/architect/decisions.jsonl` is the planner-facing authority.
A `proposed` decision emitted at plan time must be re-emitted with `status: accepted` (after the
applicable inline or explicitly requested review gate) and again with `status: implemented` (after the plan lands) — the typed
lifecycle governs what the planner admits as current; the OKF emit does not. An `implemented`
record must carry non-empty `implementationRefs` so the citation is reconstructable.

**Header:** Goal (1 sentence) · Architecture (2-3 sentences) · Visual Plan (name it) · Tech Stack ·
GoalRoute artifact/receipt/selected route/expected time/revision.
When the solution-space gate fired, place the prior-art decision matrix immediately after the ADR;
the implementation tasks must carry every `adopt|morph` row and every `defer` validation gate.

**Visual** (near the top, non-trivial work = >2 files, or UI/data/API/schema change, or
multi-phase): `mermaid` by default, else file tree / before-after table / decision matrix. Compact,
tied to the plan.

**File map:** every file created/modified + its single responsibility. Decomposition locks here —
files that change together live together; prefer small focused files; in existing code follow the
established structure.

**Audit decomposition handoff:** when Architect is invoked for a confirmed Audit decomposition
candidate, return a machine-foldable `decomposition_plan` in addition to the plan doc. It MUST name:
the independently changing current responsibilities with symbols and `file:line` evidence; the
component/responsibility that stays; every target component, destination file, moved symbol,
dependency and public contract; ordered characterization/extraction/rewiring steps with a verification
gate per step; behavior-preservation contracts; risks (at least one — every decomposition has a
hazard); and this plan's path as `architect_decision_ref`. The ref must be a repo-relative regular file under `.audit/` or
`docs/plans/` — the audit renderer validates it physically (realpath containment + isFile) and
rejects absolute paths, `../` escapes, directories, and symlink/junction hops out of the repo. Its location follows the caller's write boundary: a read-only `/audit`
handoff writes the decision artifact under `<repo>/.audit/<ts>/architect/` (or appends to the typed
store `<repo>/.audit/architect/decisions.jsonl`), never `docs/plans/`; audit-fix or a direct
Architect engagement may write `docs/plans/` as usual. LOC reduction is not a design goal and cannot
justify a boundary.

> **Superseded:** "`/audit`" now means Oracle's audit route (the `legion` CLI-backed assurance pass).
> "Audit-fix" means Oracle routing a deterministic finding to remediation per its own doctrine
> (`doctrine/oracle.md` §Audit-fix routing) rather than a separate skill.
> **Superseded:** original history used `Seer`; current authority is `Oracle`.

**Tasks:** derive task order from selected GoalRoute DAG, then use bite-sized
**red-green-refactor TDD** per behavior change:
1. smallest failing test → 2. run, verify it fails for the right reason → 3. minimal code to pass →
4. run focused test + relevant suite → 5. record status.
Each task: exact file paths · **complete code in every code step** · exact commands + expected output.
**No placeholders** — "TBD", "add error handling", "handle edge cases", "similar to Task N",
"write tests for the above" are plan failures. No commit steps unless the user asked.

**Verification patterns for non-behavior work — choose proportionately:**
- **Refactor** (behavior preserved, structure changed): add characterization/invariant tests first,
  refactor, then prove behavior is unchanged. Add a regression test when exploration exposes an
  unprotected edge; do not intentionally change behavior inside the refactor slice.
- **Schema migration**: use expand-contract (new shape → dual-write → backfill → switch reads →
  remove old shape) **when backward compatibility or live traffic requires it**. An offline,
  additive, or local-config migration may use a smaller reversible path with an explicit rollback.
- **Library swap**: define contract/parity tests at the dependency boundary. Use parallel-run and a
  feature flag only when the swap is behavior-sensitive, high-risk, or needs gradual rollout.
- **Performance optimization**: capture a representative baseline first, optimize one variable,
  then prove the target metric improved without violating correctness (or revert).

End with the implementation handle (CodeRight contract):
```
### Critical Files for Implementation
- path/to/file1.ts
- path/to/file2.ts   (3-5 most critical)
```

## Self-review (inline — same context)
1. **Spec coverage** — every requirement maps to a task? list gaps, add tasks.
2. **Placeholder scan** — fix any TBD / vague-handling / missing-code.
3. **Type consistency** — names/signatures match across tasks (`clearLayers()` in Task 3 vs
   `clearFullLayers()` in Task 7 is a bug).
4. **Visual check** — does the visual clarify on first read? If not, simplify.
Fix inline; don't re-review.

**Note:** self-review is intentionally inline (same context). It catches mechanical errors and
challenges claims against evidence. It does not claim independence. External `/covenant` review is
explicit opt-in only and, when requested, reports its separate verdict.

## Gate + handoff
- **External review is explicit opt-in for every design.** Apply the risk/blast-radius definition
  above and complete inline evidence review. Run `/covenant` or `runAutoJury` only when Adrian names
  that mechanism; ordinary substantive work proceeds without an external gate.
- When requested, Covenant advises and its internal Jury reports a verdict; neither wins merely
  because of its label. Resolve conflicting claims with code, tests, logs, or a targeted rerun. Adrian
  remains the taste/visual authority and the escalation point for genuinely unresolved decisions.
- Proceed to execution: **native fan-out** (parallel Claude subagents — no external model APIs) for independent workstreams, or **inline** with checkpoints. Do not create worktrees/branches unless explicitly asked.

> **Superseded:** "Proceed to execution" now means compiling the Execution Compile route and
> handing the sealed contract to Alchemist — Sage never performs the effect itself (see
> `doctrine/sage.md` Boundaries).

**Fan-out coordination protocol (multi-workstream):** give each worker OWN (may edit) / READ
(read-only) / FORBIDDEN scope plus an explicit output contract. In the **same parallel wave**, two
workers must not edit overlapping files or the same shared component/config/schema; assign one
owner or use a serialized handoff for hot files. Serialize builds/renders/installs only when they
contend for the same output or resource. The orchestrator assigns scopes from the plan, synthesizes
instead of dumping outputs, integrates, then verifies the combined result. Ask Adrian only when the
remaining ambiguity is a true reserved decision or blocker.

## Hard rules
- Read-only until the plan doc is written (no production code).
- Visual near the top for non-trivial work.
- Every code step shows complete code + exact command + expected output; no placeholders.
- End with the `### Critical Files for Implementation` list.
- **Best-shape truth gate:** never say or imply `best`, `complete`, `optimal`, or `best-in-class` while
  a material Cortex coverage gap is unsearched, `undetermined`, or `defer` without a named gate.
  The honest status is "internally hardened; external solution-space review incomplete."
