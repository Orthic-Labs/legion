# Archived Legion Architecture Synthesis

> Historical research only. `docs/LEGION-CANONICAL-SSOT.md` supersedes all architecture claims here.

**Date:** 17 August 2026
**Status:** archived, non-normative research provenance.
**Question this document answers:** not *"which of these 18 repos' features should we copy?"* but *"what is the smallest whole-system shape that keeps every Legion invariant true, and which of the candidate shapes is it?"*

**Its load-bearing claim** is Part VI: Legion's honesty controls should be two cheap adversaries rather than an accumulating chain of producer-side artifacts — one adversary checking that a shape is not more than was asked, one checking that a completion claim is true — and the receipt/packet/seal machinery those adversaries supersede should be deleted in the same change that adds them.

**Inputs.**

1. Legion as it exists at `7eb184a` — measured, not described (Part I).
2. `dsv4flash/` — 18 commit-pinned absorb-lists over the agent-skills / agent-harness ecosystem (16 with code, 2 catalog-only).
3. The existing `docs/research/2026-08-12-legion-architecture-book-final.md` (3,324 lines, five stacked amendments) and current doctrine under `doctrine/`.

**What supersedes what.** This document does not supersede the Architecture Book's *rules*. It supersedes its *shape*: the Book is a constitution that grew by amendment, and amendment growth is the specific failure this synthesis is meant to stop. Every `G-A*` rule survives; where it survives it is relocated to exactly one of the five layers in Part IV, and the relocation is the deliverable.

---

## Part I — Legion as measured, not as described

Counts at `7eb184a`, excluding `node_modules`:

| Area | Files | What it is |
|---|---:|---|
| `skills/` | 762 | 27 skills; the largest single mass in the repo |
| `qualification/` | 322 | certification books |
| `lib/` | 297 | the actual engine (44 subsystems) |
| `packages/` | 272 | `arcane`, `contracts`, `kernel`, `oracle`, `context` |
| `providers/` | 256 | deterministic evidence producers |
| `tests/` | 222 | |
| `bench/` | 154 | |
| `schemas/` | 120 (44 top-level entries) | |
| `doctrine/` | 118 | prose authority |
| `registry/` | 112 | routing/control/provider data |

Three structural facts follow from those numbers, and they set the whole problem:

**F1 — Legion is already a platform, and is still governed as a document.** 297 `lib/` files and 272 `packages/` files implement behavior; 118 `doctrine/` files plus a 3,324-line Book assert behavior. The two are coupled by prose and by `canon-map.md`, not by types. Every corpus repo that got this right (swe-agent, mini-swe-agent, agentfield, SWE-AF) has the opposite ratio: a small typed core that *is* the rule, and documentation that merely explains it.

**F2 — The Book's growth mode is amendment, and amendments do not delete.** Five amendments in two days (control-closure, external-practices, control-integrity, finalization, plus the base synthesis) each added controls; none retired any. The Book itself now carries a clause that no further amendment is admissible without material invalidation evidence — which is a freeze, not a shape. A constitution that can only grow is the ceremony source the user is asking to cut.

**F3 — The invariants are excellent and the enforcement is uneven.** "No false clean", "independent Oracle before final delivery", "one canonical owner per concept", "reconstruct scope from raw user turns", "bounded execution" are the right five invariants — better stated than anything in the corpus. But four of the five are enforced by an agent reading prose and choosing to comply. trailofbits, obra, mini-swe-agent, and swe-agent each enforce their weaker equivalents mechanically.

**The gap is not an idea gap. It is an enforcement-locus gap** — the same conclusion the Book's own external-practices amendment reached, restated as an architecture problem instead of a control list.

---

## Part II — What the system must actually do

Stripped of vocabulary, Legion has five jobs. Any candidate architecture is judged on all five.

- **J1 Route.** Given a request, pick tier (answer / ambient / Sage / contract / Oracle) and domain, and dispatch.
- **J2 Execute under bounds.** Do bounded transformations without unbounded loops, unbounded cost, or silent scope growth.
- **J3 Prove.** Produce evidence that survives an adversary who assumes the producer is lying.
- **J4 Gate.** Deny classified effects; stop on ceilings; require independent validation before "done".
- **J5 Evolve.** Absorb new capability without the doctrine mass growing faster than the engine.

And it must do all five while satisfying the standing constraint the user restated: **ceremony proportional to blast radius**. A twenty-minute change must not cost twenty minutes of process. The Book already says this (tier 2, ambient default). The architecture must make it structurally true rather than rhetorically true.

**Evaluation criteria** (used for dominance elimination in Part III):

| | Criterion |
|---|---|
| C1 | Invariants are machine-checked, not prose-checked |
| C2 | Ceremony scales with blast radius (near-zero at tier 2) |
| C3 | Doctrine mass grows sub-linearly with capability |
| C4 | One canonical owner per concept is enforceable, not just asserted |
| C5 | Adding a domain/skill is additive, touching no core |
| C6 | Failure modes are typed and distinguishable (budget vs format vs policy vs defect) |
| C7 | Portable across hosts (Claude Code, Codex, others) without duplicated truth |
| C8 | Migratable from today's tree in stages, each stage shippable |

---

## Part III — Five candidate whole-system architectures

These are genuinely different shapes, not variations of one. Each is described as if it were the whole answer, then eliminated or kept on evidence.

### A. Constitutional monolith (status quo, extended)

One canonical Book plus a doctrine tree; the engine implements what the Book says; conformance is prose review plus `legion:check`. New capability arrives as a new Part or amendment.

- **For:** zero migration cost; the reasoning stays in one readable place; genuinely strong at C4 in intent.
- **Against:** fails C1 (prose enforcement), C3 (the Book is 3,324 lines and every amendment grew it), C2 (a reader must load constitutional context before deciding a tier-2 change is tier-2). Measured F2 is this architecture's failure mode, observed.
- **Verdict: eliminated.** Not because the Book is wrong — because *document* is the wrong enforcement locus for an engine of this size. Its content survives; its role does not.

### B. Distributed control plane (agentfield shape)

A service — typed event bus, execution state machine, OTel spans, scoped memory, approval service integration, BM25 agent discovery. Roles become workers on the bus; Arcane becomes a state-guarded transition set; receipts become bus events.

- **For:** strongest C1 and C6 in the corpus; genuinely excellent observability; execution lifecycle becomes checkable.
- **Against:** fails C2 catastrophically. Every tier-2 change acquires an execution id, a lifecycle, and a transport. Fails C8 — there is no shippable first stage that isn't "stand up a control plane." Adds a process boundary, which is exactly the Distribution Tax the Book's own MINIMIZE phase requires you to justify, and there is no justification: Legion is one operator, one workspace, one process.
- **Verdict: eliminated as a shape.** Its *state machine* and *typed event* ideas are absorbed into the winner as in-process constructs (Part IV, L2/L4).

### C. Nested-loop harness (SWE-AF / swe-agent shape)

The system is fundamentally three nested bounded loops — plan-revision (outer), adaptation (middle), repair (inner) — each with an explicit numeric budget, typed terminal results, a checkpoint file, and seam-injected `CallFn`/`MemoryFn`/`NoteFn`.

- **For:** near-perfect C6 and strong C1 for the execution half; the *exact* mechanical form of Legion's "one repair plus one recheck", "third revision forces a terminal choice", and `BUDGET_STOP`, which today are numbers written in prose. Directly checkpointable, therefore resumable, therefore auditable.
- **Against:** silent on J1 routing and J5 evolution — it assumes the task already arrived, and it says nothing about how 27 skills stay non-overlapping.
- **Verdict: kept as the execution core.** It is the right answer to J2/J4 and a partial answer to J3. It is not the whole architecture.

### D. Skill federation with a thin kernel (mattpocock / trailofbits / LambdaTest shape)

The system is a curated catalog of self-contained capability packs. Each pack owns its skill file, its scripts, its references, its eval corpus, and its manifest entry. A small kernel does routing, invocation-scope enforcement, and packaging. Nothing is shared except the kernel and the schema.

- **For:** strongest C5, C3, and C7 in the corpus. `trailofbits` runs 40+ plugins this way; `mattpocock` adds promoted/in-progress/deprecated buckets so drafts exist without shipping; `LambdaTest` makes "no capability without an eval corpus" structural (44 skills, 44 eval files).
- **Against:** weak on C1 for cross-cutting invariants — a federation has no natural home for "no false clean". Weak on C6.
- **Verdict: kept as the capability layer.** It is the right answer to J5 and the right shape for `skills/`' 762 files, which today have no promotion model at all.

### E. Policy-as-data (coderabbit / hookify shape)

Behavior lives in versioned config — review policy YAML with `mode: error` gates and per-path instructions, declarative hook rules (field/operator/pattern → warn|block) executed by a ~200-line engine. Doctrine becomes data; the engine is small and stable.

- **For:** excellent C1 and C3 for *gate-shaped* rules; makes Oracle's PASS/BLOCK reproducible rather than narrated; rules are editable without touching engine code.
- **Against:** cannot express the judgment half of Legion. "Is this the right architecture for this problem" is not a pattern match, and forcing it into one produces the checklist theatre Legion explicitly rejects.
- **Verdict: kept as the gate layer, bounded.** Data expresses *deny/allow/block*; it never expresses *decide*.

### Dominance elimination

A dominates B when it is at least equal on all eight criteria and better on one. On that test: **A is dominated by D** (D wins C1/C2/C3/C5, ties elsewhere) and **B is dominated by C** (C wins C2/C8 and matches C6, at the cost of C1-for-observability only, which is recoverable in-process). A and B are out. C, D, E survive and are non-dominated with respect to each other — C owns execution, D owns capability, E owns gates. **Three non-dominated candidates covering disjoint jobs is not a tie; it is a decomposition.** The answer is their composition, and the architecture's real work is defining the seams between them so the composition doesn't become a fourth thing.

---

## Part IV — The chosen architecture: five layers, one loop, four numbers, three artifacts

> **The whole system in one sentence:** a thin typed kernel runs one bounded loop over a federation of self-contained capability packs, with deny-shaped rules expressed as data and honesty enforced by two cheap adversaries — one that checks the shape isn't more than was asked, one that checks the claim is true — instead of by artifacts the producer emits about itself.

### The five layers

```
L5  CAPABILITY PACKS        skills/*, providers/*, lenses/*  — federated, self-contained, additive
     ↑ declares                                                (candidate D)
L4  GATES (data)            registry/*.json, policy files    — deny/allow/block/require; no judgment
     ↑ constrains                                              (candidate E)
L3  ROLES                   Sage · Alchemist · Oracle        — judgment; the only layer that decides
     ↑ dispatched by                                           (unchanged from today)
L2  LOOP                    bounded execute → verify → gate  — four numbers, typed results, checkpointed
     ↑ driven by                                               (candidate C)
L1  KERNEL                  types, state, seams, receipts    — small, stable, the only shared truth
```

Ownership is strict and one-directional: **L1 knows nothing about L5.** A capability pack may not reach into the kernel; it declares, and the kernel reads its declaration. This is what makes C5 (additive growth) true rather than aspirational, and it is the single rule most likely to be violated during migration — Part IX gates on it.

### The one loop (L2)

Legion has exactly one execution loop, parameterized by tier. There is no separate ambient path, contract path, and audit path — there is one loop whose budgets and gate set differ.

```
open(unit)                     → typed Unit{scope, tier, budgets, gates}
  while not terminal:
    act()                      → effect proposal
    gate(proposal)             → L4 data check: allow | deny | require-approval
    apply()                    → Arcane authorizes classified effects; journal appends
    verify()                   → proportional to blast radius, NOT proportional to tier ceremony
    decide()                   → CONTINUE | REPAIR | ESCALATE | terminal
  close(unit)                  → typed Result + checkpoint + adversary verdict (Part VI)
```

Terminal results are types, never prose and never exceptions: `DONE | REPAIR_EXHAUSTED | BLOCKED_DECISION | BUDGET_STOP | FAILED_CONTRACT | NEEDS_AMENDMENT`. Only two things throw: fatal harness error and cancellation (SWE-AF's rule; adopted verbatim because the alternative — a recoverable condition escaping as an exception — is how "no false clean" gets violated by accident rather than by dishonesty).

### The four numbers

Every dispatched unit at every tier carries all four, and the loop stops on arithmetic rather than on judgment (mini-swe-agent's whole stopping contract, adopted):

```
step_limit                    steps before forced terminal
cost_limit                    spend before forced terminal
wall_time_limit_seconds       authenticated waits alone pause the clock
max_consecutive_same_class    N identical-fingerprint failures → stop, do not retry
```

The fourth is the mechanical form of Legion's existing "same failure fingerprint without material change stops rather than retries", and of the Book's absolute revision ceiling of 3. `BUDGET_STOP` becomes a computed predicate over accumulated stats — `remaining < min_budget_for_new_attempt` — not a decision anyone makes. The 10%-variance allowance stays, but as a constant in the predicate, not a discretionary grant.

### The three artifacts

The loop persists exactly three things, and nothing else is durable by default (this is the ceremony cut, made structural):

1. **Trajectory** — append-only per-session JSON journal of `{timestamp, event_type, payload}`. Written as a side effect of the loop, always, at every tier. Costs nothing (NeoLabHQ proves the pattern at ~40 lines; mini-swe-agent proves it is free at the core).
2. **Checkpoint** — the resumable unit state, written at each level boundary; crash → reload → resume (SWE-AF).
3. **Authorization log** — Arcane's record that a classified effect was approved and applied. Narrow by design: it proves *permission*, never *correctness*. Correctness is Part VI's job.

Per-item evidence files on disk exist in exactly one case — an operator-invoked full audit, where the subject is too large for one pass. They are not part of ordinary delivery.

Everything else Legion writes today — plans, receipts-as-documents, ledgers, review artifacts — is either derived from these three or is ceremony, and Part VII names which.

### Where ceremony actually goes

The loop is uniform; the *ceremony* is a function of blast radius, and it is computed, not chosen:

| Tier | Gates active | Persisted | Oracle |
|---|---|---|---|
| Answer | none | trajectory | validation on the answer's claims |
| Ambient (default) | L4 deny-set only | trajectory | Completion Validation |
| Sage | + decision record | trajectory + ADR | Completion Validation |
| Contract | + all locked-domain gates | all three artifacts | full independent packet |

The critical property: **a tier-2 change runs the same loop with three of four gate categories inactive and one artifact written automatically.** The twenty-minute change costs twenty minutes because the machinery is the same machinery, configured down — not because a human remembered to skip steps.

---

## Part V — What each corpus repo contributes, by layer

Only mechanisms that survive the whole-system argument appear here. Everything else is in Part VIII (rejected) — including two repos that contribute nothing, which is itself a finding.

### L1 Kernel

| From | Mechanism | Why it belongs in the kernel |
|---|---|---|
| swe-agent, mini-swe-agent | Typed exceptions for harness control flow; typed results for everything else | The single most transferable idea in the corpus; makes C6 true |
| NeoLabHQ | Typed host-payload model, compiled once | The host API changes; a compile-checked contract against it beats defensive parsing in 40 places |
| NeoLabHQ | Append-only per-session journal | Legion's receipts and Oracle evidence get one substrate instead of several |
| SWE-AF | Seam-injected `CallFn`/`MemoryFn`/`NoteFn` | The same loop must run under test double and live agent, or the loop is untestable and therefore unenforced |
| gstack, SWE-AF | Small JSON state file per unit of work | Inspectable, resumable, cheap |
| mini-swe-agent | `StrictUndefined` template rendering with runtime-state merge | A contract with an unbound placeholder must not ship silently |
| swe-agent | Prompt-cache-aware history shaping | Legion carries heavy doctrine context; this is a direct cost lever |

### L2 Loop

| From | Mechanism |
|---|---|
| mini-swe-agent | The four numeric limits as the entire stopping contract |
| mini-swe-agent | `max_consecutive_format_errors` generalized to same-class-failure counting |
| swe-agent | Budget-aware retry as arithmetic (`cost_limit`, `max_attempts`, `min_budget_for_new_attempt`) |
| swe-agent | Chooser vs scorer retry semantics — rank candidates when Alchemist produces several; gate when it produces one |
| SWE-AF | Nested loops with independent budgets; recoverable conditions as data, fatal as exceptions |
| SWE-AF | Adaptation outcomes incl. **accept-with-debt** as a first-class terminal, with debt riding along in the result |
| SWE-AF | Checkpoint-per-level with tolerant decoding of legacy shapes |
| swe-agent | Trajectory replay as the grading substrate — replay beats live re-run for evidence |
| gstack | Two-path iteration: try context threading, fall back to accumulated-feedback prompt |
| gstack | Staggered parallel calls + exponential backoff on 429 |

### L3 Roles

| From | Mechanism |
|---|---|
| **trailofbits** `spec-to-code-compliance` | **The Oracle design spec** — see Part VI. Requirement-split, one fresh agent per requirement, refutation by non-authors, bound-schema records, per-requirement evidence files, explicit anti-inline rationale |
| obra | The Iron Law + 5-step verification gate as an executable procedure with a claim→evidence table |
| the Book's own Distribution Tax + MINIMIZE ladder | Given a dispatcher — the Scope Adversary — instead of remaining a rule the author applies to their own proposal |
| obra | "Rulings, not stalls" with a `Ruling: what — why — cost if wrong` ledger line, and exactly four stop conditions |
| obra | Subagent dispatch with crafted context and pinned SHAs, never session history |
| swe-agent | `ReviewSubmission` carries the whole trajectory + stats — the reviewer sees everything or the review is theatre |
| NeoLabHQ | Kaizen-style separate diagnosis modes (5-whys, cause-effect, root-cause-tracing) for Sage's Diagnose |
| trailofbits | External-model second opinion as a cheap, well-scoped escalation for strong-tier calls |

### L4 Gates (data)

| From | Mechanism |
|---|---|
| coderabbit | Review policy as versioned config: named checks with `mode: error`, per-path instructions, `inheritance: false` |
| claude-code `hookify` | Declarative rule files (field/operator/pattern → warn\|block) + a ~200-line engine |
| gstack | Freeze-boundary PreToolUse deny for locked domains (`tools/rhook/**`, `qualification/**`), permissive when unconfigured |
| instructa | Commit/PR policy as a config file with plan/apply split and `--json` output |
| NeoLabHQ | Cycle-safe Stop handler: consecutive-STOP detection, relevant-event filtering, block with a specific instruction |
| NeoLabHQ | `(?<![:/])\bword\b` — trigger detection that cannot trigger itself |
| claude-code, EricGrill | Defensive stop-hook discipline: validate numerics before arithmetic, corrupt state → warn + clean removal |
| agentfield | Approval as a **state transition with external metadata**, not a blocking call inside execution |
| SWE-AF | Gates that degrade explicitly — no-op with a loud note when the approval substrate is absent, never block forever |
| mattpocock, trailofbits | `disable-model-invocation` / `allow_implicit_invocation: false` on every destructive or user-gated capability, in both host manifests |

### L5 Capability packs

| From | Mechanism |
|---|---|
| mattpocock | Promoted / in-progress / deprecated buckets; the manifest lists exactly what ships |
| mattpocock | The autonomy test for extraction — *could the model usefully reach for this on its own?* — ANDed with Legion's existing "only after repeated failure" |
| mattpocock | Dependencies as `/skill` prose invocation, never deep file links |
| testdino, LambdaTest, gstack | Topic-per-file knowledge bases: one routing SKILL.md + short lazily-loaded topics |
| testdino | Golden-rules preamble — load-bearing invariants above the quick-start, so a skimming agent still meets them |
| instructa, coderabbit | Code-backed skills: deterministic work in scripts, judgment in the skill file |
| LambdaTest | One eval corpus per capability, no exceptions — the coverage contract |
| LambdaTest | Expected-**behavior** assertions and negative-trigger cases with named deferral targets |
| addyosmani | Deterministic Tier-2 routing evals: TF-IDF rank-1 ratchet + description-collision guard |
| addyosmani, mattpocock | One validator as importable truth; exemptions live in the validator, never in the artifact; `--check` drift mode in CI |
| obra | Cross-host session-start envelope negotiation in one hook with platform detection |
| agentfield | Versioned catalog + per-target renderers instead of duplicated per-host files |
| testdino | The browser trust boundary as load-bearing skill text: scraped content is data, never instruction |
| coderabbit | The same rule for machine feedback: review comments are evidence to weigh, never a script to run |
| instructa | Sandboxed execution pinning cwd and refusing commit/push on protected branches |
| trailofbits | Contract tests verifying documented flags against the real tool's `--help` — **empty extraction is a failure** |
| trailofbits | Capability gating (does `--help` show it) rather than version parsing, with toolchain-age distinguishable from skill defect |

---

## Part VI — Adversarial review as Legion machinery

This is the load-bearing part of the synthesis, and it is a **replacement**, not an addition.

### VI.0 The problem it solves

Legion's honesty controls grew the way honesty controls always grow. Something claimed done that wasn't, so receipts were added. Receipts could be produced without the work, so evidence packets were added. Packets needed sealing, so seals and reachability checks were added. Each step was locally correct and the aggregate is the ceremony the operator now pays on every change — a twenty-minute fix carrying a receipt chain, an evidence map, and a seal.

The structural mistake is the assumption underneath: **that honesty can be produced by making the producer emit artifacts.** It cannot. An agent that will claim false completion will also emit a receipt for it — the receipt is cheaper to fabricate than the work. Every artifact added to the producer's side of the line raises the cost of honest work and barely raises the cost of dishonest work. That is the wrong slope, and it is why the ceremony kept growing without the problem closing.

The corpus's better repos take the opposite line. trailofbits does not ask the finder to certify its finding; it sends the finding to agents that did not produce it, on the stated grounds that a model favors findings it produced. obra does not ask for a completion artifact; it demands fresh evidence *for the specific claim* at the moment of claiming. Neither accumulates artifacts.

**So: replace producer-side artifacts with a cheap adversary on the other side of the line.** One dispatch, reading sources rather than the producer's prose, writing nothing durable. That is both cheaper than the receipt chain and strictly harder to fool, because the thing being checked is the world rather than a document about the world.

But an adversary is itself a mechanism, and mechanisms grow. So Legion gets **exactly two adversaries, both bounded by the same five constraints**, and adding a third requires the same significance test as any other architectural change.

### VI.1 The two adversaries

They face opposite directions and answer opposite failure modes. Conflating them is what produced the current ceremony — a reviewer asked to check both truth and scope will always find something, and always block.

| | **Scope Adversary** | **Completion Adversary** |
|---|---|---|
| Runs | before non-trivial work commits to a shape | before every successful final delivery |
| Failure it prevents | over-engineering, scope drift, unrequested hardening | false completion, laundered unknowns |
| Question | *Is this more than was asked, or more machinery than the problem needs?* | *Is what is claimed actually true of the source?* |
| Reads | the raw request + the proposed shape | the raw request + the actual diff/artifact |
| May block on | scope expansion; unjustified new mechanism; new boundary | incorrect requested behavior; regression; data loss; concrete safety failure |
| May never block on | implementation taste, naming, style | taste, adjacent concerns, missing ceremony, absent receipts |
| Owner | Sage seat, dispatched independently | Oracle |
| Cost | one dispatch, no artifact | one dispatch, no artifact |

The Completion Adversary is Oracle, and its contract is unchanged in every respect that matters: read-only, semantic, source-first, no test reruns, no durable artifact, one repair plus one recheck, second BLOCK returns to the operator, and the four blocking criteria stay exactly four. What VI.3 adds is *rigor of looking* and *what it must record in-band* — never a wider licence to block.

The Scope Adversary is new as a named role, and it is the half Legion is missing. Every honesty control it has points at the end of the work. Nothing points at the beginning, which is why over-engineering has only ever been caught by the operator noticing.

### VI.2 The five constraints that keep an adversary from becoming ceremony

These bind both adversaries. An adversary violating any of them is a defect in the adversary, not a finding about the work.

1. **One dispatch, one round.** No recursive assurance — the existing `G14` reasoning generalizes. The Scope Adversary runs once per shape; the Completion Adversary runs once, plus at most one fresh recheck after repair.
2. **Writes nothing durable.** No receipt, no ledger, no packet, no review file. Its output is a chat-scale verdict that lives in the trajectory like everything else. This is what makes it cheap, and it is non-negotiable — the moment an adversary produces an artifact, that artifact acquires a lifecycle, and the lifecycle is the ceremony.
3. **Closed blocking list.** Each adversary may block only on its own named criteria above. Everything else it notices is reported as a note and does not gate. A finding outside the list that turns out to matter is the operator's call, not the adversary's.
4. **Scoped to the request, reconstructed from raw turns.** Never from the producer's summary. It cannot widen the objective; an adjacent concern is reported as out-of-scope, never converted into a gate.
5. **Proportional to blast radius.** Both adversaries are budgeted by the same four numbers as any other unit. A tier-2 change gets a tier-2 adversary — a single pass, minutes, no split. This is the constraint that makes the cheap path stay cheap.

### VI.3 The Completion Adversary — mechanism

Four mechanisms, imported because they raise the cost of a false pass without raising the cost of an honest one.

**The Iron Law** (obra), as an executable gate rather than a principle: identify the command or source that would prove the claim → consult it fresh → read the full output *and* exit code → confirm it proves *this specific* claim → only then claim. Skipping a step is not sloppiness; it is asserting something unchecked.

**Requirement-split for multi-requirement deliveries** (trailofbits). One fresh agent per requirement, each with its own context. The rationale from the source is worth keeping in doctrine because it names the exact failure: honest per-requirement checking does not fit in one context window — inlined, the first few requirements get real checks and the rest get plausible ones, and a verdict resting on a promising function name reads exactly like one resting on having read the function. Single-requirement deliveries do not split; this is where constraint 5 does its work.

**Refutation by non-authors** (trailofbits). Every verdict — including a PASS — is checkable by an agent that did not produce it: one re-reads the source, one re-reads the request. This is the mechanism that replaces the seal. A seal asserts that work was verified; a refutation attempt actually tries to break the verification, and either breaks it or does not.

**Records that cannot be prose.** The adversary returns which sources it read and which searches it ran, in-band, in its verdict. Not as a file — as fields. `absent` verdicts carry the patterns tried and their results, so a real absence is distinguishable from a search that stopped early. And **an empty record is a BLOCK, not a PASS**: a validation that found nothing to check has not checked anything. This single rule does what the entire receipt chain was trying to do, at the cost of two lines in a verdict.

Two supporting guards, both mechanical: consecutive-invocation detection so the completion gate cannot cycle (NeoLabHQ), and an authority-pressure test suite (obra) that feeds *"I know what this means"*, *"skip the formalities"*, *"you already checked this"* and asserts the gate still fires. Invariants that erode under operator pressure must be tested under operator pressure.

### VI.4 The Scope Adversary — mechanism

It answers one question in two halves, and it can only answer *more than asked*, *right-sized*, or *under-built*.

**Half one — scope.** Reconstruct the request from raw turns. List what the proposed shape will change. Anything on the second list not implied by the first is flagged. Unrequested hardening, adjacent cleanup, and "while we're here" are the named patterns. Legion already has the rule ("no silent scope expansion"); this gives it a checker that is not the same context that wrote the plan.

**Half two — mechanism cost.** Three tests, in order, and the first failure is a block:

1. **New-boundary test.** Does this add a process, service, daemon, transport, store, or distributed state? If yes, it must carry an explicit justification naming what fails without it. (This is the Book's existing Distribution Tax, given a dispatcher. Candidate B in Part III dies on this test, correctly.)
2. **Reuse test.** Does a capability that already exists do this? Legion has 297 `lib/` files and 272 `packages/` files; the default answer to "we need a mechanism for X" is that one exists.
3. **Ladder test.** Is there a version of this with one fewer moving part that satisfies the actual request rather than the anticipated one? Anticipated requirements are the ones that produce ceremony.

**Its most important power is to block Legion's own machinery from growing.** A proposed new control, gate, receipt type, or doctrine rule goes through the Scope Adversary like any other change, and the new-boundary and ladder tests apply to it. That is the mechanism that keeps Part I's F2 — amendment growth with no retirement — from happening again. It is also the reason this document does not add a `G-A` law: it would not survive its own gate.

**When it runs.** Not on every prompt. It runs when a shape is proposed that is (a) tier 3 or above, (b) adds a mechanism rather than changing behavior, or (c) touches Legion's own control surfaces. A tier-2 edit does not convene an adversary to ask whether it is over-built — that would be the exact ceremony this replaces.

### VI.5 What this retires

The adversary pair is only a win if the machinery it supersedes is actually deleted. Proposed retirements, contingent on the pair landing (Part IX Stage 2):

| Retired | Because |
|---|---|
| Receipts as *proof of honest work* | Never proved it; a false claim emits a receipt as easily as a true one. Receipts survive **only** in Arcane's narrow role: recording that a classified effect was authorized and applied. That is an authorization log, not an honesty control, and it stays. |
| Evidence packets and seals for ordinary delivery | Replaced by refutation-by-non-author plus in-band records. Sealed independent packets remain for operator-invoked full audits, where the subject is too large for one pass. |
| Completion-gate evidence maps at tiers 1–3 | Replaced by the Iron Law gate. Line-rate evidence maps stay for contracted work only, as doctrine already says and practice does not. |
| Plans and process files as a precondition for work | Replaced by the Scope Adversary. A plan reviewed by its author is not a control; a shape checked by a non-author is. |
| Self-certification of any kind | Structurally impossible under refutation-by-non-author, which is the point. |

The net accounting, stated plainly so it can be checked: this part **adds** one role (Scope Adversary), one record shape (sources-read/searches-run, in-band), and one test suite (authority pressure). It **removes** receipts-as-honesty, packets, seals, evidence maps below tier 4, and precondition plans. Two dispatches replace an artifact chain. If the removals do not land, the additions are not worth making, and Stage 2 should be reverted rather than half-adopted.

---

## Part VII — What gets deleted

Ceremony is not cut by resolving to be less ceremonious. It is cut by deleting the artifacts that carry it. Proposed retirements, each with what replaces it:

| Retire | Replaced by | Why |
|---|---|---|
| The Book's amendment-stacking mode | Layer-assigned rules + this document's Part IV | Five amendments in two days with zero retirements is unbounded growth (F2) |
| Doctrine prose that restates an enforced rule | The enforcing code or data, plus a one-line pointer | Dual ownership is the failure `canon-map.md` exists to catch; deleting the duplicate is cheaper than mapping it |
| Per-tier bespoke process paths | One loop, configured down (Part IV) | Ceremony becomes computed, not remembered |
| Durable process files at tiers 1–2 | The trajectory, written automatically | Already doctrine ("create process files only when protocol requires"); now structural |
| Big multi-invariant doctrine files | Rule-per-file packs (NeoLabHQ `ddd/rules/*.md`) | Targeted review of one invariant stops loading twelve |
| Duplicated per-host skill/manifest files | Versioned catalog + per-target renderers (agentfield) | Drift between hosts is a class of bug, not an incident |
| Unpromoted skills shipping by existence | Promotion buckets + manifest curation (mattpocock) | 762 files in `skills/` currently ship because they exist |
| Discretionary budget judgment | The four-number predicate | A judgment call about whether budget is exhausted is a judgment call that can be wrong in one's own favor |
| Receipts-as-honesty, evidence packets, seals, sub-tier-4 evidence maps, precondition plans | The two adversaries (Part VI.5) | A producer-side artifact is cheaper to fabricate than the work it attests to; a non-author adversary is not |

**Non-goals, explicitly** (these are the tempting over-builds the corpus offers and the answer is no):

- ❌ No control plane, service, or daemon. Legion is one operator in one workspace. (Rejects agentfield's shape, gstack's daemon.)
- ❌ No parallel receipt/ledger/evidence stores. Three artifacts, one journal substrate.
- ❌ No new `G-A` laws from this synthesis. Every mechanism lands inside an existing control or a layer.
- ❌ No weighted-scoring config, no second audit tool, no jury/council wiring. (Consistent with `references/audit-design-decisions.md` D7 and its non-goals.)
- ❌ No auto-install of toolchains; capability-gate and report absence loudly.

---

## Part VIII — Rejected, with reasons

| Mechanism | Source | Why not |
|---|---|---|
| Typed pub/sub event bus with subscribers | agentfield | The in-process journal gives the audit value; the bus adds machinery for observability Legion does not consume yet. Revisit if multi-writer concurrency becomes real. |
| DID + X25519 identity/encryption | agentfield | Solves a multi-tenant trust problem Legion does not have. |
| BM25 ranked role discovery | agentfield | Legion has 3 roles and 5 domains; a static tree plus routing evals is better than ranked search at this cardinality. |
| Persistent design daemon | gstack | Process boundary, lifecycle, and shutdown-refusal logic for a problem a state file solves. Vision-based `check`/`diff` gates are kept; the daemon is not. |
| Multi-agent consensus manager, circuit breakers | EricGrill | Consensus over 3 roles is ceremony; Legion already has an escalation path (Covenant) with a stopping rule. |
| MCP memory/state service with embedding-backend fallback | EricGrill | Crypt shims already own durable memory; a second store violates one-canonical-owner. |
| MDM / managed-settings distribution | claude-code | Enterprise fleet policy; Legion is one operator. |
| `justfile` as task runner | NeoLabHQ | `manage.py` / `pnpm` scripts already own this; a third runner is drift. |
| Skill-submission issue templates | ArabelaTso | Repo has no code at all; the one process artifact is not worth an intake ceremony for a single-operator system. |
| Awesome-list intake format | VoltAgent | Repo has no code. Publication decision, not architecture. |

Two of eighteen corpus repos contain no code. That is worth stating as a result: **the ecosystem's catalog layer is thick and its engineering layer is thin.** The mechanisms worth taking cluster in five repos — trailofbits, swe-agent, mini-swe-agent, SWE-AF, obra — and those five are precisely the ones that treat verification as machinery rather than as instruction.

---

## Part IX — Migration: four stages, each shippable

Each stage ends in a state that is better than the one before it and does not require the next stage to be correct. No stage rewrites the engine.

**Stage 1 — Kernel types and the journal.** Add L1: typed results, typed harness exceptions, the append-only session journal, the four-number budget struct, seam injection. Wire the existing loop to emit the journal. Nothing changes behaviorally.
*Done when:* every existing dispatch path produces a trajectory, and `BUDGET_STOP` is computed by the predicate rather than asserted.

**Stage 2 — The adversary pair, and the retirements it pays for.** Implement Part VI: the Completion Adversary's four mechanisms (Iron Law gate, requirement-split, refutation by non-authors, in-band records with empty-record-is-BLOCK), the Scope Adversary as a dispatchable Sage seat with its scope/boundary/reuse/ladder tests, the mechanical cycle guard, and the authority-pressure suite. **In the same stage, delete what VI.5 retires** — receipts-as-honesty, evidence packets and seals for ordinary delivery, evidence maps below tier 4, plans as a precondition. Arcane's authorization log stays.
*Done when:* a delivery verdict carries its sources-read/searches-run record, the authority-pressure suite is green, and the retired artifacts are gone from the ordinary path — measured, not asserted.
*Watch for:* two specific regressions. First, adversary scope creep into blocking on taste; the blocking lists in VI.1 are closed and do not change in this stage or any other. Second, adopting the additions without landing the removals, which would leave Legion with both the artifact chain and the adversaries — strictly worse than today. If the removals cannot land, revert the stage.

**Stage 3 — Gates as data.** Move deny-shaped rules from prose into `registry/` policy files with a small engine: locked-domain freeze boundaries, commit/push policy, model caps, per-path review instructions, invocation-scope flags in both host manifests. Prose that duplicates a now-enforced rule is deleted in the same commit that enforces it.
*Done when:* `legion:check` fails on prose that duplicates an enforced rule, and every destructive capability carries its user-invoked flag in both manifests.

**Stage 4 — Capability federation.** Promotion buckets for `skills/`, one eval corpus per shipped capability, routing evals with a rank-1 ratchet and a description-collision guard, topic-per-file restructuring for deep domains, one versioned catalog with per-target renderers, contract tests for documented tool surfaces.
*Done when:* the manifest — not the filesystem — determines what ships, and no capability ships without its corpus.

**The invariant that governs the migration itself:** L1 never learns about L5. If a kernel change is needed to add a skill, the layering is wrong and the stage stops. This is the one condition under which migration halts for a decision rather than proceeding.

---

## Part X — How you would know this is real

Conformance checks, not confidence. Each is mechanical and each fails loudly:

1. **Layer direction.** No import from `lib/core` (L1) to `skills/` (L5). Grep-checkable; fails the build.
2. **One owner per concept.** `canon-map.md` entries with two source owners fail `legion:check`. Already partly true; extend to enforced-rule-vs-prose duplication.
3. **Budget arithmetic.** Every dispatched unit's terminal result names which of the four numbers ended it, or names its non-budget terminal type. A result that names none is a defect.
4. **Evidence records.** Every Oracle PASS carries lines-read and searches-run. A PASS with an empty record is a BLOCK (empty extraction = failure).
5. **Routing regression.** Rank-1 ratchet over skill descriptions with a committed baseline; description cosine similarity above threshold fails.
6. **Coverage contract.** Shipped capability count equals eval corpus count. Inequality fails CI.
7. **Drift.** `--check` mode on every generated artifact — agent-rules overlays, host manifests, catalog renderings.
8. **Pressure.** The authority-pressure prompt suite stays green.
9. **Ceremony budget.** Count the durable artifacts an ordinary tier-2 delivery produces. Target: one (the trajectory), plus an authorization log entry only if a classified effect occurred. Any other durable artifact on the ordinary path is a regression, whoever added it.
10. **Adversary independence.** Every blocking verdict names the context it was produced in, and that context is not the producing context. A verdict from the producing context is void, not persuasive.
11. **Doctrine mass.** Track `doctrine/` line count against `lib/` + `packages/` line count across releases. C3 says the ratio must fall. If it rises across two releases, the architecture is being violated in the direction it was designed to prevent.

Checks 9 and 11 are the ones that matter most, because they are the only two that catch the failure this whole document exists to stop — and they catch it in the two forms it takes: artifacts accumulating on the delivery path, and rules accumulating in the doctrine tree.

---

## Appendix — Corpus map

| # | Repo | Evidence role | Contributes to |
|---|---|---|---|
| 01 | addyosmani/agent-skills | skill collection + eval harness | L5 (routing evals, validator SoT), L4 (hook cache) |
| 02 | Agent-Field/agentfield | Go control plane | L2 (state machine), L4 (approval-as-transition), L5 (catalog + renderers) — shape rejected |
| 03 | Agent-Field/SWE-AF | three-loop SWE harness | L1 (seams), L2 (nested budgets, checkpoints, debt) |
| 04 | anthropics/claude-code | vendor reference | L4 (hook protocol, hookify, envelope shape) |
| 05 | ArabelaTso/Coding-Skills-Collection | catalog only | — |
| 06 | coderabbitai/skills | review policy repo | L4 (policy-as-config, per-path instructions), L5 (untrusted input) |
| 07 | EricGrill/agents-skills-plugins | plugin collection | L4 (stop-hook discipline), rest rejected |
| 08 | garrytan/gstack | design engine + hooks | L2 (iteration fallback, backoff), L3 (vision gates), L4 (freeze hook) |
| 09 | instructa/agent-skills | code-backed skills + tooling | L4 (commit policy, sandbox), L5 (code-backed norm) |
| 10 | LambdaTest/agent-skills | 44 skills + eval corpora | L5 (coverage contract, behavior assertions, negative triggers) |
| 11 | mattpocock/skills | invocation doctrine + ADRs | L5 (promotion, autonomy test, prose deps), L4 (invocation flags) |
| 12 | NeoLabHQ/context-engineering-kit | reflexion hooks | L1 (journal, typed payloads), L4 (cycle guard, trigger regex), L3 (diagnosis modes) |
| 13 | obra/superpowers | skill suite + tests | L3 (Iron Law, rulings ledger, dispatch), L5 (cross-host hook, pressure tests) |
| 14 | swe-agent/swe-agent | mature harness | L1 (typed errors), L2 (budget math, chooser/scorer, replay) |
| 15 | SWE-agent/mini-swe-agent | minimal harness | L1 (strict templates), L2 (**the four numbers**) |
| 16 | testdino-hq/playwright-skill | browser KB | L5 (topic-per-file, golden rules, trust boundary) |
| 17 | trailofbits/skills | 40+ security plugins | **L3 (the Oracle spec)**, L5 (contract tests, eval graders) |
| 18 | VoltAgent/awesome-agent-skills | catalog only | — |
