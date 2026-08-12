# Convergence doctrine — gap analysis

**Question answered:** agents dispatched into architecture work cycle for hours — revision after
revision — instead of converging. What doctrine is Legion missing, judged against the strongest
external skill/harness corpus?

**Corpus studied:** obra/superpowers, addyosmani/agent-skills, mattpocock/skills,
instructa/agent-skills, NeoLabHQ/context-engineering-kit, garrytan/gstack, trailofbits/skills,
coderabbitai/skills, SWE-agent/swe-agent + mini-swe-agent, Agent-Field/SWE-AF + agentfield,
anthropics/claude-code (feature-dev plugin, best-practices doc, engineering blog).

---

## 1. Verdict

Legion's anti-loop doctrine is strong **everywhere except where the looping happens.**

- **Diagnose** converges by construction: hypotheses get disconfirmed, the 3-failed-fixes rule
  forces a structural change, time budgets are advisory signals, the fast path "earns the ceremony."
- **Alchemist** converges: failure fingerprints ("same fingerprint twice → stop and report, never
  loop"), typed terminal states including `BUDGET_STOP`.
- **Oracle** is explicitly forbidden recursion (G14: "recursive assurance has no stopping boundary").
- **The Architect route has none of this.** No revision counter, no cap, no satisficing bar, no
  finding-severity floor, no scoped re-review, no reopening protocol for settled decisions, no
  paper-vs-execution escalation. Worse, four of its mandatory gates are **churn amplifiers**
  (§3). Design is also the one route with no external falsifier — a failing test ends a debugging
  loop; nothing ends a design loop except doctrine, and the doctrine isn't there.

Every escalation path in current doctrine points *into* more design (Diagnose → Architect route,
Alchemist blocker → Sage, Oracle finding → Sage, Covenant → revision). No bounded path leads *out*.
That asymmetry is the whole failure mode.

---

## 2. What Legion already has (do not re-invent)

| Mechanism | Where | Status |
|---|---|---|
| Attempt cap with forced structural change | `sage-diagnose.md`: "3+ attempted fixes fail → stop, you are in a local minimum" → Architect route or Covenant differential diagnosis | ✅ Diagnose only |
| Retry fingerprint / no identical retries | `alchemist.md`: same fingerprint twice → stop | ✅ Alchemist only |
| No recursive assurance | `oracle.md` G14 | ✅ |
| Ceremony proportional to request | `legion.md` tiers; G17 "output depth follows user intent"; "a small change that takes twenty minutes of process is a system failure" | ✅ at routing; not inside Sage |
| Fast path ("earn the ceremony") | `sage-diagnose.md` Phase 0 | ✅ Diagnose only — no Architect equivalent |
| Bounded options | `sage-architect.md`: "2-3 approaches when meaningful trade-offs exist"; lead with a recommendation | ✅ partial |
| Decision lifecycle states | `proposed → accepted → implemented → superseded` in the typed decision store | ⚠️ states exist; **no rules govern reopening** |
| Advisory time budgets | `sage-diagnose.md` | ✅ Diagnose only |
| Explicit amendments | G10: `EC-N v1 → A-k → EC-N v2`, never silent | ⚠️ contracts only; design artifacts invalidate from root instead |

---

## 3. Why the Architect route loops — churn amplifiers in current doctrine

These are not missing rules; they are present rules that *generate* revision cycles:

**A1 — Invalidate-from-root.** The minimize gate: "Any semantic correction, undeclared
file/dependency, or changed policy invalidates decision plus all downstream route work." GoalRoute:
"Semantic correction or changed constraints invalidate route from root and require a new receipt."
One nit → full re-ceremony → the re-ceremony surfaces new nits → no fixed point. Contracts got
amendment semantics (G10); design artifacts got demolition semantics. Superpowers' own post-mortem
of the identical bug: "fresh full reviews each round are the churn engine."

**A2 — Maximizing mandates.** "Never downgrade; name the ceiling," best-in-class comparison duty,
and the best-shape truth gate set the bar at *best* — which is not checkable and therefore never
satisfied. An agent chasing the right to say "best" keeps searching. There is no counterweight
stating that the normal bar is *acceptance criteria met*, and that "best-shape" is a special
claim produced only on explicit request.

**A3 — Unbounded mandatory search.** Step 0 requires 2–3 credible external approaches **per
material mechanism class** with ≥2 primary sources each, no timebox, no coverage cap. On a wide
gap list this is hours of research the request never asked for.

**A4 — Unscoped re-review.** Nothing restricts a revision round (inline lenses or a re-convened
Covenant) to the previous round's findings. Every pass is a fresh full review; a reviewer asked to
find gaps always finds some (Anthropic best-practices: "a reviewer prompted to find gaps will
usually report some, even when the work is sound — chasing every finding leads to
over-engineering"). The criticism set never shrinks, so the loop never converges.

**A5 — Nothing counts revisions.** No revision counter exists, so no rule *can* trigger on one.
Diagnose counts failed fixes; Architect counts nothing.

---

## 4. Doctrine matrix — corpus vs Legion

Mechanisms the corpus converges on, ranked by how many independent systems carry them:

| # | Mechanism | Strongest sources | Legion (Architect route) |
|---|---|---|---|
| M1 | Revision cap + forced structural change at the cap | superpowers (3 fixes / 5 rounds), addy doubt-driven (3 cycles → "don't grind a fourth alone"), gstack (escalate after 3 failed attempts), NeoLab (max 3 + model ladder → "escalate to the user, never loop"), SWE-AF (5/2/2 nested caps) | ❌ |
| M2 | Satisficing bar / bounded discretion | NeoLab Iteration Discretion Rule ("burning iterations on nitpicks so the task never completes → the task is failed"; ≤1 nitpick-driven iteration), addy ("perfect code doesn't exist"), Google-style default-approve | ❌ — A2 pushes the opposite way |
| M3 | Severity/confidence floor on findings that may reopen design | claude-code reviewer (report only ≥80 confidence), SWE-AF (blocking = security/crash/data-loss/wrong-algorithm only; "don't block on style"), coderabbit (stop at info-level), trailofbits (dismissal-first brocards; "if uncertain, open a discussion, not a bug report") | ❌ |
| M4 | Scoped re-review (criticism set shrinks monotonically) | superpowers SDD ("re-review verdicts prior findings ADDRESSED/NOT ADDRESSED; new observations go to the ledger as deferred minors — they never extend the loop") | ❌ |
| M5 | Decide-with-debt terminal state | SWE-AF `COMPLETED_WITH_DEBT` ("prevents stalling when the reviewer keeps requesting minor polish"), SWE-agent forced autosubmit at cost cap with labeled exit status | ❌ — no terminal state for "good enough, concerns recorded" |
| M6 | Decision finality + governed reopening | gstack decisions.jsonl ("do not silently re-litigate; if you're about to reverse one, say so"), mattpocock ADRs ("record rejections so someone doesn't suggest GraphQL again in six months"), NeoLab decay (Refresh/Deprecate/Waive as the only legal moves; reopen only when a carrier file changed) | ⚠️ lifecycle states exist, reopening rules don't |
| M7 | Reversibility-scaled ceremony (one-way/two-way doors) | mattpocock ADR test #1 ("if easy to reverse, skip it — you'll just reverse it"), gstack door types, addy ("anything you can't undo with `git revert`" triggers doubt + sign-off; else flow) | ⚠️ reversibility is an ADR *field*, never an effort *governor* |
| M8 | Paper-iteration limit → spike | mattpocock prototype skill ("learn something fast… capture the verdict and the question it settled"), addy risk-first slicing | ❌ — riskiest-assumption + smallest-test is authored but nothing forces *running* it instead of another paper revision |
| M9 | Scoped amendment, not invalidate-from-root | NeoLab `--refine` ("Architecture section changed → re-run from Phase 3 onwards"), G10 itself | ❌ for design artifacts (A1) |
| M10 | Loop self-detection + rationalization table | superpowers red-flag tables ("'one more round will converge' → past the cap, rounds don't converge"), gstack Context Health ("looping on the same diagnostic, same file, or failed fix variants → STOP"), SWE-AF (`_detect_stuck_loop`; "oscillating between two approaches without converging"), addy ("re-spawning fresh context on an unchanged artifact — you'll get the same findings; you're stalling") | ❌ in Architect (Alchemist's fingerprint is the pattern) |
| M11 | Bounded divergence (option/search/word/question budgets; frontier convergence) | addy idea-refine (3–5 questions, 5–8 variations, "resist adding steps"), superpowers (200–300 words per design section), mattpocock grilling (done when the frontier of open questions is empty), addy interview-me (95%-confidence stop) | ⚠️ options bounded; search and prose unbounded (A3) |
| M12 | Decisiveness at the gate | claude-code code-architect ("pick one approach and commit… rather than presenting multiple options"), superpowers reviewer prompts ("approve unless there are serious gaps"; recommendations "advisory, do not block approval"), mattpocock ("be opinionated — the user wants a strong read, not a menu") | ⚠️ "lead with a recommendation" exists; reviewer calibration doesn't |

Universal corpus consensus worth stating plainly: **when the loop budget feels insufficient, the
artifact is too big — decompose it. Never raise the budget.** (addy: "the artifact is too big —
return and decompose. Do not lift the bound.")

---

## 5. Proposed doctrine — Sage convergence rules

Drafted in Legion's voice, ready to fold into `doctrine/sage.md` + `doctrine/bundles/sage-architect.md`
(and one clause each into `legion.md` and Covenant). Numbered CV-1… so they can be renumbered into
the G-series on adoption.

### CV-1 — The revision counter exists

Every Architect engagement tracks a **design revision count**: a revision is any pass that reopens
a previously emitted ADR/decision block, option set, or plan in the same engagement. Emitting the
first version is not a revision. The count is reported in the artifact header.

### CV-2 — Three revisions, then the cap (the Architect twin of the 3-failed-fixes rule)

At revision 3, stop revising. The next action is one of exactly three, chosen and recorded:

1. **Decide-with-debt** — adopt the leading option now; every unresolved concern becomes a named
   debt item (`NG-*`, an `OPEN` follow-up, or a Crypt note), none of which blocks the decision.
2. **Spike** — the disagreement is empirical: run the riskiest-assumption test / throwaway
   prototype and let its result decide. The spike's verdict closes the question; capture it.
3. **Escalate** — the disagreement is a genuinely reserved decision or a one-way door: present the
   frozen option set (≤3, with a recommendation) to the operator. Never present the loop itself as
   progress.

"One more revision will converge" is a red flag, not a plan: past the cap, revisions don't
converge — the failure is structural (artifact too big, oracle missing, or authority contested).
If the cap feels insufficient, the decision unit is too big: **decompose the decision; never lift
the cap.**

### CV-3 — Satisficing is the default bar

The bar for every design is **acceptance criteria met**, not *best*. `best / optimal /
best-in-class` are special claims produced only when the operator explicitly requests a best-shape
review — the best-shape truth gate governs that claim's honesty, and its existence never obligates
the search on ordinary work. "Never downgrade" forbids regressions against a named axis; it does
not command an upgrade hunt. A design meeting all `AC-*` with no blocking findings **ships as-is**;
polish beyond the criteria is recorded as optional debt, not performed.

### CV-4 — Finding severity floor: only blockers reopen a design

Findings against a design (embedded lenses, Covenant seats, self-review) are typed:

- **BLOCKING** — violates a stated requirement/invariant, breaks correctness/security/data
  safety, or makes an acceptance criterion unmeetable. Reopens the design (counts toward CV-2).
- **ADVISORY** — everything else: style, elegance, "could be more", speculative generality,
  unrequested scope. Recorded in the artifact as debt; **structurally cannot trigger a revision.**

A finding that cannot cite the requirement, invariant, or evidence it violates is advisory by
definition. Reviewer calibration is default-approve: approve unless a named blocking class is
present; imperfection is not a class.

### CV-5 — Scoped re-review

A revision round re-reviews **only the prior round's blocking findings** (verdict each
`ADDRESSED / NOT ADDRESSED`) plus breakage introduced by the fix itself. New observations join the
debt ledger; they never extend the loop. Fresh full reviews of an already-reviewed design are
forbidden inside the same engagement — the criticism set must shrink monotonically. (Same law for
re-convened Covenant: same packet lineage, seats verdict the prior findings, no fresh sweep.)

### CV-6 — Scoped amendment replaces invalidate-from-root

A semantic correction invalidates **the artifacts downstream of the corrected decision**, not the
engagement. Recompute the minimize/GoalRoute/plan sections that depend on the changed decision;
carry the rest forward under an explicit amendment (`v1 → A-k → v2`, G10 semantics extended to
design artifacts). Full re-ceremony is reserved for a changed goal (A/B redefinition), not a
corrected step.

### CV-7 — Settled decisions are settled

An `accepted` or `implemented` decision is settled law. Reopening it is a governed act requiring a
named trigger: new evidence that falsifies a stated assumption, a change in the files/constraints
the decision rests on, or the operator's explicit reversal. Reopening produces an explicit
`superseded`-chain record — never a silent re-derivation. Rejected alternatives are recorded *with
the rejection reason* precisely so they are not re-proposed; a durable rejection cites a durable
reason, not a temporary circumstance. When about to reverse a settled call, say so in those words.

### CV-8 — Ceremony scales with reversibility (the door rule)

Before designing, classify the decision:

- **Two-way door** (reversible with `git revert` or a config flip; no schema/auth/money/public
  contract/data-migration surface): decide in one pass — recommendation, one-paragraph rationale,
  go. No decision matrix, no external search, no GoalRoute. Recording it is optional ("if a
  decision is easy to reverse, skip the record — you'll just reverse it").
- **One-way door** (the substantive-trigger list): full route, and the CV-2 cap still applies.

Reversibility is an effort governor, not a report field. The existing substantive/trivial gate
decides *whether* Sage engages; the door rule decides *how much* Sage does once engaged.

### CV-9 — Analysis has a budget; execution breaks ties

The external solution-space search is bounded up front: name the mechanism classes to be searched
and the budget (default: top 2 classes by blast radius, 2 approaches each, timeboxed). Beyond the
budget, `defer` with a named gate is the honest verdict — coverage debt, not extended search.
When two options survive comparison and revision 2 hasn't separated them, **stop comparing on
paper**: the ADR's riskiest-assumption test is run as a spike, and its result decides. Analysis
past that point is the loop.

### CV-10 — Design red flags (rationalization table)

These thoughts mean STOP — you are cycling:

| Thought | Reality |
|---|---|
| "One more revision will converge" | Past the cap, revisions don't converge. Route via CV-2. |
| "This option set feels familiar" | If it matches a previously rejected set, you are oscillating. Check the decision record; spike or escalate. |
| "The reviewer will find something anyway" | Then only blockers count (CV-4) and the re-review is scoped (CV-5). |
| "It isn't best-in-class yet" | The bar is acceptance criteria (CV-3). "Best" was not requested. |
| "Re-running the lenses fresh will help" | Fresh reviews on an unchanged artifact return the same findings. You're stalling. |
| "The plan must be perfect before Alchemist sees it" | The plan is a hypothesis; EXACT/BOUNDED typing plus amendments (G10) exist precisely so execution can surface the rest. |
| "This correction means starting over" | Amend the affected sections (CV-6). Demolition is for changed goals. |

### CV-11 — The lead watches the clock (Legion-level tripwire)

Legion, as dispatcher, applies churn detection to its own cohort: an Architect engagement that
crosses its third revision, oscillates between the same alternatives, or materially exceeds the
declared budget is interrupted and routed through CV-2 — decide-with-debt, spike, or surface to
the operator with the frozen options. Hours of silent design revision is a system failure of exactly the
kind the twenty-minute rule already names for small changes. An engagement never reports the loop
as progress.

### CV-12 — Design done is a checklist, run once

A design/plan is done when: every `R-*` maps to a task or an explicit `NG-*`; no placeholders; no
`OPEN` questions in an artifact claimed executable (G9); names/signatures consistent; blocking
findings resolved or spiked. Self-review runs **once** — fix inline, no re-review of the review.
Anything past the checklist is debt, not work.

---

## 6. Adoption map

| Rule | Lands in |
|---|---|
| CV-1, CV-2, CV-9, CV-10, CV-12 | `doctrine/bundles/sage-architect.md` (new "Convergence" section; CV-2 cross-referenced from `sage.md` boundaries) |
| CV-3 | `sage-architect.md` — as the stated counterweight adjoining "never downgrade" and the best-shape truth gate |
| CV-4, CV-5 | `sage-architect.md` lens/gate sections + `doctrine/covenant-seat.md` (finding typing; scoped re-convene) |
| CV-6 | minimize-gate and GoalRoute sections of `sage-architect.md` (replace invalidate-from-root language) |
| CV-7 | `sage.md` (decision lifecycle) + Crypt/decision-store guidance |
| CV-8 | `sage.md` routing + `sage-architect.md` (before Phase 2) |
| CV-11 | `doctrine/legion.md` (lead invariants) |

The existing Diagnose and Alchemist rules need no change — they are the house pattern these rules
extend to the one route that lacked them.

---

## 7. Source notes

Strongest single artifacts per mechanism, for deeper reading:

- **NeoLab Iteration Discretion Rule** — `context-engineering-kit/skills/plan-task/SKILL.md` (also in `do-and-judge`, `do-in-parallel`): numeric quality floor, discretion band, ≤1 nitpick iteration, severity override, mandatory cost reasoning before re-launch.
- **Superpowers SDD fix-loop redesign** — `docs/superpowers/specs/2026-07-15-sdd-fix-loop-redesign-design.md` + `skills/subagent-driven-development/SKILL.md`: 5-round cap, rounds 4–5 model escalation, breaker adjudication with mandatory ledger entries, scoped re-review ("fresh full reviews each round are the churn engine").
- **SWE-AF stuck-loop machinery** — `swe_af/execution/coding_loop.py` (`_detect_stuck_loop`), `swe_af/prompts/qa_synthesizer.py` ("same test failing 3+ times; oscillating between two approaches"), `COMPLETED_WITH_DEBT` outcome.
- **gstack decision memory** — `CLAUDE.md` cross-session decisions (`decisions.jsonl`, `--supersede`, "do not silently re-litigate"), Context Health preamble, one-way/two-way door confirmation gates.
- **mattpocock ADR + out-of-scope stores** — `skills/engineering/domain-modeling/ADR-FORMAT.md` (3-part record-worthiness test), `skills/engineering/triage/OUT-OF-SCOPE.md` (concept-keyed rejection store), `grilling` frontier convergence.
- **instructa ownership finality** — `skills/architecture-ownership/SKILL.md` (runtime owner vs first-fix owner vs canonical owner — fix now, record direction, don't re-architect mid-task), `hard-cut` (one canonical codepath; delete the losing owner).
- **claude-code feature-dev** — `plugins/feature-dev/agents/code-reviewer.md` (confidence ≥ 80 floor, clean-exit path), `code-architect.md` ("pick one approach and commit"), phase gates where divergence is parallel and one-shot, convergence is a human decision.
- **SWE-agent** — `sweagent/agent/agents.py`: forced autosubmission at every budget cap with labeled exit statuses; retries spend a shared envelope and stop at the acceptance score.
- **trailofbits** — `vulnerability-triage-brocards` (dismissal-first triage), `fp-check` ("LLMs are biased toward seeing bugs and overrating severity"), pervasive "When NOT to Use" sections.
- **Anthropic best-practices** — over-review warning; two-strikes-then-reset; "if you could describe the diff in one sentence, skip the plan"; Stop-hook override after 8 consecutive blocks.
