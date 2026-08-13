# Legion vs. the 18-repo External Practice Corpus
## Full comparison and recommendation set

**Date:** 13 August 2026
**Compared against:** `2026-08-12-legion-architecture-book-final.md` (the canonical plan) + current live doctrine (`tools/skills/legion/doctrine/*.md`, `AGENTS.md`, workspace rules)
**Corpus root:** `/tmp/legion-practices-sources.GtrSei` (18 repos, macOS temp storage — original SWE-AF clone is `agent-field-swe-af`; `agent-field-swe-af-snapshot` is the abandoned-workflow snapshot)
**Method:** every repo was surveyed for concrete, numbered, mechanically expressible controls (caps, thresholds, gates, schemas, state machines) with file paths. Mechanisms were then mapped against (a) what Legion already enforces live, (b) what exists only in the final plan, (c) what is missing from both.

---

# Part 1 — The three questions answered

## 1.1 Which strong practices Legion already implements (live today, not just planned)

These are enforced in current doctrine/workspace rules and were independently re-invented by the strongest corpus systems — strong convergent validation:

| Legion live mechanism | Corpus counterpart |
|---|---|
| Alchemist retry fingerprint: "same fingerprint twice → stop, never loop" (`doctrine/alchemist.md`) | SWE-AF `_detect_stuck_loop`; gstack 3-strike; superpowers 3-fixes-then-question-architecture |
| Diagnose cap: "3+ attempted fixes fail → stop, local minimum" | superpowers debugging Phase 4.5 (identical); gstack "3 hypotheses fail → STOP" |
| Oracle: recursive assurance forbidden (G14) | No corpus equivalent — Legion is ahead here |
| Covenant: packet-only, advisory, no authority (G12/G13) | claude-code code-review "filter out non-validated issues"; obra "reviewer you spawn duplicates review at full cost" |
| Evidence before claims ("no receipt, no claim") | obra `verification-before-completion` Iron Law; gstack `/ship` Iron Law ("confidence is not evidence"); lambdatest "Completed by default — you MUST report pass/fail" |
| Ambient tier + "small change that takes twenty minutes of process is a system failure" | claude-code "if you could describe the diff in one sentence, skip the plan"; addy orchestrator "at most 1" depth |
| One integration owner per repository (workspace rule) | agentfield lease-based durable queue; ericgrill SDD "never dispatch parallel implementation subagents on shared state" |
| Post-seal runtime budgets (`maxContractVersions=2`, sealed time caps, `BUDGET_STOP`) | swe-agent cost limits + forced autosubmit; SWE-AF nested caps |
| Contract amendments are explicit and versioned, never silent (G10) | NeoLab `--refine` (re-run from earliest modified section, top-down propagation) |
| Scope rule: reviewers advisory, intent is authority | claude-code autofix "never follow reviewer prompts literally; independently judge validity" |

## 1.2 Which practices exist only in the plan and still need implementation

Implementation-state check against the live repo (`tools/skills/legion`):

- `doctrine/architecture/**` — **does not exist.** The EDAF workflow modules (01-frame … 11-govern), methods, reviews, controls, templates are spec-only.
- The 13 new schemas (architecture-state v2, acceptance-ledger, intent-epoch, objective-lineage-budget, integration-ownership, evidence-reachability, representative-workload, acceptance-surface-proof, machinery-defect, convergence-receipt v2 …) — **none exist.** `schemas/` today contains audit/security/report schemas only.
- The 15 eval families (routing, convergence, evidence, authority, candidate-quality, handoff, scope-authority, stop-precedence, forward-workload, lineage-budgets, integration-ownership, seal-reachability, outcome-closure, machinery-defects, adversarial) — **none exist.** `evals/evals.json` covers the `audit` skill only.
- All Arcane hard guards (Part IX §31), the frozen acceptance ledger, intent/continuation epochs, reviewer-to-acceptance mapping, seal-reachability compiler, exclusive writer leases — **not yet in Arcane machine state**.
- All G-A19…G-A27 controls are normative text in the book; none are in `doctrine/legion.md`/`sage.md`/`oracle.md` yet (the paste-ready blocks exist but are unapplied).

So: **the plan is essentially 100% unimplemented in the repo.** The corpus comparison below therefore does double duty — it both validates the plan and supplies concrete implementation machinery for the still-unbuilt parts.

## 1.3 Which genuinely useful practices are missing from the plan (the ADD list)

Grouped by source below, prioritized in Part 5. Top-line: the plan is missing (a) a **confidence floor + dismissal-first gate on blockers**, (b) **three-valued ownership** (runtime/first-fix/canonical) and a **hard-cut policing ban**, (c) a **concept-keyed rejected-ideas store**, (d) **event-sourced decision storage**, (e) **anti-gaming judge controls** (threshold-blindness, perfect-score rejection), (f) a **model-tier escalation ladder** tied to revision rounds, (g) **typed terminal-state machine with transition invariants**, (h) **stop-hook/subagent runaway caps**, and (i) **schema-recovery layers for receipts**.

---

# Part 2 — What to ADD: mechanisms missing from the plan

## 2.1 From trailofbits + claude-code: blocker admission controls (strengthens G-A13, G-A20)

The plan says *what* may block (frozen acceptance ID / invariant ID / safety class) but not *how much evidence a blocking claim needs* nor *in what order dismissal is attempted*. The corpus supplies both:

1. **Confidence floor for blockers.** claude-code code-reviewer: "only report issues with confidence ≥ 80" (0/25/50/75/100 scale). ToB zeroize-audit: a finding needs **≥2 independent signals** to be `confirmed`; 1 signal → `likely`; 0 → `needs_review`. **Add to the review-finding schema and G-A20:** a BLOCKER requires `confidence ≥ threshold` or two independent evidence signals; single-signal findings are `ADVISORY` at best.
   - Source: `anthropics-claude-code/plugins/feature-dev/agents/code-reviewer.md`; `trailofbits-skills/plugins/zeroize-audit/skills/zeroize-audit/SKILL.md` (Confidence Gating).
2. **Dismissal-first brocard sequence.** ToB's seven brocards are a sequential triage tree: (1) no vulnerability without a threat model — report must answer "attacker with [capability] can [action] to achieve [impact]"; (2) no exploit from the heavens — required capabilities already exceed the impact; (3) no vulnerability outside usage — unreachable code paths aren't findings; (4) no vulnerability from standard behavior; (5) no vulnerability from documented behavior; (6) no cure worse than the disease — remediation disruption must not exceed impact; (7) CVE/CVSS are not evidence. "Stop at the first DISMISS by default."
   - **Adopt as `doctrine/architecture/reviews/dismissal-brocards.md`** and wire into G-A20: a `SAFETY_BLOCK` must survive the brocard sequence. This operationalizes "demonstrated safety failure" — it is the check that separates demonstration from assertion.
   - Source: `trailofbits-skills/plugins/vulnerability-triage-brocards/skills/vulnerability-triage-brocards/SKILL.md` + `references/brocards-detail.md`.
3. **Severity ≠ confidence — two axes, never collapsed.** ToB variant-analysis triage: severity = impact *if real*; confidence = certainty *it is real*. The plan already separates provenance type from evidence grade (G-A4); the same split must exist on findings. **Add `confidence` as an independent finding field** in the review-finding template.
4. **Finding-wording discipline (claim calibration).** ToB trailmark-review-gate: output is "gate fired", never "vulnerability found"; "review target", never "exploit path"; "graph evidence supports", never "proves"; "a triggered rule creates a review obligation; it does not prove a vulnerability"; "a PASS does not mean the change is secure."
   - **Add to the Oracle/Covenant finding format:** findings must state what evidence supports (not proves) and what the finding authorizes (a re-check obligation, not a verdict).
5. **"When NOT to Use" as a mandatory skill/review header.** Every ToB skill opens with an explicit negative-scope block ("NOT for bug hunting, NOT for general review, NOT for quick scans"). This is the mechanism behind reviewer non-expansion at the routing layer — every Covenant seat and every review module should declare its non-scope before its scope.
6. **Rationalizations-to-reject register.** ToB fp-check lists six named reasoning failures with corrective actions, e.g. "This is clearly critical" → *"LLMs are biased toward seeing bugs and overrating severity"* → "complete devil's-advocate review; prove it with evidence"; "this pattern looks dangerous" → *"pattern recognition is not analysis"* → "trace the data flow first." **Add this register to Covenant/Oracle doctrine verbatim-adapted** — it is the counterweight to the well-documented LLM severity-inflation bias.
   - Source: `trailofbits-skills/plugins/fp-check/skills/fp-check/SKILL.md` lines 23–34.

## 2.2 From instructa: ownership and hard-cut sharpening (strengthens G-A24, one-canonical-owner)

The plan's "one canonical owner per concept" (Part X §37) is flat. instructa's mechanism is strictly richer and prevents a known failure (patching at the wrong layer "temporarily"):

7. **Three-valued ownership.** Every duplicated rule must be recorded as: *runtime owner* (where behavior currently happens), *first-fix owner* (where the bug is patched now — often the orchestration layer), *canonical long-term owner* (where reusable policy belongs — often the domain layer). Decision order: name the runtime concern → name the layer where wrong behavior happens → decide whether it is only first-fix or also canonical → if reusable business policy, move long-term ownership out of the orchestration layer → delete the duplicate/fallback/dual path.
   - **Change Part X §37 and G-A24:** ownership declarations become three-valued. The invariant stays one canonical owner; the mechanism now says *how to migrate* without re-architecting mid-task ("fix now, record direction, don't re-architect mid-task").
   - Source: `instructa-agent-skills/skills/architecture-ownership/SKILL.md` + `references/ownership-matrix.md`.
8. **Hard-cut policing ban.** instructa `hard-cut`: not only no fallbacks/shims/dual shapes, but also **no fail-fast guards whose purpose is to reject old shapes, no tests asserting rejection of old shapes, no validation branching on legacy discriminators/aliases** — policing an old shape is still keeping it. Default assumption: previous shapes are internal drafts unless there is concrete evidence of a persisted external obligation ("mere existence of old code is not proof of a compatibility obligation"). Exception (persisted user data, on-disk state, wire format, real public contract) must name the exact boundary and limit compatibility to it.
   - **Add to the plan's "eliminating competing code paths" and to G-A15/G-A27:** the ten hard-cut rules, including the policing ban, with the named-boundary exception.
   - Source: `instructa-agent-skills/skills/hard-cut/SKILL.md`.
9. **First-unintended-side-effect root cause.** instructa `root-cause-finder`: "find the first unintended side effect or write" — trace the causal chain past the first contract/parse/type/null/schema error to the first write that should not have happened; ask "should this request/mutation have happened at all?"; treat non-explicit writes (hooks, observers, subscribers, retries, background jobs, cache refreshers) as suspicious.
   - **Add to the Diagnose route** (it sharpens "separate symptom from cause") and to G-A9's local-invalidation cone: the cone starts at the first unintended side effect, not the downstream symptom.
10. **Test consolidation by owning layer.** One primary layer per invariant (unit / integration / e2e); never duplicate the same invariant across layers unless each covers a named different failure mode; never add a standalone regression test just because it's faster. Tie-break toward integration; "never pick a higher layer just because it's easier to reproduce there."
    - **Add to Oracle doctrine + evals** as the audit-fix routing rule for remediation tests.
    - Source: `instructa-agent-skills/skills/consolidate-test-suites/SKILL.md`.

## 2.3 From mattpocock: rejection memory and bounded questioning (strengthens G-A8, G-A12, G-A13)

11. **Concept-keyed out-of-scope store.** `.out-of-scope/*.md`, one file **per concept** (not per issue), with "why out of scope" + "prior requests", matched **by concept similarity, not keywords** ("night theme" matches `dark-mode.md`). Two poisoning rules: write only when an enhancement is rejected `wontfix`; never write when the item was closed as already-implemented (that "poisons the dedup checks with false rejections"). Maintainer may Confirm / Reconsider / Disagree.
    - **Add to G-A8** (rejected alternatives with durable reasons): the durable reason needs a concept-keyed, similarity-matched, poisoning-guarded store — otherwise "someone suggests GraphQL again in six months" is precisely what happens.
    - Source: `mattpocock-skills/skills/engineering/triage/OUT-OF-SCOPE.md`.
12. **ADR record-worthiness test (3 parts, all required).** Offer an ADR only when the decision is (1) hard to reverse, (2) surprising without context, AND (3) the result of a real trade-off. "If any of the three is missing, skip the ADR." An ADR can be one paragraph: context, decision, why.
    - **Add as a pre-condition on the ADR template** (§47): G-A1 (significance) decides *architecture vs not*; this 3-part test decides *ADR vs decision log entry*.
13. **Frontier questioning.** Map the decision space as a tree; the frontier = every decision whose prerequisites are settled. "Ask the whole frontier in one round: number each question, give your recommended answer, wait." A question dependent on an open answer belongs to a later round. Facts are the agent's job (dispatch, don't ask); decisions are the user's. "Done when the frontier is empty."
    - **Add to Phase 1 FRAME and to Covenant DECISION_CHALLENGE:** one challenge round = one frontier sweep. This is the mechanical form of "one design → one challenge".
    - Source: `mattpocock-skills/skills/productivity/grilling/SKILL.md`.
14. **Fog-vs-ticket test.** "Fog or ticket? Can you state the question precisely now — not whether you can answer it now." If you can state it, it's a ticket (deferral with precision); if not, it's fog (don't pretend to plan it).
    - **Add to the six-disposition taxonomy** as the operational test that separates `DEFER_TO_LATER_SLICE` (stateable) from `ASSUMPTION_TO_TEST` (stateable + falsifiable) from genuine fog (record, don't schedule).
    - Source: `mattpocock-skills/skills/engineering/wayfinder/docs/engineering/wayfinder.md`.
15. **Prototype as primary source, decision as the artifact.** Prototypes: no tests, no persistence, no abstractions; default 3 variants, cap 5; "variants must disagree about structure, not colour." When done: fold only the validated decision into real code; park the prototype on a throwaway branch as a **primary source**; main keeps the decision, not the prototype.
    - **Add to G-A12 spike semantics:** explicit parking + "primary source" status for the spike artifact, and a promotion ban without re-evaluation (the plan already forbids prototype-promotion; this adds the parking mechanics).
16. **Design-it-twice with divergent constraints.** Spawn 3+ parallel design subagents with deliberately different constraints (minimize interface vs maximize flexibility vs optimize the common caller), then compare on depth/locality/seam placement. Divergence is one-shot parallel; convergence is one committed recommendation.
    - **Add as a conditional mechanism for BEST_SHAPE candidate generation** (Part IV §7) — it is the concrete form of "broad external search authorized".
    - Source: `mattpocock-skills/skills/engineering/codebase-design/DESIGN-IT-TWICE.md`.
17. **Deletion test** (from codebase-design): "If complexity vanishes, it was a pass-through; if it reappears across N callers, it was earning its keep." And "one adapter means a hypothetical seam; two adapters means a real one."
    - **Add to MINIMIZE (§18)** as cheap mechanism-justification probes.

## 2.4 From gstack: decision storage and door mechanics (strengthens G-A8, Part IV door rule)

18. **Event-sourced decision log.** `decisions.jsonl` append-only with three event kinds — `decide` / `supersede` / `redact`. "Active" is **computed** (a decide whose id is not referenced by a later supersede/redact), not a mutable status field. Redact expunges on compaction (secrets leave for good). Reads go to a bounded `active.json` snapshot (O(active), not O(history)). Concurrency guarded by an O_EXCL lock. Preamble rule: "treat active decisions as prior settled calls — do not silently re-litigate; if you're about to reverse one, say so explicitly."
    - **Add to Part IX/Arcane state design:** the machine decision store should be event-sourced with computed-active and redact semantics. The plan's ADR dual-status stays for human-readable ADRs; the *machine* store gets event semantics. This also cleanly implements G-A8's "reversal must be explicit."
    - Source: `garrytan-gstack/lib/gstack-decision.ts`, `scripts/resolvers/preamble/generate-context-recovery.ts`.
19. **Door classification: registry + destructive-pattern classifier + typed confirmation.** One-way/two-way door classification order: registry lookup first (each question declares `door_type`) → skill-category defaults → `DESTRUCTIVE_PATTERNS` list (rm -rf, drop table, force push, reset --hard, terraform destroy, credential rotation, schema migration, breaking change) → default two-way. One-way doors: "require an explicit typed confirmation (the exact option letter or word), state plainly what is irreversible, and NEVER proceed on a vague, partial, or ambiguous reply — re-ask instead."
    - **Add to the plan's door rule** (Part IV interaction rules): the plan says reversibility governs effort but lacks confirmation mechanics. The typed-confirmation rule and the destructive-pattern classifier are the missing enforcement.
20. **Fixed stop-list / never-stop-list for automation.** gstack `/ship`: "Only stop for [enumerated 10 items]" / "Never stop for [enumerated 6 items]" — non-interactive automation must enumerate both lists up front.
    - **Add to `doctrine/legion.md` tier 2 (commit/push is mechanical):** the stop-list/never-stop-list pattern is how "never reopens review of the diff" is enforced operationally. Also the operational form of G-A27's "take the sanctioned path and continue".
21. **Review staleness window.** gstack review dashboard: reviews older than 7 days ignored; "may be stale — N commits since review". Session liveness window: 120 minutes.
    - **Add to evidence expiry (G-A15 review triggers + Part XV metrics):** concrete default staleness windows make "observable trigger" real rather than aspirational.
22. **Context-health [PROGRESS] markers.** During long sessions: periodic "done, next, surprises" summaries; "if you are looping on the same diagnostic, same file, or failed fix variants, STOP and reassess"; progress summaries must never mutate git state.
    - **Add to Alchemist/Sage long-running loops and to handoffs** — a semantic complement to the plan's fingerprints (fingerprints catch identical; this catches *similar-but-different* grinding).

## 2.5 From NeoLab: anti-gaming judging (strengthens G-A13, Oracle, Covenant)

23. **Threshold-blind judging.** "NEVER provide the score threshold to the judge… the judge must not know the passing line, to avoid bias." Corollary: **reject perfect scores as hallucination** — "a judge score of 5.0 is treated as a hallucination and rejected/re-run."
    - **Add to Covenant/Oracle dispatch:** seats receive the packet and lens, never the pass threshold; Oracle score-distribution guards flag perfect or missing scores.
24. **Judge generates the reference result first.** The judge must produce its own correct reference answer *before* reading the artifact (anti-anchoring).
    - **Add to Oracle assurance protocol** for any scored comparison.
25. **Reasoning-before-scoring.** "Produce reasoning FIRST, then score. Never score first and justify later."
26. **Iteration discretion band, relative to target.** NeoLab plan-task: quality band `3.0 ≤ score < THRESHOLD` with a **bounded drop** — "NEVER accept a score more than 1.0 below THRESHOLD; effective floor = max(3.0, THRESHOLD − 1.0)". At most ONE nitpick-driven retry; if it again surfaces only nitpicks → report PASS with recorded nitpicks and stop. Severity override: any High/Critical finding removes discretion entirely. **Cost reasoning before re-launch is mandatory**: "burning retries and context on nitpicks" vs "reporting genuinely poor quality".
    - **Change G-A13's "≤1 nitpick iteration"** from a flat rule to this band formulation. The plan's phrasing is validated; the band + relative floor + severity override + cost-reasoning make it implementable.
27. **Model-tier escalation ladder (shared with obra).** NeoLab: escalate **both** producer and evaluator one tier on first-iteration quality failure; opus is the ceiling → "escalate to the user, never loop." Meta-judge is never re-run (criteria must stay constant across attempts). obra SDD: rounds 1–3 resume the original implementer; rounds 4–5 dispatch a **fresh implementer one tier above** ("a loop that survives three resumes means the implementer cannot see its own problem"); at the cap, adjudicate.
    - **Add to G-A7 revision mechanics:** tie model escalation and fresh-context dispatch to revision rounds. The plan caps revisions but says nothing about *who* runs round 2/3 — the corpus consensus is: same context first, fresh + stronger tier later, adjudication at cap. This closes the "re-review by the same reviewer finds the same things" failure.
28. **Adjudication ledger format (obra).** "Rulings, not stalls": every adjudication logged as `Ruling: <what> — <why> — <what it costs if wrong>`. "Adjudicate only at the cap. Adjudicating earlier to end a loop is pre-judging with a different name." "A silent discard is forbidden."
    - **Add to DECIDE_WITH_DEBT / G-A13:** the terminal choice must produce a ruling ledger entry in this format, and adjudication is legal only at the cap.
29. **Doubt-theater detection (addy).** "Across 2 or more cycles where the reviewer surfaced substantive findings, zero were classified as actionable — you are validating, not doubting. Stop and escalate." Also: pass the reviewer only ARTIFACT + CONTRACT, never the CLAIM (handing over your conclusion "biases it toward agreement").
    - **Add to G-A6/§31:** a concrete non-fingerprint loop signal — repeated reviews with zero actionable findings.
30. **Change-size and file-size signals (addy).** ~100 lines good, ~300 acceptable if one logical change, ~1000 → split; ~1000-line file is a review signal; refactors >500 lines should use automation (codemods), not hand edits.
    - **Add to G-A2 proportionality and plan templates** as cheap scope signals.

## 2.6 From the harnesses: terminal states, submissions, runaway caps (strengthens G-A23, G-A25, G-A27, Arcane)

31. **Typed terminal taxonomy + irreversible-transition state machine.** agentfield: canonical statuses `pending → queued → running → {succeeded | failed | cancelled | timeout}`, with **test-enforced invariants** — terminal states are irreversible; `timeout` is semi-terminal (may only → running or cancelled); `queued → succeeded` (skipping running) is invalid. Alias normalization (`done/ok` → succeeded, etc.).
    - **Add to Arcane (Part IX §32):** the plan's state-transition model exists on paper; add a transition-invariant test suite exactly like `execution_state_invariant_test.go`. This is how "no false clean" becomes mechanical.
    - Source: `agent-field-agentfield/control-plane/internal/storage/execution_state_invariant_test.go`, `pkg/types/status.go`.
32. **Forced submission at every budget cap + promising-patch semantics.** swe-agent: every terminal error path (cost/context/timeout/api/format/environment) forces a submission via `git add -A && git diff`; the exit status is typed (`exit_cost`, `exit_format`, …). Crucially: `_is_promising_patch` is true **only** for `exit_status == "submitted"` — budget-forced submissions are saved but explicitly not "promising" candidates.
    - **Add to G-A25/terminal states:** budget-stop must produce a `CANDIDATE` artifact (never nothing), and that artifact must be tagged **low-confidence/forced** — never `COMPLETE`, never silently promoted. mini-swe-agent's counterexample (budget exhaustion → empty submission → candidate lost) shows why the forced-submission rule matters.
33. **Schema/output recovery layers (agentfield).** Four recovery layers before declaring an agent output dead: (1) parse+validate; (2) cosmetic repair (strip fences, close brackets, trailing commas) + revalidate; (3) one tool-less LLM repair call; (4) full harness retry. Large schemas written to file and referenced by path (>4000 tokens); incremental schema mode builds output field-by-field.
    - **Add to G-A26 seal machinery:** receipts and sealed artifacts need these recovery layers plus replay/substitution rejection (which the plan already has). The recovery ladder turns "malformed output" from a seal defect into a bounded repair.
    - Source: `agent-field-agentfield/sdk/python/agentfield/harness/_schema.py`.
34. **Transient-pattern retry classification (agentfield).** Retry only on rate-limit/connection/5xx-class errors; **timeouts are deliberately excluded** ("a 30-min subprocess timeout implies a wrong prompt/model, not a transient"); ±25% jitter on backoff.
    - **Add to Alchemist worker retries and to G-A27 recovery paths** — prevents retry loops on non-transient failures.
35. **Runaway control-plane caps (claude-code).** Stop hooks that block repeatedly are capped by the runtime: **8 consecutive blocks → turn ends with a warning** (`CLAUDE_CODE_STOP_HOOK_BLOCK_CAP`). Subagent caps: max concurrent (default 20), max per session (200), spawn depth off by default, budget cap halts background subagents.
    - **Add to G-A27 + Arcane:** the plan bounds design/review loops but has **no cap on hook-loop runaway** — machinery that itself loops forever. The 8-block cap and subagent depth/count caps are the missing mechanical controls. Note: the final book's appendix cites an Anthropic "two-strikes-then-reset" practice — **that mechanic does not exist in the cloned claude-code repo**; the real control is the 8-block cap (see Part 4 §4.4 for the citation fix).
36. **Change-level completion gates (claude-code feature-dev).** Divergence is one-shot parallel (2–3 explorers, 2–3 architects, 3 reviewers) but **convergence is a single committed decision** ("pick one approach and commit"), with hard human gates between phases ("DO NOT START implementation without user approval").
    - **Validates the plan's** "parallelize evidence, serialize decision" law; add the explicit pattern that parallel divergence phases must collapse into exactly one committed choice.
37. **Stuck-loop detection signals (SWE-AF).** `_detect_stuck_loop`: window of 3, all entries `action=="fix"` with `review_blocking==False` → stuck. QA synthesizer's stuck patterns: "same test failing with same error 3+ times", "coder making the same change repeatedly", "oscillating between two approaches without converging."
    - **Add to §30/§31 fingerprint machinery:** fingerprints catch exact repeats; these *semantic* signals catch non-identical grinding. Use both.
38. **Typed debt with adaptation records (SWE-AF).** `IssueAdaptation`: adaptation type, original/modified/dropped acceptance criteria, failure diagnosis; debt carries severity and propagates downstream. Advisor budget-awareness: on the final invocation, "This is your LAST invocation. If you choose RETRY, the coding loop runs once more — consider ACCEPT_WITH_DEBT if the code is close." Split-depth guard: "Do NOT choose SPLIT again — use ACCEPT_WITH_DEBT to prevent infinite recursion."
    - **Adopt the debt typing + last-invocation signal + split-depth guard** into DECIDE_WITH_DEBT mechanics. **Do NOT adopt** SWE-AF's completion-with-debt trigger (completing when the reviewer is merely non-blocking and any files changed, even if ACs unmet) — that contradicts G-A25 (Part 4 §4.3).
39. **Ci-fixer "legitimate fix" rules (SWE-AF).** Forbids skipping/xfail/commenting-out tests, loosening assertions, `try/except: pass`, editing CI config, or "retry CI" commits; requires re-running failing tests locally and a `rejected_workarounds` audit trail.
    - **Add to G-A27 sanctioned-path definition and Alchemist self-audit** — the sanctioned repair path must enumerate forbidden workarounds.

## 2.7 From the QA/testing repos: representative-workload mechanics (strengthens G-A21, G-A25)

40. **Named, observable environment spec for the representative workload.** lambdatest: `browserName:version:platform` project convention + toolchain pin (`playwrightClientVersion`); testdino: env tuple (baseURL + retry policy) per environment. "Keep the cross-product small until one run succeeds" — prove one real browser/OS path, then expand.
    - **Add to the representative-workload template (§51):** the "representative environment" must be a named tuple (browser+version+platform, or equivalent surface identity + toolchain pin), not a label like "staging".
41. **Typed evidence allowlist for acceptance-surface proof.** testdino artifacts: `trace.zip`, failure screenshot, `video.webm`, JUnit XML, scoped HAR; "retries surface flakiness, they don't fix it"; "a test that needs retries is a test with a bug." lambdatest accessibility: the surface has "no results API, no exit code, no build-gating flag" — a surface that cannot return typed machine-readable evidence **cannot satisfy G-A25**; "passing an automated scan is necessary, not sufficient."
    - **Add to G-A25:** (a) enumerate the artifact classes that count as observed-at-surface; (b) encode the rule that surfaces without a results API produce `CANDIDATE`, never `COMPLETE`; (c) retry counts are recorded and a retry may not lower the evidence requirement.
42. **Retry discipline split.** testdino `retries: 2 CI / 0 local` + lambdatest "retry only for actionable config/environment fixes; retry only after validation passes" — combined: retries are capped, environment-gated, and never change the evidence requirement.
    - **Add to Alchemist's retry fingerprint** (already strong) as the environment-gating refinement.
43. **Mock boundary rule.** "Mock only external services, never your own app" (testdino Golden Rule 10) — the representative workload isn't representative if the app under test is mocked.
    - **Add to G-A21's forbidden-proxies list.**

## 2.8 Cross-cutting meta-mechanisms (all sources)

44. **Single source of truth for every constant.** SWE-AF's internal drift (`max_retries_per_issue=2` in BuildConfig vs `1` in ExecutionConfig) is the cautionary tale; gstack's resolver-generated preambles (one generator, rendered into every SKILL.md) is the positive pattern. The plan already does this in Part 0 §0.4 — **keep it, and extend it: every numeric cap lives in exactly one schema file, rendered everywhere else.**
45. **Doctrine/policy drift detection within a repo.** coderabbit's own repo contains two opposite mechanics — the code-review skill treats Info-level as the stop condition, while its `.coderabbit.yaml` blocks approval until *every* comment including nitpicks is resolved. This is exactly Legion's G-A27 machinery-defect pattern applied to *doctrine itself*. **Add an eval case: the same rule must not exist in two opposite forms anywhere in `doctrine/`** (extends the plan's Part XV "acceptance_fingerprint_drift" metric).
46. **Definition of Done ≠ acceptance criteria (addy).** A standing project-wide DoD (correctness/quality/integration/documentation/ship-readiness) that is not renegotiated per task, distinct from per-task acceptance criteria.
    - **Add to G-A19:** the frozen acceptance ledger is per-task; a standing DoD is global. Both exist; neither is renegotiated silently.
47. **Clarification convergence (addy interview-me).** Stop clarifying when "you can predict the user's reaction to the next three questions you would ask" (95% confidence); hypotheses carry a 0–100 number; "three rounds without confidence visibly rising → wrong questions, reframe."
    - **Add to Phase 1 FRAME convergence guard** — the plan says product ambiguity becomes EXTERNAL_BLOCKER rather than re-invention; this is the stop test that distinguishes "more questions would help" from "asking is the delay".

---

# Part 3 — What to CHANGE (refinements to existing plan items)

| Plan item | Refinement | Source |
|---|---|---|
| G-A13 severity floor (BLOCKER…NIT) | Add an independent **confidence** field (two axes: severity = impact if real; confidence = certainty). A BLOCKER additionally requires a confidence floor (≥80% or 2 independent signals) and must survive the dismissal-brocard sequence. | ToB, claude-code |
| G-A13 "≤1 nitpick iteration" | Reformulate as a **relative band**: effective floor `max(3.0, THRESHOLD − 1.0)`; one nitpick retry; High/Critical findings remove discretion; mandatory cost reasoning before any re-launch; "accepted within band" = PASS with recorded nitpicks (debt ledger), never silent. | NeoLab |
| G-A7 revision mechanics | Add a **model-tier escalation ladder** tied to rounds: rounds 1–3 same implementer (context intact); rounds 4–5 fresh implementer one tier up; adjudication only at the cap; adjudication = ledger `Ruling:` entry (what — why — cost if wrong). "Escalate to the user, never loop." | obra, NeoLab |
| Part X §37 one-canonical-owner | Change to **three-valued ownership** (runtime / first-fix / canonical) + hard-cut policing ban (delete rejection guards, rejection tests, legacy discriminators). Fix now at first-fix owner; record canonical direction; never re-architect mid-task. | instructa |
| G-A24 one shared-state writer | Add lease semantics from agentfield (lease owner + expiry on durable queue) — the plan names the owner but not the lease/recovery mechanics. | agentfield |
| G-A25 terminal states | Add **forced CANDIDATE submission at every budget cap** with a low-confidence tag (never empty, never COMPLETE, never "promising"); add typed debt adaptation records (dropped/modified ACs + failure diagnosis) to COMPLETED_WITH_DEBT. | swe-agent, SWE-AF |
| G-A23 budgets | Add subagent concurrency/session/spawn-depth caps and a **stop-hook consecutive-block cap** (8 default) to the budget set — control machinery itself needs runaway limits. | claude-code |
| G-A8 decision finality | Store machine decisions as an **append-only event log** (decide/supersede/redact; active computed; redact expunges). Keep dual-status ADRs for humans; the machine store gets event semantics so reversal is explicit by construction. | gstack |
| Part IV door rule | Add door **classification machinery**: registry first → destructive-pattern classifier → default two-way; one-way doors require exact typed confirmation and a stated irreversibility; vague replies → re-ask, never proceed. | gstack |
| G-A12 spike | Add prototype parking as **primary source on a throwaway branch** (main keeps the decision, never the prototype); prototype rules: no tests/persistence/abstractions, 3 default variants (cap 5), variants disagree on structure not colour. | mattpocock |
| G-A19 frozen ledger | Add the mattpocock poisoning guards to the DEFERRED/OUT_OF_SCOPE dispositions: concept-keyed storage, similarity matching, never store "already implemented" as a rejection. | mattpocock |
| §47 ADR template | Add the 3-part record-worthiness pre-test (hard to reverse AND surprising AND real trade-off) as a gate *before* authoring an ADR. | mattpocock |
| §32 state-transition model | Add **test-enforced transition invariants** (irreversible terminals; timeout semi-terminal; no queue→success) as an Arcane test suite. | agentfield |
| G-A26 seal | Add the 4-layer output-recovery ladder (parse → cosmetic repair → LLM repair → retry) before declaring a seal unsound on malformed output. | agentfield |
| G-A27 machinery isolation | Add the stop-list/never-stop-list pattern for sanctioned paths and the ci-fixer forbidden-workaround list ("legitimate fix" rules). | gstack, SWE-AF |
| G-A6/§30 fingerprints | Add semantic loop signals (doubt-theater: repeated reviews with zero actionable findings; same-file/same-diagnostic/same-error-window signals) alongside exact fingerprints. | addy, SWE-AF, gstack |
| Appendix A citation | Replace the "two-strikes-then-reset" Anthropic citation with the actual mechanism: 8-consecutive-block stop-hook cap + auto-mode consecutive-block limit. | claude-code repo |
| Part VI Phase 1 FRAME | Add clarification-convergence stop test (predict the next 3 answers at 95% → stop asking; confidence must rise across rounds or reframe). | addy |
| G-A21 representative workload | Require a named environment tuple (browser:version:platform or surface identity + toolchain pin); "keep the cross-product small until one run succeeds"; mock-only-external-services rule; surfaces without a results API cannot close acceptance items. | lambdatest, testdino |
| Part XV metrics | Add: blocker-confidence-floor violations, perfect-score rejections, doubt-theater events, stop-hook block-cap trips, doctrine-drift findings (same rule in two opposite forms). | NeoLab, addy, claude-code, coderabbit |

---

# Part 4 — What to REMOVE or explicitly NOT adopt

## 4.1 Findings that contradict the plan and must be rejected

1. **ToB "do not suppress findings you judge minor; filter downstream."** (`variant-analysis/references/triage.md` line 79: "a finding you decline to mention is a finding nobody sees.") This is the opposite of G-A20 reviewer non-expansion. Legion's disposition is: emit *classified* findings, but only mapped blockers may gate. Reject the "emit everything ungated" stance; adopt the wording-discipline instead.
2. **ToB "when uncertain, err toward higher severity (security-conservative)."** (`rust-review/agents/rust-review-fp-judge.md` line 324.) Contradicts the calibrated-severity goal of the same corpus (fp-check explicitly fights LLM severity inflation). Reject the err-high rule; adopt the fp-check rationalizations-to-reject register.
3. **SWE-AF COMPLETED_WITH_DEBT bypass.** Default-path stuck loops complete with debt when the reviewer is merely non-blocking and any files changed — even if acceptance criteria are unmet. This contradicts G-A25 (COMPLETE requires observed acceptance-surface proof for every REQUIRED item). Adopt the debt *typing*; reject the bypass trigger. Legion's equivalent terminal is `CANDIDATE` + debt ledger, never COMPLETE.
4. **swe-agent untyped exit-status strings.** (`f"submitted ({step.exit_status})"` free-form.) Reject in favor of agentfield's typed enum + transition invariants.
5. **mini-swe-agent budget exhaustion → empty submission.** Loses the candidate entirely. Legion must force a `CANDIDATE` artifact at every cap (swe-agent pattern).
6. **coderabbit `.coderabbit.yaml` blocks on every comment including nitpicks.** While its own skill says info-level findings are the stop condition. Adopt the skill's stop-at-info rule; treat the yaml as the negative example of policy/drift (see §2.8 item 45).
7. **mattpocock "be opinionated — the user wants a strong read, not a menu."** Partially adopted: Legion's plan already requires a recommendation-led design (one design → one challenge). But the corpus's parallel-divergence pattern (claude-code feature-dev, design-it-twice) shows menus-as-parallel-evidence are fine when they collapse into one committed recommendation. Reject only the anti-menu *presentation* stance; keep parallel divergence as evidence generation.
8. **NeoLab "ACCEPTED below floor" ambiguity.** do-and-judge accepts 3.0–4.0 as PASS-with-nitpicks. Legion should not silently pass below its threshold: within-band → PASS with recorded nitpick debt; below-floor → FAIL and escalate. One nuance, no ambiguity.

## 4.2 Catalog content that must not enter the plan

- voltagent/ericgrill/arabelatso are discovery catalogs. Their convergent capability families (TDD, code review, systematic debugging, git/PR, planning+execution, subagent orchestration, verification gates, docs, security review, frontend, CI/CD, browser testing) are **already covered** by Legion's engineering cohort; the lifecycle-shaped taxonomy (arabelatso: Requirements → Design → Implementation → Testing → Verification → Deployment → Maintenance) is a useful cross-check for the skill registry but adds nothing to doctrine.
- Nothing in the three catalogs covers Legion's **commercial cohort** (Commercial/Research/Editorial/Design) — that is Legion's differentiator, not a gap. No catalog action needed.

## 4.3 Mini-harness lesson (swe-agent-mini)

The mini harness proves budget enforcement, one tool (bash), a 100-line agent loop, and linear history are *sufficient* for many episodes. Legion's lesson is not "cut to the mini shape" — Legion's anti-ceremony machinery is richer — but: **every control Legion adds must be removable in the D0/ambient path** (the mini harness is the existence proof that the ambient tier can stay near-zero machinery). Add to Part IV §7: D0 must be expressible as a mini-harness-shaped loop (no bundles, no history processors, one command tool, truncation at 10k chars).

## 4.4 Citation correction for the final book

Appendix A.5 cites an "Anthropic best-practices — over-review warning; two-strikes-then-reset; … Stop-hook override after 8 consecutive blocks." The cloned claude-code repo contains the 8-block stop-hook cap (`CHANGELOG.md` line 1675, `CLAUDE_CODE_STOP_HOOK_BLOCK_CAP`) and an auto-mode consecutive-block limit — but **no "two-strikes-then-reset" mechanic exists in the checkout.** Correct the citation: the runtime-enforced controls are the 8-consecutive-block cap and the auto-mode block limit; "two-strikes-then-reset" should be re-sourced or dropped.

---

# Part 5 — Prioritized adoption order

Ordered by (leverage × current absence) — the plan's Part XVI adoption sequence stands; these insert into it where noted.

**Tier 1 — blocker admission + reviewer scope (insert into Part XVI steps 2 and 10):**
1. Confidence floor + two-signal rule on BLOCKER; severity/confidence as two finding axes.
2. Dismissal-brocard sequence as the G-A20 "demonstrated safety failure" test.
3. Rationalizations-to-reject register for Covenant/Oracle.
4. Finding-wording discipline ("supports", never "proves"; "gate fired", never "vulnerability found").
5. Three-valued ownership + hard-cut policing ban (into G-A24 / one-canonical-owner).
6. Concept-keyed out-of-scope store (into G-A8).

**Tier 2 — loop termination + anti-gaming (insert into Part XVI step 9):**
7. Threshold-blind judging + perfect-score rejection + reference-first judging.
8. Model-tier escalation ladder tied to revision rounds + fresh implementer after round 3 + adjudication-only-at-cap with `Ruling:` ledger entries.
9. Doubt-theater and semantic loop signals alongside fingerprints.
10. Stop-hook consecutive-block cap + subagent count/depth caps.

**Tier 3 — state and completion machinery (insert into Part XVI steps 3–5, 8):**
11. Typed terminal taxonomy + transition-invariant tests.
12. Forced CANDIDATE submission at every budget cap, tagged low-confidence; typed debt adaptation records.
13. Event-sourced decision store (decide/supersede/redact, computed active).
14. Door classifier + typed confirmation for one-way doors.
15. Output-recovery ladder + transient-pattern retry classification.
16. Named-environment representative workload + typed evidence allowlist + no-results-API rule.

**Tier 4 — hygiene (insert into Part XVI steps 6–7, 11–12):**
17. ADR 3-part record-worthiness test; DoD ≠ acceptance criteria.
18. Frontier questioning + fog-vs-ticket test; clarification-convergence stop test.
19. Change-size/file-size signals; mock-only-external-services; stop-list/never-stop-list.
20. Single-source-of-truth constants (extend §0.4); doctrine-drift eval.
21. Fix the Appendix A.5 two-strikes citation.

---

# Part 6 — Verdict

The 18-repo corpus **validates the plan's direction almost uniformly**: every major convergence control (revision caps with forced structural change, satisficing defaults, severity floors, scoped re-review, decide-with-debt, decision finality, reversibility-scaled ceremony, spike-after-two-non-separating-rounds, decompose-don't-lift) exists in at least two independent strong systems, most already cited in the book's M1–M12 matrix. The corpus adds **what the plan lacks at the edges**: admission evidence for blockers (confidence + dismissal order), anti-gaming judging, ownership migration mechanics, event-sourced decisions, terminal-state machine tests, runaway caps for control machinery itself, and named-surface completion evidence. None of the additions contradict the plan's core laws; the few corpus mechanisms that do (emit-everything review, err-high severity, complete-with-debt bypass) are identified and rejected above. Nothing in the corpus justifies removing or weakening any of G-A1…G-A27; the corpus justifies *adding* the Tier 1–4 items and *sharpening* the changed items in Part 3.

**Net recommendation:** keep the plan as the chassis; merge the 21 Tier-1/2 additions first (they close the remaining admission and termination gaps); apply the Part 3 refinements as each affected module is implemented; reject Part 4.1 items explicitly in doctrine so they cannot creep back.

---

# Appendix — Source index (file paths)

- `addy-agent-skills`: `skills/doubt-driven-development/SKILL.md`, `skills/interview-me/SKILL.md`, `skills/code-review-and-quality/SKILL.md`, `skills/incremental-implementation/SKILL.md`, `skills/planning-and-task-breakdown/SKILL.md`, `skills/spec-driven-development/SKILL.md`, `references/orchestration-patterns.md`, `references/definition-of-done.md`, `skills/code-simplification/SKILL.md`
- `obra-superpowers`: `skills/subagent-driven-development/SKILL.md` (+ `task-reviewer-prompt.md`, `re-review-prompt.md`), `skills/test-driven-development/SKILL.md`, `skills/systematic-debugging/SKILL.md` (+ `root-cause-tracing.md`), `skills/verification-before-completion/SKILL.md`, `skills/receiving-code-review/SKILL.md`, `skills/writing-plans/SKILL.md`, `skills/brainstorming/SKILL.md`
- `garrytan-gstack`: `lib/gstack-decision.ts`, `bin/gstack-decision-log`, `scripts/resolvers/preamble/generate-context-health.ts`, `generate-context-recovery.ts`, `generate-completion-status.ts`, `scripts/one-way-doors.ts`, `scripts/question-registry.ts`, `ship/SKILL.md`, `context-save/SKILL.md`, `investigate/SKILL.md`, `scripts/resolvers/review.ts`
- `mattpocock-skills`: `skills/engineering/domain-modeling/ADR-FORMAT.md`, `skills/engineering/triage/OUT-OF-SCOPE.md`, `skills/engineering/triage/SKILL.md`, `skills/productivity/grilling/SKILL.md`, `skills/engineering/prototype/SKILL.md` (+ `docs/engineering/prototype.md`), `skills/engineering/codebase-design/{SKILL,DESIGN-IT-TWICE}.md`, `skills/engineering/wayfinder/{SKILL.md,docs/engineering/wayfinder.md}`
- `neolab-context-engineering-kit`: `plugins/sadd/skills/{do-and-judge,do-in-parallel,do-in-steps}/SKILL.md`, `plugins/sdd/skills/{plan-task,implement-task}/SKILL.md`, `plugins/sadd/agents/{judge,meta-judge}.md`, `plugins/fpf/skills/decay/SKILL.md`, `plugins/fpf/skills/actualize/SKILL.md`
- `instructa-agent-skills`: `skills/architecture-ownership/SKILL.md` (+ `references/ownership-matrix.md`), `skills/hard-cut/SKILL.md`, `skills/root-cause-finder/SKILL.md`, `skills/consolidate-test-suites/SKILL.md`, `skills/find-duplicate-ownership/SKILL.md`
- `trailofbits-skills`: `plugins/vulnerability-triage-brocards/...`, `plugins/fp-check/...` (esp. `references/{brocards-detail,false-positive-patterns,gate-reviews}.md`), `plugins/variant-analysis/references/triage.md`, `plugins/trailmark/skills/trailmark-review-gate/references/gate-rules.md`, `plugins/zeroize-audit/skills/zeroize-audit/SKILL.md`
- `coderabbitai-skills`: `skills/code-review/SKILL.md`, `skills/autofix/SKILL.md`, `.coderabbit.yaml`, `agents/code-reviewer.md`
- `testdino-playwright-skill`: `core/{locator-strategy,flaky-tests,configuration}.md`, `ci/reporting-and-artifacts.md`, `playwright-cli/test-generation.md`, `SKILL.md`
- `lambdatest-agent-skills`: `hyperexecute-skill/reference/{yaml-patterns,troubleshooting}.md`, `shared/testmu-cloud-reference.md`, `accessibility-skill/{SKILL.md,reference/playbook.md}`, `playwright-skill/reference/cloud-integration.md`
- `swe-agent`: `sweagent/agent/{models,agents,reviewer}.py`, `sweagent/run/common.py` (`_is_promising_patch`), `sweagent/types.py`
- `swe-agent-mini`: `src/minisweagent/{agents/default.py,environments/local.py,config/default.yaml}`
- `agent-field-swe-af`: `swe_af/execution/{coding_loop,schemas,dag_executor,ci_gate}.py`, `swe_af/prompts/{code_reviewer,qa_synthesizer,ci_fixer,issue_advisor}.py`
- `agent-field-agentfield`: `control-plane/pkg/types/status.go`, `control-plane/internal/storage/execution_state_invariant_test.go`, `sdk/python/agentfield/harness/{_runner,_schema}.py`, `docs/design/execution-observability-rfc.md`
- `anthropics-claude-code`: `plugins/feature-dev/{commands/feature-dev.md,agents/code-reviewer.md,agents/code-architect.md}`, `plugins/code-review/commands/code-review.md`, `plugins/plugin-dev/skills/hook-development/*`, `examples/settings/settings-strict.json`, `CHANGELOG.md` (lines 81, 1675), `plugins/ralph-wiggum/hooks/stop-hook.sh`
