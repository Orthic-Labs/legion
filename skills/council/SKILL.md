---
name: council
description: Convene Legion's optional independent challenge chamber for a named decision, work artifact, blocker, or packet-only review preparation. Use /council.
kind: entrypoint
discoverability: explicit
target: challenge:council
operations:
  - analyze
  - evaluate
  - produce
effects:
  - source-read
hostRequirements:
  - legion
---

# Council

PRIMARY_DELIVERABLE: Digest-bound Council request, record, or packet-only artifact.
CHILD_AGENTS_MAX: 10
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Mode-specific record exists, or packet-only marker proves no panel ran.

Use only on explicit request. Council is Legion's optional independent challenge chamber, and the
whole run is advisory to the user: its findings grant no product authorization, seal nothing, and
close no Oracle finding. Inside the run the Jury is the designated gate; Council advice never blocks.

It reviews through different angles, not repeated copies of one reviewer. Every seat holds one
**stance** (its angle of attack, `references/stances/`) and one **role card** (whose expertise it
brings, `references/lenses/`). A Jury seat also holds the artifact's **rubric**
(`references/rubrics/`).

One **loop** is: convener self-review, the **Council** panel (blind positions, then one peer-debate
round), the owner's disposition and revision, then a fresh adversarial **Jury**.

## Convener

The convener is the Legion main thread only. It convenes on the user's `/council` (also `/covenant`
and `/jury`), or when Sage returns a `COUNCIL_REQUESTED: <decision>` line. No other agent, seat, or
skill convenes Council, a seat never convenes a successor, and Council is never convened as ceremony
for routine work.

| Invocation | Runs |
|---|---|
| `/council` | One full loop: self-review, Council positions, peer debate, disposition, revision, Jury |
| `/council quick`, `/jury` | The Jury stage only: a fresh verdict panel on the artifact as it stands |
| `/council packet` | PACKET_ONLY: author an outside-reviewer brief, run nothing |
| BLOCKER_CONSULT | One stage, three seats; see Limits |

`quick` is not a complete loop and does not consume one, but it is still tied to a real artifact
state: never run it again on unchanged material.

## The loop

Before anything runs, capture `git status --short` and `HEAD`. They are the read-only baseline.

1. **Request.** Build the request JSON per `lib/schemas/council-request-v1.schema.json`. Use
   DECISION_CHALLENGE for a named decision or work artifact (a disputed finding is one too) and
   BLOCKER_CONSULT for a named execution blocker. Set `loop` (1 or 2). Embed the real artifact and
   the user's request **verbatim** in `userIntent.verbatim`; the implementer's restatement goes in
   `interpretedSuccessCriteria`, where it is visibly the author's claim and can be disputed. Council
   never creates a prerequisite authority route. State the phase boundary in the request's
   `constraints` and `nonGoals` so the panel judges the phase, not the whole roadmap. Run
   `legion script council/digest <request.json|->` and store the printed digest as `packetDigest`.
2. **Self-review.** The convener reviews the artifact first and records what it found in the
   request's `knownWeaknesses`, each labelled `self-review`. A self-review is the author's own pass,
   never a seat, and never counts toward independence.
3. **Council positions.** Launch three seats in parallel, one per stance: `improvement-path`,
   `scope-alternatives`, `user-outcome`, each with one role card (seat mix below). Each gives a
   **blind opening position** (`round: POSITION`): no seat sees another's.
4. **Peer debate (one round only).** Re-launch each Council seat once. Each receives the packet, its
   own position, and the other two seats' positions. For each of its own findings it may **sustain**,
   **revise**, or **withdraw** it, and it may **contest** or endorse any other seat's finding, citing
   packet evidence (`round: DEBATE`). There is no second debate round. Record every contested
   finding as `contested: true` with `sustainedBy` listing the lens ids that still hold it after the
   debate (empty when the author withdrew it).
5. **Synthesis.** The convener dedupes findings, keeps seat attribution, and lists contradictions
   between seats under `disagreements`. It never averages seats into one view and never drops a
   dissent. Return the Council record (`dispositionState: PENDING`) to the owner.
6. **Disposition.** The owner accepts, rejects, or defers every finding with rationale (`ACCEPT`,
   `REJECT`, `DEFER_TO_PHASE`, `NEEDS_EVIDENCE`, `SUPERSEDED`). Council never dispositions its own
   findings. **Only the user rules a sustained contest**: the owner may not `REJECT` or `SUPERSEDE`
   a finding that is contested and still sustained; record the user's ruling as `ruledBy: USER`.
   - **A blocker** is an `IN_SCOPE_DEFECT` of the phase under review that the owner accepts as
     must-fix before building or shipping. A concern that cannot honestly be judged until a later
     phase exists is `LATER_PHASE` and takes `DEFER_TO_PHASE` with `owningPhase`: it is not a
     blocker and does not fail the loop. A later phase being unbuilt or unproven by design is never
     a blocker for the current phase.
   - **For every accepted blocker, research the current best-practice fix first**: current primary
     sources for the up-to-date solution (security advisories, current library or API documentation,
     recent papers). Cite at least one source in the disposition rationale, and apply the fix in this
     same loop when it is inside the artifact's scope. An accepted but unresearched blocker is an
     incomplete disposition.
   Validate before and after: a PENDING record validates without dispositions; a COMPLETE one requires
   them.
7. **Revision.** The owner applies the accepted fixes. Build a NEW request with a new digest for the
   revised artifact, marked `seatPolicy.stage: JURY`. It carries **no Council findings,
   dispositions, votes, or preferred verdict**, because the Jury must come to it unprimed. Record
   `revisionSubjectId` and `revisionDigest` on the Council record; set `freshVerdictRecordId` only
   once `dispositionState` is COMPLETE.
8. **Jury.** Launch four fresh seats in parallel, one per stance: `red-team`, `minimize`,
   `security-ops`, `user-outcome`. Each gets one role card and the artifact's rubric, on the revised
   packet only. Jurors never see each other, and no Council seat is reused: a seat that saw the first
   round is not fresh. Each returns a position, a 1-10 score, per-dimension scores, `top_concern`,
   forced answers, and tiered P0/P1/P2 findings.
9. **Verdict.** Aggregate the Jury positions by one rule: any seat failure or UNRESOLVED gives
   UNRESOLVED; otherwise any REVISE gives REVISE; otherwise SUPPORTED (`aggregate_decision_verdict`
   in `p9_skills/council.rs`). Record splits and dissent explicitly; a REVISE from one seat is never
   outvoted into silence. Never average the Council and Jury panels: report them under their own
   labels, and the Jury wins only because it is the designated gate. The Council record holds
   `outcome: UNRESOLVED` by definition (advice renders no verdict); the verdict is the Jury record's.
10. **Read-only assertion.** Before reporting, confirm `git status --short` and `HEAD` equal the
    baseline. A seat that mutated the tree has invalidated its own evidence: set
    `integrity.mutationDetected`, treat the review as failed rather than as a finding, and say so.
11. **Meta-review (one blind-spot pass).** The convener asks once, over the whole run: what might ALL
    seats have missed? A modality nobody reviewed, a flow no packet section covered, a shared
    unstated assumption, or a finding every seat repeated without naming its root cause. Add anything
    real to the Jury record's `risks`, labelled `meta-review`. It does not reopen the verdict.
12. **Validate.** Assemble each record per `lib/schemas/council-record-v1.schema.json` and run
    `legion script council/validate-record <record.json> --request <request.json>`. Exit 0 is valid,
    1 is invalid, 2 is usage. A record needs at least three seats with distinct lens ids (a Council
    seat appears once per round). Revalidate source revision and packet digest at each gate; a
    changed subject makes a prior verdict stale.
13. **Hand off.** Return both records and the labelled results, then drive the next state, not just
    the verdict:
    - `SUPPORTED`: offer the next concrete step, for example `/commit` for code, or beginning
      execution for a plan.
    - `REVISE`: apply the requested revisions and stop, or run loop 2 when the artifact has reached
      its post-build state and a loop remains.
    - `UNRESOLVED`: surface the open decision to the user.

## Phased lifecycle: at most two complete loops

A complete loop is one full run of the steps above tied to a **real artifact state**, never a re-run
on unchanged material. A stateless panel re-litigates settled gates when looped; the cap, plus a
build-and-measure step between loops, is what makes the process converge.

- **Loop 1: plan or design review, before the build.** The panel marks only immediate, in-scope
  defects as blockers. Later-phase concerns are `LATER_PHASE` and deferred to their phase. Fix every
  accepted blocker in-loop (with the researched fix), then **build and measure** the phase.
- **Loop 2: evidence review, after the build.** Re-present the built phase **with its measurements
  and validation data**. The Jury judges real evidence, not projections. A deferred item is judged
  once here, with data, not re-flagged every round.
- **After two loops, stop.** The phase ships on its evidence, or one named hard blocker goes to the
  user. No third panel on the same phase.

## Limits

- Seats launched in one loop never exceed CHILD_AGENTS_MAX: 10 (3 Council positions, 3 debate
  re-launches, 4 Jury).
- `loop` is 1 or 2 on every request and record.
- BLOCKER_CONSULT is single-stage: three seats (`improvement-path`, `red-team`, `security-ops`),
  each judging only whether the proposed resolution is contract-safe, with no debate round. Outcomes
  are CONTRACT_SAFE, AMENDMENT_REQUIRED, or INSUFFICIENT_EVIDENCE.

## Seats

Launch each seat as `subagent_type: legion:council-seat` with `fork_turns: "none"`. The prompt
embeds, and nothing else:

- the packet (never another seat's output, except the Council debate round below);
- the seat's stance file, in full;
- exactly one role card, copied from the domain file (the card section, not the whole file);
- in the Jury, the artifact's rubric;
- in a Council debate re-launch only, the seat's own position and the other seats' positions.

Seat lens id: `<stance>/<domain>:<role>`, with the role name lowercased and non-letters collapsed to
hyphens, for example `red-team/code:lead-architect`, `improvement-path/code:qa-test-lead`.

**Packet grounding.** A seat reviews the actual artifact, never a description of it. A code packet
embeds the real diff or file contents, not a prose summary of the change. A visual artifact (design,
image, video, rendered UI) carries the real pixels or frames. A seat without them returns
INSUFFICIENT_EVIDENCE rather than judging code it cannot see or describing what it cannot see.

### Seat mix by artifact type

Role names below are the card titles in `references/lenses/`. Seat order follows stance order:
Council `improvement-path`, `scope-alternatives`, `user-outcome`; Jury `red-team`, `minimize`,
`security-ops`, `user-outcome`.

| Artifact | Domain file | Council | Jury |
|---|---|---|---|
| code | `code.md` | Senior Developer, Lead Architect, QA/Test Lead | Lead Architect, Senior Developer, Security/Reliability Reviewer, QA/Test Lead |
| plan | `plan.md` | Implementation Lead, Decision Reviewer, Customer/User Lens | Risk Inversion Reviewer, Implementation Lead, Operator, Customer/User Lens |
| copy, blog | `blogs.md` | Editor, SEO/Discovery Reviewer, Brand Voice Editor | Fact Checker, Editor, Claims/Substantiation Reviewer (from `compliance-risk.md`), Brand Voice Editor |
| design | `design.md` | Interaction Designer, Product Designer, Conversion UX Reviewer | Visual Designer, UX Copy Editor, Accessibility Reviewer, Product Designer |
| offer | `offer.md` | Hormozi Offer Architect, Pricing/Friction Reviewer, Brand Guardian | Demand Skeptic, Pricing/Friction Reviewer, Proof/Claims Reviewer, Hormozi Offer Architect |
| launch | `launch.md` | Product Readiness Reviewer, GTM Lead, Comms Reviewer | Ops Risk Reviewer, GTM Lead, Analytics Reviewer, Product Readiness Reviewer |
| ad | `ad.md` | Creative Strategist, Media Buyer, Skeptical Buyer | Landing Page Skeptic, Creative Strategist, Compliance Reviewer, Brand Guardian |
| other domain | its file | the first three cards in file order | the file's inversion or skeptic card first, then the rest in file order |

Pair the rubric with the same name (`code.md`, `plan.md`, `blogs.md`, `design.md`, `offer.md`,
`launch.md`, `ad.md`); other domains use the rubric of their domain file, and rendered screenshots
use `audit-visual.md`. A card used twice in one stage is a defect: change one assignment. The
blog row borrows one card from `compliance-risk.md` because the blog file has no claims reviewer;
this is the only cross-file card.

## Degradation

If the `legion:council-seat` agent is unavailable, record DEGRADED and stop. Never simulate seats
inline, and never claim independence for a single-agent run. A Council seat that failed leaves its
stance uncovered and is recorded as such; it is not replaced by the convener. A Jury seat failure
makes the outcome UNRESOLVED. A seat that fails its debate re-launch keeps its blind position and
is recorded as not having debated.

## PACKET_ONLY

For `/council packet`, fill `assets/external-review-packet-template.md` and validate it with
`legion script council/validate-external-review-packet`. This mode runs no seats and produces no
record or outcome: no self-review, disposition, or verdict. To use outside reviewers, export the
packet PACKET_ONLY, run it elsewhere, and ingest their replies as seat records (each with its own
stance, role card, and `isolated` flag); Council itself makes no external or cross-vendor calls.
Seats are host-native.
