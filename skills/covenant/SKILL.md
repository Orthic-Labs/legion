---
name: covenant
description: Convene Legion's optional independent challenge chamber for a named decision, work artifact, blocker, or packet-only review preparation. Use /covenant.
kind: entrypoint
discoverability: explicit
target: challenge:covenant
operations:
  - analyze
  - evaluate
  - produce
effects:
  - source-read
hostRequirements:
  - legion
---

# Covenant

PRIMARY_DELIVERABLE: Digest-bound Covenant request, record, or packet-only artifact.
CHILD_AGENTS_MAX: 7
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Mode-specific record exists, or packet-only marker proves no panel ran.

Covenant is Legion's optional independent challenge chamber. Its findings are advisory: they grant
no product authorization, seal nothing, and close no Oracle finding.

It reviews through different angles, not repeated copies of one reviewer. Every seat holds one
**stance** (its angle of attack, `references/stances/`) and one **role card** (whose expertise it
brings, `references/lenses/`). A verdict seat also holds the artifact's **rubric**
(`references/rubrics/`). Two stages run in order: a constructive advisory Council, then, after the
owner has dispositioned and revised, a fresh adversarial Jury.

## Convener

The convener is the Legion main thread only. It convenes on the user's `/covenant` (also `/council`
and `/jury`), or when Sage returns a `COVENANT_REQUESTED: <decision>` line. No other agent, seat, or
skill convenes Covenant, and a seat never convenes a successor.

| Invocation | Runs |
|---|---|
| `/covenant` | Self-review, stage 1 Council, synthesis, disposition gate, revision, stage 2 Jury |
| `/council` | Stage 1 only: advisory, no verdict |
| `/covenant quick`, `/jury` | Stage 2 only: a fresh verdict panel on the artifact as it stands |
| BLOCKER_CONSULT | One stage, three seats; see below |

## Procedure

1. **Request.** Build the request JSON per `lib/schemas/covenant-request-v1.schema.json`. Use
   DECISION_CHALLENGE for a named decision or work artifact (a disputed finding is one too) and
   BLOCKER_CONSULT for a named execution blocker. Embed the real artifact and the user's verbatim
   request; Covenant never creates a prerequisite authority route. Run
   `legion script covenant/digest <request.json|->` and store the printed digest as `packetDigest`.
2. **Self-review.** The convener reviews the artifact first and records what it found in the
   request's `knownWeaknesses`, each labelled `self-review`. A self-review is the author's own pass,
   never a seat, and never counts toward independence.
3. **Stage 1, Council (advisory).** Launch three seats in parallel, one per stance:
   `improvement-path`, `scope-alternatives`, `user-outcome`. Give each one role card from the
   artifact's domain file (seat mix below). Council advice never blocks.
4. **Synthesis.** The convener dedupes findings, keeps seat attribution, and lists contradictions
   between seats under `disagreements`. It never averages seats into one view and never drops a
   dissent.
5. **Disposition gate.** Return the stage 1 record (`dispositionState: PENDING`) to the decision
   owner, who dispositions every finding as accepted, rejected, or deferred with rationale
   (`ACCEPT`, `REJECT`, `DEFER_TO_PHASE`, `NEEDS_EVIDENCE`, `SUPERSEDED`). Covenant never
   dispositions its own findings. Validate before and after: a PENDING record validates without
   dispositions; a COMPLETE one requires them.
6. **Revision.** The owner revises the artifact. Build a NEW request with a new digest for the
   revised artifact. It carries no stage 1 findings, votes, dispositions, or preferred verdict,
   because the verdict panel must come to it unprimed. Mark it `seatPolicy.stage: JURY`. Record
   `revisionSubjectId` and `revisionDigest` on the stage 1 record; set `freshVerdictRecordId` only
   once `dispositionState` is COMPLETE.
7. **Stage 2, Jury (verdict).** Launch four fresh seats in parallel, one per stance: `red-team`,
   `minimize`, `security-ops`, `user-outcome`. Each gets one role card and the artifact's rubric.
   Each returns a position, a 1-10 score, per-dimension scores, `top_concern`, forced answers, and
   tiered P0/P1/P2 findings. No stage 1 seat is reused: a seat that saw the first round is not fresh.
8. **Outcome.** Aggregate the stage 2 positions by one rule: any seat failure or UNRESOLVED gives
   UNRESOLVED; otherwise any REVISE gives REVISE; otherwise SUPPORTED
   (`aggregate_decision_verdict` in `p9_skills/covenant.rs`). Record splits and dissent explicitly;
   a REVISE from one seat is never outvoted into silence.
9. **Validate.** Assemble each record per `lib/schemas/covenant-record-v1.schema.json` and run
   `legion script covenant/validate-record <record.json> --request <request.json>`. Exit 0 is valid,
   1 is invalid, 2 is usage. A record needs at least three seats with distinct lens ids.
   Revalidate source revision and packet digest at each gate; a changed subject makes a prior
   verdict stale.
10. **Return** both records to the decision owner, who dispositions the stage 2 findings too.

The stage 1 record holds `outcome: UNRESOLVED` by definition: advice renders no verdict. The verdict
is the stage 2 record's outcome.

## Limits

- At most two full loops (Council, revision, Jury) per decision. A third needs the owner's explicit
  request on a materially changed artifact.
- `/covenant quick` and `/jury` skip stage 1; `/council` stops after the disposition gate.
- Seats launched in total never exceed CHILD_AGENTS_MAX: 7 (3 plus 4).
- BLOCKER_CONSULT is single-stage: three seats (`improvement-path`, `red-team`, `security-ops`),
  each judging only whether the proposed resolution is contract-safe. Outcomes are CONTRACT_SAFE,
  AMENDMENT_REQUIRED, or INSUFFICIENT_EVIDENCE.

## Seats

Launch each seat as `subagent_type: legion:covenant-seat` with `fork_turns: "none"`. The prompt
embeds, and nothing else:

- the packet (never another seat's output);
- the seat's stance file, in full;
- exactly one role card, copied from the domain file (the card section, not the whole file);
- in stage 2, the artifact's rubric.

Seat lens id: `<stance>/<domain>:<role>`, with the role name lowercased and non-letters collapsed to
hyphens, for example `red-team/code:lead-architect`, `improvement-path/code:qa-test-lead`.

Visual artifacts (design, image, video, rendered UI): the packet must carry the real pixels or
frames. A seat without them returns INSUFFICIENT_EVIDENCE rather than describing what it cannot see.

### Seat mix by artifact type

Role names below are the card titles in `references/lenses/`. Seat order follows stance order:
stage 1 `improvement-path`, `scope-alternatives`, `user-outcome`; stage 2 `red-team`, `minimize`,
`security-ops`, `user-outcome`.

| Artifact | Domain file | Stage 1 Council | Stage 2 Jury |
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

If the `legion:covenant-seat` agent is unavailable, record DEGRADED and stop. Never simulate seats
inline, and never claim independence for a single-agent run. A stage 1 seat that failed leaves its
stance uncovered and is recorded as such; it is not replaced by the convener. A stage 2 failure
makes the outcome UNRESOLVED.

## PACKET_ONLY

For packet-only review preparation, fill `assets/external-review-packet-template.md` and validate it
with `legion script covenant/validate-external-review-packet`. This mode runs no seats and produces
no record or outcome. To use outside reviewers, export the packet PACKET_ONLY, run it elsewhere, and
ingest their replies as seat records (each with its own stance, role card, and `isolated` flag);
Covenant itself makes no external or cross-vendor calls. Seats are host-native.
