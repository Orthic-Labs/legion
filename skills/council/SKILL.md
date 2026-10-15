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
  - web-search
---

# Council

PRIMARY_DELIVERABLE: Digest-bound Council request, record, or packet-only artifact.
CHILD_AGENTS_MAX: 7
EXTERNAL_REQUESTS_MAX: 0 beyond the seat and adjudicator CLI or API sessions (the owner's source research in step 8 is outside them)
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Mode-specific record exists, or packet-only marker proves no panel ran.

Use only on explicit request. Council is Legion's optional independent challenge chamber. The run is
advisory to the user: its findings grant no product authorization, seal nothing, and close no Oracle
finding. Inside the run the adjudicator is the designated decider.

It reviews through different angles, not repeated copies of one reviewer. Every seat holds one
**stance** (its angle of attack, `references/stances/`), one **role card** (whose expertise it brings,
`references/lenses/`), and the artifact's **rubric** (`references/rubrics/`).

One **round** is: six blind seats in parallel on one immutable packet, then one **adjudicator**. There
is no peer-debate round, no separate Jury, and no self-review seat. Three seats are **helpful**
(`improvement-path`, `scope-alternatives`, `user-outcome`) and give advice findings with no score.
Three are **challenging** (`red-team`, `security-ops`, `minimize`) and return a position, a 1-10 score,
and per-dimension rubric scores.

## Convener

The convener is the Legion main thread only. It convenes on the user's `/council` (also `/covenant`),
or when Sage returns a `COUNCIL_REQUESTED: <decision>` line. No other agent, seat, or skill convenes
Council, a seat never convenes a successor, and Council is never convened as ceremony for routine work.

| Invocation | Runs |
|---|---|
| `/council` (aliases `/jury`, `/council quick`) | One round: six seats, then the adjudicator |
| `/council again`, or the user asks for a second round | Round 2: the same six stances in fresh sessions on the revised artifact, then the adjudicator |
| `/council packet` | PACKET_ONLY: author an outside-reviewer brief, run nothing |
| BLOCKER_CONSULT | Three seats and the adjudicator; see Limits |

A second round runs only when the user asks for it. Run at most two rounds per artifact state. A changed
artifact makes a prior verdict stale; never re-run on unchanged material.

## The round

Before any seat launches, capture `git status --short` and `HEAD`. They are the read-only baseline.

1. **Request.** Build the request JSON per `lib/schemas/council-request-v2.schema.json`. Use
   DECISION_CHALLENGE for a named decision or work artifact (a disputed finding is one too) and
   BLOCKER_CONSULT for a named execution blocker. Set `round` (1 or 2). Embed the real artifact, and in
   `userIntent.verbatim` **every user turn that states or corrects the request**, copied from the
   transcript, never paraphrased, trimmed or reordered; keep earlier turns and mark which later
   correction overrides them. Every seat gets this same full text and traces its review to it, so a
   missing turn is a requirement no seat can check. Supply `userIntent.transcriptRef` (transcript path
   and sha256) so the adjudicator can check the verbatim text for completeness. The implementer's
   restatement goes in `interpretedSuccessCriteria`, where it is visibly the author's claim and can be
   disputed. Council never creates a prerequisite authority route. State the phase boundary in
   `constraints` and `nonGoals` so the panel judges the phase, not the whole roadmap: quote the user's
   words for each, and prefix anything the convener adds with `convener:`. The `question` asks what the
   user asked; it never offers options the user did not (for example "include, exclude or defer" when
   the user asked "where does each go"). Seats flag any convener text that drops or narrows a verbatim
   requirement as a P0 packet defect. Finish the request content before computing its digest.
2. **Digest.** Record the author's own known weaknesses in `knownWeaknesses`, each labelled
   `self-review`; this is the author's note, never a seat, and never counts toward independence. Run
   `legion script council/digest <request.json|->` and store the printed digest as `packetDigest`. The
   command excludes only the top-level `packetDigest` field, so the digest stays stable after
   insertion; any nested field named `packetDigest` remains covered. Recompute it after any request
   change; if seats already received the old request, relaunch them against the new digest before
   accepting their results.
3. **Seats.** Launch six seats in parallel, each in a distinct session, one per stance, each with one
   role card (seat mix below). Every seat receives the same packet (full verbatim user intent
   included) and the artifact's rubric, does its requirement trace and framing check first, then its
   stance. Seats are blind: none sees another's output.
4. **Adjudicator.** When the seats return, launch the adjudicator (Seats below) with the packet, the
   `userIntent.transcriptRef`, and all seat replies. It works in this order:
   1. **Own requirement trace** from the verbatim intent alone, before it reads any seat reply.
   2. **Intent completeness**: compare the packet's verbatim intent against the transcript the
      `transcriptRef` points to (check the sha256); report any missing or altered user turn.
   3. **Verify every seat finding** against the packet and, read-only, the repository where a finding
      cites it: `VERIFIED`, `UNGROUNDED`, or `WRONG`.
   4. **Merge and dedupe** verified findings, keeping seat attribution.
   5. **Rule contradictions** between seats (`ruledBy: ADJUDICATOR`). The user may override any ruling
      (`ruledBy: USER`). Keep every dissent; never average seats into one view.
   6. **Verdict** by this rule: any failed challenging seat gives UNRESOLVED; any verified `MISSING`
      verbatim requirement or verified P0 gives REVISE; otherwise the adjudicator's judgement with
      stated reasons (SUPPORTED, REVISE, or UNRESOLVED).

   An adjudicator failure yields no verdict: the outcome is UNRESOLVED. Rerun the adjudicator only, on
   the same model, never on another. If the artifact was authored by Codex or Astra, Fable adjudicates
   and Astra takes the `red-team` seat.
5. **Read-only assertion.** Before reporting, compare `git status --short` and `HEAD` with the
   baseline. A seat or adjudicator that mutated the tree has invalidated its own evidence: set
   `integrity.mutationDetected`, treat the review as failed rather than as a finding, and say so.
   Owner fixes happen after the run, so they never conflict with this check.
6. **Validate.** Assemble the record per `lib/schemas/council-record-v2.schema.json` and run
   `legion script council/validate-record <record.json> --request <request.json>`. Exit 0 is valid,
   1 is invalid, 2 is usage. Revalidate source revision and packet digest at each gate.
   Record mapping (the schema is the authority): `recordId` is `CV-<n>`; each seat's reply maps
   `requirement_trace` → `requirementTrace`, `framing_check` → `framingCheck` (`matchesUserIntent`
   true only when it found no distortion, the rest in `distortions`/`notes`), and each finding →
   `{findingId, statement, tier, classification, recommendedAction}`; `top_concern` and forced answers go
   in the statement of the seat's first finding. The adjudicator's merged `findings` (ids `F-<n>`) hold
   only findings it ruled VERIFIED; UNGROUNDED and WRONG ones appear only in `findingRulings`.
   `integrity` carries `baselineHead` and `baselineStatusDigest` from step 5. A user override sets
   `ruledBy: USER` and `userOverride {originalVerdict, reason, overriddenFindingIds}`; it can clear a
   P0 or MISSING forcing, never a failed challenging seat or a missing adjudication.
7. **Report.** Return the record and the adjudicated result with seat attribution, rulings, and
   dissents. State plainly any failed or missing seat, any degraded run, and any intent-completeness
   finding.
8. **Fix.** The owner (the author) applies fixes after the run. The adjudicator, not the author,
   decides which findings stand: the owner may not reject or supersede a verified finding, and a
   finding the adjudicator ruled stands unless the user overrides it. **A blocker** is an
   `IN_SCOPE_DEFECT` of the phase under review that the adjudicator verified. A concern that cannot
   honestly be judged until a later phase exists is `LATER_PHASE`, with the owning phase named in its `recommendedAction`: it is not a
   blocker. **For every blocker, research the current best-practice fix first**: cite at least one
   current primary source (security advisory, current library or API documentation, recent paper) and
   apply the fix when it is inside the artifact's scope.
9. **Hand off.** Drive the next state, not just the verdict:
   - `SUPPORTED`: offer the next concrete step, for example `/commit` for code, or beginning
     execution for a plan.
   - `REVISE`: apply the fixes and stop. Offer round 2 (`/council again`) on the revised artifact;
     never start it unasked.
   - `UNRESOLVED`: surface the open decision to the user.

## Limits

- Seats in one round never exceed CHILD_AGENTS_MAX: 7 (six seats plus the adjudicator).
- `round` is 1 or 2 on every request and record; after round 2 the phase ships on its evidence, or
  one named hard blocker goes to the user. No third round on the same artifact state.
- BLOCKER_CONSULT is single-round: three seats (`improvement-path` Wonder, `red-team` Fable,
  `security-ops` GLM 5.3) and Astra adjudicating. Each seat judges only whether the proposed
  resolution is contract-safe and states **contract term, proposed change, preservation evidence** in
  its findings' `statement` text. In the record, a challenging blocker seat's `position` maps
  SUPPORTED = contract-safe, REVISE = amendment required, UNRESOLVED = insufficient evidence; its
  `score` rates contract preservation (10 = every term kept, shown), with `scores`
  `{contract_preservation, evidence}`. Outcomes are CONTRACT_SAFE, AMENDMENT_REQUIRED, or INSUFFICIENT_EVIDENCE,
  each judged against the packet's contract text and the proposed resolution:
  - `CONTRACT_SAFE`: the resolution keeps every stated contract term and acceptance criterion, and the
    packet shows that it does.
  - `AMENDMENT_REQUIRED`: the resolution is sound only if a named contract term is amended; the packet
    names the term.
  - `INSUFFICIENT_EVIDENCE`: the packet lacks the contract text, the resolution, or the proof needed to
    judge either. A seat without the real artifact returns this.

## Seats

Seven models across five vendors; no seat reviews its own vendor's work when avoidable. Each is a
fresh headless session started with no conversation history.

| Seat | Model (requested id) | Role | Launch |
|---|---|---|---|
| Wonder full | `muse-wonder-full-1.0` | `improvement-path` | `muse exec --model muse-wonder-full-1.0 --disable-write --disable-shell --prompt-file seat.md` |
| DeepSeek V4.1 Flash | `deepseek-ai/deepseek-v4.1-flash` | `scope-alternatives` | NIM |
| Kimi K2.6 | `moonshotai/kimi-k2.6` | `user-outcome` | NIM |
| Fable 5.1 | `claude-fable-5-1` | `red-team` | `claude -p --model claude-fable-5-1 --permission-mode plan < seat.md` |
| GLM 5.3 | `z-ai/glm-5.3` | `security-ops` | NIM |
| GLM 5.3 Flash | `z-ai/glm-5.3-flash` | `minimize` | NIM |
| Astra 6 | `gpt-6-astra` | adjudicator | `codex exec -m gpt-6-astra -s read-only --skip-git-repo-check - < adjudicator.md` |

NIM seats launch with
`legion script council/nim-seat --model <id> --prompt-file seat.md --out reply.md --reasoning-effort high`.
It streams, reads the key from env `NIM_API_KEY` or `NVIDIA_API_KEY`, else the OS credential store service `NIM_API_KEY`, and
never prints it. Measured NIM behaviour (2026-10-14 pilot): free-tier queueing of 4-20 minutes before
the first token; Kimi K3 (retired 2026-10-15) and GLM 5.3 defaulted `reasoning_effort` to max; GLM 5.3 returned HTTP 504 twice.
Budget for the wait and run the six seats concurrently.

Record each seat's CLI or transport, requested model, reported model, and timings. Never substitute a
model or CLI for a seat; a failed seat is recorded as failed. A host without a seat's CLI (for example
no Muse CLI on the Windows Dell) records that seat as failed.

The seat file (`seat.md`) holds the `council-seat` agent instructions (`agents/council-seat.md` body)
followed by the seat prompt. The adjudicator file (`adjudicator.md`) holds the adjudicator
instructions (step 4) followed by the packet and the six seat replies. A seat prompt embeds, and
nothing else:

- the packet, always including the full verbatim user intent (never another seat's output);
- the seat's stance file, in full;
- exactly one role card, copied from the domain file (the card section, not the whole file);
- the artifact's rubric.

Seat lens id: `<stance>/<domain>:<role>`, with the role name lowercased and non-letters collapsed to
hyphens, for example `red-team/code:lead-architect`, `improvement-path/code:senior-developer`.

**Packet grounding.** A seat reviews the actual artifact, never a description of it. A code packet
embeds the real diff or file contents, not a prose summary of the change. A visual artifact (design,
image, video, rendered UI) carries the real pixels or frames. A seat without them returns
INSUFFICIENT_EVIDENCE rather than judging what it cannot see.

**Visual review.** Seats need a verified image path. A visual run requires each seat CLI to pass a
known-defect screenshot test first (it must report the planted defect from the pixels); a seat that
fails the test is recorded as failed for the run. NIM seats are text-only unless an image endpoint is
verified, so a visual run without a verified endpoint records them as failed, and missing pixels is
always UNRESOLVED.

### Seat mix by artifact type

Role names are the card titles in `references/lenses/`. Seat order follows stance order: helpful
`improvement-path`, `scope-alternatives`, `user-outcome` | challenging `red-team`, `security-ops`,
`minimize`. **A card may hold at most one helpful and one challenging seat; never two seats on the
same side.**

| Artifact | Domain file | Helpful seats | Challenging seats |
|---|---|---|---|
| code | `code.md` | Senior Developer, Lead Architect, QA/Test Lead | Lead Architect, Security/Reliability Reviewer, Senior Developer |
| plan | `plan.md` | Implementation Lead, Decision Reviewer, Customer/User Lens | Risk Inversion Reviewer, Operator, Implementation Lead |
| blogs | `blogs.md` | Editor, SEO/Discovery Reviewer, Brand Voice Editor | Fact Checker, Claims/Substantiation Reviewer (from `compliance-risk.md`, the only cross-file card), Editor |
| design | `design.md` | Interaction Designer, Conversion UX Reviewer, Product Designer | Visual Designer, Accessibility Reviewer, UX Copy Editor |
| offer | `offer.md` | Hormozi Offer Architect, Pricing/Friction Reviewer, Demand Skeptic | Demand Skeptic, Proof/Claims Reviewer, Pricing/Friction Reviewer |
| launch | `launch.md` | Product Readiness Reviewer, GTM Lead, Comms Reviewer | Product Readiness Reviewer, Ops Risk Reviewer, Analytics Reviewer |
| ad | `ad.md` | Creative Strategist, Media Buyer, Skeptical Buyer | Landing Page Skeptic, Compliance Reviewer, Media Buyer |
| business-plan | `business-plan.md` | Finance/Unit Economics Reviewer, Growth/GTM Reviewer, Market Skeptic | Risk Inversion Reviewer, Operator, Finance/Unit Economics Reviewer |
| brand-voice | `brand-voice.md` | Brand Guardian, Cross-Brand Isolation Reviewer, Audience Empathy Reviewer | Claims Police, Cross-Brand Isolation Reviewer, Brand Guardian |
| compliance-risk | `compliance-risk.md` | Platform Policy Reviewer, IP/Trademark Reviewer, Claims/Substantiation Reviewer | Claims/Substantiation Reviewer, Payments/Account Risk Reviewer, IP/Trademark Reviewer |
| content-strategy | `content-strategy.md` | Editorial Director, Distribution Strategist, Audience Researcher | Editorial Director, Distribution Strategist, Capacity Operator |
| idea | `idea.md` | Operator, Market Skeptic, JTBD Reviewer | Munger Inversion Reviewer, Operator, Graham Validator |
| image | `image.md` | Art Director, Creative Director, Skeptical Viewer | Creative Director, Production QA, Art Director |
| priority | `priority.md` | Portfolio Operator, Strategic Fit Reviewer, Energy/Attention Reviewer | Opportunity Cost Reviewer, Cashflow Reviewer, Portfolio Operator |
| seo | `seo.md` | Technical Foundation Reviewer, On-Page/Keyword Reviewer, Answer-First/AEO Reviewer | Search Skeptic, Off-Page White-Hat Reviewer, E-E-A-T Evidence Reviewer |
| video | `video.md` | Editor, Creative Director, Skeptical Social Viewer | Continuity Supervisor, Production QA, Editor |

Pair the rubric with the same name as the domain file (`code.md`, `plan.md`, `blogs.md`, and so on);
each domain uses its own rubric. `audit-visual.md` is used ONLY for rendered UI screenshots; `image`
and `video` keep their own rubrics. The helpful seats receive the rubric for its forced questions and
fail modes but return no score.

## Degradation

- Fewer than four of the six seats returned: report DEGRADED to the user and write no record.
- The adjudicator failed: no verdict; the outcome is UNRESOLVED (rerun the adjudicator only, on the
  same model).
- A failed challenging seat makes the verdict UNRESOLVED; a failed helpful seat leaves its stance
  uncovered and is recorded as failed.

Say so to the user in each case. A failed seat is never relaunched on another model, never replaced by
the convener, and never simulated inline; never claim independence for a single-agent run.

## PACKET_ONLY

For `/council packet`, fill `assets/external-review-packet-template.md` and validate it with
`legion script council/validate-external-review-packet`. This mode runs no seats and produces no
record or outcome: no digest verdict and no adjudication. To use outside reviewers, export the
packet PACKET_ONLY, run it elsewhere, and ingest their replies as seat records (each with its own
stance, role card, and `isolated` flag).
