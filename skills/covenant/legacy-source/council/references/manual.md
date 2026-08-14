# Council — one review skill, two internal panels

MODE: DIAGNOSE
PRIMARY_DELIVERABLE: Advisory review verdict from immutable redacted packet.
DISCOVERY_PROFILE: D1_SCOPED_SOURCE
EFFECT_PROFILES: child_packet
SPECIALIST_REFS_MAX: 0
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Frozen packet receives requested advisory verdict; child activation remains explicit.

`/council` runs full workflow. `/council packet` is separate authoring mode: it prepares context for third-party agents but never runs Council, Jury, subagents, APIs, CLIs, or review tools. There is no separately exposed `/jury` skill and no user-facing panel-only review mode.

The old manual CLI-review lane (Codex / CodeRabbit / Command Code / Claude CLI) is RETIRED
(2026-07-14): CodeRabbit's review surface is absorbed by `/audit`'s lenses; a new MiniMax + Muse
review system is being set up separately. Do not propose CLI reviewers.

```text
artifact -> self -> Council Room (blind positions, then debate) -> disposition/revise -> fresh blind 4-seat Jury -> verdict
```

Architect remains separate: it designs the artifact and packet; Council reviews the resulting artifact.

## Packet-only mode — external help brief

Trigger only when request contains `/council packet`, `Council packet`, or unmistakably asks to prepare Council context for outside agents.

1. Do not enter Required workflow below.
2. Do not self-review, judge, disposition, invoke `dual-review`, spawn seats, call external APIs, or report verdict.
3. Read relevant task evidence & author [assets/external-review-packet-template.md](assets/external-review-packet-template.md).
4. Default output is durable Markdown at `<project>/tasks/council-packets/<YYYY-MM-DD>/<slug>.md` or existing project packet directory.
5. If the operator explicitly says `inline`, return packet inline instead of writing file.
6. Explain problem + the operator's intent simply enough for zero-context third-party agent, while retaining exact failure evidence, current state, constraints, attempted approaches, & requested response.
7. Embed essential evidence unavailable to outside agent. Local paths alone do not transfer content.
8. End packet with response contract asking reviewer to diagnose root cause, propose concrete changes, identify bypasses/failure paths, & separate must-fix from optional additions.
9. Validate exact output before delivery:

   ```powershell
   # Durable Markdown mode
   py -3.11 D:/workspace/tools/skills/council/scripts/validate-external-review-packet.py <packet.md>

   # Explicit inline mode: validate draft bytes before pasting exact content
   py -3.11 D:/workspace/tools/skills/council/scripts/validate-external-review-packet.py <draft.md> --inline
   ```

   Require exit `0` + `PASS:`. Inline validation draft may be disposable because user explicitly selected inline output; Markdown packet must use durable project storage.

Packet-only output carries no fabricated reviewer finding, vote, or verdict. Writing packet is completion.

## Authority and isolation

- Council is constructive advice. It never blocks ship.
- The active agent is the self seat and owns accept/reject/defer decisions.
- Jury is adversarial and owns the ship gate.
- Jury receives only the revised packet. Never include Council findings, dispositions, votes, model names, or preferred verdict.
- Every Council Room starts with service-blind `Positions`: seats cannot see one another's opening reads until the service advances to `PeerDebate`. Every Jury is a fresh isolated pass and never sees room output or another juror's output. The room never exposes model/provider plumbing. A fallback may reuse a model with a different lens; distinct prompts and isolated context still produce independent evidence.
- **`USER_INTENTION` carries the operator's request VERBATIM, never the implementer's restatement.** The packet is written by the agent whose work is under review, so a paraphrased objective launders the implementer's framing into the gate — the panel then judges "did this meet the goal as I described it," which it always did. Quote the original ask; put the restatement in `SUCCESS_CRITERIA` where it is visibly the author's claim and can be disputed.
- **Review is read-only: assert it.** Before reporting a verdict, confirm `git status --short` is unchanged from the pre-review state and `HEAD` has not moved. A review seat that mutates the working tree has invalidated its own evidence; treat any diff as a failed review, not a finding.
- the operator's eyes remain the visual/taste authority.

## Phased review lifecycle — max 2 COMPLETE loops, not N re-reviews

Reviews are **phased and measured**, capped at **2 complete loops** per design. A "complete loop"
is one full present → panel → disposition cycle tied to a *real artifact state* — never a re-run of
the panel on unchanged paper. A stateless panel re-litigates settled gates when looped
(`feedback-jury-loop-oscillation-cap`); the cap plus a build-and-measure step between loops is what
makes it converge.

- **Loop 1 — plan/design review, BEFORE the build.** Present the plan. The panel marks **only
  immediate, in-scope defects** as `blocker` (must fix before building). Anything that cannot be
  honestly judged until a later phase exists is marked **`defer-to-phase:<phase>`** ("re-show after
  phase N") — it is NOT a blocker and does not fail the loop. Then: research + fix every blocker
  in-loop (per step 5), and **build + measure the required phase**.
- **Loop 2 — evidence review, AFTER the build.** Re-present the built phase **with its measurements
  and validation data** from Loop 1's phase. The Jury judges on real evidence, not projections. This
  is the ship gate for that phase; a `defer-to-phase` item is judged **once, here, with data** — not
  re-flagged every round.
- After 2 complete loops, **stop**: the phase ships on its evidence, or a single named hard blocker
  escalates to the operator. Do not run a 3rd panel on the same phase.

Steps 1-8 below are what happens *inside* one loop.

## Required workflow

1. Identify the review kind and read exactly one matching `references/<kind>.md`.
2. Build a valid fenced `packet` with `ARTIFACT`, `SUCCESS_CRITERIA`, `NON_GOALS`, `CONSTRAINTS`, `ALTERNATIVES_CONSIDERED`, `KNOWN_WEAKNESSES`, `USER_INTENTION`, and `OMISSIONS`.
3. Perform the current-agent self review using the role card.
4. Run the advisory stage in the Council Room for Loop 1, Loop 2, and single-loop reviews. The recorded P-1 correctness and value gates have passed, so the room is the normal Council lane. `--rebuttal` remains only the historical P-1 peer-debate experiment; it is not a finding-termination mechanism and cannot authorize Jury.

   ```powershell
   # Every Council advisory stage
   dual-review <jury-kind> --stage advisory --room --input <packet.md> --output-dir <review-dir>
   ```

   When this returns `status: room_active`, **send the returned `user_notification.message` to the operator immediately**, in commentary, before any other work. Link delivery is mandatory, not optional. After the message is visible to the operator, acknowledge delivery and resume the same room:

   ```powershell
   dual-review <jury-kind> --stage advisory --room --ack-room-link-delivered --input <packet.md> --output-dir <review-dir>
   ```

   The driver persists `room.link_delivery.status: pending` in `review.state.json` and will not export or complete the Council advisory until the explicit acknowledgement changes it to `acknowledged`. Never pass the acknowledgement flag on the initial launch or before sending the link. The acknowledgement durably records the active agent's assertion that it performed the required handoff; it cannot independently prove client rendering. The URL remains a private loopback capability and must not be posted anywhere except the operator's current task.

5. Read `council.advisory.json`. Room dispositions are authored through typed `room_dispose` calls: each original finding author must `accept|recontest`, and only the operator may rule a sustained re-contest. No finding may close as merely noted or acknowledged. Fold accepted changes into the artifact and rebuild the packet. A Loop-1 `defer-to-phase` remains a durable scheduled obligation carried into Loop 2, not a closed third exit.
   - **Research the fix, in-loop (mandatory for every `accepted` blocker).** Before you write the disposition, WebSearch current primary sources for the up-to-date best-practice solution to the accepted finding (security CVEs/OWASP, current library/API docs via reflect `query-docs`, recent papers). Cite ≥1 source in the rationale and **apply the fix in this same round when it is within the artifact's scope** — do not defer a fixable blocker to "later" or wait for the user to ask for research. The point of Council is to catch what the orchestrator missed and *close it here*, not to re-flag it each round. An accepted-but-unresearched blocker is an incomplete disposition.
   - **Separate a phase defect from an out-of-scope "unproven" flag** (per the phased lifecycle above). Classify each finding as either (a) an in-scope defect of the current phase → `blocker`, fix now, or (b) a later-phase item that is unbuilt/unproven *by design* → **`defer-to-phase:<phase>`** with the owning phase named, to be judged once — with measurements — in Loop 2. A later-phase "not proven yet" is NOT a ship-blocker for the current phase; treating it as one makes a correctly-phased plan loop without converging. State the phase boundary explicitly in the packet's `SUCCESS_CRITERIA`/`NON_GOALS` so the panel judges the phase, not the whole roadmap. The `review.disposition.json` `action` for these is `"defer-to-phase"` with a `"phase"` field.
6. Write `review.disposition.json` with this minimum shape:

   ```json
   {
     "loop": 1,
     "self_review": [],
     "advisory_dispositions": [
       {"finding": "immediate in-scope defect", "action": "accepted", "rationale": "...", "source": "https://..."},
       {"finding": "needs a later phase to judge", "action": "defer-to-phase", "phase": "Task 2", "rationale": "..."},
       {"finding": "not a real issue", "action": "rejected", "rationale": "..."}
     ]
   }
   ```

7. Run the internal verdict stage against the revised packet. For `lane: room|room-fallback`, the driver first verifies the typed finding-ledger schema and SHA-256 receipt and refuses to call Jury unless every finding is terminal with an accepted or the operator-ruled `folded|refuted` exit and structurally valid receipt refs:

   ```powershell
   dual-review <jury-kind> --stage verdict --input <revised-packet.md> --disposition <review.disposition.json> --output-dir <review-dir>
   ```

8. Report the labeled Council advice, applied/rejected changes, Jury verdict, blockers, and residual risk. Do not average the panels into one vote; Jury wins only because it is the designated gate.
   - **Meta-review (one blind-spot pass, main session).** Before reporting, the active agent runs a single synthesis pass over the whole review asking "what might ALL seats have missed" — a modality never reviewed (e.g. a flow no packet section covered), an unstated shared assumption, or a finding every seat repeated without anyone naming the root cause. Panels find symptoms; this pass names the disease. Add anything real as a residual-risk note; it does not re-open the verdict.
   - **Post-verdict handoff (drive the next state, do not just print).** Act on the Jury verdict: `SHIP` + code → offer "run `/commit` to ship this?"; `SHIP` + plan → offer to begin execution via native fan-out; `REVISE` → apply the requested revisions in-loop if loops remain (≤2), else surface the single named hard blocker to the operator. Do not print the verdict and stop.

## Seats

| Internal panel | Seats | Source of truth |
|---|---:|---|
| Self | 1 | active agent + role card |
| Council | 3 CLI room seats | `tools/review/agent_room_driver.py` + room charters |
| Jury | 4 API jurors | the selected skill's `jurors` in `tools/review/models.yaml` |

Do not duplicate model slugs in this skill. The room driver is authoritative for Council seats; the registry is authoritative for Jury seats.

## Resumption

The advisory stage checkpoints by skill and input hash. Re-running the same stage reuses `council.advisory.json`; changed input forces a new panel. Every P-1 peer-debate run must live under `tools/review/.council-runs/<run-id>/`; the driver writes artifact paths + SHA-256 values to `evidence.manifest.json` and `review.state.json`, and refuses a digest-invalid resume. The verdict stage writes `jury.verdict.json`, `council-review.json`, and a completed `review.state.json`. A room lane additionally records `lane`, transcript path, finding-ledger digest, open-finding count, escalation rate, and durable scheduled obligations.

## Routing

| Kind | Engine key | Read reference |
|---|---|---|
| `ad` | `jury-ad` | `references/ad.md` |
| `blogs` | `jury-blogs` | `references/blogs.md` |
| `brand-voice` | `jury-brand-voice` | `references/brand-voice.md` |
| `business-plan` | `jury-business-plan` | `references/business-plan.md` |
| `code` | `jury-code` | `references/code.md` |
| `compliance-risk` | `jury-compliance-risk` | `references/compliance-risk.md` |
| `content-strategy` | `jury-content-strategy` | `references/content-strategy.md` |
| `design` | `jury-design` | `references/design.md` |
| `idea` | `jury-idea` | `references/idea.md` |
| `launch` | `jury-launch` | `references/launch.md` |
| `offer` | `jury-offer` | `references/offer.md` |
| `plan` | `jury-plan` | `references/plan.md` |
| `priority` | `jury-priority` | `references/priority.md` |
| `seo` | `jury-seo` | `references/seo.md` |

For rendered UI/screenshots, use `jury-design` or the internal `audit-visual` engine key with real image input. The normal Qwen vision cap is three images; split larger reviews into coherent batches.

**Multimodal packet grounding (a text summary is lossy — give the panel the actual evidence).** `jury-code`: the packet MUST embed the real git diff or file contents in a fenced block, not a prose description of the change — a model cannot judge code it cannot see. `jury-design`: the packet MUST carry absolute paths to the screenshot artifacts so `dual_review.py` attaches the real pixels (same "no pixels = no verdict" rule as `audit-visual`). When a design review needs more than the three-image cap, split it into coherent batches (e.g. desktop pass, then mobile pass) and judge each — never truncate the evidence down to three and call it reviewed.

## Discipline

- Run this external workflow only when the operator explicitly opts in under the workspace review-routing rule.
- Do not skip the disposition/revision gate by sending the original packet to both panels.
- Do not fabricate a panel result if a provider fails; surface fallback/error state.
- Room unavailable or implementer timeout in either loop enters the full `room-fallback` two-pass lane (fresh isolated finding pass, then a separate disposition-check pass). It never skips author acceptance and never merges its ledger with a partial aborted room. If the disposition-check pass fails, that loop is a blocker.
- **Native fallback on provider failure (do not lose the review).** If `dual_review.py` returns a provider failure (missing key, 5xx, timeout, rate limit) for a panel and the user did not explicitly mandate the external providers, do not halt — spawn native Claude subagents with the same *isolated, distinct-lens* prompts (this is exactly the reuse-a-model-with-a-different-lens fallback already permitted under Authority and isolation). Subagents obey the workspace ceiling: **`sonnet` per seat, never Opus** (Opus reasoning stays in the main session; if a seat truly needs it, run that seat inline). Keep Council and Jury isolated exactly as with the API panels, emit the identical JSON shape, and log `lane: native-fallback` in `review.state.json`. the operator gets the multi-perspective review even when the external endpoints are down; diversity comes from distinct lenses + isolation, not from provider identity.
- Do not automatically invoke CLI reviewers. A specifically named CLI reviewer is a separate explicit request.
- Keep Council/Jury labels in artifacts and closeout even though they share one skill.
