# Covenant stances

A stance is a seat's angle of attack. A role card (`../lenses/`) says whose expertise the seat brings;
a stance says which way it pushes. The two layer: the same card reviews differently under red-team
than under improvement-path.

**Rule: one stance AND one role card per seat.** Never hand a seat two stances or a whole domain file.
Seats that share a stance in one stage would share a blind spot, so a stage uses each stance once.

| Stage | Stance | Spirit | Forced answer key |
|---|---|---|---|
| 1 Council (advisory) | `improvement-path` | Constructive: smallest change that most improves the artifact | `highest_leverage_improvement` |
| 1 Council (advisory) | `scope-alternatives` | Constructive: is this the best route to the intent? | `best_alternative_and_decider` |
| 1 and 2 | `user-outcome` | Score against the want, not the mechanism | `intention_alternative_path` |
| 2 Jury (verdict) | `red-team` | Adversarial: default REVISE, argue against | `strongest_known_counterexample` |
| 2 Jury (verdict) | `minimize` | Adversarial: what can be removed, deferred, shrunk | `smallest_removable_slice` |
| 2 Jury (verdict) | `security-ops` | Adversarial: trust boundaries, abuse, observability | `exploitable_or_unguarded_path` |

Stage 1 stances give advice and never block. Stage 2 stances return a position and score against the
artifact's rubric (`../rubrics/`). In both stages the seat:

- answers its stance's forced answer in one or two sentences, citing packet evidence;
- tiers every finding P0 (invalidates the outcome or safety), P1 (should change before ship), or P2 (worth knowing);
- labels anything it cannot ground in the packet as speculation;
- stays inside its stance. Another seat covers the other angles.

`user-outcome` is the only stance used in both stages. It reads the verbatim user request, never the
author's restatement of it.

Seat lens id: `<stance>/<domain>:<role>`, for example `red-team/code:lead-architect`.
