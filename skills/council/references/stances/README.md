# Council stances

A stance is a seat's angle of attack. A role card (`../lenses/`) says whose expertise the seat brings;
a stance says which way it pushes. The two layer: the same card reviews differently under red-team
than under improvement-path.

**Rule: one stance AND one role card per seat.** Never hand a seat two stances or a whole domain file.
Seats that share a stance in one round would share a blind spot, so a round uses each stance once.

| Side | Stance | Spirit | Forced answer key |
|---|---|---|---|
| Helpful | `improvement-path` | Constructive: smallest change that most improves the artifact | `highest_leverage_improvement` |
| Helpful | `scope-alternatives` | Constructive: is this the best route to the intent? | `best_alternative_and_decider` |
| Helpful | `user-outcome` | Advise against the want, not the mechanism | `intention_fidelity` |
| Challenging | `red-team` | Adversarial: default REVISE, argue against | `strongest_known_counterexample` |
| Challenging | `security-ops` | Adversarial: trust boundaries, abuse, observability | `exploitable_or_unguarded_path` |
| Challenging | `minimize` | Adversarial: what can be removed, deferred, shrunk | `smallest_removable_slice` |

One round runs all six seats blind and in parallel on one packet; one adjudicator then verifies and
merges their findings. Helpful seats give advice findings and no score. Challenging seats return a
position and a score against the artifact's rubric (`../rubrics/`). No seat sees another. In every seat:

- answers its stance's forced answer in one or two sentences, citing packet evidence;
- tiers every finding P0 (invalidates the outcome or safety), P1 (should change before ship), or P2 (worth knowing);
- labels anything it cannot ground in the packet as speculation;
- stays inside its stance. Another seat covers the other angles.

Every seat in every stance first traces the verbatim user request, never the author's restatement of
it (`agents/council-seat.md`, requirement trace and framing check); the stance only sets where a seat
attacks. `user-outcome` goes deeper on the want: friction the
user did not ask for and how success will be observed.

Seat lens id: `<stance>/<domain>:<role>`, for example `red-team/code:lead-architect`.
