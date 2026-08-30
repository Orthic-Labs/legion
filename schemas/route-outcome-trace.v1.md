# Route/outcome trace v1 — metric formulas

Companion to `route-outcome-trace.v1.schema.json` and
`engine/crates/legion-contracts/src/trace.rs::RouteOutcomeTrace` (tracker
P1.6). v0 is schema-only — no collector/emitter is implemented here;
recording sites are wired later. This note fixes the four Arcane §30
("Telemetry (feeds Section 29 / tracker P1.6)") metric formulas as pure
functions over a corpus of `RouteOutcomeTrace` records, so a later
dashboard/query can be written mechanically without re-deriving
definitions.

All four metrics are computable with no human judgment at measurement
time: every term below is a recorded field on `trace.challenge`.

```text
let T = a corpus of RouteOutcomeTrace records

challenge_yield =
  count(t in T where t.challenge.invoked
                  and t.challenge.level == L1
                  and t.challenge.outcome in {NARROW, REVISE})
  / count(t in T where t.challenge.invoked and t.challenge.level == L1)

user_challenge_rate =
  count(t in T where t.challenge.user_challenge_event)
  / count(t in T where t.challenge.assumption_dependent_conclusion)

reactive_challenge_yield =
  count(t in T where t.challenge.user_challenge_event
                  and t.challenge.evidence_available_at_first_answer
                  and t.challenge.outcome in {NARROW, REVISE})
  / count(t in T where t.challenge.user_challenge_event)

avoidable_user_challenge_rate =
  count(t in T where t.challenge.user_challenge_event
                  and t.challenge.evidence_available_at_first_answer
                  and t.challenge.outcome in {NARROW, REVISE})
  / count(t in T where t.challenge.assumption_dependent_conclusion)
```

Field-to-doc mapping, verbatim from Arcane §30's prose:

- "L1 passes invoked" -> `t.challenge.invoked and t.challenge.level == L1`
- "passes ending NARROW or REVISE" -> `t.challenge.outcome in {NARROW, REVISE}`
- "user challenge events" -> `t.challenge.user_challenge_event`
- "materially assumption-dependent conclusions" -> `t.challenge.assumption_dependent_conclusion`
- "challenged turns" -> `t.challenge.user_challenge_event` (a turn where the
  user explicitly challenged a prior answer)
- "decisive evidence was available before the first answer" ->
  `t.challenge.evidence_available_at_first_answer`

`avoidable_user_challenge_rate` is the north star (§30): it should trend
toward zero as L1 triggers learn from traces, since it counts exactly the
cases where a user had to ask "are you sure?" about a conclusion for which
the falsifying evidence was already sitting there before the first answer.

Every count above filters `T` on boolean/enum fields only; none require
inspecting trace content, so a dashboard query is a straight `COUNT(...) /
COUNT(...)` over recorded traces once a collector persists them.
