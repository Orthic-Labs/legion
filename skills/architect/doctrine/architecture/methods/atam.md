# ATAM
```json
{"schema":"architecture-method-module.v1","method_id":"atam","when_to_use":["material tradeoffs"],"when_not_to_use":["ATAM routine D1"],"allowed_phases":["evaluate-select"],"inputs":["scenarios"],"outputs":["tradeoff analysis"],"prohibitions":["auto-all"]}
```

Use focused ATAM analysis when a candidate's quality-attribute interactions create material
trade-offs, risks, or sensitivity points. Routine D1 decisions do not need a formal ATAM pass.

## Procedure

1. Bound evaluation to the decision, candidate structures, quality scenarios, constraints, and
   available evidence. Identify the architectural approaches whose behavior can change a scenario.
2. Walk the most decision-relevant scenarios through each approach. Record expected response,
   evidence, and limits; distinguish supported claims from assumptions.
3. Identify risks (a scenario may miss its target), non-risks (evidence supports the target),
   sensitivity points (small parameter or design changes alter an outcome), and trade-off points
   (one decision affects multiple quality goals).
4. Trace only interactions that could change selection. Name the smallest useful experiment,
   analysis, or follow-up needed to resolve consequential uncertainty; stop when more analysis
   cannot change the choice or its qualification.

## Output

Produce a scoped trade-off record tied to scenario IDs: evaluated approaches, risks and non-risks,
sensitivity and trade-off points, evidence limits, and any decision-changing follow-up. This is
architecture evaluation, not independent completion review or authority to accept risk.

## Bounded example

For a service with recovery and completion-time scenarios, compare durable work recording before
acknowledgement with acknowledgement before recording. The first may support recovery while adding
work to the request path; the second may shorten that path while leaving a loss window. Record the
scenario response and evidence needed to determine whether either effect crosses its target. If no
target or evidence exists, mark the comparison unresolved instead of declaring a winner.
