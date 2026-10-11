# Conditional architecture brainstorming

```json
{"schema":"architecture-method-module.v1","method_id":"brainstorming","when_to_use":["intent or constraints admit materially different architecture directions"],"when_not_to_use":["clear bounded request with one materially adequate route","routine or architecture-insignificant work"],"allowed_phases":["frame","context","candidates","evaluate-select"],"inputs":["intent","constraints","current state","drivers"],"outputs":["credible alternatives","decision checkpoint"],"prohibitions":["universal gate","fixed option count","approval gate","visual-companion runtime"]}
```

Use this method only when resolving the request requires choosing among plausible directions
whose consequences differ materially. Clarify the user's outcome, constraints, and success
conditions only where missing information could change the architecture. Use current-state and
shared-capability evidence before generating options.

Develop the smallest useful set of **meaningfully different, credible** alternatives. Include
reuse/extend/build-new where relevant, and state each option's defining trade-off, fit to the
drivers, and material downside. Do not pad the set to hit a number; if evidence leaves one
materially adequate direction, say why it dominates and retain the strongest rejected alternative
only when it changes the decision.

At the decision checkpoint, state the selected or deferred direction, decision basis, unresolved
assumption or user-owned trade-off, and what would reopen the choice. Ask a focused question only
when that unresolved point changes the result and cannot be answered from current evidence or
the user's request. Otherwise give the recommendation and continue at the depth the request
authorizes. This checkpoint is not approval to begin ordinary implementation: user intent and
execution policy govern that boundary.
