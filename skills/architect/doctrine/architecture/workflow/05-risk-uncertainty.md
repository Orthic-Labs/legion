# Risk uncertainty

```json
{"schema":"architecture-workflow-module.v1","module_id":"05-risk-uncertainty","phase":"risk-uncertainty","ordinal":5,"reads":["boundaries","current state"],"writes":["five uncertainty classes","VOI","stop"],"entry_conditions":["invariants"],"exit_conditions":["VOI stop rule"],"next_phase":"06-candidates","reopen_requirements":["material delta cause scope IDs"],"prohibitions":["risk acceptance","generic more-review","invented thresholds"]}
```

Classify epistemic, requirements, technical, operational, consequence uncertainty; use VOI and stop.
