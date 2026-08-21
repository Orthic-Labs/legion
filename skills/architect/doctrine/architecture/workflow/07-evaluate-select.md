# Evaluate select

```json
{"schema":"architecture-workflow-module.v1","module_id":"07-evaluate-select","phase":"evaluate-select","ordinal":7,"reads":["candidates","scenarios","evidence"],"writes":["typed outcome","selection evidence"],"entry_conditions":["gates"],"exit_conditions":["gates scenarios economics evidence dominance sensitivity"],"next_phase":"08-minimize","reopen_requirements":["material delta cause scope IDs"],"prohibitions":["weighted comparison before gates","numeric theater","risk acceptance"]}
```

Evaluate gates, then scenarios, economics, evidence, dominance, sensitivity, and typed outcome.
