# Candidates

```json
{"schema":"architecture-workflow-module.v1","module_id":"06-candidates","phase":"candidates","ordinal":6,"reads":["drivers","risk","current state"],"writes":["candidates","baselines","caps","failure stories"],"entry_conditions":["risk stop"],"exit_conditions":["D2 candidates build-buy-reuse baselines caps failure stories"],"next_phase":"07-evaluate-select","reopen_requirements":["material delta cause scope IDs"],"prohibitions":["tech-first ADD","weighted comparison before gates","auto-all"]}
```

Build/buy/reuse candidates with baselines, caps, and failure stories.
