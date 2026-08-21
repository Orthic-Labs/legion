# Drivers quality scenarios

```json
{"schema":"architecture-workflow-module.v1","module_id":"03-drivers-quality-scenarios","phase":"drivers","ordinal":3,"reads":["context","current state"],"writes":["drivers","measurable scenarios"],"entry_conditions":["context complete"],"exit_conditions":["measurable scenarios"],"next_phase":"04-domain-data-change","reopen_requirements":["material delta cause scope IDs"],"prohibitions":["invented thresholds","objective self-upgrade"]}
```

Express material drivers as measurable scenarios.
