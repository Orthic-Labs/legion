# Domain data change

```json
{"schema":"architecture-workflow-module.v1","module_id":"04-domain-data-change","phase":"domain-data-change","ordinal":4,"reads":["drivers","current state"],"writes":["boundaries","invariants","change"],"entry_conditions":["measurable drivers"],"exit_conditions":["domain data change boundaries and invariants"],"next_phase":"05-risk-uncertainty","reopen_requirements":["material delta cause scope IDs"],"prohibitions":["backward no cause scope","no REQUIRED expansion"]}
```

Set domain/data/change boundaries and invariants.
