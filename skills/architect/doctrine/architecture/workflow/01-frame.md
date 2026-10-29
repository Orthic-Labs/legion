# Frame

```json
{"schema":"architecture-workflow-module.v1","module_id":"01-frame","phase":"frame","ordinal":1,"reads":["current state","intent","host shared-capability index","workspace agent rules","prior art"],"writes":["outcome","scope","authority","acceptance fingerprint","reuse decision","prior art"],"entry_conditions":["active intent"],"exit_conditions":["outcome scope authority acceptance fingerprint frozen"],"next_phase":"02-context-stakeholders","reopen_requirements":["material delta cause scope IDs"],"prohibitions":["frame no fingerprint","objective upgrade","no REQUIRED expansion","invented thresholds"]}
```

Frame outcome, scope, authority, and acceptance. D1 Lite frame is valid; cancelled epoch, unknown phase, and reviewer REQUIRED stop work.

## Shared platform first

Before proposing a new component, service, or third-party dependency, read the host's declared
shared-capability index (an ownership or capability index the host injects at session start, or a
host-declared lookup command) and the workspace/repository agent rules. Never invent an index or
assume one exists.

For each capability the work needs, decide in order: **reuse owner** (use the owner as-is) →
**extend owner** (change the owner, keeping its public boundary) → **build new**. Record the
decision with the owner id or the lookup result. Building new, or adding a third-party dependency
for a capability the index declares, requires a recorded reason (owner cannot meet a named
quality scenario, extension is blocked, or the owner is out of authority) and routes through the
normal alternatives/trade-off phases. If the host declares no index, state that once and proceed
on current-state evidence; absence is not a finding.

## Prior art

Before any design, bakeoff, export, or runtime change, survey open-source projects that already
solve or attempt the same problem. Record each with its runtime, format, adoption numbers (dated),
licence, and source URL, then mark it REUSE or NOT_REUSE with the reason. Research performs the
lookup; Architect decides. Record the outcome in the Prior art section of the architecture brief
and option evaluation. Frame closes with a Prior art entry, even when the entry is "none found,"
with the searches named.
