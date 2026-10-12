# QAW
```json
{"schema":"architecture-method-module.v1","method_id":"qaw","when_to_use":["conditional drivers"],"when_not_to_use":["universal QAW","broad research under SUFFICIENT"],"allowed_phases":["drivers"],"inputs":["stakeholders"],"outputs":["quality scenarios"],"prohibitions":["auto-all"]}
```

Use when stakeholder goals or constraints leave a material quality driver unclear or contested.
Do not run broad elicitation when supplied requirements settle the drivers, or when the charter's
`sufficient` objective does not justify extra research.

## Procedure

1. Start from the frame, stakeholders, constraints, and existing drivers. Ask only affected
   stakeholders for missing or conflicting quality needs; do not reopen settled scope.
2. Turn each material need into a scenario: source, stimulus, operating environment, system
   response, and measurable target. Record who supplied each target and whether it is accepted,
   provisional, or unknown.
3. Have stakeholders rank scenario importance and architects record implementation difficulty
   separately. Resolve only rankings or targets that could change candidate selection; otherwise
   preserve disagreement as an assumption or unknown with an owner.
4. Carry ranked scenarios into risk and candidate evaluation. Stop when decision-relevant drivers
   are stable; do not seek consensus for its own sake.

## Output

Produce a small set of traceable quality scenarios and a ranked driver list, including source,
target status, unresolved disagreement, and follow-up owner. Use the existing
`../templates/quality-scenario.md` shape where a durable artifact is needed.

## Bounded example

For a partner-import service, operations says recovery after a worker restart matters, while a
product owner says import completion time matters. Record one restart/recovery scenario and one
completion-time scenario. Ask each owner for a target or mark it unknown; do not invent a latency
limit. If later evidence shows recovery time cannot affect the choice, retain it as context rather
than expanding the architecture exercise.
