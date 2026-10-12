# ADD
```json
{"schema":"architecture-method-module.v1","method_id":"add","when_to_use":["driver-led decomposition"],"when_not_to_use":["ADD pre-drivers"],"allowed_phases":["candidates"],"inputs":["drivers"],"outputs":["candidate structure"],"prohibitions":["tech-first"]}
```

Use after drivers, boundaries, and material invariants are known. ADD develops a candidate
structure from those forces; it is not a technology-first recipe and does not require every
architecture task to produce a decomposition.

## Procedure

1. Select the drivers that materially distinguish this candidate. State which are fixed constraints
   and which are quality goals, using their scenario IDs or source statements.
2. Choose a responsibility boundary that can address those drivers. Assign each responsibility to
   an element and state its ownership, information authority, and lifecycle where these affect the
   result.
3. Define only interfaces needed to explain collaboration, data/control flow, and relevant
   failure behavior. Check that each boundary preserves the frame's scope and invariants.
4. Walk the candidate against selected scenarios. Record what the structure supports, what it makes
   harder, and which assumptions need evidence. Iterate only for an unmet material driver or a
   consequential boundary conflict.

## Output

Produce a candidate structure with responsibilities, key interfaces, driver-to-structure rationale,
known risks, and unresolved assumptions. Keep it at the level needed to compare candidates; defer
implementation detail that cannot change the architecture decision.

## Bounded example

For partner imports with duplicate delivery and restart recovery as drivers, allocate receipt
deduplication to the import boundary and durable progress to the job-state owner. State that the
boundary records a receipt before acknowledging it, then check that structure against both
scenarios. Do not pick a queue or database until that choice is needed to evaluate a driver or
constraint.
