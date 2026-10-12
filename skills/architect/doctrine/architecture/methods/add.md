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
3. For each material module, state caller-visible facts beyond its types: required invariants,
   operation ordering, configuration, and error behavior. Use the deletion test: if removing the
   module makes complexity disappear, it may be a pass-through; if complexity spreads across
   callers, name the leverage the module provides.
4. Place the smallest seam justified by a dependency that actually varies or must be substituted
   for a required test. Use production and test adapters only when both are needed; keep internal
   test seams private. Do not add indirection for hypothetical variation.
5. Walk the candidate against selected scenarios. Prefer observable tests through the module's
   public interface; retain existing behavior coverage until equivalent interface-level coverage
   is established. Record what the structure supports, what it makes harder, and which assumptions
   need evidence. Compare interface shapes only when they change a material driver. Iterate only
   for an unmet material driver or consequential boundary conflict.

## Output

Produce a candidate structure with responsibilities, key interfaces, driver-to-structure rationale,
known risks, and unresolved assumptions. Keep it at the level needed to compare candidates; defer
implementation detail that cannot change the architecture decision.

These checks apply only to architecture-significant decomposition. Do not force a decomposition,
alternate-interface exercise, dependency seam, or test-adapter design for routine or insignificant
work.

The module-depth, deletion-test, public-test-surface, and seam checks are informed by Matt Pocock's
[Codebase Design skill](https://github.com/mattpocock/skills/blob/main/skills/engineering/codebase-design/SKILL.md),
[Deepening guide](https://github.com/mattpocock/skills/blob/main/skills/engineering/codebase-design/DEEPENING.md),
and [Design It Twice guide](https://github.com/mattpocock/skills/blob/main/skills/engineering/codebase-design/DESIGN-IT-TWICE.md).
They are adapted to ADD's driver-led method; they do not require delegation or multiple candidates.

## Bounded example

For partner imports with duplicate delivery and restart recovery as drivers, allocate receipt
deduplication to the import boundary and durable progress to the job-state owner. State that the
boundary records a receipt before acknowledging it, then check that structure against both
scenarios. Do not pick a queue or database until that choice is needed to evaluate a driver or
constraint.
