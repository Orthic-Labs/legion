# Architect route manual

Canonical method lives in [`../../../doctrine/bundles/sage-architect.md`](../../../doctrine/bundles/sage-architect.md)
and [`../../../doctrine/sage.md`](../../../doctrine/sage.md). This compatibility artifact exists so
legacy entrypoint consumers retain a stable manual path.

Read `../../../agents/sage.md` first. Architect is Sage's decision route: it establishes what should
exist, compares meaningful options, freezes requirements/decisions/invariants/non-goals/acceptance,
and compiles an executable contract only when user asks for implementation. It never performs a
product-source effect; hand settled effects to Alchemist.
