# Progressive architecture

## Map before changing

Identify target, scheme, modules/packages, UI boundary, domain state, persistence, network
clients, native host bridges, generated sources, resources, and test targets. Record which
type owns each lifetime. Keep current ownership unless an observed defect or requirement
demands a move.

Prefer this progression:

1. Put behavior in the existing concrete type when one implementation and one consumer
   exist.
2. Extract a narrow dependency or protocol when a second implementation, a test seam, or
   a stable public boundary is real.
3. Generalize only after repeated structure is visible in more than one caller; keep
   generic constraints smaller than the behavior they protect.

Do not create protocols for every class, wrappers that only rename one method, or modules
whose only purpose is visual separation. A module split must show ownership, reuse,
build-time, or access-control benefit, plus no new dependency cycle or resource/test gap.

## State & effects

Keep state transitions deterministic. Put I/O, clocks, randomness, persistence, and
networking behind the boundary that owns them. A view sends intent; domain code decides
state; an effect reports an outcome. Avoid routing high-frequency UI events through domain
state when view-local filtering can discard irrelevant events first.

For reducer-style code, name user actions by what happened, keep expensive work out of
the synchronous transition, cancel long-lived work when its owning state disappears, and
use parallel effects only when ordering is not part of behavior. Make ordering explicit
when one effect depends on another.

## Compatibility gate

Before changing a public API, persisted model, concurrency boundary, or native bridge,
write down old/new behavior, migration or fallback, deployment availability, and focused
acceptance. Preserve existing clients where possible. New SDK APIs require availability
checks or a project deployment change supported by the request.

## Generated code & hot reload

Use Sourcery or another generator only when repetitive output has a stable source template,
approved toolchain, pinned version, and deterministic regeneration command. Generated files
are outputs; edit templates/configuration, then regenerate and compile. Keep generated
ownership visible in the target and exclude generated output from hand-maintained logic.

Inject-style hot reload is a debug iteration aid. It may sit at a development-only seam,
but it does not replace runtime architecture, tests, or a normal build. Keep linker/build
settings scoped to supported Debug targets, verify distribution configurations do not carry
development behavior, and use an existing approved setup only. Do not install InjectionIII,
alter linker flags, or run source-rewriting helpers merely because a reference mentions them.
