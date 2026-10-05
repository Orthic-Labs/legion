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

### Reducer composition decisions

Apply these rules within the existing reducer framework; they do not require adopting TCA
or replacing a working framework version.

- Actions describe events at a boundary. To share a synchronous transition, call a state
  helper or a helper receiving `inout` state from each relevant action branch. Dispatching an
  extra action solely as a helper call adds scheduling, observation & ordering work. Keep
  delegate events when they communicate an actual child-to-parent outcome.
- Put change observation at a composition level that encloses the relevant mutation. A
  child observer may never see state changed by its parent. Trace where mutation occurs &
  when the observer compares old/new state before adding another notification.
- Scope projections run frequently. Keep them cheap, pure & based on current state; never
  read UserDefaults, files, network or dynamic dependencies there. Store or precompute costly
  derived data at its owning transition instead of redoing it for every action. Avoid
  recreating reference objects inside a projection.
- Model a feature as optional when absence means it is inactive. Remove owned subscriptions
  & effects when that state disappears; hiding a view alone may leave its reducer/effects
  working. Preserve state explicitly when product behavior requires resuming it later.
- Keep temporary hover/high-frequency pointer state local to the view unless another
  feature consumes it or restoration requires it. Send meaningful edge events to domain
  state instead of repeated default-state actions from every cell appearance.
- Observe only state needed by a view. Action-only callers need not acquire a broad state
  subscription; use the project's existing event-sending path.

### Subscription initialization

An existing TCA `ViewStore` current-value publisher may invoke its subscriber synchronously
while subscription is being created. In AppKit bridges, finish control/delegate setup before
subscribing & inspect whether a callback can send an action back into a partially initialized
store/view. Keep UI work on its established main-actor boundary.

If a callback is specifically for subsequent changes & initial UI state was already applied,
conditionally use `dropFirst()` on that current-value stream. If initial state must populate
the UI, retain the first emission & make initialization/reentrancy safe. Never apply this
operator indiscriminately to event-only streams or subscriptions that require initial state.
Let the bridge/controller own its cancellable, cancel it before rebinding or teardown &
avoid a strong subscriber-to-owner cycle.

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

For an in-scope integration, use [Inject procedures](inject.md) or
[Sourcery procedures](sourcery.md) for version-matched operational details.
