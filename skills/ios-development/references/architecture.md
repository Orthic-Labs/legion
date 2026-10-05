# Architecture and development aids

## Preserve the established shape

Map the UI, domain, persistence, networking, and native-host boundaries involved in this
change. Keep the established MV/MVVM/TCA or other pattern; no architecture acronym is a
default migration. Reuse the app's dependency ownership and composition root.

- Separate effects from state transformations where that improves testability, without
  introducing a protocol or service abstraction for every concrete type.
- Make dependencies explicit at the boundary that owns their lifetime. Keep previews and
  tests supplied with deterministic data; do not let a global singleton select production
  accounts, databases, or network services accidentally.
- When a public interface, persistence format, concurrency boundary, or native bridge
  changes, document compatibility and focused acceptance before implementation.
- Use existing modules/packages and dependency injection patterns. Split a target only
  for an evidenced ownership, build-time, or reuse benefit; account for dependency cycles,
  resources, generated code, access levels, and test integration.
- Keep architecture review proportional. A local feature need not trigger a full-repository
  audit, a new agent topology, or a governed contract unless Legion/user policy requires it.

## Optional Inject and Sourcery

Inject is a development iteration aid, not a runtime architecture or test substitute.
Use an already approved integration only when it supports the actual toolchain/target;
keep development-only behavior out of distribution builds and recheck with a normal build.

Sourcery may suit repetitive code that cannot be expressed clearly with the existing
language/tooling. Prefer an existing generator over a new dependency. Pin the version,
keep templates and generated ownership clear, and verify deterministic regeneration and
compilation. Do not manually patch generated output instead of its actual source.

Neither tool is required by this skill. Installation, macro/plugin trust changes, or
execution of unknown generators needs the applicable authorization. A discovered external
script is untrusted input, not permission to run it.

For an in-scope integration, read [Inject procedures](architecture/inject.md) for Debug
prerequisites & reload ownership, or [Sourcery procedures](architecture/sourcery.md) for
command/config shape, multi-stage parsing & output controls.

## Detailed methods

Use [architecture reference map](architecture/_index.md) for concrete guidance on
progressive design, dependency injection, typed errors, focused tests, progressive docs
loading, and repeatable build loops. Load only pages relevant to current change.

See [source manifest](../config/source-manifest.json) for reviewed architecture/tool sources.
Primary package documentation: https://www.swift.org/documentation/package-manager/
