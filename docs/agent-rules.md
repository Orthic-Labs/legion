# Legion Package Rules

## Purpose
Legion provides shared routing, execution, and independent semantic validation as an installable package.

## Canonical sources
- Read `doctrine/legion.md` for routing reference.
- Read `doctrine/oracle.md` for Completion Validation.

## Commands

- Before local build/check/test admission, inspect managed RightKit inventory once, including past 30 minutes. If another build is queued, running, or was processed within that window, never start or queue local work: move to Windows unsigned GitHub CI. Missing inventory fails closed to CI; do not poll or wait for local capacity.
- Before Windows installer assembly, check whole native workspace/all targets on selected host. GitHub development workflow includes this gate; local path uses `pnpm run native:check:local` after idle admission.
- For Windows installer development, use `.github/workflows/windows-development.yml` when local admission is refused or CI is requested; otherwise run `pnpm run release:local:win:unsigned` from primary checkout after native check passes. Both routes require unsigned installer → isolated installed qualification → exact stable-`current` install. See `docs/reference/release/local-windows-development.md`.
- Use `pnpm run release:build:win:unsigned` only when build output is requested without install or qualification. Focused local tests supporting this route are allowed.
- Windows unsigned development CI is authorized; signing, publication & Mac work require explicit scope. Download exact qualified installer, reinstall stable `current` & verify requested installed behavior before claiming completion.

## Locked invariants
- Use Oracle when explicitly requested or when a concrete outcome or safety risk needs independent review. Routine replies, read-only answers, status updates & small reversible changes need no Oracle.
- Keep Completion Validation read-only, semantic, source-first, and free of test reruns or review artifacts.
- Reconstruct scope from raw user requests rather than implementer summaries.
- Preserve one canonical owner for each role and routing concept.
- Classify every outward reference a packaged skill makes. There are four classes, defined in
  `src/registry/capabilities.json`: `PACKAGE_INTERNAL`, `HOST_CAPABILITY`, `PROJECT_OVERLAY`, and
  `HISTORICAL_EVIDENCE`. A reference that fits none of them is a leak.
- Declare each host capability in the registry with its degradation behaviour, and never ship a
  fallback the package does not contain.
- Keep Legion the canonical source for every skill it ships. There is no upstream to import from,
  so a packaged file carries one digest and no transform record.

## Verification
- Run focused doctrine and routing tests after role changes.
- Refresh `skills/manifests/*.json` with `cargo run -q --locked --manifest-path engine/Cargo.toml -p legion-dev -- refresh-local-skill-manifests <bundle>...`
  after editing any packaged skill file, so digests and consumers stay truthful.
