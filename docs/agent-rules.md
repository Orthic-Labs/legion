# Legion Package Rules

## Purpose
Legion provides shared routing, execution, and independent semantic validation as an installable package.

## Canonical sources
- Read `doctrine/legion.md` for routing reference.
- Read `doctrine/oracle.md` for Completion Validation.

## Commands

- For Windows installer development, run `pnpm run release:local:win:unsigned` from primary checkout. This is default pre-publication path: managed RightKit warm cache → unsigned installer → isolated installed qualification → exact stable-`current` install. See `docs/reference/release/local-windows-development.md`.
- Use `pnpm run release:build:win:unsigned` only when build output is requested without install or qualification. Focused local tests supporting this route are allowed.
- Do not use GitHub Actions, signing, publication, or Mac work for Windows installer development. Use public release machinery only after local installed route passes & operator explicitly requests publication.

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
