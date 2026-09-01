# Legion Package Rules

## Purpose
Legion provides shared routing, execution, and independent semantic validation as an installable package.

## Canonical sources
- Read `doctrine/legion.md` for routing reference.
- Read `doctrine/oracle.md` for Completion Validation.

## Commands

- This is an Orthic Labs public repository: `compile: github-actions-only`. Never run cargo, Rust builds/tests, packaging, signing, qualification, or release steps locally; push & read managed CI. Local scope is reads, static checks, JS/node tests, & schema validation.
- Run `pnpm test` for package coverage.
- Run focused Node tests with `node --test --test-concurrency=1 <paths>`.
- Run `pnpm legion:check` for naming, schema, and dependency-closure consistency.
- Run `pnpm closure:check` for the package boundary alone.

## Locked invariants
- Require independent Oracle Completion Validation before every successful final delivery.
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
- Refresh `skills/manifests/*.json` with `node scripts/refresh-local-skill-manifests.mjs <bundle>...`
  after editing any packaged skill file, so digests and consumers stay truthful.
