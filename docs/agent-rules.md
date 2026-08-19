# Legion Package Rules

## Purpose
Legion provides shared routing, execution, and independent semantic validation for workspace work.

## Canonical sources
- Read `doctrine/legion.md` for routing reference.
- Read `doctrine/oracle.md` for Completion Validation.
- Let `../docs/agent-rules/legion.md` remain workspace constitutional source.

## Commands
- Run `pnpm test` for package coverage.
- Run focused Node tests with `node --test --test-concurrency=1 <paths>`.
- Run `pnpm legion:check` for naming, schema, and dependency-closure consistency.
- Run `pnpm closure:check` for the package boundary alone.

## Locked invariants
- Require independent Oracle Completion Validation before every successful final delivery.
- Keep Completion Validation read-only, semantic, source-first, and free of test reruns or review artifacts.
- Reconstruct scope from raw user requests rather than implementer summaries.
- Preserve one canonical owner for each role and routing concept.
- Classify every outward reference a packaged skill makes. There are five classes, defined in
  `src/registry/capabilities.json`: `PACKAGE_INTERNAL`, `HOST_CAPABILITY`, `PROJECT_OVERLAY`,
  `HISTORICAL_EVIDENCE`, and `TEST_FIXTURE`. A reference that fits none of them is a leak.
- Declare each host capability in the registry with its degradation behaviour, and never ship a
  fallback the package does not contain.
- Authorize a path outside the package only with an explicit `dependency-class:` annotation in the
  file that contains it. Absence of an annotation is not permission.

## Verification
- Run focused doctrine and routing tests after role changes.
- Check generated agent-rule overlays after source changes.
- Refresh `skills/manifests/*.json` with `node scripts/refresh-local-skill-manifests.mjs <bundle>...`
  after editing any packaged skill file, so digests and consumers stay truthful.
