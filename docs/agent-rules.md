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
- Run `pnpm legion:check` for naming and schema consistency.

## Locked invariants
- Require independent Oracle Completion Validation before every successful final delivery.
- Keep Completion Validation read-only, semantic, source-first, and free of test reruns or review artifacts.
- Reconstruct scope from raw user requests rather than implementer summaries.
- Preserve one canonical owner for each role and routing concept.

## Verification
- Run focused doctrine and routing tests after role changes.
- Check generated agent-rule overlays after source changes.
