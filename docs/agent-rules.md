# Legion Package Rules

## Purpose
Legion provides shared routing, execution, and independent semantic validation as an installable package.

## Canonical sources
- Precedence: `docs/LEGION-CANONICAL-SSOT.md` > `AGENTS.md` > `src/roster/*` & `doctrine/*` > `skills/<id>/SKILL.md` > generated projections.
- Read `docs/LEGION-CANONICAL-SSOT.md` for system architecture and ownership boundaries.
- Read `doctrine/legion.md` for routing reference.
- Read `src/roster/*.md` for role identity, authority, and trigger boundary; `doctrine/sage.md`, `doctrine/alchemist.md` & `doctrine/oracle.md` for role method (Oracle: Completion Validation).
- `docs/provenance/**` (including `docs/provenance/canon/` & `docs/provenance/pending/`) is frozen history that cites deleted code. It is not authoritative and not a pending-work index.

## Commands
- Compile locally, one build per host through RustRight: dev profile, incremental, primary checkout, warm cache, never cold. RustRight queues concurrent builds; never divert local work to CI because another build is queued or running. Legion is public, so GitHub CI also qualifies every push in parallel; CI never replaces the local build.
- Windows installer commands (native check, unsigned development build, CI route) live in `docs/reference/release/local-windows-development.md`. Read it before any installer work.

## Locked invariants
- Use Oracle for any independent review or verification of work Legion did not produce itself; never for its own fix. Routine replies & read-only answers need no Oracle.
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
- Every skill file, script, hook, doctrine file, agent-rule file, or native CLI command module deleted after `c1d80c9d` gets a row in `docs/provenance/retirements.md` naming the path (or a parent or glob) and its successor or why it was dropped; `legion-dev check-retirements` enforces it.

## Verification
- `legion-dev check-skill-evals` validates eval structure only; model-graded cases report `requires-model` and are not proof.
- Run focused doctrine and routing tests after role changes.
- Refresh `skills/manifests/*.json` with `cargo run -q --locked --manifest-path engine/Cargo.toml -p legion-dev -- refresh-local-skill-manifests <bundle>...`
  after editing any packaged skill file, so digests and consumers stay truthful.
