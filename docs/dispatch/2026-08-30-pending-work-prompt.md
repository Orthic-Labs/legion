# Captured prompt — 2026-08-30 pending-work dispatch

Verbatim user request:

> Create /dispatch for all pending work. Then orchestrate 1st dispatch by handing parallel lanes
> to /luna then next, then next. luna writes code, you run tests and integrate and mark what's
> done in the doc.

Scope source: `docs/pending/PENDING-WORK-2026-08-29.md` (rev 5, commit 42f38e4b), items P0.1–P5.30.

Excluded from worker lanes (owned by the integration owner, not dispatchable):
- P0.1 / P0.4 / P1.6 / P1.11(arcane doctrine): already in flight as uncommitted work in this
  checkout (`engine/crates/legion-contracts/src/{policy,trace,id,lib}.rs`,
  `engine/crates/legion-application/src/lib.rs`, `engine/bins/legion-hook/src/main.rs`,
  `doctrine/arcane.md`, `schemas/route-outcome-trace.v1.*`,
  `src/packages/arcane/policy/README.md`).
- P0.2 redeploy the installed `legion-hook.exe` — a build/deploy effect, integration owner only.
- P1.9 groundwork restore — a checkout in the workspace repository, outside this repository.
