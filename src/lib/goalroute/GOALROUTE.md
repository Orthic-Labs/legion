# Internal GoalRoute Engine

This is cross-skill infrastructure, not a user-invocable skill. Dispatch, Tasklist, Architect,
Audit-fix, Script, & Debugger own its invocation.

Select route before decomposing tasks or optimizing execution.

## Iron law

```text
NO NONTRIVIAL MUTATION STARTS UNTIL:
1. exact STATE_A and verifiable STATE_B are frozen;
2. authority, safety, scope, quality, and cost constraints are evidence-bound;
3. feasible routes are dependency-expanded;
4. expected time to verified B includes retry and terminal-failure rework;
5. selected route passes validate-route.py and has a matching receipt.
```

“Easiest” is not objective. “Fastest” means shortest **expected time to verified B**, not shortest
happy-path command list.

## Ownership

- **Architect** produces target design and its implementation route.
- **Audit-fix** produces a fix route from current finding/gate vector and refreshes it after material re-audit change.
- **Dispatch** packages a route for executors and must not silently redesign accepted architecture.
- **Tasklist** owns direct same-agent execution routes when no accepted upstream route exists.
- **Script** consumes selected route and optimizes its concrete execution.
- **Debugger** uses `DIAGNOSTIC` purpose for cheapest complete route to a proven cause or resolved diagnostic decision.
- **Commit, Handoff, Blueprint, Council, Test Author, and read-only Audit** do not select routes. They verify, transfer, map, review, test, or diagnose fixed denominators.

One producer owns route. Downstream skills verify receipt and bind to `selected_route_id`.
Tracked receipts bind exact bytes plus Git-root-relative `route_path`, so identical authority
verifies after checkout relocation across macOS and Windows. Untracked artifacts retain absolute
locators.

## Create artifact

Copy [assets/goal-route-template.json](assets/goal-route-template.json) to durable project location:

- plan/design: beside plan as `<plan-name>.route.json`;
- audit-fix/debug: `<repo>/.audit/<timestamp>/goal-route.json`;
- dispatch: beside dispatch packet;
- direct script: beside script/run packet.

Do not use OS Temp, scratch, or chat-only prose as canonical route.

Fill contract:

1. `purpose`: `DELIVERY` or `DIAGNOSTIC`.
2. `state_a`: exact observed current state plus evidence locator/hash/check.
3. `state_b`: exact target plus executable proof and evidence path.
4. `constraints`: evidence-bound `authority`, `safety`, `scope`, `quality`, `cost`.
5. `candidates`: 2–3 feasible paths, or one path with proof alternatives are infeasible.
6. candidate DAG steps: operation, dependencies, minimum duration, and observable B-state delta or required safety dependency.
7. probability-weighted retry/rework:

```text
EXPECTED_TIME_TO_VERIFIED_B_MS =
NOMINAL_CRITICAL_PATH_MS
+ ceil(RETRY_PROBABILITY_BPS × RETRY_COST_MS / 10000)
+ ceil(TERMINAL_FAILURE_PROBABILITY_BPS × REWORK_COST_MS / 10000)
```

8. selected route: minimum expected time among constraint-passing candidates. On equal expected time,
   reject selection dominated on cost, risk, and rework.
9. selected critical path, independent parallel lanes, bottleneck, deleted work, deferred work.
10. correction/invalidation record and Alchemist binding for non-routine work.

Probabilities are evidence-backed estimates, not decorative precision. If unresolved uncertainty can
change winner, gather cheapest discriminating evidence before selecting.

## Semantic corrections

Latest user intent or changed constraints invalidate route plus every downstream task/script gate:

1. stop affected execution;
2. preserve prior outputs as evidence only;
3. increment route revision;
4. set `semantic_correction` to `RECOMPILED_FROM_ROOT`;
5. name invalidated prior route IDs;
6. restate A/B and constraints;
7. rebuild candidates and arithmetic;
8. issue new receipt.

Local route patching is forbidden.

## Validate

Windows:

```powershell
py -3.11 src/lib/goalroute/scripts/validate-route.py <route.json> --write-receipt <route.receipt.json>
```

macOS:

```bash
python3 src/lib/goalroute/scripts/validate-route.py <route.json> --write-receipt <route.receipt.json>
```

Downstream consumer:

```powershell
py -3.11 src/lib/goalroute/scripts/validate-route.py <route.json> --verify-receipt <route.receipt.json>
```

Do not proceed until output begins `PASS:` or `RECEIPT_PASS:` and receipt matches exact bytes plus
current validator.

## Consumer contract

Every consumer records:

```text
GOAL_ROUTE_ARTIFACT: <path>
GOAL_ROUTE_RECEIPT: <path>
GOAL_ROUTE_SCHEMA: goal-route.v2
SELECTED_ROUTE_ID: <id>
EXPECTED_TIME_TO_VERIFIED_B_MS: <integer>
ROUTE_REVISION: <integer>
```

Consumer may expand exact commands but may not change A, B, constraints, candidate winner, dependency
order, deleted work, or deferred gates. Required change means recompile route at owner.

## Audit-fix route

Set A to current audit gate vector + open finding fingerprints. Set B to full clean truth gate:
applicable checks/lenses/tests green, zero open code-quality findings, behavior surfaces preserved.

Build root-cause DAG from `caused_by`; prefer a safe fix which clears multiple downstream symptoms.
Compare complete fix sequences by expected time-to-clean, not individual patch size or severity order.
Parallelize independent file/state clusters only. Recompile after re-audit changes finding set,
severity, affected spans, constraints, or behavior surface. Dependency-directed scanner/lens reruns
remain validation optimization, not route selection.

## Architect route

Architecture option/ADR chooses target shape. Route then compares implementation strategies to that
same target, including migration, characterization tests, rollback, compatibility, and rework risk.
Phase-3 tasks are generated from selected route DAG, not document order.

## Diagnostic route

Set B to a proven root cause or exact diagnostic decision, not “more information.” Candidate paths are
complete evidence sequences. Existing logs/state outrank new instrumentation; non-invasive probes
outrank code perturbation. Select route with lowest expected time to proof while preserving root-cause
standard. A cheap probe which cannot discriminate live hypotheses does not advance B.

## Hard rules

- Hard constraints filter routes before optimization.
- Quality and proof belong in B/constraints; route speed cannot weaken acceptance.
- Never select by nominal wall time alone.
- Every candidate duration and probability has an evidence locator.
- Every step advances B or is a named safety/dependency requirement.
- Parallel lanes contain no dependency relationship.
- Existing progress has no priority unless compatible with current route.
- Non-routine route requires Alchemist checkpoint `GOAL_ROUTE_V2`.
- Semantic correction invalidates route from root.
- One artifact, one receipt, one selected route.
