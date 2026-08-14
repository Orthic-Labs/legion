# Tasklist durable workflow

```text
MODE: OUTPUT_ONLY
PRIMARY_DELIVERABLE: Durable same-agent task list.
DISCOVERY_PROFILE: D1_SCOPED_SOURCE
EFFECT_PROFILES: source_read, output_write
SPECIALIST_REFS_MAX: 0
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Ordered execution record names verified end state, checks, and exact next action.
```

Produce a compact execution record for current agent/user, then optionally execute it. Keep
user-facing Markdown simple; enforce route quality through GoalRoute v2 sidecars.

## Boundary

| Need | Skill |
|---|---|
| Same agent executes or user records goal steps | `/tasklist` |
| Another agent receives zero-context task packet | `/dispatch` |
| New chat resumes prior work | `/handoff` |
| Architecture/target design is undecided | `/architect`, then `/tasklist` |
| Casual personal todos or transient bullets | normal response |

Never inflate `/tasklist` into dispatch ownership, handoff context, or architecture design.

## Prime directive

```text
Choose minimum expected time to VERIFIED success after hard constraints.
Never choose by fewest tasks, easiest-looking route, or nominal wall time alone.
```

Five steps at 60% success are worse than twelve steps at 99% when retries/rework make twelve-step
route faster to verified B. Use internal GoalRoute arithmetic and receipt as authority.

## Deliverables

For nontrivial work, always create four permanent sibling artifacts:

```text
<name>.tasklist.md
<name>.tasklist.receipt.json
<name>.route.json
<name>.route.receipt.json
```

User-facing artifact is Markdown tasklist. Route files and receipts are audit sidecars. Never use
OS Temp, scratch, cache, chat-only prose, or a temporary validation file as canonical output.

For trivial one-step work with no alternative path, risk, retry, or durable-record request, act
directly. Explicit `/tasklist` always creates artifacts.

## Workflow

1. Freeze exact current state A, target state B, proof of B, scope, non-goals, and hard constraints.
2. Reuse upstream validated Minimize decision or compile `<tasklist-stem>.minimize.json` plus receipt;
   select first safe rung, reject earlier rungs with evidence, and declare every new file/dependency.
   Sidecars are internal and omitted from user-facing tasklist.
3. Reuse upstream validated GoalRoute v2 when architect/audit/debug already owns route.
4. Otherwise compile route through `tools/lib/goalroute`; `/tasklist` owns direct same-agent
   execution route.
5. Validate route and write route receipt.
6. Copy [tasklist template](../assets/tasklist-template.md) to permanent project path.
7. Compile only selected route DAG into tasks. Exclude rejected, deleted, deferred, diagnostic, and
   “nice to have” work.
8. Give every task exact action, dependencies, observable B delta, done check, expected result,
   evidence path, and executable continuation on failure.
9. Validate tasklist and write receipt; validator fail-closes on missing/stale Minimize sidecars.
10. If user asked to execute, begin Task 1 immediately. If user asked to set a goal, bind goal objective
   to State B and record goal ID. Otherwise return list without mutating project.

## Task compilation

One selected route step maps to exactly one task. Preserve DAG:

- root step → `START`;
- dependent step → `AFTER:<route-step-id>[,<route-step-id>]`;
- independent roots may run in parallel;
- document order must be topological, not source-document order;
- task action must equal selected route operation;
- task B delta must equal route step delta.

Every task contains:

```text
STATUS: TODO | IN_PROGRESS | DONE | TRUE_BLOCKER
ROUTE_STEP: <selected-route-step>
ACTION: <exact operation>
DEPENDS_ON: START | AFTER:<prior route steps>
ADVANCES_STATE_B: <observable delta>
CHECK: <exact verification command/action>
EXPECTED: <specific pass state>
EVIDENCE: <permanent absolute path>
TRY: <primary recovery>; FALLBACK: <safe continuation>; RECOMPILE_IF: <route-invalidating condition>
```

Do not add tasks merely for completeness. If task cannot advance B, satisfy hard constraint, or
produce required proof, delete it.

## Progress contract

Update tasklist atomically at every task boundary:

- before action: `IN_PROGRESS`;
- after done check passes: `DONE` plus evidence;
- after recoverable failure: remain `IN_PROGRESS`, record attempt, run continuation;
- after semantic correction: stop affected work and recompile route/list from root;
- after all tasks: run final State B proof, then set overall `COMPLETE`.

Regenerate tasklist receipt after every durable update. Stale receipt means list is untrusted.

## Goal binding

When user asks to set a goal:

1. objective = exact State B plus success proof;
2. create/update goal through host goal tool;
3. record returned goal ID in tasklist;
4. keep tasklist tasks as execution ledger;
5. mark goal complete only after final proof passes.

Tasklist is durable plan/evidence record; host goal is continuation control. Neither substitutes for
other.

## Failure & TRUE_BLOCKER

Blocked is last branch. A task may become `TRUE_BLOCKER` only after:

1. primary recovery attempted to bound;
2. fallback and independent safe work exhausted;
3. route alternatives reconsidered;
4. missing external input/state is exact;
5. permanent blocked artifact records:
   `SYMPTOM`, `ATTEMPTS`, `MISSING_INPUT`, `UNBLOCK_CHANGE`, `RESUME_ACTION`, `OWNER`.

If another feasible route exists, recompile GoalRoute; do not mark blocked.

## Semantic corrections

Latest user intent invalidates route and tasklist downstream state:

1. stop affected execution;
2. preserve old outputs as evidence only;
3. increment route and tasklist revision;
4. set route `semantic_correction=RECOMPILED_FROM_ROOT`;
5. rebuild A/B, constraints, candidates, winner, DAG, and tasks;
6. issue new route and tasklist receipts.

Local clause patching is forbidden.

## Validate

Windows:

```powershell
py -3.11 D:/Claude/tools/skills/tasklist/scripts/validate-tasklist.py <name>.tasklist.md --write-receipt <name>.tasklist.receipt.json
```

macOS:

```bash
python3 /Volumes/D/claude/tools/skills/tasklist/scripts/validate-tasklist.py <name>.tasklist.md --write-receipt <name>.tasklist.receipt.json
```

Before execution/resume:

```powershell
py -3.11 D:/Claude/tools/skills/tasklist/scripts/validate-tasklist.py <name>.tasklist.md --verify-receipt <name>.tasklist.receipt.json
```

Proceed only after `PASS:` or `RECEIPT_PASS:`.

## Hard gates

- Permanent Markdown file always.
- Exact-byte tasklist and GoalRoute receipts always.
- Selected route minimizes expected time to verified B.
- Task set exactly equals selected route DAG.
- Every task has runnable done proof and permanent evidence path.
- Rejected/deferred work cannot leak into tasks.
- Parallel roots remain parallel.
- False completion and casual blocked status fail validation.
- Same-agent scope only; use dispatch/handoff at boundary.
- User correction recompiles globally.
