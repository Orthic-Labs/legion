---
name: delivery
description: "Carry an engineering change to its requested delivery state: branch pushed, pull request ready for user handoff, or merge when explicitly authorized. Use for end-to-end PR delivery, bounded CI/review follow-through, modernizing a change against a new base, or taking over an existing change with attribution."
kind: capability
capabilityClass: workflow
discoverability: public
domain: null
operations:
  - analyze
  - evaluate
  - execute
  - produce
effects:
  - source-read
  - artifact-write
  - repository-write
  - process-exec
  - network-request
hostRequirements:
  - legion
  - github-read
---

# Delivery

PRIMARY_DELIVERABLE: The requested engineering delivery state with exact revision evidence and remaining blockers.
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: dispatch, commit, wake
TERMINAL: Requested state is evidenced, or bounded work stops with named blockers and a concrete resume action.

Legion owns integration and delivery. This workflow coordinates capabilities; it grants no role or
effect authority. Read `references/manual.md` before carrying a change beyond a local edit.

1. Recover live user intent, exact repository/change, exclusions, acceptance criteria and terminal
   state: **branch-pushed**, **PR-ready-for-user**, or **merged**. Default an unspecified PR handoff
   to PR-ready-for-user. Merge needs explicit current-request authorization; a phrase such as
   "full-send" or "full-stop" alone specifies neither scope nor permission.
2. Assign one integration owner for HEAD, index, receipts and outward effects. Use Dispatch for
   independently ready changes with disjoint writes. Keep implementation moving while admitted
   checks run, respecting project build admission and root-only verification rules.
3. Complete and verify the requested change. Have Oracle independently review others' work against
   raw intent and exact head/base; preserve unresolved outcome or safety findings. Council remains
   optional bounded advisory challenge. Use the native review-loop assessment for a declared bounded
   ledger; it does not perform review or replace Oracle.
4. Use Commit for its frozen-diff, verified commit-and-push endpoint. Before a push on a PR intended
   for user handoff, inspect existing auto-merge and merge-queue state: the push itself can trigger
   an already configured merge. Stop that effect until the user authorizes it or the existing
   mechanism is safely disabled through an authorized host action.
5. For a PR goal, collect one bounded native observation with `legion delivery observe`; bind all
   checks, policy and proofs to the current head/base. An imported `legion delivery assess` result
   is diagnostic assertion data. Missing access, incomplete pages, pending checks, stale proofs or
   unknown policy leave readiness unproven. Do not invent success or repeatedly poll.
6. Return PR-ready-for-user only after required checks/reviews/threads and exact-revision proofs
   pass, with auto-merge disabled and the PR outside the merge queue. For authorized merge, use an
   existing Guard-gated host action, revalidate the revision immediately before it, then read back
   merged state and merge commit. A ready assessment has `effectAuthority: none`.

Report only reached states. Branch pushed, PR ready, merged, deployed and verified in production
are different outcomes. Use Wake only for a real host event or one bounded authorized inspection;
without an external event source return a blocker and resume action, never a watcher loop.
