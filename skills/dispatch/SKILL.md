---
name: dispatch
description: Delegate bounded work to fresh-context agents with clear ownership & integration. Use for subagents, parallel workers, or executor instructions. Same-agent planning uses Tasklist; new-session continuity uses Handoff.
kind: capability
capabilityClass: workflow
discoverability: public
domain: null
operations:
  - route
  - produce
effects:
  - source-read
  - artifact-write
  - process-exec
hostRequirements:
  - legion
---

# Dispatch

PRIMARY_DELIVERABLE: Concise zero-context assignment for bounded delegation.
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Assignment states scope, exclusions, exact ownership, evidence, expected result, & next integration action.

1. Start bounded subagents with `fork_turns: "none"`. Give each fresh worker current scope, exclusions, exact OWN/READ/FORBIDDEN path scopes & writable allowlists, bounded evidence pointers, & expected result; bound each assignment's scope to the requester's words, and where an inventory term admits a wider set, take the narrower reading and list what it excludes; never copy the full transcript or inherit turns unless explicitly requested. Bound reads & tool output to relevant excerpts. Split work when one assignment would accumulate excessive context. Workers are edit-only; bounded read-only inspection is allowed. Prohibit Cargo, tests, builds, generators, installs, commits, pushes, merges, heavy checks, and post-merge verification. Never create worktrees or branches. The root integration owner is sole checker per repository & host on the primary checkout; defer one verification batch until all coding is complete. Workers report changed paths, source-level result, and blockers without claiming command-based checks.
Launch prompts for `legion:alchemist-specialist` name the bounded function, the compile-but-wrong failure ordinary checks could miss, and the reason (risk or failed mechanical attempt). Subject examples such as security or concurrency never promote a whole assignment.
Split disjoint work across tiers; keep inseparable risky changes in one specialist assignment.
Report the actual model mix (tier per assignment) in the lead's report.
On Codex hosts, spawn a role with the host's agent-spawn tool (`spawn_agent`), passing the role name
(`oracle`, `sage`, `alchemist`, `sentry`, `council-seat`) as `agent_type`, then wait for it with
`wait_agent`. A request for independent or fresh-context review is an explicit spawn request. Claim
independent or fresh-context review only when a child agent actually ran; otherwise say the work was
not independently reviewed.

2. Assign one agent per ready repository or bounded change within real host capacity, budget,
ownership, & safety limits. At each lead turn, compare ready open issues with active assignments
& dispatch missing work; name concrete dependencies or limits for ready work left idle. One
integration owner per repository reconciles output, runs the sole root verification batch on the
primary checkout after coding completes, & advances remaining work. Reads may overlap; write
ownership may not. Continue independent edits while checks are deferred; no worker runs checks or
builds.
3. Add contracts, receipts, recovery schemas, dependency waves, or strict return fields only for
explicit/locked governed work. Load `references/manual.md` only for that path.
   When shared-repository units need executable ownership/dependency and evidence accounting, use
   `references/work-plan.md` and `legion work-plan validate --input work-plan.json` before assignment.
   Its ready-unit result validates declarations only; it neither dispatches agents nor grants effects.
4. Root integration verifies acceptance on requested platform or user-visible surface after coding
is complete. Worker prose is evidence, never completion or new user authority.

Gate only affected operations & their actual dependents. Preserve checks, Guard decisions, &
exact-artifact verification while unrelated authorized work continues. Derive dependencies from
consumed outputs, shared writes, or required effect order; assistant-authored sequence adds no
permission gate. Ordinary delegation needs only this compact assignment.

Use `assets/dispatch-template.md` only for explicit legacy compatibility. Never rely on unseen chat
or delegate user-reserved decisions.
