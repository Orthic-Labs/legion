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

1. Start bounded subagents with `fork_turns: "none"`. Give each fresh worker current scope, exclusions, bounded owned paths or modules, bounded evidence pointers, & expected result; never copy the full transcript or inherit turns unless explicitly requested. Bound reads & tool output to relevant excerpts. Split work when one assignment would accumulate excessive context.
On Codex hosts, spawn a role with the host's agent-spawn tool (`spawn_agent`), passing the role name
(`oracle`, `sage`, `alchemist`, `sentry`, `council-seat`) as `agent_type`, then wait for it with
`wait_agent`. A request for independent or fresh-context review is an explicit spawn request. Claim
independent or fresh-context review only when a child agent actually ran; otherwise say the work was
not independently reviewed.

2. Assign one agent per ready repository or bounded change within real host capacity, budget,
ownership, & safety limits. At each lead turn, compare ready open issues with active assignments
& dispatch missing work; name concrete dependencies or limits for ready work left idle. One
integration owner per repository reconciles output, runs relevant root checks, & advances remaining
work. Reads may overlap; write ownership may not. Coding continues while admitted builds queue or
run; build admission still governs build launch.
3. Add contracts, receipts, recovery schemas, dependency waves, or strict return fields only for
explicit/locked governed work. Load `references/manual.md` only for that path.
4. Verify acceptance on requested platform or user-visible surface when applicable. Worker prose is
evidence, never completion or new user authority.

Gate only affected operations & their actual dependents. Preserve checks, Guard decisions, &
exact-artifact verification while unrelated authorized work continues. Derive dependencies from
consumed outputs, shared writes, or required effect order; assistant-authored sequence adds no
permission gate. Ordinary delegation needs only this compact assignment.

Use `assets/dispatch-template.md` only for explicit legacy compatibility. Never rely on unseen chat
or delegate user-reserved decisions.
