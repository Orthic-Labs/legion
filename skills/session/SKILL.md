---
name: session
description: "Use only for explicit `/session` compatibility modes: status, init, brief, context-hygiene, or file-search."
kind: entrypoint
discoverability: explicit
target: workflow:session
operations:
  - analyze
effects:
  - source-read
  - process-exec
hostRequirements: []
---

# Session

This is an explicit compatibility entrypoint, not a new router or session-state owner. Use
`/session status`, `/session init`, `/session brief`, `/session context-hygiene`, or
`/session file-search`; bare `/session` means `status`. Legion owns task facts and routing. Arcane
owns context shaping and response policy. Each mode delegates to those existing owners and creates
no durable state by default.

## Modes

- **status** — Report `CURRENT TASK`, `PROVEN COMPLETE`, `PENDING`, `BLOCKERS`, `CHANGED PATHS`,
  and `NEXT ACTION`. Use only current conversation and observed evidence; say when a field is
  unknown. A task snapshot is distinct from installed Legion/client health. If installed health is
  requested, use `legion --json setup status` when available and report its observed result.
- **init** — Apply current workspace defaults, user preferences, and relevant context-measurement
  guidance. Use host-reported context measurements when available and relevant; don't invent a
  reading. Don't write configuration or resurrect retired session rules. Native `legion init`
  scaffolding is a separate operation.
- **brief** — Shape the current response with concise, accurate prose, full grammar, and no filler;
  honor the user's newest style instructions.
- **context-hygiene** — Keep work task-shaped: read targeted sources, bound large outputs, and
  reconcile older summaries against newest instructions and current evidence. Preserve constraints,
  decisions, changed paths, blockers, and next action in chat when useful. Don't create notes or
  `HANDOFF.md` by default. `/handoff` owns explicit new-chat transfer; never create a chat here.
- **file-search** — Search a scoped path with `rg`, previewing or capping broad results and refining
  as needed. Use `sg` only when installed and structural matching helps. Keep results bounded.
  Ordinary file search does not invoke Blueprint and does not replace Debugger or Audit.

These modes do not activate automatically from ordinary natural-language requests. They do not
override current instructions, grant effects, or create universal legacy governance.
