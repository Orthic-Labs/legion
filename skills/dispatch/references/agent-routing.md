# Dispatch routing

Use Dispatch for bounded executor delegation. Ordinary workers stay ambient. Attach Sage for design, adjudication, or reassessment when a material choice exceeds routine capability judgment. Use Alchemist for any assignment that writes files, runs effectful commands, or produces an artifact. Use Oracle for any independent review or verification of work Legion did not produce itself. Fresh-session continuity uses Handoff. Dispatcher retains integration ownership; worker write scopes do not overlap, while reads may overlap.

## Role names the model

Every subagent launch names a role as its subagent type, and the role sets the model. Use this table. Do not pick a model for a role by hand.

| Role | Model |
|---|---|
| `legion:alchemist` | haiku |
| `legion:alchemist-specialist` | sonnet, only with a "Specialist reason:" line |
| `legion:oracle`, `legion:sage` | opus |
| `legion:sentry` | haiku |
| `legion:council-seat` | per the Legion model-tier map, only inside `/council` |
| read-only lookup types (`Explore`, `general-purpose`) | haiku by default, sonnet at most |

Ordinary subagents never run on opus. Opus is for Oracle and Sage, the frontier-judgment roles.

A `legion:alchemist-specialist` launch carries a `Specialist reason:` line. The line names the bounded function and why a mistake there would still compile or pass but be wrong or unsafe, or it names the failed attempt on `legion:alchemist`.

Read-only lookup types never write files and never stand in for a role that writes or reviews.

Legion's hook enforces this table and fills each role's model automatically. A launch that sets a model must use the model in this table.
