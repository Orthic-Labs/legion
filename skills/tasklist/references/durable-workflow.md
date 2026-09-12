# Durable Tasklist Workflow

Use this only when an explicit contract or locked-domain/effect requirement
calls for a durable execution record. Ordinary `/tasklist` work stays inline.

1. Freeze current authority, scope, exclusions, target state, integration owner,
   & acceptance proof. Reuse a governing route only when that contract requires
   it; do not create a second route for an ordinary plan.
2. Create the contract-required tasklist, packet, & receipt files. Each task
   names its exact path allowlist, action, real dependency, lane when useful,
   observable done check, evidence path, & bounded recovery when needed. Every
   planned changed file belongs to exactly one task.
3. Follow the governing contract's validator, receipt, & review requirements.
   Revalidate after any packet or scope change. Do not add Oracle ceremony to an
   ambient inline plan merely because work is delegated.
4. On changed user intent, stop affected work & rederive the durable record from
   current authority before resuming. Preserve prior outputs as evidence only
   when the contract requires that record.
