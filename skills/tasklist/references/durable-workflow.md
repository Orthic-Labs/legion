# Durable Tasklist Workflow

Use this only when persistence, audit receipts, or a reusable execution record was requested.

1. Reuse a validated upstream GoalRoute when present; otherwise create direct same-agent route through `lib/goalroute`.
2. Create permanent sibling tasklist, route, & receipt files. Never use temporary or chat-only state.
3. Compile selected route into typed `legion-authority-dispatch` execution packet. Every task needs number, exact path allowlist, action, dependency, lane, observable target delta, check, expected result, evidence path, & recovery. Every planned changed file belongs to exactly one task.
4. Obtain fresh adversarial subagent review of action order, exact paths, one-touch ledger, dependency/parallel lanes, scope, & proof before submission. Any byte change invalidates review.
5. Validate packet with Tasklist compatibility wrapper; it delegates to package-local `lib/dispatch-validator/validate-tasklist.py` & writes sibling receipt. Re-review after any correction.
6. On changed user intent, recompile route, packet, & receipt from root, then obtain fresh review before submission.
