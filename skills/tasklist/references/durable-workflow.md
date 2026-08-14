# Durable Tasklist Workflow

Use this only when persistence, audit receipts, or a reusable execution record was requested.

1. Reuse a validated upstream GoalRoute when present; otherwise create direct same-agent route through `tools/lib/goalroute`.
2. Create permanent sibling tasklist, route, & receipt files. Never use temporary or chat-only state.
3. Compile selected route into typed `legion-authority-dispatch` execution packet. Every task needs action, dependency, observable target delta, check, expected result, evidence path, & recovery.
4. Validate packet with Tasklist compatibility wrapper; it delegates to `tools/lib/dispatch-validator/validate-tasklist.py` & writes sibling receipt.
5. On changed user intent, recompile route, packet, & receipt from root.
