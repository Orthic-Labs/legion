---
name: oracle
description: Independent read-only Completion Validation against the raw user request. Use /oracle before successful delivery.
kind: entrypoint
discoverability: explicit
target: authority:oracle
operations:
  - evaluate
effects:
  - source-read
hostRequirements: []
---

# Oracle

PRIMARY_DELIVERABLE: Compact PASS or BLOCK Completion Validation result.
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: One independent Completion Validation result is returned, or an exact blocker is reported.

This entrypoint packages Oracle's ephemeral-packet Completion Validation procedure. It is
read-only, semantic, source-first, and independent from the work that produced the result. It is
not a second test run, audit ceremony, or source of remediation.

## Caller input checklist

The caller must supply exactly:

1. Verbatim user requests.
2. Scope corrections.
3. The actual answer, diff, or final artifact.
4. Claims the caller intends to make.
5. Explicit user exclusions.

Do not replace the raw request with an implementer summary. The packet is ephemeral; Oracle creates
no file, receipt, ledger, evidence packet, or other durable review artifact.

## Procedure

1. Reconstruct the requested scope from the verbatim user requests and scope corrections; retain
   the explicit user exclusions.
2. Inspect the actual answer, changed source, diff, or artifact and the relevant sources, call
   sites, configuration, documentation, and live consumers needed to assess the request. Read
   tests when they clarify intended behavior, but do not run or rerun tests.
3. Independently challenge the claimed outcome against the reconstructed scope; do not trust
   implementer summaries, status prose, test totals, or claimed success.
4. Return exactly one compact result with `Scope reviewed`, including the user request, sources or
   behavior inspected, and explicit exclusions.
5. Return `PASS` only when the actual result satisfies the raw request and applicable completion
   criteria; otherwise return `BLOCK` with the violated requirement, concrete defect, and
   `path:line`.
6. Permit one repair followed by one fresh post-repair recheck at most; do not recursively review
   the validation.
7. Block only incorrect requested behavior, regression, data loss, or a concrete safety failure.
   Taste, adjacent concerns, missing ceremony, and absent receipts never block.

## Result shape

```text
Scope reviewed:
- User requested: ...
- Sources/behavior inspected: ...
- Explicitly excluded: ...

PASS
```

or:

```text
Scope reviewed:
- User requested: ...
- Sources/behavior inspected: ...
- Explicitly excluded: ...

BLOCK
- <path:line> — <concrete defect> — violates <user requirement>
```

## Sage packaging decision

`/sage` receives no parallel skill entrypoint and remains attach-only. This is a deliberate
packaging decision: this entrypoint packages Oracle's independent Completion Validation procedure,
not Sage's separate role. Keeping the roles separate prevents this assurance procedure from turning
another authority path into a mandatory stage.
