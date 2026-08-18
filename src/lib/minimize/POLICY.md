# MINIMIZE

Minimize is internal engineering policy, not user-visible mode.

## Contract

1. Freeze verified state A, verified state B & hard constraints.
2. Test implementation rungs in order:
   `NOT_BUILD → REUSE → STDLIB → NATIVE → INSTALLED_DEP → ONE_LINE → MIN_CUSTOM`.
3. Select first rung able to reach B safely; record concrete rejection evidence for every earlier rung.
4. Delete work unable to change current decision or advance B.
5. Preserve understanding, trust boundaries, security, data-loss prevention, accessibility, hardware calibration & explicit user scope.
6. Declare every new file & dependency before mutation. Undeclared scope is forbidden.
7. Bind decision receipts to exact decision bytes & this policy.
8. Bind commit receipts to exact staged Git tree, exact review bytes & this validator.
9. Any material correction invalidates downstream decisions; re-derive globally from latest user intent.
10. Never represent structural completeness as semantic correctness.

## Mutation check

Before code creation or modification, emit `MINIMIZE:CHECK` with selected rung, reused source, declared new files/dependencies & deleted work.

## Commit check

Every code commit requires clean Minimize review plus receipt matching current staged tree. Missing, invalid or stale receipt blocks commit.
