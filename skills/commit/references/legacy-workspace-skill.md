---
name: commit
description: "Review, fix, verify, commit, and push one frozen diff using audit, minimize, security, schema, and focused tests. Use for /commit, review and commit, or commit and push."
---

# Commit

MODE: EXECUTE
PRIMARY_DELIVERABLE: Verified frozen diff committed & pushed.
DISCOVERY_PROFILE: D1_SCOPED_SOURCE
EFFECT_PROFILES: diff_broker, focused_check
SPECIALIST_REFS_MAX: 0
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Frozen diff is verified, committed, pushed, & identity-proven.

For every invocation, read `references/manual.md`; it is the guarded commit procedure.

Required order:

1. Confirm primary checkout, current branch, repository overlay, remote, & worktree ownership.
2. Freeze exact diff; preserve unrelated user changes & nested-repository work.
3. Run secret, conflict-marker, schema, generated-file, minimize, & focused behavior checks.
4. Review every staged line; repair only in-scope defects.
5. Write or refresh rerunnable audit evidence with findings, checks, & residual risks.
6. Stage explicit paths; verify staged diff equals frozen scope.
7. Commit with an audit-oriented message explaining outcome & evidence.
8. Read `docs/rules/github-access.md`, push current branch, & prove local HEAD equals remote HEAD.

Do not claim installed, live, visual, cross-host, release, or production acceptance without matching receipts.
