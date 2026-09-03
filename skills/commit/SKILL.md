---
name: commit
description: "Review, verify, commit, & push one frozen diff through Legion's guarded Commit workflow. Use for /commit, review and commit, or commit and push."
kind: entrypoint
discoverability: explicit
target: workflow:commit
operations:
  - analyze
  - evaluate
  - execute
effects:
  - source-read
  - repository-write
  - process-exec
  - network-request
hostRequirements: []
metadata:
  legion:
    provenance: legion-authored
    licenseState: licensed
    rightsReceipt: LICENSE
    publish: true
---

# Commit

Route one frozen diff through packaged `references/manual.md`. This entrypoint does not recreate
review lenses, test gates, or Git effects.

```text
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Frozen diff is verified, committed, pushed, & identity-proven.
```
Per-step tool/model authority is declared inline below via each step's `EXECUTOR` block, which
supersedes the legacy flat `SPECIALIST_REFS_MAX` cap with a per-step capability declaration.

1. Confirm primary checkout, branch, overlay, remote, worktree ownership, & exact frozen scope.
   EXECUTOR:
     semantic: forbidden
     capabilities:
       - repository-truth-read
2. Preserve unrelated edits; run shared secret, conflict, schema, generated-file, minimize, &
   focused behavior checks.
   EXECUTOR:
     semantic: forbidden
     capabilities:
       - process-exec
       - source-read
3. Review every staged line; repair only in-scope defects.
   EXECUTOR:
     semantic: required
     capabilities:
       - source-read
       - structured-text-edit
4. Write or refresh rerunnable audit evidence with findings, checks, & residual risks.
   EXECUTOR:
     semantic: forbidden
     capabilities:
       - repository-truth-read
5. Stage explicit in-scope paths, prove staged diff equals frozen scope, then use shared commit
   & push procedure with its required receipts. Read the host's GitHub access rules before
   pushing, & prove local HEAD equals remote HEAD after push.
   EXECUTOR:
     semantic: forbidden
     capabilities:
       - process-exec
       - repository-truth-read
6. Route repository-wide diagnosis to `/audit`; only route remediation from a frozen Audit report
   to `/audit-fix`.
   EXECUTOR:
     semantic: required
     capabilities:
       - architecture-reasoning
       - repository-truth-read

Do not claim installed, live, visual, cross-host, release, or production acceptance without
matching receipts.
