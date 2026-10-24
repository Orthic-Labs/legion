---
name: preflight
description: "Before any build, push, merge, release or done claim, run the repository's deterministic check first, read every finding, and fix it or baseline it with a filed issue. Use for push this, ship it, merge it, is it done, or before building."
kind: capability
capabilityClass: workflow
discoverability: public
domain: engineering
operations:
  - analyze
  - evaluate
  - execute
effects:
  - source-read
  - repository-write
  - process-exec
hostRequirements:
  - repo-gate
---

# Preflight

The repository's deterministic check runs before anything is built, pushed, merged, released, or called done. It reads the committed tree offline and prints every finding in one run, so one pass shows the whole job.

1. Run it: `pnpm exec right-release check` (the same check ships as `rightkit-gate check`). It checks the committed HEAD; `--worktree` previews uncommitted work. A repository with no `check` command yet uses its own documented preflight script; say so, and treat that script as the gate.
2. Read all of the output. Each `FAIL` line carries a rule, a gap id, `path:line`, and a `fix:` line. Apply the fix at its source, commit, and rerun until the last line reads `check: <sha> passed <N> rules`.
3. A finding that cannot be fixed in this change is baselined, never bypassed: file an issue in the owning repository, list the finding's identity in the repository's baseline with that issue, and rerun. RightKit approves baselines; one it does not list is itself a finding.
4. Never route around the gate: no `--no-verify`, no `core.hooksPath` change, no `HUSKY=0`, no editing the check to pass. The Legion hook denies those shapes. In a workspace, `python3 tools/setup-workspace.py --check` shows whether the pre-push hook is installed.
5. Say done only with the gate's green line for the exact head, a CI run URL on that head, or a host receipt. An Oracle verdict, a local run, or a worker report never replaces a required check.

The owning docs are RightKit's `PIPELINE-ARCHITECTURE.md` (check, admission, compile) and the repository's agent rules; this skill does not restate them.

```text
PREFLIGHT_RESULT
status: green | fixed | baselined | blocked
head: <sha>
check: <command and its last line>
baselined: <finding identities with issue numbers, or none>
```
