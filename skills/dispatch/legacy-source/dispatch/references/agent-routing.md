# Agent routing

Load this file only when delegating or running parallel work. RHook enforces model caps.

## Authority

- Keep orchestration, synthesis, acceptance, & user communication in the parent task.
- Give each worker one objective plus explicit `OWN`, `READ`, & `FORBIDDEN` paths.
- Use the primary checkout & current branch unless the operator explicitly authorizes another.
- Never let a worker read `~/.claude/`; the parent reads sensitive local paths.
- Never treat a worker summary as evidence; verify its files, commands, digests, & receipts.

## Parallelism

- Parallelize freely; serialize only for a named reason: data dependency, shared mutable resource (same file/index/port/DB), effect ordering (commit before push, install before qualify), or capacity saturation.
- Same-source rule for multi-machine work: the machine that produces the change commits & pushes; every other machine runs `git fetch && git checkout <sha>` then `python3 tools/sync-gate.py <sha>` (Windows `py -3.11`) BEFORE task work. The gate refuses stale or dirty source — that is the whole cross-machine guarantee; no daemon, keys, or attestation.
- Serialize builds, installs, renders, deploys, & shared-file edits unless the work is partitioned onto non-overlapping paths.

## Models & bounds

- Set an explicit model on every worker.
- Let a worker spawn only a cheaper model within its contract and concurrency budget.
- Treat model depth as analysis capacity, not execution discipline or evidence.
- Keep prompts machine-minimal; RHook injects the canonical directive.

## Completion

- Reconcile Git before dispatch & after integration.
- Accept only inspected artifacts plus rerunnable receipts.
- State plainly when no release, deployment, or promoted result exists.
