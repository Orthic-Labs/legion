---
name: debugger
description: "Reproduce, isolate, diagnose, fix, and verify code or system failures. Use for /debugger, errors, crashes, leaks, intermittent tests, staging or production differences, wrong data, or unexplained slowness."
---

# Debugger

MODE: EXECUTE
PRIMARY_DELIVERABLE: Root-cause finding plus verified minimal fix or evidence.
DISCOVERY_PROFILE: D1_SCOPED_SOURCE
EFFECT_PROFILES: source_read, focused_check, output_write
SPECIALIST_REFS_MAX: 0
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Root cause plus verified minimal fix or unresolved evidence.

Never fix before reproducing or bounding the failure.

1. Freeze symptom, expected behavior, environment, revision, inputs, frequency, & last known good.
2. Check Crypt recall, Cortex map, recent diffs, logs, & existing tests before broad search.
3. Use `references/manual.md` for non-obvious, intermittent, performance, data, or multi-component failures.
4. Reproduce with the smallest real case; record exact command & output.
5. Change one variable per test; maintain hypothesis, prediction, result, & disposition.
6. Identify root cause before editing; make the smallest correct fix.
7. Verify regression, adjacent behavior, negative cases, & original environment.
8. For repeated failures or over two changed files, use Forge assess through close.
9. Report root cause, evidence, fix, tests, limits, & unresolved risk.

Use exact Morph tool command only when transcript mining is needed; Morph is not a routing skill.
