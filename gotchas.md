# Gotchas

### 2026-08-31 — Never treat partial Audit composition as repository evidence
- Symptom: Repeated Audit runs returned no useful findings after prior runs had produced substantial improvement work.
- Root cause: Native cutover emitted empty/partial provider plans while Audit skill set `CHILD_AGENTS_MAX: 0`, disabling required reasoning-lens fan-out.
- Correction: Route package CLI through complete declarative runner, reject empty/partial native composition, & restore parallel native lens subagents.
- Prevention: Audit contract/tests must require nonempty frozen providers, all applicable reasoning lenses, & typed incomplete status for `native-provider-composition-partial`, `fullAudit: false`, or missing lenses.
- Evidence: `.audit/windows-closure-js-20260828-054630/{plan.json,facts.json,reports/report.json}`; `.audit/trace-check/plan.json`; `skills/audit/SKILL.md`; `tests/audit-skill-reference-parity.test.mjs`; user-confirmed recurrence 2026-08-31.

### 2026-09-13 — Capture complete installer evidence before each rebuild
- Symptom: Repeated signed installer rebuilds consumed roughly two hours while installation remained unqualified; multiple runs exposed only another failure in diagnostic handling, & one release dispatch used a mistyped commit SHA.
- Root cause: Installer failure evidence initially preserved tree inventory but omitted activation log content; follow-up edits repaired individual null dereferences instead of first making every diagnostic path null-safe & line-addressable, while release SHA was manually transcribed.
- Correction: Preserve installer log, activation events, full exception location, child exit/output, rollback state, & nonzero setup exit in one failure artifact; derive release revision directly from `git rev-parse HEAD`.
- Prevention: Before rebuilding, prove failure artifact can identify stage, source line, child exit, stdout, stderr, timeout, & rollback; dispatch workflows with command-derived SHA only; never report installer work complete before installed qualification passes normal, forced-refresh-failure, & stalled-child cases.
- Evidence: GitHub Actions runs `34717927742`, `34719152424`, `34720164666`, `34721176353`, `34721225116`, & `34722157676`; commits `98d5b56f`, `a892230f`, `722f6e1f`, & `cda7307a`; `scripts/release/windows/qualify-installed.mjs`; `scripts/release/windows/activate.ps1`; user-confirmed wasted time & incomplete result on 2026-09-13.
