# Gotchas

### 2026-08-31 — Never treat partial Audit composition as repository evidence
- Symptom: Repeated Audit runs returned no useful findings after prior runs had produced substantial improvement work.
- Root cause: Native cutover emitted empty/partial provider plans while Audit skill set `CHILD_AGENTS_MAX: 0`, disabling required reasoning-lens fan-out.
- Correction: Route package CLI through complete declarative runner, reject empty/partial native composition, & restore parallel native lens subagents.
- Prevention: Audit contract/tests must require nonempty frozen providers, all applicable reasoning lenses, & typed incomplete status for `native-provider-composition-partial`, `fullAudit: false`, or missing lenses.
- Evidence: `.audit/windows-closure-js-20260828-054630/{plan.json,facts.json,reports/report.json}`; `.audit/trace-check/plan.json`; `skills/audit/SKILL.md`; `tests/audit-skill-reference-parity.test.mjs`; user-confirmed recurrence 2026-08-31.
