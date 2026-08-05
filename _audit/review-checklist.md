# Skill A+ Review Checklist

Use this checklist for each direct non-router skill.

## Identity

- Skill:
- Folder:
- Public invocation:
- Router/direct source of truth checked:
- Compatibility alias needed:

## RED Baseline

- `validate_skills.py --skill <skill>` output captured:
- `run_evals.py --skill <skill> --schema-only` output captured:
- `run_evals.py --skill <skill> --discovery --dry-run` output captured:
- Baseline issue summary:

## Local Use

- First-loaded `SKILL.md` is focused and under budget or intentionally exempt:
- Local paths/scripts are verified:
- Deterministic commands are PowerShell-compatible:
- Destructive/API/download/OAuth/daemon actions require confirmation:
- Stunning Strangers commercial boundary checked where applicable:

## Eval Discipline

- `evals/evals.json` exists:
- Categories present: should-trigger, should-not-trigger, output-quality, safety, pressure, compatibility:
- Assertions are machine-checkable where practical:
- At least one pressure/adversarial case exists:
- Discovery dry-run passes:

## Compatibility

- Existing public invocation still works:
- Folder/name mismatch has alias or was normalized safely:
- Claude index and Codex compatibility rules remain aligned:
- Shared `SKILL.md` did not receive Codex-only wording:

## GREEN Proof

- Focused audit command:
- Focused schema command:
- Focused discovery command:
- Residual warnings:
- Decision: PASS | NEEDS-REVISION | BLOCKED
