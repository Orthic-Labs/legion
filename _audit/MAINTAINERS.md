# Skill Audit Maintenance

## Source Of Truth

- Canonical skill bodies live in `D:/Claude/tools/skills`.
- Router/direct classification lives in `D:/Claude/docs/SKILL-ARCHITECTURE.md` (single merged
  Claude+Codex catalogue; the old per-agent rule-index split was retired 2026-08-04).
- Compatibility aliases live in `D:/Claude/tools/skills/_audit/compatibility-matrix.json`.

## Update Triggers

Run the audit checklist when any of these change:

- A new skill is added.
- A skill folder or frontmatter `name` changes.
- A skill moves between direct and router status.
- A description changes enough to affect discovery.
- A skill gains a destructive, external, paid, OAuth, download, deploy, or daemon action.
- A referenced local script/path/link changes.

## Required Checks

```powershell
py -3.11 D:/Claude/tools/skills/_audit/validate_skills.py --json
py -3.11 D:/Claude/tools/skills/_audit/run_evals.py --schema-only --json
py -3.11 D:/Claude/tools/skills/_audit/run_evals.py --discovery --dry-run --json
```

## Model-Judged Gate

Use this when changing eval coverage or preparing a broader skill-quality pass:

```powershell
py -3.11 D:/Claude/tools/skills/_audit/run_evals.py --model-judge --provider cerebras --model llama3.1-8b --json
```

If a provider is rate limited, rerun the affected skill with another configured council provider and keep both artifacts.

## Ownership Workflow

- Skill author updates `SKILL.md` and `evals/evals.json` together.
- Skill author updates `docs/SKILL-ARCHITECTURE.md` when direct/router discoverability or
  Codex-relevant mechanics change.
- Skill author updates `compatibility-matrix.json` before any name/folder mismatch is accepted.
- Final reviewer checks command output, not memory.
