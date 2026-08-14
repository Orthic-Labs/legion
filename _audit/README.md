# Local Skill Audit Harness

Static checks plus optional model-judged eval quality checks for Adrian's local skill library.

## Commands

```powershell
py -3.11 D:/Claude/tools/skills/_audit/validate_skills.py --json
py -3.11 D:/Claude/tools/skills/_audit/validate_skills.py snapshot --out D:/Claude/tools/skills/_audit/snapshots/current-discovery.json
py -3.11 D:/Claude/tools/skills/_audit/run_evals.py --schema-only --json
py -3.11 D:/Claude/tools/skills/_audit/run_evals.py --discovery --dry-run --json
py -3.11 D:/Claude/tools/skills/_audit/migrate_evals.py --json
py -3.11 D:/Claude/tools/skills/_audit/run_evals.py --model-judge --provider cerebras --model llama3.1-8b --json
py -3.11 D:/Claude/tools/skills/_audit/security_scan_skills.py
```

## Scope

- Validates owned direct non-router skills under `D:/Claude/tools/skills`; downloaded upstream
  sources under `tools/skills/legion/repos/` remain outside workspace eval gates.
- Uses `D:/Claude/docs/SKILL-ARCHITECTURE.md` as the router/direct source of truth (the merged
  catalogue that replaced the separate per-agent Claude and Codex rule indexes on 2026-08-04).
- Preserves local Windows paths; it reports missing local paths instead of rewriting them.
- Does not call external APIs unless `run_evals.py --model-judge` is explicitly used.
- Writes model-judge artifacts under `D:/Claude/tools/skills/_audit/model-eval-runs/`.
- `security_scan_skills.py` scans local skill roots only by default: `D:/Claude/tools/skills`,
  `C:/Users/adrds/.agents/skills`, and `D:/Claude/.agents/skills`. Use `--include-plugin-cache`
  only when intentionally auditing cached third-party/plugin skills too.

## Current Checks

- YAML frontmatter presence and parseability.
- Skill name format.
- Folder/frontmatter mismatch unless listed in `compatibility-matrix.json`.
- Direct-index presence.
- Missing eval manifests for direct skills.
- Broken local markdown links.
- Missing referenced local `D:/...` paths.
- Long `SKILL.md` bodies.
- Linux/container path leaks such as `/mnt/user-data`.
- Bash heredoc examples in local PowerShell-oriented guidance.
- Skill-layer security/safety hazards via `security_scan_skills.py`: secret literals, remote
  shell/eval execution, destructive shell guidance, prompt-injection-style text, remote dependency
  fetches, risky external links, and link-heavy skills.

## Eval Manifest Shape

New eval files use `schema_version: 1` and these categories:

- `should_trigger`
- `should_not_trigger`
- `output_quality`
- `safety`
- `pressure`
- `compatibility`

Legacy manifests with `skill_name` and `evals` are accepted as legacy and reported for migration.
