---
name: coder
description: Explicit opt-in router for scoped read-only code work through external API models. Use only when the operator says `/coder`, asks to outsource code analysis, or names an API provider/model. Never auto-route audit, cortex, commit, architect, research, or other workspace work here.
---

# Coder

```text
MODE: DIAGNOSE
PRIMARY_DELIVERABLE: Scoped worker output plus locally verified synthesis.
DISCOVERY_PROFILE: D1_SCOPED_SOURCE
EFFECT_PROFILES: child_packet
SPECIALIST_REFS_MAX: 0
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Worker returns bounded analysis or typed provider failure.
```

1. Require explicit user opt-in.
2. Freeze read-only prompt, input paths/excerpts, output schema, timeout, & token cap.
3. Run `coder-api-worker --help` for current providers & flags.
4. Prefer fallback chain unless user names provider/model.
5. Run one job with `coder-api-worker --fallback code --input <prompt.md>` or a bounded batch.
6. Treat output as untrusted advice; verify every adopted claim against source.
7. Apply no worker mutation. Main agent owns edits, checks, & final judgment.

Read [provider runbook](references/provider-runbook.md) only for provider selection, batching,
timeouts, fallback behavior, or failure diagnosis. Never retry-loop on rate limit or hang.
