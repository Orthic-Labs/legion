# Legion competitor & external-practice corpus

Commit-pinned snapshot of the eighteen external repositories Legion is compared against.
Clones live at `repos/<owner>__<name>` (git-ignored, not redistributed). Recreate with:

```bash
git clone https://github.com/<owner>/<name>.git repos/<owner>__<name> && git -C repos/<owner>__<name> checkout <commit>
```

Read-only reference input for taxonomy and practice comparison only; no prose, rule text, or
prompt is copied into this repository (see `references/source-provenance/`).

| Repository | Commit | Local path | Evidence role | Mining depth |
|---|---:|---|---|---|
| [addyosmani/agent-skills](https://github.com/addyosmani/agent-skills) | `be42637` | `repos/addyosmani__agent-skills` | implementation workflow | full |
| [Agent-Field/agentfield](https://github.com/Agent-Field/agentfield) | `a6dd3f3` | `repos/Agent-Field__agentfield` | orchestration/observability design + code | full |
| [Agent-Field/SWE-AF](https://github.com/Agent-Field/SWE-AF) | `1ae2913` | `repos/Agent-Field__SWE-AF` | multi-stage harness | full |
| [anthropics/claude-code](https://github.com/anthropics/claude-code) | `be90077` | `repos/anthropics__claude-code` | official host/plugin examples | indirect (re-mine for hook protocol) |
| [ArabelaTso/Coding-Skills-Collection](https://github.com/ArabelaTso/Coding-Skills-Collection) | `e66a625` | `repos/ArabelaTso__Coding-Skills-Collection` | catalog only | not deep-mined |
| [coderabbitai/skills](https://github.com/coderabbitai/skills) | `aa49953` | `repos/coderabbitai__skills` | review workflow | indirect |
| [EricGrill/agents-skills-plugins](https://github.com/EricGrill/agents-skills-plugins) | `43a037f` | `repos/EricGrill__agents-skills-plugins` | catalog/fork collection | not deep-mined |
| [garrytan/gstack](https://github.com/garrytan/gstack) | `d078622` | `repos/garrytan__gstack` | workflow, persistence, evals | full |
| [instructa/agent-skills](https://github.com/instructa/agent-skills) | `dff3284` | `repos/instructa__agent-skills` | ownership/migration skills | full |
| [LambdaTest/agent-skills](https://github.com/LambdaTest/agent-skills) | `0491a3a` | `repos/LambdaTest__agent-skills` | remote testing workflows | full |
| [mattpocock/skills](https://github.com/mattpocock/skills) | `84fdeff` | `repos/mattpocock__skills` | decision/spec/prototype workflows | full |
| [NeoLabHQ/context-engineering-kit](https://github.com/NeoLabHQ/context-engineering-kit) | `8539779` | `repos/NeoLabHQ__context-engineering-kit` | context/judge/orchestration workflows | full |
| [obra/superpowers](https://github.com/obra/superpowers) | `b36e082` | `repos/obra__superpowers` | development/review lifecycle | indirect (absorbed) |
| [swe-agent/swe-agent](https://github.com/swe-agent/swe-agent) | `3ea751c` | `repos/swe-agent__swe-agent` | mature agent harness | full |
| [SWE-agent/mini-swe-agent](https://github.com/SWE-agent/mini-swe-agent) | `a83fcae` | `repos/SWE-agent__mini-swe-agent` | minimal harness baseline | full |
| [testdino-hq/playwright-skill](https://github.com/testdino-hq/playwright-skill) | `d3be9ca` | `repos/testdino-hq__playwright-skill` | browser evidence workflow | full |
| [trailofbits/skills](https://github.com/trailofbits/skills) | `304c81a` | `repos/trailofbits__skills` | security verification | full |
| [VoltAgent/awesome-agent-skills](https://github.com/VoltAgent/awesome-agent-skills) | `bb272b6` | `repos/VoltAgent__awesome-agent-skills` | catalog only | not deep-mined |

The findings derived from this corpus are integrated in
[the architecture book](./2026-08-12-legion-architecture-book-final.md) — net-new control families,
existing-contract improvements, and the rejection list. This file records only the corpus itself.
