# Legion Stage 4 license disposition

| Atom/mechanism | Repository | Observed license/SPDX | Evidence location | Obligations | Permitted reuse actions |
|---|---|---|---|---|---|
| LEG-021 — `DefaultAgent.forward` / `forward_with_handling` parse-normalize-correct loop | `swe-agent__swe-agent` | MIT | `LICENSE@3ea751c087f32b16e039a2233dd6eefecef325d5`; mechanism `sweagent/agent/agents.py` at same commit | Preserve copyright & permission notice for copied/substantial material. | `ADOPT`, `DIRECT_PORT`, `TRANSLATE_PORT`, `BEHAVIORAL_REIMPLEMENT`, `COMPOSE`, `GREENFIELD`; selected `BEHAVIORAL_REIMPLEMENT` because donor is Python-agent-specific while Legion requires executor-neutral contract semantics. |
