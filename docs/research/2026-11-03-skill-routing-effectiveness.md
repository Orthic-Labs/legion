# Skill routing effectiveness: how other agent stacks make procedures apply

**Issue:** Orthic-Labs/legion #130 ("Skills are not used when they apply").
**Date of research:** 2026-11-03. Pages were opened on that date. Pages that show no date are marked "undated".
**Scope:** external mechanisms and one measured evaluation. Ungrounded claims are omitted and listed under "Not grounded".

## 1. Question

Legion's skills (for example `legion:debugger` after a failed build, `legion:commit` before a commit,
Oracle review that covers the path from intake to the asserting layer) were skipped although they applied.
How do other agent stacks make procedural guidance actually get applied, and what does Legion change?

## 2. Comparison

| Stack | How a procedure is triggered | Enforced or advisory | Failure mode | Survives long session / compaction | Measured effect |
| --- | --- | --- | --- | --- | --- |
| Claude Code hooks | Lifecycle events and tool names (`PreToolUse`, `PostToolUse`, `SubagentStop`, `SessionStart` with `compact` matcher, `PreCompact`) | `PreToolUse` **blocks** the call (exit 2 or `permissionDecision: "deny"`). `PostToolUse` observes but can add `additionalContext` next to the tool result. `SubagentStop` can block a subagent from stopping. | A timed-out `PreToolUse` hook does not block unless `"onFailure": "block"` is set (fails open by default). | Hooks run at each event, so they re-fire. `SessionStart` with `compact` matcher exists. | None in the source. |
| Claude Code skills | Model reads the `description` and loads the skill, or the user types `/skill-name` | Advisory. The page gives no guarantee of invocation. Body loads only when invoked. | Not invoked when the description does not match. The docs state "Seeing a skill trigger tells you Claude found it, not that it did what you intended." | Once loaded, content "stays in context across turns". | None in the source. |
| OpenAI Codex (AGENTS.md) | Always on for the project. Chain built once per run. | Advisory context | Instructions not refreshed mid-session; default 32 KiB cap (`project_doc_max_bytes`) | Built at start only; the page does not mention compaction | None in the source. |
| Cursor rules | Always, Auto Attached (glob), Agent Requested (description), Manual (`@rule`) | Advisory context | For Agent Requested, the agent decides from the description alone. | Rules are included at the start of the context. | Guidance: keep rules under 500 lines. |
| Cline rules | Always (no frontmatter), or conditional on `paths` | Advisory context. Conditional rules show "Conditional rules applied" in the UI. | A conditional rule does not activate if no path matches. | Not stated | None in the source. |
| Aider conventions | Explicit `/read`, `--read`, or `read:` config | Advisory; always included when loaded | No automatic trigger | Included each run per config | None in the source. |
| GitHub Copilot instructions | Repo-wide file always; `*.instructions.md` by `applyTo` glob; nearest `AGENTS.md` | Advisory. Instructions are "automatically added to requests". | Not model-selected, so no trigger miss. | Not stated | None in the source. |
| Devin Knowledge | "Retrieved when relevant, not all at once or all at the beginning"; trigger is a description matched to current work; pinning to a repo forces it | Advisory, model-chosen retrieval | The page warns a vague trigger "loads at the wrong time or not at all" (trigger guidance is in the text, not quoted here) | Retrieved per task | None in the source. Page says Knowledge is being migrated to Skills in Plugins (undated). |
| Windsurf rules | `always_on`, `glob`, `model_decision` (description), `manual` | Advisory | `model_decision` depends on the agent choosing the rule | Not stated | None in the source. |
| Kiro hooks | File save, tool use (`PreToolUse` / `PostToolUse` with matcher), `Stop` | `PreToolUse` can "block tool execution unless preconditions are met". Command hooks get session JSON on stdin; default timeout 60 s. Agent-action hooks inject a prompt. | Command timeout behavior is not stated in the excerpt | Hooks activate when a session starts | None in the source. |
| OpenHands | Repository context always loaded in full; keyword `triggers` inject a skill when a term appears in a user message; path-triggered rules injected once per conversation when a matching file is touched | Advisory context. Keyword match fires only on user text. | Keyword triggers do not match agent-internal events (for example "build failed"). | Path rules injected once per conversation | None in the source. |
| Vercel eval (not a stack; an evaluation) | Compared a compressed docs index in `AGENTS.md` (passive) with a skill | n/a | "With AGENTS.md, there's no moment where the agent must decide 'should I look this up?'" | n/a | See section 3. |

## 3. Measured effect

- **Vercel, "AGENTS.md outperforms skills in our agent evals", published 2026-01-27** (https://vercel.com/blog/agents-md-outperforms-skills-in-our-agent-evals). Reported: an 8 KB compressed docs index in `AGENTS.md` reached a 100% pass rate; skills reached 79% at most; the no-docs baseline was 53%; skills with no explicit instructions scored 53%. "In 56% of eval cases, the skill was never invoked." The author notes: "Agents not reliably using available tools is a known limitation of current models." This is one vendor's evaluation on one framework's tasks. It supports the claim that model-chosen loading misses applicable guidance; it does not show that hooks improve outcomes.
- No other stack in the table published a measured effect in the pages opened.

## 4. What the comparison shows

1. Only Claude Code and Kiro offer enforcement at the moment a tool call happens. Both can block a call, and Claude Code can also inject context at that point (`additionalContext`).
2. Every model-chosen mechanism (skill description, Cursor Agent Requested, Windsurf `model_decision`, Devin Knowledge, OpenHands keyword triggers) depends on the wording of the trigger matching the moment. Legion's failure mode (triggers written as user phrases, not as agent events) is the same one.
3. Always-on context (AGENTS.md, Copilot repo instructions, Cline no-frontmatter rules) has no decision point to miss, which is the result Vercel measured.
4. Codex and Claude skills load once per session or per invocation. Nothing re-asserts them after compaction unless a hook does so (Claude Code's `SessionStart` matcher `compact` is the documented place).

## 5. Ranked recommendations for Legion

Each item names its ground. Items marked "internal" rest on the #130 failure evidence, not on an external source.

1. **Event hook on a failed test or build.** A `PostToolUseFailure` or `PostToolUse` hook (matcher on the build and test commands) returns `additionalContext` that names `legion:debugger` before the next fix. Ground: Claude Code hook events and `additionalContext` (code.claude.com/docs/en/hooks, undated, opened 2026-11-03). Addresses #130 hypothesis 3 (no enforcement at the decision point).
2. **Passive index of the procedures most often skipped.** Put a short, always-loaded index in `AGENTS.md` or the SessionStart text that maps events to skills (failed build to debugger; commit to commit; Oracle scope). Ground: Vercel 2026-01-27 (100% vs 79%; skill never invoked in 56%). Single vendor eval.
3. **Commit gate.** A `PreToolUse` hook on the Bash tool that denies `git commit` outside `legion:commit` with a stated reason. Ground: Claude Code `PreToolUse` deny via `permissionDecision` (undated, opened 2026-11-03). Addresses about 12 unreviewed commits in #130. Note: the hook must not be skipped by an "exit 2" bypass; check fail-open setting (`onFailure`).
4. **Re-assert key rules after compaction.** A `SessionStart` hook with matcher `compact` re-injects items 1 to 3. Ground: Claude Code `SessionStart` matchers include `compact` (undated, opened 2026-11-03). Codex loads once per run and does not re-read (learn.chatgpt.com/docs/agent-configuration/agents-md, undated, opened 2026-11-03). Addresses hypothesis 2.
5. **Oracle scope gate.** A `SubagentStop` hook (agent type `legion:oracle`) blocks a stop when the scope line lacks the intake-to-assertion path. Ground: Claude Code `SubagentStop` can block (undated, opened 2026-11-03). The requirement itself is internal (#130 RED-build evidence).
6. **Event-keyed skill descriptions.** Lead each `description` with the agent event ("build or test failed", "about to run git commit") as well as the user wording. Ground: Claude Code says the description is "the main signal Claude uses" and is truncated at 1,536 characters (undated, opened 2026-11-03). Cursor and Windsurf use the same description-driven choice. Lower rank because the trigger still depends on the model choosing it (Vercel 56%).
7. **Skipped-record log.** Write a record each time a skill applies and is skipped (format in section 6). Ground: internal. It makes #130's success measurable. The Claude skill doc's warning about trigger-versus-intent supports measuring outcomes, not just invocation. Ground: code.claude.com/docs/en/skills, undated, opened 2026-11-03.
8. **Pre-flight checklist for test expectations.** Before asserting an error message, trace the first layer that refuses. Ground: internal only (#130 RED builds 5929152e and df48167d). No external source was found for this; treat as unvalidated.

Not recommended from this evidence: adding more always-on text alone. Vercel's result and Codex's once-per-run loading suggest passive text helps only when it is compact and kept in front of the agent (item 2); long text decays.

## 6. Skipped-record format (spec only)

Spec, not implemented. Fields:

- `turn`: integer, the assistant turn index in the session where the decision point occurred.
- `skill`: the Legion skill id that applied (for example `debugger`, `commit`, `oracle`).
- `trigger`: the agent event or user words that made it applicable, quoted (for example `non-zero exit from cargo test`).
- `reason`: the reason stated for skipping, quoted, or `none stated`.

Written as one JSON object per line, appended to `/Volumes/D/scratch/legion-skill-routing/skipped.jsonl` (run output, under the workspace scratch rule). It is written by the hook from item 1 or 3 when it fires, never authored by the skill. It is not a decision record and does not go in `decisions.md`.

## 7. Test plan

Goal: show that the changes raise the rate at which applicable skills run, measured on replayed decision points, not on assertions.

- **Fixtures.** The three RED builds (5929152e, 7b24288a, df48167d) and the about twelve commits made without `legion:commit` in #130. Each becomes a decision point: the event, the state before, and the skill expected.
- **Arms.** (a) current behavior (baseline); (b) passive index only (item 2); (c) hooks (items 1 and 3) with index; (d) hooks plus compact re-injection (item 4).
- **Metric.** Per decision point, whether the expected skill ran before the next action (Skill tool call or hook-injected instruction). Report counts per arm, not percentages alone.
- **Pass.** Arm (c) or (d) runs the expected skill at every decision point in the fixtures. A missing skill run is a failure, never a pass by default.
- **Negative check.** Replay non-applicable events (for example a passing test) and count false triggers.
- **Limits.** Replay does not prove the model acts on injected context; it proves the hook fired and the context was delivered. Outcome measures (failed builds avoided) need a live session after approval.
- **Execution.** Not run here. Root integration runs the replay after approval, per workspace rules. No command was run for this document.

## 8. Not grounded (omitted from claims)

- Factory: only search snippets were seen (docs.factory.ai pages were not opened). Not used.
- Amp (ampcode.com/manual): the page opened showed no loading or hook content. Not used.
- Windsurf per-file character limit: the page gives none. Not stated.
- Devin "Accessed Knowledge" indicator: seen only in search snippets of a Japanese page. Not used.
- The university study cited by a third-party aggregator on context files lowering success. Not opened. Not used.
- Claude Code hook behavior past the first 100,000 characters of the page was not read. Claims are limited to the lifecycle table and exit-code rules that were read.
- OpenHands "knowledge microagents" naming: the current page uses "skills" with `triggers`; the older term is not claimed.

## 9. Sources opened

- https://code.claude.com/docs/en/hooks (undated; opened 2026-11-03; redirected from docs.claude.com)
- https://code.claude.com/docs/en/skills (undated; opened 2026-11-03; redirected from docs.claude.com)
- https://learn.chatgpt.com/docs/agent-configuration/agents-md (undated; opened 2026-11-03; redirected from developers.openai.com)
- https://cursor.com/docs/context/rules (undated; opened 2026-11-03)
- https://docs.openhands.dev/usage/prompting/microagents-overview (undated; opened 2026-11-03)
- https://kiro.dev/docs/hooks/ (undated; opened 2026-11-03)
- https://docs.cline.bot/features/cline-rules (undated; opened 2026-11-03)
- https://aider.chat/docs/usage/conventions.html (undated; opened 2026-11-03)
- https://docs.github.com/en/copilot/how-tos/configure-custom-instructions/add-repository-instructions (undated; opened 2026-11-03)
- https://docs.devin.ai/product-guides/knowledge (undated; opened 2026-11-03)
- https://docs.devin.ai/desktop/cascade/memories (Windsurf rules page; undated; opened 2026-11-03; redirected from docs.windsurf.com)
- https://vercel.com/blog/agents-md-outperforms-skills-in-our-agent-evals (published 2026-01-27; opened 2026-11-03)

Search results were used only to find the pages above, except where section 8 says otherwise.
