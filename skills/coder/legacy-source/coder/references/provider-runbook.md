# Coder provider runbook

```text
MODE: DIAGNOSE
PRIMARY_DELIVERABLE: Scoped read-only worker packet plus synthesized analysis.
DISCOVERY_PROFILE: D1_SCOPED_SOURCE
EFFECT_PROFILES: child_packet
SPECIALIST_REFS_MAX: 0
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Frozen worker packet returns bounded analysis or a typed provider stop.
```

> ## ⛔ OPT-IN ONLY — NOT for workspace fan-outs (locked 2026-07-05)
> This skill is the ONE sanctioned lane to external model APIs, and it fires ONLY on Adrian's
> explicit request ("/coder", "use the API models", a named provider). No other skill may route
> through it: `/audit`, `/cortex`, `/seo`, `/commit`, `/architect`, `/research` all run
> self-sufficient on native Claude subagents — provider rate limits and network registration
> repeatedly hung their runs. The other sanctioned external-API surface is `/council`,
> whose two internal panels are likewise explicit-invocation. The old
> `cheap-review-routing` PreToolUse hook that force-rerouted review spawns here is retired and
> unwired. If a provider hangs or 429s mid-run, report it and fall back to native — do not retry-loop.

## Overview

Use API models as cheap read-only workers. The main thread remains the editor, verifier, and owner of final judgment.

## First rule

Do not let API workers mutate the repo. Send them scoped prompts, diffs, facts, or file excerpts; apply any useful patch locally after verification.

## Model roster

All providers below probed **LIVE 2026-06-23** (after the api-worker.py User-Agent +
UTF-8-stdout fixes — bare urllib's default UA was CF-WAF-banned by Groq+Cerebras, and
non-ASCII model output crashed cp1252 stdout on Windows; both fixed).

| Tier | Use | Provider/model |
|---|---|---|
| small | Bulk triage, naming, simple review, fast second opinion | `groq/openai/gpt-oss-20b` |
| small-code | Focused code review, bug hypotheses, SEO/content lenses | `groq/qwen/qwen3.6-27b` |
| agent-fast | Tool-use planning, automation decomposition, long-context non-thinking passes | `nim/qwen/qwen3-next-80b-a3b-instruct` |
| big | Long-context code/repo reasoning and agentic review | `nim/minimaxai/minimax-m3`, `nim/nvidia/nemotron-3-super-120b-a12b` |
| big-general | Requirements, docs, RAG, multilingual/generalist review, enterprise-style reasoning | `nim/mistralai/mistral-large-3-675b-instruct-2512` |
| big-code | Risky code review, complex patch plan | `nim/deepseek-ai/deepseek-v4-pro` |
| fast-big | Deep external seat (gpt-oss-120b) | `groq/openai/gpt-oss-120b`, `cerebras/gpt-oss-120b` |

**Fallback chains** (api-worker.py `--fallback <name>` — first member that answers wins,
retries 429/5xx/timeout onto the next): `bulk` (nim minimax → nemotron),
`code` (nim deepseek-v4 → nemotron), `fast` (nim qwen3-next → minimax). Use a chain instead of
`--provider`/`--model` when you care about getting an answer more than which model gives it.

Default choices:
- Use `groq/openai/gpt-oss-20b` for bulk triage.
- Use NIM `minimaxai/minimax-m3` for panel-style advisory work.
- Use NIM `qwen/qwen3-next-80b-a3b-instruct` for fast agent planning and decomposition when coding specialization is less important than tool/workflow reasoning.
- Use NIM `nemotron-3-super-120b-a12b` for long context and agentic reasoning.
- Use NIM `mistralai/mistral-large-3-675b-instruct-2512` for generalist review, requirements, docs, RAG-style synthesis, multilingual work, and broad enterprise codebase critique.
- Use NIM `deepseek-ai/deepseek-v4-pro` for code specialist review when slow is acceptable.

**Routing internals (handled automatically by `api-worker.py`, mirrors the jury engine):**
- NIM reasoning models (deepseek-v4-pro, nemotron-super, omni) are **streamed** + sent `chat_template_kwargs:{enable_thinking:false}` — they HANG on non-stream buffered reads.
- NIM calls are **serialized** (a global lock) — NIM free tier 504s on concurrent requests; Groq/Cerebras still run concurrently in a batch.
- Groq output is capped at 6000 tokens — its free tier has an ~8000 tokens-per-minute wall (prompt+output); a larger request 413s.
- NIM timeout floors at 120s (reasoning models think server-side before the first token).

Non-default but available:
- NIM `qwen/qwen3.5-397b-a17b`: use only when Qwen 3.6 is unavailable or a very large Qwen-family comparison is specifically useful; avoid as a default because it overlaps with the Qwen 3.6 code seat.
- NIM `nvidia/nemotron-3-ultra-550b-a55b`: reserve for rare deep-review attempts; it is listed by NIM but can be slow enough to time out on tiny smoke tests.
- NIM `mistralai/mistral-medium-3.5-128b`: callable, but keep out of the default roster while Mistral Large 3 is available.

## Worker command

One-off call:

```powershell
coder-api-worker `
  --provider groq --model openai/gpt-oss-20b --input prompt.md
# or let a chain pick a live model:
coder-api-worker --fallback code --input patch-review.md
```

**Batch (the fan-out — this is how you offload N lenses without spending Claude).** Write a
manifest, run one command, get one JSON array back:

```powershell
# manifest.json — one object per independent read-only job
# [{"id":"ai-slop","provider":"groq","model":"openai/gpt-oss-20b","prompt_file":"lenses/ai-slop.md"},
#  {"id":"schema","fallback":"code","prompt_file":"lenses/schema.md","max_tokens":3000}]
coder-api-worker --batch manifest.json --pool-size 4
# -> [{"id":"ai-slop","ok":true,"output":"..."}, {"id":"schema","ok":true,"output":"..."}]
```

Each item: `id` + either `provider`+`model` or `fallback` (chain), and `prompt_file` or inline
`prompt`; optional `system`, `max_tokens`. Pool default 4 concurrent. Failures are per-item
(`{"ok":false,"error":...}`) — one bad lens never aborts the batch.

Provider env vars:
- `NVIDIA_API_KEY` · `GROQ_API_KEY` · `CEREBRAS_API_KEY`

## Ultracode / Workflow offload — how to route work off Claude

A Workflow's `agent()` spawns **only Claude-family** subagents (haiku/sonnet/opus/fable) — you
cannot set `model:'nim/minimax-m3'` on an `agent()`. Two real ways to push the work onto the
cheap APIs:

- **Pattern A — one haiku shell for the whole batch (inside the workflow).** A single
  `agent({model:'haiku'})` runs the *entire* `--batch` manifest and relays the JSON array. Do NOT
  spawn one agent per lens — write all lenses into one manifest, run them in one haiku shell. Cost
  = **1 haiku call + N free/cheap lens calls** (vs N sonnet agents). The haiku only relays; the
  reasoning is on MiniMax/NIM.
  ```js
  // inside a Workflow script — replaces a parallel() of N sonnet review agents
  const batch = await agent(
    `Run exactly: coder-api-worker --batch /tmp/lenses.json --pool-size 4
     Return its stdout (a JSON array) verbatim, nothing else.`,
    { label: 'offload:lenses', model: 'haiku', schema: BATCH_RESULTS_SCHEMA })
  // then synthesize `batch` on sonnet/main — that's the only Claude-grade step
  ```
- **Pattern B — batch outside (cheapest).** Run `api-worker.py --batch` directly from Bash in the
  main session (zero Claude tokens), and use the workflow only for the synthesis/verify. Prefer
  this when the lenses don't need a workflow progress row.

Rule of thumb: **lenses/reviews/triage → cheap models** (Pattern A or B); **synthesis, the patch
itself, and the ship gate → the main agent or Council's internal Jury**. One haiku relay beats N sonnet reviewers every time.
**Never offload the final ship gate** — `/council` or local tests decide (see Hard stops).

## Prompt shape

Keep prompts scoped:

```text
TASK: <one precise read-only job>
INPUT: <diff, facts.json excerpt, file excerpts, URL evidence>
OUTPUT: <bullets or JSON shape>
CONSTRAINTS:
- Do not ask to edit files.
- Cite exact file:line or evidence locus.
- If evidence is missing, say missing.
- No <think>; final answer only.
```

## Use from other skills

- parallel read-only fan-out: use API workers for independent read-only analysis; use real subagents only for edits, live browser work, or local tool workflows.
- `audit`: feed redacted `facts.json` slices and file excerpts to API workers for lenses; deterministic scanners remain local truth.
- `seo`: API workers can run parallel technical/content/schema/GEO reasoning after crawl evidence is collected; live SEO tools and authenticated exports stay local.

## Hard stops

- Never send secrets, private keys, `.env`, license tokens, customer data, or full repo dumps with credentials.
- Never trust API worker file-line claims without local verification.
- Never use API workers as the final ship gate; `/council` or local tests decide.
