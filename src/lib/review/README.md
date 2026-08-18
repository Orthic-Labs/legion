# Council — multi-LLM review pipeline

API engine behind the unified `/council` skill (advisory Council panel -> disposition/revision ->
fresh Jury verdict via `dual_review.py`; the separate `/jury` skill was folded in 2026-07-14).

Review stack:
- `/council` runs the full workflow: 3-seat advisory panel, then a fresh 4-seat Jury verdict.
- The old Level-2 manual CLI-review lane (Codex/CodeRabbit/Command Code via `cli-review.py`) was
  RETIRED 2026-07-14: CodeRabbit's review surface is absorbed by `/audit`'s lenses, and a new
  MiniMax + Muse review system is being set up separately.

## Layout

```
council/
├── models.yaml       # provider + skill registry (source of truth)
├── jury.py        # CLI entry
├── engine.py         # orchestration (parallel API jurors, fallbacks)
├── synthesizer.py    # markdown verdict table renderer
├── cache.py          # content-hash cache (cache/ + cache/.errors/)
├── providers/
│   ├── base.py
│   ├── openai_compat.py   # NIM, Groq, Cerebras (same wire format)
│   └── subprocess_cli.py  # subprocess wrapper for the codex_cli engine provider
├── rubrics/
│   └── code.md             # /jury-code rubric (more to come)
├── cache/                  # juror response cache
└── shadow_log/             # parity logs vs old /code-verdict
```

## Run

```bash
python jury.py jury-code --input D:/workspace/some/file.py
python jury.py jury-code --input - < file.py
python jury.py jury-code --input file.py --flag irreversible=true
python jury.py jury-code --input file.py --json
python jury.py jury-code --input file.py --shadow   # save full result
```

## Agent Room P-1 gate (rev 2026-07-18c)

### Mandatory room-link handoff

The room watch link is a user-facing capability, not optional launcher output. The launcher creates
it only after every configured seat has joined and posted durable readiness. The room driver then
persists this gate in `<review-dir>/review.state.json`:

```text
room_launching
  -> all seats ready
  -> room_active + room.link_delivery.status=pending
  -> active agent sends user_notification.message to the operator immediately
  -> --ack-room-link-delivered
  -> room.link_delivery.status=acknowledged
  -> export/advisory completion is allowed
```

The first `--room` call always stops at `pending`, even if an acknowledgement flag is supplied
prematurely. Re-running without acknowledgement returns the same mandatory notification and cannot
export the ledger. After the link is visible in the operator's current task, resume with the same arguments
plus `--ack-room-link-delivered`. The acknowledgement timestamp and URL digest remain in the review
state as durable evidence.

The watch URL contains the loopback pairing capability. Send it only to the operator in the current task;
do not copy it into public logs, commits, external messages, or model prompts. On readiness failure,
no watch link is announced: the driver aborts the owned room, preserves diagnostics, and enters the
existing fallback lane.

P0 infrastructure was blocked until both the local protocol gate and the frozen three-review value
gate pass. The admissible implementation lives here first:

- `room_protocol.py` — typed finding lifecycle, two exits, scope-motion digest checks, blindness,
  idempotency, timeout/escalation bounds, mode gates, and untrusted peer projection.
- `review_evidence.py` — canonical run receipts, terminal-ledger verification, scheduled findings,
  the two-pass fallback state, the non-configurable value-gate evaluator, and a combined-sample
  builder that copies both experimental branches into one digest-pinned run.
- `dual_review.py --rebuttal` — P-1 peer-debate flag only; persisted phase name is `PeerDebate`.
  It is not a finding-termination mechanism and cannot substitute for a room ledger. P-1 rounds
  bypass response caches and preserve provider-reported call/token accounting.

Canonical run artifacts must be immediate children of `src/lib/review/.council-runs/`:

```powershell
py -3.11 -m pytest src/lib/review/tests/test_room_protocol.py src/lib/review/tests/test_review_evidence.py -q
py -3.11 src/lib/review/review_evidence.py pin src/lib/review/.council-runs/<run-id>
py -3.11 src/lib/review/review_evidence.py verify src/lib/review/.council-runs/<run-id>
```

Build one frozen-gate sample only after the blind and peer-debate branches have each completed their
disposition and isolated Jury pass. `adjudication.json` must identify the operator and record the
minority-erasure decision. The builder copies the load-bearing artifacts into the sample directory,
then pins every copy and the derived sample in one manifest:

```powershell
py -3.11 src/lib/review/review_evidence.py sample <sample-run-id> `
  --blind-run <blind-branch-dir> `
  --peer-debate-run <peer-branch-dir> `
  --review-kind jury-code `
  --adjudication adjudication.json

py -3.11 src/lib/review/review_evidence.py evaluate `
  src/lib/review/.council-runs/<sample-1> `
  src/lib/review/.council-runs/<sample-2> `
  src/lib/review/.council-runs/<sample-3>
```

The builder derives escalation numerator/denominator from the pinned response audit; callers cannot
supply or reinterpret that rate. It also requires identical packet bytes/input hashes and verifies
the predeclared blind versus `required_contest` conditions. Use `dual_review.py --no-resume
--no-cache` for each control branch. `--rebuttal` forces no-cache
for every peer round even when the flag is omitted accidentally. Missing provider usage is recorded
as incomplete and makes the frozen gate sample inadmissible; token counts are never estimated.

The frozen evaluator requires exactly three distinct, digest-valid, real Loop-2 run directories,
complete provider-reported or CLI-self-reported calls/tokens, and the operator's artifact-grounded
minority-position adjudication. The
self-referential Agent Room plan packet is rejected; other `jury-plan` reviews are eligible.

## Provider rules baked in

| Provider | Concurrency | Failover | Quota signal |
|---|---|---|---|
| NIM | serialized 2s gap per key | single key | 429/503/504/timeouts |
| Groq | parallel safe | n/a | 429 + headers |
| Cerebras | DISABLED 2026-05-27 (`disabled: true`) | n/a | n/a — skipped in chains |

Current text juror spine:

| Role | Primary |
|---|---|
| Generalist | Groq `openai/gpt-oss-120b` |
| Agentic | Groq `groq/compound` |
| Reasoning | NIM `moonshotai/kimi-k2.6` / `minimaxai/minimax-m3` |
| Kimi track | NIM `moonshotai/kimi-k2-thinking` / `moonshotai/kimi-k2.6` |
| Code specialist | NIM `deepseek-ai/deepseek-v4-pro` |
| Long-context agentic | NIM `nvidia/nemotron-3-super-120b-a12b` fallback, thinking disabled unless explicitly tested |
| ~~Cerebras fallback~~ | DISABLED 2026-05-27 — `llama3.1-8b` 8K context can't hold review prompts (HTTP 400) + free-tier 429s. Engine skips `disabled: true` providers. |

Do not promote a model from provider catalog visibility alone. A model must pass the actual provider wrapper and a full rubric JSON smoke before becoming primary or fallback. Example:

```bash
python jury.py jury-plan --input - --no-cache --json
```

## Config

All model + skill config in `models.yaml`. Bump `prompt_version` to invalidate cache when juror prompt template changes.

## Pack a whole small repo for a juror (Repomix)

When the review question is **cross-file** ("is this app coherent", architecture review, security sweep of a small service) — i.e. no single file is the input — pack the repo into one artifact and feed it to a juror:

```bash
# pin <ver> to the version you smoke-tested; `npx` floating to latest is the reproducibility risk
npx repomix@<ver> --stdout --style markdown <dir> | py -3.11 src/lib/review/jury.py jury-plan --input -
```

**Token-cap guard (mandatory — a silently truncated pack reads half the repo and looks complete):**
```bash
TOK=$(npx repomix@<ver> --token-count-tree <dir> | awk '/Total Tokens/{gsub(/,/,"",$3); print $3}')
[ "${TOK:-999999}" -lt 180000 ] || { echo "PACK TOO BIG ($TOK) — use --compress or --include <glob>"; exit 1; }
```

- **Validated 2026-06-20:** `sampleapp/crates/ocr` → 4 files, 9,082 tokens, clean markdown. Works.
- **Use for:** `jury-plan` / `jury-code` over a whole small repo/crate/package.
- **Do NOT use for:** `/audit` (walks the tree + runs scanners itself), `/council` (single artifact), **SampleApp** (its agentic ripgrep + content-addressed retrieval beats a flat blob — a pack regresses it).
- No install: runs via `npx`. Design rationale + ADR: `Roadmap/transcripts-research/plans/repomix-absorb-plan.md`.

## Roadmap

- [x] /jury-code
- [x] /jury-image, /jury-video (vision-input scaffold; provider support varies)
- [x] /jury-plan, /jury-idea, /jury-launch
- [x] /jury-content-strategy, /jury-blogs, /jury-brand-voice
- [x] /jury-offer, /jury-ad
- [ ] Shadow-mode parity test vs `/code-verdict` against 3 documented HR misses
- [ ] Delete `/verdict` and `/code-verdict` after parity proven
