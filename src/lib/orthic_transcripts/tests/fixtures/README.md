# Synthetic transcript fixtures (plan 5.6 contract tests)

These fixtures are structurally equivalent stand-ins for real, observed
Claude Code and Codex CLI sessions. The original real captures were removed
from this public repository on 2026-08-19 (they contained a real session id,
real timestamps, real file paths, and actual conversation turns) and are
preserved outside the repo; see the workspace overlay's
`transcript-fixtures/README.md` for that history.

| File | Host | Rows | Bytes | Notes |
|---|---|---|---|---|
| `claude_real_25aa1534_prefix.jsonl` | Claude Code | 60 | ~46KB | Synthetic session with the same row-type distribution as the original capture: `mode`, `permission-mode`, `file-history-snapshot`, `user`, `attachment`, `ai-title`, `assistant`, `last-prompt`, `system`, `queue-operation`; mixed user + assistant + `tool_use` + `tool_result` blocks. Session id, timestamps, cwd, and all narrative text are invented. |
| `codex_real_019fbc85_prefix.jsonl` | Codex CLI | 101 | ~59KB | Synthetic archived-rollout shape: `session_meta`, `response_item/message`, `response_item/function_call`, `response_item/function_call_output`, `response_item/custom_tool_call`, `response_item/custom_tool_call_output`, and `response_item/reasoning` (private-reasoning flag exercised). Session id, timestamps, cwd, and all narrative text are invented. |

Both files are generated (not hand-authored) so their JSON shape, key set,
and `tool_use`/`tool_result`/`call_id` pairing exactly track what a real
session produces — the parser code paths under test are unchanged from what
ran against the original captures. The filenames keep the original
`*_real_*_prefix.jsonl` naming only so the fixture-consuming tests do not
need path updates.

## Regenerating

The generator that scrubs a real capture into one of these synthetic
fixtures is a one-off script (not checked into this repo); it walks each
JSONL row, preserves structural/id fields verbatim (uuids, call ids,
`sessionId`, `type`, etc. — remapped to fresh fake values where the field is
itself an identifier), and replaces narrative/free-text string values with
synthetic sentences. Do not hand-edit these files piecemeal — regenerate
from a fresh real capture through the same scrub if the parser's expected
row shapes change.

Do not commit a byte-faithful real transcript to this file location again —
this repository is public.
