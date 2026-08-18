# Real-transcript fixtures (plan 5.6 contract tests)

These are byte-faithful prefixes of real, observed sessions from this machine.
Frozen so the contract tests are deterministic and don't depend on live session
files that keep growing during a real run.

| File | Host | Source | Rows | Bytes | Selection reason |
|---|---|---|---|---|---|
| `claude_real_25aa1534_prefix.jsonl` | Claude Code | `/Users/operator/ClaudeProfiles/claudecodex-profile/claude-config/projects/-Volumes-D-claude/25aa1534-d163-4f09-a3eb-d0ff1d20dba5.jsonl` (this session's own log) | 60 | ~156KB | First 60 rows of this very Claude session; mixed user + assistant + tool_use + tool_result + queue-operation meta |
| `codex_real_019fbc85_prefix.jsonl` | Codex CLI | `/Users/operator/.codex/archived_sessions/rollout-2026-08-01T14-21-48-019fbc85-bbe9-79c3-a781-b726d94fdc36.jsonl` | 101 | ~331KB | Real archived Codex rollout with `session_meta`, `response_item/message`, `response_item/function_call`, `response_item/function_call_output`, `response_item/custom_tool_call`, `response_item/custom_tool_call_output`, and `response_item/reasoning` (private-reasoning flag exercised) |

Both files were produced by an actual host, not synthesized. They are checked
into the repo so the test never reads a live session file that the harness or
the user is still appending to.

## Refreshing

When the parser is upgraded in a way that legitimately changes event ids
(prefix-digest, span, kind, or payload fingerprint), the prefix digest in the
frozen prefix receipt changes for both fixtures. Regenerate by re-running
whatever extraction step produced these files (see git history of this
folder) and re-verify the contract tests stay green.

Do not edit the fixtures by hand — that would decouple the contract from
reality.