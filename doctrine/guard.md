---
name: guard
---

# Guard — the Stop decision

The Guard is the one deterministic enforcement point Legion keeps. It answers one
question:

> **May Claude stop working now?**

The seed is the `legion-hook` binary. It receives host hook frames, records
non-blocking context and evidence, and refuses a `Stop` only when a typed
verification requirement or the evidence ledger says the work is not finished.
The Guard is a sibling of the Arcane cognitive plane, not a lower-level
implementation of Arcane.

## Definition

> **The Guard is a deterministic adapter between the host `Stop` event and the
> verification decision.**

It owns the Stop decision, the evidence ledger Stop reads, and enforcement-health
reporting.

The Guard does not gate tool calls. Permissions for shell commands, git actions,
file writes, deletes, MCP tools and the rest live in the host's own settings and
configuration (Claude Code settings, Codex config), not in Legion. It does not
interpret user intent, choose capabilities, attach Sage, Alchemist, or Oracle,
decompose work, supervise subagents, route cognition, or shape the final
response. Legion owns capability selection, authority attachment, &
orchestration; Arcane owns cognitive processing & response policy.

## Guard and Arcane

```text
ARCANE   how should this request be processed?
LEGION   what work exists, and who does it?
GUARD    may Claude stop?
```

Arcane keeps no receipts for its cognitive route, and a route envelope never
satisfies a Guard decision.

## Seed implementation

`engine/bins/legion-hook/src/main.rs` dispatches in a bounded, deterministic
order:

1. parse and validate the versioned host frame;
2. for `Stop`, run the Stop decision (below);
3. for `UserPromptSubmit` and `SessionStart`, deliver context;
4. acknowledge every other lifecycle and post-tool observation.

A `PreToolUse` frame is accepted and acknowledged without a decision. Nothing
in Legion registers it.

## Hook event surface

`hooks/hooks.json` invokes `legion-hook` for:

| Event | Current registration | Current Guard treatment |
| --- | --- | --- |
| `SessionStart` | `startup`, `resume`, `clear`, `compact` | inject the hand-maintained `SESSION_START_CONTEXT` routing/scope text and the standing orders as additional context (`engine/bins/legion-hook/src/main.rs`); that text must stay in step with `AGENTS.md` |
| `SubagentStart` | all | acknowledge as lifecycle |
| `SubagentStop` | all | acknowledge as lifecycle |
| `UserPromptSubmit` | all | record the prompt and deliver standing orders added by other chats; open an evidence turn |
| `PostCompact` | `manual`, `auto` | acknowledge as lifecycle |
| `PostToolUse` | shell, file-edit, patch, `Skill`, `WebFetch`, `WebSearch` & `mcp__*` tools | append one evidence-ledger row |
| `PostToolUseFailure` | the same plus `Agent` & `Task` | append a failed evidence-ledger row |
| `Stop` | all | the Stop decision |

The binary also accepts the lower-case protocol aliases `session-start`,
`subagent-start`, `subagent-stop`, `user-prompt-submit`, `post-compact`,
`post-effect`, `post-effect-failure`, and `stop`, plus `ci-boundary`. Those
aliases are protocol support; they are not additional registrations in
`hooks/hooks.json`.

## The Stop decision

`Stop` blocks in three cases and no other:

1. **Typed verification requirement.** Stop never infers assurance from a
   mutation. A route or completion producer must set `verificationRequirement`;
   only the `oracle` requirement consumes a receipt, and that receipt
   (`oracle-completion-validation-v1`) must be a fresh PASS bound to the exact
   delivery digest and source revision. Missing, stale, unbound, or non-PASS
   receipts block (`ARC_VERIFICATION_REQUIRED`, `ARC_ORACLE_RECEIPT_INVALID`).
2. **Completion claim without evidence.** A completion claim (done, fixed, green,
   installed, live) with no matching successful command after the last edit in
   the evidence ledger blocks once per turn (`ARC_EVIDENCE_REQUIRED`).
3. **Incomplete approval request.** An `APPROVAL REQUEST` block that omits a
   field, cites no Class A run after the last edit, or carries no will-pass
   verdict blocks once (`ARC_APPROVAL_REQUEST_INCOMPLETE`).

Cases 2 and 3 start in shadow mode (they log would-blocks) and block once
switched to enforce. When `stop_hook_active` is set, or the re-entry cap is
reached, Stop does not block again, so the path never loops. After a block, the
turn may end with an `UNRESOLVED:` line that states what stays unproven. Arcane
response policy cannot create Stop re-prompt loops.

A non-blocking reminder is added once per session when files changed and the
final message cites no evidence; it never blocks.

## Fail closed and enforcement health

The hook response is schema-versioned and includes `allowed`, `code`, `reason`,
and `enforcementHealth`. A malformed frame, an unsupported event, or an I/O or
serialization failure returns `allowed: false`; hosts act on that only for
events they can block. Ordinary validated decisions are labelled `strong`; I/O &
serialization failures are labelled `unsupported`.

Codex bridges invoke installed stable `current/bin/legion-hook --host codex`.
This native transport emits Codex context output & exit 2 for a refused `Stop`;
default transport retains its versioned response envelope. Accepted Stop events
may notify configured computer-use cleanup with bounded thread/turn identity &
a 500 ms deadline. Missing, stale, invalid, failed, or timed-out cleanup remains
diagnostic only: it never changes Guard's decision.

## Receipts

The `legion-hook` protocol emits a decision response envelope and appends
non-blocking route-outcome and child-lifecycle trace lines. It does not emit a
dedicated effect receipt, because it no longer decides effects. A Guard artifact
must never be replaced by an Arcane route trace.

## Guard invariants

1. Stop never infers assurance from a mutation; only an explicit typed
   requirement demands an Oracle receipt.
2. A refused Stop is deterministic and bounded; it never loops.
3. The Guard does not gate tool calls or Legion's orchestration dispatch;
   permissions belong to the host's settings.
4. Guard receipts belong to the Guard; Arcane keeps no receipts.
5. Evidence and context events observe and never block.
