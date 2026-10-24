---
name: guard
---

# Guard — deterministic effect and safety enforcement

The Guard is the deterministic effect boundary for Legion. It answers one
question:

> **May this typed effect proceed under the applicable policy?**

The current seed is the `legion-hook` binary. It receives host hook frames,
classifies pre-effect requests, applies hard safety gates, loads a validated
native policy, and returns a typed allow, ask, or deny response. The Guard is a sibling
of the Arcane cognitive plane, not a lower-level implementation of Arcane.

## Definition

> **The Guard is a fail-closed, deterministic adapter between host hook events
> and effect policy.**

It owns effect classification, policy matching, approval-boundary refusal,
hard safety refusals, enforcement-health reporting, and effect-decision
receipts when that receipt path is implemented.

The Guard does not interpret user intent, choose capabilities, attach Sage,
Alchemist, or Oracle, decompose work, supervise subagents, route cognition, or
shape the final response. Legion owns capability selection, authority attachment,
& orchestration; Arcane owns cognitive processing & response policy.

Arcane may describe the processing topology of a request, but it cannot
authorize an effect. A route envelope is ephemeral and is not a Guard
receipt.

## Guard and Arcane

```text
ARCANE
  how should this request be processed?
       |
       v
LEGION / HOST
  what work and typed effects exist?
       |
       v
GUARD
  may this effect proceed under deterministic policy?
```

Arcane keeps no receipts for its cognitive route. Effect decisions are a
Guard concern and must not be represented as Arcane cognitive evidence.

## Seed implementation

`engine/bins/legion-hook/src/main.rs` is the current Guard seed. Its dispatch
order is bounded and deterministic:

1. parse and validate the versioned host frame;
2. acknowledge lifecycle and post-effect observations;
3. reject unsupported event shapes;
4. apply hard gates for destructive commands and rewrite pushes (force pushes to
   the default branch are rewrites and stay denied);
5. apply the hook-v2 gates (see Hook v2 gates): the `Agent`/`Task` model
   ceiling, hook-bypass denials, and the confirmations for merging and for
   pushing the default branch;
6. construct and validate a typed `EffectRequest`;
7. load the native application and its policy;
8. authorize the effect through `NativeApplication::authorize_hook`.

A pre-effect request is never allowed merely because classification or policy
loading failed. The failure response is a denial.

The native application can receive a versioned JSON configuration inline or
from the path named by `LEGION_NATIVE_APPLICATION_CONFIG`. If that variable is
unset, `default_for_repository` builds the canonical default application. A
configured application replaces the default composition in this seed; policy
artifacts are not merged here.

## Hook event surface

Explicit reviewed-scope freezes use `legion-policy::frozen_scope` & native
`legion authority freeze` broker. Protected host enrollment & broker-launched
reviews supply authority; hashes, caller JSON & hook actor labels do not. Consult
[broker boundaries](../docs/architecture/frozen-scope-broker.md) before claiming
installed delivery coverage. Hooks remain early effect feedback, not universal
mutation interception or publication authorization.

`hooks/hooks.json` currently invokes `legion-hook` for:

| Event | Current registration | Current Guard treatment |
| --- | --- | --- |
| `SessionStart` | `startup`, `resume`, `clear`, `compact` | acknowledge as lifecycle, and inject the hand-maintained `SESSION_START_CONTEXT` routing/scope/gate text as additional context (`engine/bins/legion-hook/src/main.rs`); that text must stay in step with `AGENTS.md` (a test pins the shared gate keywords). Inside a workspace (a `tools/setup-workspace.py` above the session cwd, with `docs/agent-rules/` or `decisions.md` beside `tools/`) it also runs `setup-workspace.py --check`, bounded to seven seconds, and adds its result to the context and the operator message |
| `SubagentStart` | all | acknowledge as lifecycle |
| `SubagentStop` | all | acknowledge as lifecycle |
| `UserPromptSubmit` | all | acknowledge as lifecycle; record HEAD and a working-tree digest as the turn baseline, so Stop can tell a shell edit from a conversational turn |
| `PostCompact` | `manual`, `auto` | acknowledge as lifecycle |
| `PreToolUse` | shell, command, file-edit, patch, `Agent`, `Task`, & `mcp__*` tools | classify typed effects & authorize; allow MCP reads as observations; apply the hook-v2 gates |
| `PostToolUse` | the pre-effect tools plus `WebFetch` & `WebSearch` | acknowledge as post-effect |
| `PostToolUseFailure` | the same post-effect matcher | acknowledge as post-effect |
| `Stop` | all | deliver response policy and verify proportionally; hold a turn that changed the repository and claims completion without objective evidence (Stop evidence gate) |

The binary also accepts the lower-case protocol aliases `session-start`,
`subagent-start`, `subagent-stop`, `user-prompt-submit`, `post-compact`, `pre-effect`,
`post-effect`, `post-effect-failure`, and `stop`, plus `ci-boundary`.
Those aliases are protocol support; they are not additional registrations in
`hooks/hooks.json`.

Lifecycle and post-effect acknowledgements are not effect authorization. The
`Stop` path does not infer unfinished work from assistant wording or block prose.
Arcane response policy cannot create Stop re-prompt loops. Stop completion
verification is proportional: it consults a typed verification requirement and
checks the `oracle-completion-validation-v1` receipt only when that requirement
demands one, rather than treating any file write as grounds for mandatory
assurance. The one other Stop denial is the evidence gate below, which reads
tool results and never wording as evidence. `SubagentStop` is registered as lifecycle observation. `mcp__*`
write/send/delete tools map to `EXTERNAL_SIDE_EFFECT`, which asks (see
Approval boundary); known read-only MCP tools are `MCP_KNOWN_OBSERVATION` and
other MCP reads remain unclassified observations.

The current hook surface deliberately does not treat `Task` or `Agent`
dispatch as an effect class. Dispatch is Legion orchestration; the
subagent's own effects are guarded inside its session. A launch is still
gated on the one thing it chooses, the model (Subagent model ceiling below).

## Effect classification

`legion-contracts::EffectClass` is the runtime effect vocabulary (the semantic names used in SKILL `effects:` map onto it in `docs/LEGION-CANONICAL-SSOT.md` section 7):

```text
FILE_WRITE          FILE_DELETE          FILE_MOVE
COMMAND_EXEC        NETWORK_EGRESS       PROCESS_SPAWN
CREDENTIAL_ACCESS   DEPENDENCY_INSTALL   VCS_COMMIT
VCS_PUSH            PUBLISH              EXTERNAL_SIDE_EFFECT
MCP_UNCLASSIFIED_OBSERVATION  MCP_KNOWN_OBSERVATION
```

`parse_effect_class` gives an explicit `effectClass` or `effect_class`
precedence. It normalizes case, hyphens, spaces, and slashes and accepts the
implemented aliases such as `WRITE`, `DELETE`, `SHELL`, `NETWORK`, `PUSH`, and
`PUBLISH`. An unknown explicit class is not guessed.

Without an explicit class, the seed maps:

```text
Write, Edit, MultiEdit, NotebookEdit  → FILE_WRITE
WebFetch, WebSearch                   → NETWORK_EGRESS
shell, shell_command, Bash,
PowerShell, apply_patch               → command classification
any payload with a command             → command classification
```

Command classification recognizes adjacent token pairs in command segments:

```text
 git push       → VCS_PUSH
 git commit     → VCS_COMMIT
 npm install/ci, pnpm install/add,
 yarn install/add, cargo install/add  → DEPENDENCY_INSTALL
 otherwise                           → COMMAND_EXEC
```

The command scan separates shell segments at `;`, `&`, `|`, and newlines; it
is not a shell parser. A command or tool that supplies neither a recognized
class nor a recognized command cannot construct an effect and is denied as an
invalid host event. The Guard must not claim a stronger classification than
its parser established.

The adapter derives an effect target from explicit effect/source/payload
fields, then from `tool_input` fields (`file_path`, `path`, `url`, or `query`),
and finally from the command. It derives an operation from explicit fields,
then the tool name, then the class default (`write`, `delete`, `move`,
`execute`, `connect`, `spawn`, `access`, `install`, `commit`, `push`, or
`publish`). Request identity and source revision are also required before a
policy decision.

## Canonical default policy

The canonical default is a built-in `PolicyPack` returned by
`canonical_default_policy_pack`. It is always present in the normal installed
path: an unset `LEGION_NATIVE_APPLICATION_CONFIG` selects it, rather than
meaning that policy is absent.

Ambient permission is an explicit policy decision, never the absence of a
rule. The baseline explicitly allows ordinary reversible effects:

```text
FILE_WRITE       allow
FILE_MOVE        allow
VCS_COMMIT       allow
COMMAND_EXEC     allow
```

It also explicitly allows `PUBLISH`, `VCS_PUSH`, `DEPENDENCY_INSTALL`,
`NETWORK_EGRESS`, `PROCESS_SPAWN`, `MCP_KNOWN_OBSERVATION`, and
`MCP_UNCLASSIFIED_OBSERVATION` (the host's own permissions still apply). The
canonical pack has exactly two classes the policy refuses:

```text
CREDENTIAL_ACCESS      deny (hard denial)
EXTERNAL_SIDE_EFFECT   not grantable by policy; the hook answers "ask"
```

The policy matcher requires the effect class and matches both `targets` and
`operations` by exact value or `"*"`. Any matching deny wins. No matching
rule denies; an approval requirement or a request marked
`approval_required` also denies. Trust or enforcement requirements that the
native policy boundary cannot supply deny rather than being ignored.

The baseline policy is validated while the default native application is
built. A configured policy is validated as part of the complete versioned
application configuration. A malformed, empty, unreadable, or otherwise
unbuildable configuration therefore cannot fall through to ambient allow.

## FILE_DELETE discrimination

`FILE_DELETE` is not a sufficient safety decision by itself. A bounded source
file removal during a refactor is materially different from a recursive,
forceful, broad, or protected-target deletion.

The policy schema therefore matches both target and operation. The canonical
pack has:

- an explicit ordinary `FILE_DELETE` allow rule with `operations: ["*"]`;
- an explicit deny rule for `delete-recursive`, `delete-force`, and
  `delete-broad`.

The ordinary rule makes bounded deletion an explicit ambient policy decision;
the narrow deny rule wins for a matching destructive operation. The current
adapter defaults an explicit `FILE_DELETE` request to operation `delete`, or
preserves a supplied operation. Raw shell `rm` is currently classified as
`COMMAND_EXEC`, and recursive/broad shell deletion is hard-gated before policy
matching. Emitting the reserved operation tags from a delete-specific adapter
path is future work.

The target/operation distinction must remain in policy. Replacing it with a
class-wide delete approval would incorrectly require approval for every
ordinary refactor deletion; replacing it with a wildcard allow would erase the
safety boundary.

## Hard safety gates

Before policy authorization, the seed denies recognized destructive command
shapes, including recursive `rm`, recursive `Remove-Item`, `git clean`,
`dropdb`, Terraform apply/destroy forms, and a curl-to-shell pipeline. A
`git push` containing rewrite or delete flags (`--force`, `--delete`, `-f`, or
`-d`) is denied as approval-required, including a force push to the default
branch. These are deterministic refusals, not model judgments and not policy
fallbacks.

## Approval boundary

The Guard has three pre-effect outcomes: allow, ask, and deny.

- **Allow** is granted only by a matching policy rule.
- **Ask** hands the decision to the host permission prompt, which shows the
  exact tool and arguments and is answered by the user. On Claude Code the hook
  emits PreToolUse `hookSpecificOutput.permissionDecision: "ask"` with a reason
  naming the tool and target (code `ARC_USER_CONFIRMATION_REQUIRED`). The hook
  never emits `"allow"` for these effects and holds no approval store: it
  declines to grant, it does not record consent. Codex has no ask outcome, so
  the same response is a denial there (exit 2). An authenticated Sage or Oracle
  actor never receives ask; its external effects stay denied.
- **Deny** is a hard refusal: destructive command shapes, rewrite pushes,
  hook bypasses, subagent launches above the model ceiling,
  `CREDENTIAL_ACCESS`, role-restricted effects, and every classification,
  policy, or configuration failure.

Classes that ask:

- Merging and the default branch (hook v2, code `ARC_USER_CONFIRMATION_REQUIRED`):
  `gh pr merge`, a `gh api` call that PUTs or POSTs a `/merge` or `/merges`
  endpoint, a GraphQL `mergePullRequest` mutation, and a `git push` whose
  destination is the repository's default branch (the branch the remote's
  `HEAD` names, plus `main` and `master`). A bare `git push` asks only while the
  default branch is the checked-out branch; a dry run never asks. The
  repository is the one the command runs in, following `cd` and `git -C`.
- `EXTERNAL_SIDE_EFFECT`: a third-party MCP tool whose name or explicit
  operation identifies a write, send, or delete (leading verbs such as
  `create`, `update`, `delete`, `send`, `post`, `run`, `set`).
- Scheduled-task mutators (`mcp__scheduled-tasks__create_scheduled_task`,
  `update_scheduled_task`, `delete_scheduled_task`, `run_scheduled_task`):
  standing local configuration. `list_scheduled_tasks` and `list_task_runs`
  are known read-only observations.
- A short exact list of first-party host-security tools: `set_session_permission_mode`,
  `set_setting`, `set_auto_merge`, `delete_session`, and `set_remote_control`
  under `mcp__ccd_*`. The rest of the first-party `mcp__ccd_*` and
  `mcp__Claude_Browser__*` namespace stays host dispatch (`COMMAND_EXEC`),
  including cross-session `send_message`.

Whether a hook `ask` still prompts under `bypassPermissions` is not stated in
the Claude Code documentation; verify on the installed build before relying on
it. A policy rule that requires a non-`None` approval, or a request marked
`approval_required`, still fails closed in the native policy adapter; the
`ask` path exists only for `EXTERNAL_SIDE_EFFECT`. A target-bound approval
store is not implemented.

## Hook v2 gates

These run in `PreToolUse` after the destructive and rewrite gates and before
effect classification. Each judges the simple command the shell would run, after
unwrapping `bash -c`, `sudo`, `env`, and `xargs`; a quoted mention (a commit
message that says `--no-verify`) is one word and never matches.

**Hook bypass (deny, `ARC_HOOK_BYPASS_DENIED`).** The repository hooks are the
gate, so these are refused on every platform:

- `--no-verify` (or an unambiguous abbreviation of at least `--no-ve`) on
  `git commit`, `push`, `merge`, `am`, `rebase`, and `pull`, and `git commit -n`,
  alone or bundled (`-anm`);
- any `git config` that sets, adds, or unsets `core.hooksPath` (reads are
  allowed), `git -c core.hooksPath=...`, `git --config-env=core.hooksPath=...`,
  `GIT_CONFIG_KEY_<n>=core.hooksPath`, and `GIT_CONFIG_PARAMETERS` naming it;
- a file-tool or shell write to a git configuration file (`.git/config`,
  `.gitconfig`, `config.worktree`) that mentions `hooksPath`;
- hook-bypass environment in any shell form (`NAME=value`, `export`, `env`,
  `set`, `$env:`): `HUSKY=0`, `LEFTHOOK=0`, `SKIP=` on a hooked git command, and
  any variable whose name says it skips, disables, bypasses, or excludes hooks
  with a truthy value.

Deleting or rewriting `.githooks` itself is not covered here; the committed
hook is also run by CI.

**Merge and default branch (ask).** See Approval boundary.

### Subagent model ceiling

`src/config/model-tiers.json` is the only place model names live. Its
`subagents` block names the host, the tier order, the ceiling tier
(`balanced-executor`), the default tier (`mechanical-cheap`), and the approval
marker. The hook resolves those tiers to the host's model ids at run time, so
the rule cannot drift from the map; `legion-dev check-authority-parity` holds
each `agents/<role>.md` model equal to its tier's model.

For an `Agent` or `Task` launch the effective model is the `model` the launch
names, else the model of the packaged agent card its `subagent_type` names, else
the default tier's model. A model string is read as a list of names (whitespace,
commas, semicolons, `|`, `+`, `&`, parentheses and quotes divide them). Every
name must match a tier, so one unrecognised name makes the whole string unknown,
and a string naming several known models is judged by the strongest.

- At or under the ceiling: allowed as requested.
- No model and no packaged card: allowed with the default tier's model filled
  in through `hookSpecificOutput.updatedInput` (the whole input, with
  `permissionDecision: "allow"`; the host's own deny and ask rules still apply).
- Above the ceiling, unknown, or `inherit`: denied with
  `ARC_MODEL_CEILING_EXCEEDED`, unless the launch prompt carries a line
  `operator-approved-model: <that model>`. The marker is for a model the
  operator named in the live turn; it binds to the one model it names.

The `frontier-judgment` tier (Sage, Oracle) resolves to the ceiling model on
Claude Code; the `deliberation` tier (Council seats) ranks above it, so a seat
launched through `Agent` carries the marker (the Council skill runs its seats
through the CLI, not `Agent`). The rule is stated for agents in
`skills/dispatch/references/agent-routing.md`.

### Stop evidence gate

A `Stop` is held, once per reopening and at most three times per turn
(`MAX_STOP_REOPENINGS`), when all of these hold:

1. the turn changed the repository: its transcript shows an edit tool or a
   head-moving git command (`commit`, `merge`, `rebase`, `reset`, `checkout`,
   ...), or the working-tree digest differs from the one recorded at
   `UserPromptSubmit`;
2. the final message claims completion (done, fixed, shipped, passed, ...) and
   is not an honest partial (not done, not verified, blocked, partial, ...);
3. no objective evidence follows the last change. Evidence is read from the
   turn's tool results, never from assistant wording:
   - the gate's own green line (`<label>: <sha> passed <n> rules ...`) printed by
     a `right-release check` or `rightkit-gate check` command (or, until
     `rightkit-gate check` ships, `node scripts/preflight.mjs`, which takes no
     subcommand) that did not error, naming the current HEAD;
   - a CI run URL (`.../actions/runs/<id>`) in a tool result that also cites the
     current HEAD and a success marker with no failure marker;
   - a host receipt block: a JSON object with an id, a verifying command
     (`check`, `test`, `build`, `clippy`, `nextest`), and exit code 0.

The denial is `ARC_COMPLETION_EVIDENCE_MISSING`. A turn with no repository
change, an honest "not verified", and a transcript the gate cannot read all
pass: the gate fails open on missing instrumentation and never invents a
requirement from wording. The word "passed" in a test run is not evidence, and
neither is an Oracle verdict.

## Fail closed and enforcement health

The Guard has two separate obligations:

1. **Fail closed:** no classification, policy, identity, or configuration
   failure may authorize the effect.
2. **Report honestly:** `enforcementHealth` must describe the enforcement
   actually available, not merely accompany a denial.

The hook response is schema-versioned and includes `allowed`, `code`,
`reason`, and `enforcementHealth`. The seed returns `allowed: false` for
malformed frames, unsupported events, missing effect data, policy denial, and
native-policy failures. `HookResponse` uses `unsupported` for I/O &
serialization failures; ordinary validated decisions are labelled `strong`.

The `native_application` failure branch returns
`ARC_NATIVE_POLICY_UNAVAILABLE` with health `unsupported`. It fails closed
without claiming strong enforcement; a focused regression test pins this
label.

Codex bridges invoke installed stable `current/bin/legion-hook --host codex`.
This native transport emits Codex context output & exit 2 for Guard denials
and for ask-class effects (Codex has no ask outcome);
default transport retains its versioned response envelope. Accepted Stop events
may notify configured computer-use cleanup with bounded thread/turn identity &
a 500 ms deadline. Missing, stale, invalid, failed, or timed-out cleanup remains
diagnostic only: it never changes Guard's decision. Host bridges contain no
completion policy or notifier implementation.

## Receipts

Receipt ownership is deliberately split:

```text
Guard   → effect decisions, policy outcomes, and enforcement receipts
Arcane  → ephemeral cognitive route; no receipts
```

The current `legion-hook` protocol emits a decision response envelope. It does
not yet include or persist a dedicated effect receipt. The M1 application has
separate typed policy and invocation receipt structures, but those are not a
receipt emitted by the hook dispatch path. A complete Guard receipt—bound to
the request, effect class, target, operation, policy identity, decision,
enforcement health, and source revision—is future work. It must remain a Guard
artifact and must never be replaced by an Arcane route trace.

## Current boundary and future work

The current Guard is deterministic and local: it parses JSON, reads native
configuration and repository metadata needed for the request, matches policy,
and returns a host-compatible response. It does not run a model or shell to
make an authorization decision.

Future Guard work includes:

- a target-bound approval flow for the rewrite-push gate, which still returns
  a hard denial that tells the operator to approve it;
- emitting and retaining effect receipts;
- wiring operation-specific destructive `FILE_DELETE` classification; and
- fuzzing/property-testing malformed, nested, oversized, Unicode, shell,
  path, multi-target, and unknown-class inputs before broadening coverage.

These additions must preserve the boundary: deterministic effect enforcement
may refuse or authorize a typed effect, but it must not become a cognitive
router, a task planner, or a ceremony layer.

## Guard invariants

1. Missing or invalid policy never means ambient allow.
2. Ambient permission is always an explicit matching policy decision.
3. A denial is not approval, and denial never falls through to another
   executor or model. An ask is not approval either: the hook never emits
   allow for an effect it asked about.
4. `FILE_DELETE` decisions discriminate target and operation, not class alone.
5. Unsupported classification is denied and never reported as strong
   authorization.
6. Guard receipts belong to the Guard; Arcane keeps no receipts.
7. Lifecycle acknowledgement is not pre-effect authorization.
8. The Guard does not gate Legion's orchestration dispatch as an effect.
9. Safety enforcement remains deterministic, bounded, and independently
   testable.
