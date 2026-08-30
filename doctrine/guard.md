---
name: guard
---

# Guard — deterministic effect and safety enforcement

The Guard is the deterministic effect boundary for Legion. It answers one
question:

> **May this typed effect proceed under the applicable policy?**

The current seed is the `legion-hook` binary. It receives host hook frames,
classifies pre-effect requests, applies hard safety gates, loads a validated
native policy, and returns a typed allow/deny response. The Guard is a sibling
of the Arcane cognitive plane, not a lower-level implementation of Arcane.

## Definition

> **The Guard is a fail-closed, deterministic adapter between host hook events
> and effect policy.**

It owns effect classification, policy matching, approval-boundary refusal,
hard safety refusals, enforcement-health reporting, and effect-decision
receipts when that receipt path is implemented.

The Guard does not interpret user intent. It does not choose capabilities,
route cognition, attach Sage, Alchemist, or Oracle, decompose work, supervise
subagents, or shape the final response. Those concerns belong to Arcane,
Legion, the host, or the relevant authority.

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
4. apply hard gates for destructive commands and rewrite pushes;
5. construct and validate a typed `EffectRequest`;
6. load the native application and its policy;
7. authorize the effect through `NativeApplication::authorize_hook`.

A pre-effect request is never allowed merely because classification or policy
loading failed. The failure response is a denial.

The native application can receive a versioned JSON configuration inline or
from the path named by `LEGION_NATIVE_APPLICATION_CONFIG`. If that variable is
unset, `default_for_repository` builds the canonical default application. A
configured application replaces the default composition in this seed; policy
artifacts are not merged here.

## Hook event surface

`hooks/hooks.json` currently invokes `legion-hook` for:

| Event | Current registration | Current Guard treatment |
| --- | --- | --- |
| `SessionStart` | `startup`, `resume`, `clear`, `compact` | acknowledge as lifecycle |
| `SubagentStart` | all | acknowledge as lifecycle |
| `UserPromptSubmit` | all | acknowledge as lifecycle |
| `PostCompact` | `manual`, `auto` | acknowledge as lifecycle |
| `PreToolUse` | shell, command, file-edit, and patch tools | classify and authorize |
| `PostToolUse` | the pre-effect tools plus `WebFetch` and `WebSearch` | acknowledge as post-effect |
| `PostToolUseFailure` | the same post-effect matcher | acknowledge as post-effect |
| `Stop` | all | acknowledge as lifecycle |

The binary also accepts the lower-case protocol aliases `session-start`,
`subagent-start`, `user-prompt-submit`, `post-compact`, `pre-effect`,
`post-effect`, `post-effect-failure`, and `stop`, plus `ci-boundary`.
Those aliases are protocol support; they are not additional registrations in
`hooks/hooks.json`.

Lifecycle and post-effect acknowledgements are not effect authorization. In
particular, the current `Stop` path does not perform completion verification
or cognitive ending-shape policy. That is future work at the Arcane/host
boundary. `SubagentStop` is not currently registered or accepted; adding it
for observation and receipting is tracked future work. `mcp__*` write, send,
and delete tools are also not currently matched; widening that surface must
be accompanied by matching classifier arms.

The current hook surface deliberately does not treat `Task` or `Agent`
dispatch as an effect class. Dispatch is Legion orchestration; the
subagent's own effects are guarded inside its session.

## Effect classification

`legion-contracts::EffectClass` is the canonical effect vocabulary:

```text
FILE_WRITE          FILE_DELETE          FILE_MOVE
COMMAND_EXEC        NETWORK_EGRESS      PROCESS_SPAWN
CREDENTIAL_ACCESS   DEPENDENCY_INSTALL  VCS_COMMIT
VCS_PUSH            PUBLISH
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

It explicitly denies by default:

```text
CREDENTIAL_ACCESS   deny
PUBLISH              deny
VCS_PUSH             deny
DEPENDENCY_INSTALL  deny
NETWORK_EGRESS      deny
PROCESS_SPAWN       deny
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
`-d`) is denied as approval-required. These are deterministic refusals, not
model judgments and not policy fallbacks.

## Approval boundary

The contracts contain `ApprovalRequirement`, but the hook adapter currently
has no target-bound approval store or approval flow. The canonical reserved
classes therefore deny until that flow exists. A request that asks for
approval is not converted into an allow, and a policy rule that requires a
non-`None` approval is refused by the native policy adapter.

Implementing target-bound user or authority approval is future work. Until
then, denial is the only honest result for reserved or approval-required
effects.

## Fail closed and enforcement health

The Guard has two separate obligations:

1. **Fail closed:** no classification, policy, identity, or configuration
   failure may authorize the effect.
2. **Report honestly:** `enforcementHealth` must describe the enforcement
   actually available, not merely accompany a denial.

The hook response is schema-versioned and includes `allowed`, `code`,
`reason`, and `enforcementHealth`. The seed returns `allowed: false` for
malformed frames, unsupported events, missing effect data, policy denial, and
native-policy failures. `HookResponse` uses `unsupported` for I/O and
serialization failures; ordinary validated decisions are labelled `strong`.

There is a current honesty defect: the `native_application` failure branch
returns `ARC_NATIVE_POLICY_UNAVAILABLE` with health `strong`, even though the
policy boundary was unavailable. This still fails closed, but the health
label is too strong. Correctly distinguishing unavailable/degraded
enforcement from strong enforcement is future remediation; no consumer may
interpret a strong label as proof that a missing baseline was safely loaded.

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

- correcting enforcement-health labels when the policy baseline is
  unavailable;
- completing target-bound approval flow, while keeping reserved classes
  denied until it is real;
- emitting and retaining effect receipts;
- adding `mcp__*` write/send/delete coverage with classifier support;
- adding `SubagentStop` observation/receipting;
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
   executor or model.
4. `FILE_DELETE` decisions discriminate target and operation, not class alone.
5. Unsupported classification is denied and never reported as strong
   authorization.
6. Guard receipts belong to the Guard; Arcane keeps no receipts.
7. Lifecycle acknowledgement is not pre-effect authorization.
8. The Guard does not gate Legion's orchestration dispatch as an effect.
9. Safety enforcement remains deterministic, bounded, and independently
   testable.
