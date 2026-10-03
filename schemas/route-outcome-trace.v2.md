# Role adoption trace v2

V2 adds `roleDecisions` to v1's route/outcome record. New readers accept v1 & v2;
old strict v1 readers reject v2. Deploy compatible readers before enabling v2
writers. V1 serialization & canonical digests remain unchanged. Missing role
data emits v1; malformed supplied data emits no trace, never a false v1 fallback.

Legion selects authority above Dispatch from `src/roster/*` triggers. Host/lead
observations supply decisions; hooks never infer authority from tool names,
effects, worker labels, or prose. Each role appears at most once per record:

| State | Evidence |
| --- | --- |
| `selected` | Lead chose role; launch remains unconfirmed. |
| `bound` | Host registration/configuration resolved; launch remains unconfirmed. |
| `launched` | Host accepted role launch. This alone proves no outcome correctness. |
| `skipped` | Explicit non-launch decision with nonblank reason. |

`eligible` is an independent label: true, false, or unknown (null/absent).
Any state permits any label, so unnecessary launches remain measurable.
Fold append-ordered lifecycle updates by request ID + role; latest valid
observation wins. Reject invalid whole records. Legacy v1 provides no role
label & contributes no invented skip.

Adoption rate = eligible launches / observed labelled eligible request-role
pairs. Zero denominator returns `NotEnoughData` in hook metrics & null in replay
reports. Unnecessary launches have false labels; unknown launches have absent
labels. Eligible skips, pending selections & pending bindings stay separate.
Missing replay cases & unobserved decisions fail coverage; they never become
fabricated skips. Read coverage alongside adoption rate. Outcome counts report
recorded classifications, not independent semantic correctness.

Run `legion-dev evaluate-authority-replay --observations <recorded-observations.jsonl>`
against default `src/evals/architecture/authority-adoption.jsonl`, or pass
`--cases <labelled-cases.jsonl>`. Independent case labels override producer
self-labels. Unknown case IDs, duplicate trace IDs, invalid schemas & request
IDs shared across cases fail validation. Capture actual lead/host observations
using case IDs before evaluating prompt adaptation.

`authority-adoption-observations.jsonl` contains synthetic reference decisions
plus a sanitized observed Sage model-gate rejection/retry. It verifies grader
semantics; it does not claim an agent ran every reference prompt. Positive &
negative cases cover explicit requests, material conflict, ambient work,
controlled execution, concrete risk, pending binding & unknown eligibility.

Before changing triggers, compare identical labelled cases against observed
before/after runs. Improve missed eligible requests without increasing
unnecessary authority. Registration checks never substitute for host launch
evidence. Native Codex file/model precedence follows [OpenAI configuration
rules](https://learn.chatgpt.com/docs/config-file/config-basic) & [subagent
configuration](https://learn.chatgpt.com/docs/agent-configuration/subagents).
