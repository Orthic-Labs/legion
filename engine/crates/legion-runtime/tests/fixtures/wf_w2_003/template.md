# EXTERNAL REVIEW PACKET — {{SHORT_TITLE}}

## 0. Packet Control

- **Created:** {{ISO_8601_TIMESTAMP}}
- **Mode:** PACKET_ONLY — DO_NOT_RUN_COVENANT
- **Audience:** {{THIRD_PARTY_AGENT_OR_REVIEWER}}
- **Packet path:** {{ABSOLUTE_PATH_OR_INLINE}}
- **Requested response:** {{DIAGNOSIS_DESIGN_REWRITE_OR_REVIEW}}

## 1. Problem in Plain Language

{{SIMPLE_CONTEXT_COMPLETE_PROBLEM_DESCRIPTION}}

## 2. User Intent

### Exact request

> {{USER_WORDS_VERBATIM}}

### Desired outcome

{{CONCRETE_END_STATE}}

### Definition of success

{{OBSERVABLE_SUCCESS_CRITERIA}}

## 3. What Went Wrong

| Failure | Exact symptom/evidence | Consequence |
|---|---|---|
| {{FAILURE}} | {{RAW_ERROR_QUOTE_OR_ARTIFACT_EXCERPT}} | {{IMPACT}} |

## 4. Current System & State

{{MINIMUM_ARCHITECTURE_WORKFLOW_OR_DOCUMENT_STATE_NEEDED_TO_REASON_CORRECTLY}}

## 5. Constraints & Invariants

- {{MUST_PRESERVE}}
- {{MUST_NOT_DO}}
- {{AUTHORITY_OR_SAFETY_BOUNDARY}}

## 6. Existing Attempts & Inputs

| Attempt/input | Result | Keep, reject, or reconsider |
|---|---|---|
| {{ATTEMPT_OR_OTHER_AGENT_PROPOSAL}} | {{OBSERVED_RESULT}} | {{DISPOSITION_OR_OPEN}} |

## 7. Evidence Bundle

Embed essential text, code, errors, schemas, or excerpts here. Do not rely on local-only path access.

```text
{{EVIDENCE}}
```

## 8. Known Unknowns

- {{UNKNOWN_AND_WHY_IT_MATTERS_OR_NONE}}

## 9. Questions for Reviewer

1. What is root cause?
2. What exact design or wording changes close it?
3. Which bypasses or failure paths remain?
4. What should be enforced mechanically rather than requested in prose?
5. Which recommendations are must-fix vs optional value additions?

## 10. Response Contract

Return:

1. concise diagnosis;
2. must-fix findings with evidence;
3. concrete proposed changes;
4. failure-path / bypass analysis;
5. optional value additions;
6. final verdict: `READY_TO_IMPLEMENT` or `REVISE_PACKET`.

Do not assume access to old chat, local filesystem, or unstated context.
