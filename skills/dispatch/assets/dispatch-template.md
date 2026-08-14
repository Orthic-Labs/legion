# Dispatch packet

## Objective & authority

- Objective:
- Authority source:
- Integration owner:
- State A / State B:

## Scope

- OWN:
- READ:
- FORBIDDEN:
- Dependencies:
- Acceptance:

## Procedure

| Step | cwd | Action | Expected result | Evidence | Recovery |
|---|---|---|---|---|---|
| 1 |  |  |  |  |  |

## Failure recovery

| Class | Detect | Bounded recovery | Escalate when |
|---|---|---|---|
| path/input missing |  |  |  |
| tool/dependency missing |  |  |  |
| auth/permission |  |  |  |
| transient external |  |  |  |
| invalid schema |  |  |  |
| integrity/hash mismatch |  |  |  |
| deterministic command |  |  |  |
| dirty/conflicting state |  |  |  |
| wrong producer/provenance |  |  |  |
| resource/capacity |  |  |  |
| ambiguous requirement |  |  |  |
| unsafe/out-of-scope |  |  |  |
| unknown failure |  |  |  |

## Evidence & return

- Validator: `python3 tools/skills/legion/skills/dispatch/scripts/validate-dispatch.py <packet> --write-receipt <receipt>`
- Receiver check: `python3 tools/skills/legion/skills/dispatch/scripts/validate-dispatch.py <packet> --verify-receipt <receipt>`
- Return: `STATUS: COMPLETE | COMPLETE_WITH_NOTES | TRUE_BLOCKER`; include acceptance, artifacts, commands, recovery, & next integration action.
