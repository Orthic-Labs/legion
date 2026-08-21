# Delivery Deficit

```yaml
schema: delivery-deficit.v1
deficit_id: DD-1
origin_acceptance_id: AC-1
kind: optional_gap
severity: follow_up
status: open
owner: <named owner>
accepting_authority: <required for accepted status or accepted_risk>
affected_tasks: []
affected_claim_levels: [<prohibited claim level>]
missing_or_degraded_behavior: <precise behavior>
workaround: <if any>
evidence: []
trigger: <revisit trigger>
expiry: <expiry or review condition>
downstream_acknowledgements:
  - step_id: <consumer step>
    debt_refs: [DD-1]
    failure_refs: []
    disposition: compatible # compatible | workaround | blocked | replan
    rationale: <why downstream claim remains bounded>
```

Deficits preserve downstream claim ceilings. A required acceptance failure, safety, privacy, security, correctness, data-integrity, legal constraint, missing evidence, or missing authority cannot become accepted debt.
