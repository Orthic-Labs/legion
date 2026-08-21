# Review module contract

```yaml
schema: review-module-contract.v1
module_id: <id>
module_version: '1'
when_to_use: [<material trigger>]
when_not_to_use: [<negative scope>]
configured_scope: <scope>
eligibility_filter: <filter>
admission_gates: [process, reachability, control, real_impact, reproduction, bounds, environment]
first_failed_gate_dismisses: true
claim_language_policy: <scoped claims only>
remediation_proportionality_check: <check>
clean_claim: { meaning: configured_gates_passed, scope_binding: <scope>, state_binding: <state>, freshness_binding: <freshness> }
calibration_table_version: '1'
```
