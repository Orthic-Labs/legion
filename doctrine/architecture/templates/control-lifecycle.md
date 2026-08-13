# Control Lifecycle Record

```yaml
schema: architecture-control-lifecycle.v1
control_id: <stable ID>
status: ACTIVE # PROPOSED | ACTIVE | DEPRECATED | RETIRED | SUPERSEDED
canonical_owner: <named owner>
rationale: <purpose & scope>
live_acceptance_or_safety_obligations: []
live_consumers: []
replacement_or_supersession: <replacement reference>
migration_plan: <migration reference>
schema_eval_metric_doc_updates: []
retirement_evidence: []
conformance_result: OPEN # RETIRED/SUPERSEDED require PASS
changed_at: <RFC3339 timestamp>
```

`DEPRECATED` is transitional. `RETIRED` or `SUPERSEDED` requires migration, no live obligations or consumers, & fresh passing conformance evidence.
