# ADR

```yaml
schema: architecture-decision.v1
decision_id: ADR-1
record_worthiness: { hard_to_reverse: true, surprising_without_context: true, real_trade_off: true }
decision_status: proposed
realization_status: not_started
date: <RFC3339 timestamp>
owner: <owner>
decision_authority: <authority>
decision_question: <question>
alternatives: [{ id: C-1, description: <candidate>, disposition: selected }, { id: C-2, description: <candidate>, disposition: rejected }]
decision: <selection>
rationale: <trade-offs>
evidence_refs: []
consequences: []
residual_risks: []
reversibility_and_exit: <exit>
review_triggers: []
dependents: []
related_decisions: []
```

Author only when all three record-worthiness predicates hold; otherwise record one decision-log event.
