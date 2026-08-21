# Architecture convergence receipt

```yaml
schema: architecture-convergence-receipt.v4
decision_id: D-1
objective: sufficient
objective_lineage_id: OL-1
intent_epoch: 1
continuation_epoch: 1
execution_cancelled: false
depth: D1
rigor: standard
pass_count: 1
pass_budget: 2
revision_ceiling: 3
decision_fingerprint: sha256:<64-lowercase-hex>
evidence_fingerprint: sha256:<64-lowercase-hex>
acceptance_fingerprint: sha256:<64-lowercase-hex>
acceptance_ledger: { required: 1, passed: 0, open: 1, deferred: 0, out_of_scope: 0 }
verification: { run_id: VR-1, observed_at: <RFC3339 timestamp>, integrated_state_identity: <identity>, acceptance_fingerprint: sha256:<64-lowercase-hex>, freshness_verdict: FRESH }
terminal_state: CANDIDATE
```
