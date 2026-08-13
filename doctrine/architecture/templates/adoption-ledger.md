# Adoption ledger

```yaml
schema: architecture-adoption-ledger.v2
ledger_version: 1
acceptance_fingerprint: sha256:<64-lowercase-hex>
frozen_at: <RFC3339 timestamp>
stages:
  - stage_id: S-1
    owner: <owner>
    required_items:
      - acceptance_id: S-1-01
        outcome: <observable outcome>
        producer: <producer>
        observable_surface: <surface>
        verification_method: <method>
        evidence: []
        result: OPEN
    produce_readiness: READY_TO_PRODUCE
    integrate_readiness: NOT_READY
    activate_readiness: NOT_READY
    done_state: NOT_STARTED
consumption_dependencies:
  - consumer_stage_id: S-2
    consumer_acceptance_id: S-2-01
    producer_stage_id: S-1
    producer_acceptance_id: S-1-01
    consumed_artifact_id: <artifact-or-acceptance-output>
    consumption: INTEGRATE
    required_verification: true
```

Dependencies bind a specific consumed artifact & producer/consumer acceptance IDs. They never make stage number or whole-stage authoring an implicit edge. Independent files, fixtures, adapters, & producer work may start at `READY_TO_PRODUCE`; first `INTEGRATE` or `ACTIVATE` consumption waits for fresh verification of named producer output. One writer owns each shared artifact.
