# Frozen Acceptance Ledger

```yaml
schema: acceptance-ledger.v1
ledger_version: 1
intent_epoch: 1
acceptance_fingerprint: sha256:<64-lowercase-hex>
frozen_at: <RFC3339 timestamp>
items:
  - id: AC-1
    disposition: REQUIRED # REQUIRED | DEFERRED | OUT_OF_SCOPE
    source: <latest explicit user intent locator>
    requirement: <immutable requirement>
    observable_acceptance_surface: <required for REQUIRED>
    verification_method: <required for REQUIRED>
    owner: <named owner>
    dependencies: []
    revisit_trigger: <required for DEFERRED>
    result: OPEN # OUT_OF_SCOPE must be NOT_APPLICABLE
    evidence: []
```

Freeze before review, dispatch, or implementation. Only later explicit user intent may add a `REQUIRED` item or move an item into scope; bind every review, contract, milestone, & completion claim to `acceptance_fingerprint`.
