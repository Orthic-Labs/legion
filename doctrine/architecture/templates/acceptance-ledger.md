# Frozen Acceptance Ledger

```yaml
schema: acceptance-ledger.v2
ledger_version: 1
intent_epoch: 1
acceptance_manifest_fingerprint: sha256:<64-lowercase-hex>
schedule_fingerprint: sha256:<64-lowercase-hex>
schedule:
  schedule_version: 1
  waves: []
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
    item_fingerprint: sha256:<64-lowercase-hex>
    revisit_trigger: <required for DEFERRED>
    result: OPEN # OUT_OF_SCOPE must be NOT_APPLICABLE
    evidence: []
```

Freeze before review, dispatch, or implementation. Only later explicit user intent may add a `REQUIRED` item or move an item into scope. Bind evidence to item/stage fingerprints. Bind execution to `schedule_fingerprint`; schedule-only changes preserve acceptance evidence.
