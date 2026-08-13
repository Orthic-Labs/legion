# Representative workload

```yaml
schema: representative-workload.v1
acceptance_fingerprint: sha256:<64-lowercase-hex>
required_items_exercised: [AC-1]
smallest_complete_slice: <slice>
actual_workflow: <workflow>
actual_acceptance_surface: <surface>
environment: { os: <os>, runtime: <runtime>, browser_or_device: <surface>, locale_timezone_network: <context> }
representative_data: <data>
artifact: { kind: receipt, sensitivity: internal, trust: trusted, retention: <period>, deletion_owner: <owner>, digest: sha256:<64-lowercase-hex> }
result: { status: PASS, machine_readable: true, gateable: true, downloadable: true, trajectory_correlation_id: <id>, failure_signature: null }
matrix: { rationale: <why>, pr_subset: [], release_set: [] }
forbidden_proxies: []
observed_failures: []
hardening_disposition: DEFER
```
