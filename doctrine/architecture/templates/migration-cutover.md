# Migration cutover

```yaml
schema: migration-cutover.v1
mode: HARD_CUT
runtime_owner: <owner>
first_fix_owner: <owner>
canonical_owner: <owner>
integration_owner: <owner>
hard_cut:
  external_compatibility_obligation: null
  absence_checks: { imports: [], routes: [], runtime_registrations: [], configuration_keys: [], dependencies: [], tests: [], documentation: [], emitted_protocol_variants: [] }
bounded_coexistence: null
verdict: READY
```
