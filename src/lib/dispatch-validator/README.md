# Dispatch validator — G24 seed

Preserved from the retired `dispatch` skill. ARCHITECTURE G24 requires that **every worker
capsule passes a self-consistency validator before launch**; this is the tested implementation
that capability grows from (2,830 lines + 1,422 lines of tests).

`--packet-type legacy` preserves legacy Markdown validation. `--packet-type authority` validates
typed Sage, Seer, Alchemist, or worker JSON packets & receipt-binds every referenced artifact;
`--packet-type worker` requires worker variant specifically.

Do not delete without replacing the capability.


## Packet types (EC-C)

`validate-dispatch.py` accepts `--packet-type authority|worker|legacy`
(default `legacy`). The legacy code path is unchanged.

- **authority / worker** — input is a JSON `legion-authority-dispatch`
  packet (one of `sage`, `seer`, `alchemist`, `worker`). Each packet carries
  a `promptDigest`, `sourceRevision`, `modelRouting`, and authority-specific
  references (Sage `routeBundle` digest; Seer immutable `lens` + read-only
  `scope` + `oracle`; Alchemist sealed executable `executionContract` + OWN
  subset of contractOwn; worker canonical `workerCapsule` + lossless
  `taskProjection` / `artifactProjection` + `oracle`). The validator
  computes each referenced artifact's SHA-256 and rejects digest mismatch.
- **Receipt format** (authority/worker):
  ```json
  { "schema_version": 3, "sha256": "<packet sha256>",
    "referenced_artifacts": [{"path": "<canonical locator>", "sha256": "sha256:..."}] }
  ```
  `--verify-receipt` rejects when either the packet hash or the
  `referenced_artifacts` list has changed since the receipt was written.
- **legacy** — unchanged. Markdown dispatch with dispatch headings, tables,
  required labels, failure-recovery matrix, and `--write-receipt` /
  `--verify-receipt` against the existing dispatch-receipt format.
