# Oracle repair request

## Objective

Close four source defects from fresh independent Completion Validation without changing frozen architecture, Membrane, legacy runtime paths, or external qualification evidence.

## Required repairs

1. Audit inventory selector normalization rejects empty `anyPath.patterns`, `anyPath.paths`, & `paths.paths` arrays with typed `AuditError::Invalid`; no empty denominator may be produced by a supplied selector.
2. Blueprint absence emits one typed degradation per actual Blueprint-dependent provider, preserving exact provider identity plus unaffected provider list; never substitute operation name as provider identity.
3. External receipt terminal truth enforces completed state iff gaps are empty, receipt completeness iff completed state with empty gaps, & provider-result completeness equality.
4. Installed-product classification binds real-client release/catalog/MCP/assets identity to signed-artifact identity; it must reject any mismatch instead of comparing client identity with itself.

## Execution boundaries

- Three Luna workers edit disjoint allowlists only.
- Workers run no Cargo, builds, tests, clippy, rustfmt, Node, Python, package managers, signing, qualification, stage, commit, or push.
- Root owns merge, direct Cargo checkpoint, Oracle, commit, signing, qualification, deletion, cleanup, & push.
- Preserve Node/Python development tooling; treat legacy runtime paths as read-only.
- No Membrane changes, invented abstractions, fabricated evidence, or external release claims.
