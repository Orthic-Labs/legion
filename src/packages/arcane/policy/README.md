# Historical policy artifact

`arcane-policy-v1.json` / `arcane-policy-v1.rules` / `policy-bundle-v1.schema.json` are the
Node Arcane package's own policy bundle: a different schema (`approvalRequired`,
`trustMinimum`, `requiredEnforcement` as free-text levels) consumed only by
`lib/policy.mjs` and this package's own tests
(`tests/policy-compiler.test.mjs`, `tests/s09-completion-gate.test.mjs`) and this package's own
compatibility maps. They do not feed the Guard's live authorization path.

The Guard's canonical default policy — the pack that is always present for
`legion-hook`/`legion-application`, per `docs/provenance/migrations/2026-08-29-pending/PENDING-WORK-2026-08-29.md` P0.1 — is
`canonical_default_policy_pack()` in `engine/crates/legion-contracts/src/policy.rs`, using the
`PolicyRule`/`PolicyPack` schema in that same file (`effect_class`, `allowed`, `approval`,
`targets`, `operations`).

This bundle's rule content was reviewed while building that default pack (P0.1/P0.4,
2026-08-29): every effect-class decision here is compatible with, and superseded by, the new
pack's allow/deny split (ordinary reversible effects ambient-allow; credential access,
publish, VCS push, dependency install, network egress, process spawn deny by default pending
an approval-flow implementation). No rule content needed porting beyond what the new pack
already encodes.

Files in this directory stay as-is because they remain load-bearing for the Node Arcane
package's own tests. Their disposition (PORT/RESTORE/MOVE/RETIRE) as part of that package is
tracked separately under P0 item 5 (`src/packages/arcane/` triage), not here — this note only
resolves the "two ambiguous policy artifacts" ambiguity between this bundle and the Guard's new
canonical default.
