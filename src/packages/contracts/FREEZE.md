# Shared-contract compatibility boundary

`docs/LEGION-CANONICAL-SSOT.md` owns system architecture. This package owns current wire shapes,
enumerations, ID grammar, & executable-contract mechanics only.

Current semantic boundaries:

- Legion plus producing capability materialize settled executable contracts.
- Sage participates only when material unresolved meaning required actual adjudication.
- `openQuestions` may be non-empty in a draft, but executable validation requires it empty.
- Contract amendments are explicit, versioned, & immutable by version.
- Covenant records are advisory challenge artifacts; Covenant is not an authority or release gate.
- Arcane deterministically validates effects, receipts, freshness, invalidation, & runtime gates.
- Concrete model/provider IDs are host configuration, not contract semantics.

Wire compatibility judgments retained by current schemas include camelCase fields, opaque runtime
handles, separate invocation/domain/claim axes, explicit effect identity, authentication metadata,
replay defense, & compatibility envelopes for historical records. Historical rationale is archived
at `docs/provenance/WP2-CONTRACT-FREEZE.md` & cannot override current owners or consumers.

Run `node --test src/packages/contracts/smoke.test.mjs` after schema or enum changes.
