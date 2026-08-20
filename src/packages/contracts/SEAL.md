# Shared-contract change discipline

Current schemas are versioned compatibility contracts. Change an enum in `enums.mjs`, update each
schema projection, update structural tests, & rerun `node --test src/packages/contracts/smoke.test.mjs`.

Historical WP2 seal rationale is archived at `docs/provenance/WP2-CONTRACT-SEAL.md`. It is provenance,
not active semantic authority.
