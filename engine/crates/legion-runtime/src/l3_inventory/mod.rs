//! Port of `src/lib/inventory/**` (packet L3): the pure, in-memory graph
//! builders that turn a projection (raw filesystem/dependency evidence) plus
//! a product/release contract into the sealed inventory artifacts — product
//! targets, components, external systems, stacks, journeys, product context,
//! and the release contract merge. Every public function here is a 1:1 port
//! of one exported JS function from the corresponding `.mjs` file; see each
//! submodule's doc comment for its source file.
//!
//! All records are modelled as `serde_json::Value` rather than typed structs,
//! mirroring the loosely-typed JS records (arbitrary extra fields, optional
//! keys defaulted with `??`) so the port stays behaviourally exact without
//! inventing a schema the JS never had.
//!
//! Not yet ported from `src/lib/inventory/**`: none — all 27 source files
//! are covered. `src/lib/inventory/product-targets/detectors/index.mjs`'s
//! `discoverTargets` was `async` only because its sibling module did file
//! I/O elsewhere in the tree; the ported function here is synchronous since
//! this port takes evidence already collected as a `projection` value.

pub mod binding;
pub mod components;
pub mod error;
pub mod external_systems;
pub mod journeys;
pub mod product_context;
pub mod product_targets;
pub mod release_contract;
pub mod stacks;

pub use error::InventoryError;
