//! w2_038: Rust port of src/lib/controls/{baseline/compile,packs/registry,
//! scenarios/compile}.mjs (chunk w2_038).
//!
//! Building blocks that other packets already ported into
//! `legion_runtime::p5_core` are reused rather than re-implemented:
//! `controls_support::{Value, digest}`, `controls_selectors::{matches_selector,
//! selection_trace}`, `controls_scenarios::pairwise`, and
//! `controls_contracts::{validate_pack, validate_control}`. This chunk ports
//! the three *composition* functions that sit on top of those primitives.
//!
//! Finding for the report: `engine/crates/legion-topology/src/inspect.rs`
//! has its own `compile_baseline`/`compile_scenarios` functions, but they
//! are permanent stubs that always return an empty baseline / empty,
//! incomplete scenario matrix regardless of input -- they are not a port of
//! `compileBaseline`/`compileScenarios` at all. `legion-topology/src/packs.rs`
//! similarly has a `load_control_packs` that silently swallows every error
//! (missing file, bad JSON, schema mismatch) by returning `Vec::new()`,
//! rather than validating and erroring like `loadControlPacks`. Those are a
//! different crate (`legion-topology`, not owned by this chunk), so this
//! packet does not touch them; the real logic lives here instead. See the
//! report for the suggested wiring.
//!
//! Owned by chunk w2_038. `pub mod w2_038;` wiring in `legion-runtime`'s
//! `wf_port/mod.rs` (`pub mod wf_port;` is already present in `lib.rs`) is
//! added by the integrator, not by this file.

pub mod baseline;
pub mod registry;
pub mod scenarios;
mod util;
