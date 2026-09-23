//! Port of `src/lib/gauntlet/` (the phase 6.7 "evidence gauntlet") and its
//! self-test file `src/lib/gauntlet/tests/gauntlet.test.mjs`.
//!
//! The gauntlet feeds a code+test fixture through mutation testing,
//! changed-lines coverage, and test-order independence, then emits a
//! single Arcane-shaped `check` object. `gauntlet.test.mjs` is the
//! gauntlet's own proof: when fed a fixture where the test is too weak to
//! detect a token-flip mutant, the gauntlet must report that mutant as
//! `"survived"`. This chunk's `tests/wf_wf005.rs` ports those same four
//! assertions against the Rust orchestrator in [`gauntlet::run_gauntlet`].
//!
//! No pre-existing native coverage of this area was found under
//! `engine/` (`git grep -i gauntlet` in `engine/` was empty before this
//! port); this module is a from-scratch faithful port of every file under
//! `src/lib/gauntlet/` (`gauntlet.mjs`, `lib/diff.mjs`, `lib/mutation.mjs`,
//! `lib/coverage.mjs`, `lib/order.mjs`, `lib/arcaneshape.mjs`), scoped
//! entirely under this chunk's owned directory since none of those files
//! had a wired sibling module to build on.
//!
//! This chunk owns only `src/wf_port/wf005/**` and
//! `tests/wf_wf005.rs` — it does not modify `lib.rs`, `wf_port/mod.rs`,
//! `Cargo.toml`, or any registry file. The integrator wires
//! `pub mod wf_port;` and `pub mod wf005;`.

pub mod arcaneshape;
pub mod coverage;
pub mod diff;
pub mod gauntlet;
pub mod mutation;
pub mod order;

pub use gauntlet::{run_gauntlet, GauntletOptions, GauntletRun};
