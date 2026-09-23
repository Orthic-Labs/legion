//! Chunk w2_046: port of `src/lib/host/arcane/{codex-escalation,continuity,
//! decision-envelope,denial-circuit,discipline-controls}.mjs`.
//!
//! See each submodule's doc comment for exactly what is ported at full
//! fidelity versus left `NOT-STARTED`, and the chunk report
//! (`w2_046.md`) for the complete function inventory and the one
//! suggested `Cargo.toml` dependency patch (needed only for the
//! not-yet-ported `denial-circuit.mjs` `DenialCircuit` class).
//!
//! NOTE: this chunk owns `src/wf_port/w2_046/**` only; the integrator wires
//! `pub mod wf_port;` (crate root) and `pub mod w2_046;` (`wf_port::mod`).

pub mod canonical;
pub mod codex_escalation;
pub mod continuity;
pub mod decision_envelope;
pub mod denial_circuit;
pub mod discipline_controls;
