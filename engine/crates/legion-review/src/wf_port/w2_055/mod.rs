//! Chunk w2_055 — Rust port of `src/lib/review/{value_gate_report.py,
//! value_gate_runner.py, vision_input.py}` plus verification of the
//! already-ported `src/lib/review/untrusted-evidence-envelope.mjs`.
//!
//! `untrusted-evidence-envelope.mjs` (B7-029) is already fully covered by
//! `legion_review::review_port::evidence_envelope` — no gap found; see the
//! chunk report.
//!
//! The two `value_gate_*` scripts are one-shot CLI tools for a single,
//! dated (2026-07-19) frozen experiment (`gate-skills-controlled-20260719-*`,
//! Fable/Codex provider orchestration via `Engine`/`dual_review`/
//! `review_evidence`, none of which exist in this crate or workspace).
//! Following the w2_051/w2_053 precedent, each module ports every
//! deterministic, dependency-free piece of logic faithfully with unit tests
//! carrying the same assertions as the Python source, and documents the
//! unported orchestration/live-provider surface in its own doc comment
//! rather than reimplementing `Engine`/provider dispatch or the historical
//! CLI `main()`.
//!
//! Membrane/Blueprint: none of the four files reference either; nothing to
//! drop.

pub mod value_gate_report;
pub mod value_gate_runner;
pub mod vision_input;
