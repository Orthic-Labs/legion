//! Chunk w2_051 — Rust port of `src/lib/review/{dual_review,engine,
//! health_check,jury,ledger}.py`.
//!
//! `ledger` is a complete, faithful port of `ledger.py` (data model, file
//! I/O, disposition/round logic, and CLI arg parsing) — the file had no
//! network or YAML-config dependency and ports cleanly end to end.
//!
//! `engine_logic`, `dual_review_logic`, and `health_check_logic` port the
//! deterministic, network-free logic out of `engine.py`, `dual_review.py`,
//! and `health_check.py` respectively. `engine_run` (r59), `dual_review_run`
//! (r60), `health_check_run`, and `jury_cli`'s `run()` (r60) close the
//! remaining orchestration gap for each: the live-HTTP-calling,
//! `models.yaml`/cache-wired half, with the HTTP boundary itself behind
//! the `JuryProvider`/`VisionPrep` traits (`engine_run.rs`), exercised in
//! tests with fakes, never real network or browser I/O. `dual_review.py`'s
//! Agent Room lane additionally drives `w2_050::room_driver::run_room_advisory`
//! (already ported) through the same `RunsEvidence`/`CommandRunner` trait
//! seams. See each module's doc comment for exact scope and any residual
//! gap.

pub mod dual_review_logic;
pub mod dual_review_run;
pub mod engine_logic;
pub mod engine_run;
pub mod health_check_logic;
pub mod health_check_run;
pub mod jury_cli;
pub mod ledger;
