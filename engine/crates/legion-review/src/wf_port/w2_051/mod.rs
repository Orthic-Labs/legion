//! Chunk w2_051 — Rust port of `src/lib/review/{dual_review,engine,
//! health_check,jury,ledger}.py`.
//!
//! `ledger` is a complete, faithful port of `ledger.py` (data model, file
//! I/O, disposition/round logic, and CLI arg parsing) — the file had no
//! network or YAML-config dependency and ports cleanly end to end.
//!
//! `engine_logic`, `dual_review_logic`, `health_check_logic`, and
//! `jury_cli` port the deterministic, network-free logic out of
//! `engine.py`, `dual_review.py`, `health_check.py`, and `jury.py`
//! respectively. Those four Python files are CLI/orchestration entry
//! points built around live HTTP calls to LLM providers, a YAML
//! `models.yaml` config, an on-disk verdict cache, and (for
//! `dual_review.py`) an agent-room driver — none of which this crate or
//! chunk owns a Rust counterpart for. See each module's doc comment and
//! `docs/pending` (or the chunk report) for the exact gap.

pub mod dual_review_logic;
pub mod engine_logic;
pub mod engine_run;
pub mod health_check_logic;
pub mod health_check_run;
pub mod jury_cli;
pub mod ledger;
