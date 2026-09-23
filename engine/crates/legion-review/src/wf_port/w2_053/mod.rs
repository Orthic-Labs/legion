//! Chunk w2_053 — Rust port of `src/lib/review/providers/{openai_compat,
//! subprocess_cli}.py`, their contract tests (`test_minimax_anthropic.py`,
//! `test_openai_compat_streaming.py`), and `src/lib/review/quick-ask.py`.
//!
//! All five Python files are thin orchestration around **live** transports —
//! `urllib.request.urlopen` HTTP calls (`openai_compat.py`,
//! `test_openai_compat_streaming.py`, `test_minimax_anthropic.py` mock this
//! boundary) and `subprocess.run` child-process calls
//! (`subprocess_cli.py`, `quick-ask.py`, which wraps it for the `codex`/
//! `gemini` CLIs). Per the w2_051 precedent (`jury_cli.rs`, `engine_logic.rs`),
//! this chunk ports every deterministic, network/process-free piece of logic
//! faithfully with unit tests carrying the same assertions as the Python
//! test files, and documents the live-transport gap in each module's doc
//! comment rather than reimplementing an HTTP/subprocess client (this crate
//! has no HTTP client dependency in `Cargo.lock`; see the chunk report for
//! the suggested patch if a caller wants that filled in later).
//!
//! Membrane/Blueprint: none of these five files reference either; nothing to
//! drop.

pub mod openai_compat;
pub mod quick_ask;
pub mod subprocess_cli;
