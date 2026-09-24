//! Chunk w2_053 — Rust port of `src/lib/review/providers/{openai_compat,
//! subprocess_cli}.py`, their contract tests (`test_minimax_anthropic.py`,
//! `test_openai_compat_streaming.py`), and `src/lib/review/quick-ask.py`.
//!
//! All five Python files are thin orchestration around **live** transports —
//! `urllib.request.urlopen` HTTP calls (`openai_compat.py`,
//! `test_openai_compat_streaming.py`, `test_minimax_anthropic.py` mock this
//! boundary) and `subprocess.run` child-process calls
//! (`subprocess_cli.py`, `quick-ask.py`, which wraps it for the `codex`/
//! `gemini` CLIs).
//!
//! As of packet r60, `openai_compat.py`'s live HTTP transport is fully
//! wired (`openai_compat::call_with_key`/`call_with_metadata`, via the
//! shared `w2_052::gemini::HttpTransport` trait and `reqwest::blocking`).
//! `subprocess_cli.py`/`quick_ask.py`'s `subprocess.run` transport remains
//! unported by r60 alone — see below for R61.
//!
//! Membrane/Blueprint: none of these five files reference either; nothing to
//! drop.
//!
//! Packet R61 closed the subprocess-orchestration gap noted above for
//! `subprocess_cli.py` and `quick-ask.py`: both now have a full
//! `std::process`-backed transport (`subprocess_cli::StdCommandRunner`)
//! behind a `CommandRunner` trait, and `quick-ask.py`'s CLI entrypoint is
//! ported as `quick_ask::run`/`quick_ask::run_with`. `openai_compat.py`'s
//! live HTTP transport (this packet, r60) is built on the shared
//! `super::w2_052::gemini::HttpTransport`/`ReqwestTransport`.

pub mod openai_compat;
pub mod quick_ask;
pub mod subprocess_cli;
