//! wf_port packet r03 (area `skills/designer/engine/huashu/scripts`,
//! target crate `legion-runtime`).
//!
//! Completes three huashu scripts:
//!
//!   - `tts-doubao.mjs` -> [`tts_doubao`] — the earlier `q_q0` packet ported
//!     only the pure `.env`/argv parsing and JSON request/response shapes
//!     because `legion-runtime` had no HTTP client dependency at the time.
//!     `reqwest` (with the `blocking` feature) and `headless_chrome` are now
//!     both already declared in this crate's `Cargo.toml` (wired by later
//!     packets), so this module closes that gap for real: a real blocking
//!     HTTP POST to the Doubao endpoint and a real `ffprobe` subprocess call
//!     for duration, each behind a small trait so tests use fakes.
//!   - `render-video.js` -> [`render_video`] — full CLI parsing, the
//!     chrome-hiding CSS/JS injection strings, the ready-signal/trim
//!     decision, and a `Recorder` trait whose production implementation
//!     drives `headless_chrome` for navigation/ready-detection and captures
//!     frames via CDP screenshots (there is no WebM `recordVideo` analogue
//!     in `headless_chrome`/CDP, so the recording mechanism is a frame
//!     sequence captured *after* the ready signal, muxed by `ffmpeg`,
//!     rather than Playwright's continuous-record-then-trim; the CLI
//!     surface, output path/naming, and final MP4 format are unchanged).
//!   - `verify.py` -> [`verify`] — full CLI/argparse-equivalent parsing,
//!     viewport handling, slide-mode vs. single-shot screenshot capture,
//!     the console/page-error report text, and exit-code contract, behind
//!     a `BrowserDriver` trait whose production implementation drives
//!     `headless_chrome`.
//!
//! No test in this packet touches the network or launches a real browser or
//! subprocess; every I/O edge (HTTP, `ffprobe`/`ffmpeg`, browser
//! navigation/screenshot, filesystem) is exercised through a fake
//! implementation of the relevant trait.
//!
//! NOTE for the integrator: this module is not yet wired into
//! `wf_port::mod` (`pub mod r03;`) per the porting-packet rule against
//! editing `wf_port/mod.rs` in this pass — add that one line (and the
//! matching `wf_port::r03` imports in `tests/r03_*.rs` will then compile)
//! to register it. This mirrors the same not-yet-wired state already left
//! by the `r00`/`r07`/`r09`/`r15`/`r18` packets in this crate.

pub mod render_video;
pub mod tts_doubao;
pub mod verify;
