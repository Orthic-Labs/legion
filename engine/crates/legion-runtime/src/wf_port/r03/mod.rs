//! wf_port packet r03 (area `skills/designer/engine/huashu/scripts`,
//! target crate `legion-runtime`).
//!
//! Completes the huashu video and verification scripts.
//!
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
//! This module is registered from `wf_port::mod`; its packet tests live beside
//! the corresponding workflow-port code.

pub mod render_video;
pub mod verify;
