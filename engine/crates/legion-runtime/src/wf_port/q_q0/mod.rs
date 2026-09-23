//! Port packet Q0 — designer/huashu deck-export pipeline scripts.
//!
//! Most files in this packet (Playwright/Puppeteer capture, ffmpeg video
//! encode/mux, pptx export, raw-CDP browser drivers, and CSS-cascade/HTML
//! parsing) shell out to Node/Python tooling or need an HTML/CSS parser or
//! browser-automation crate that is not in `engine/Cargo.lock` for this
//! crate (`legion-runtime`'s `Cargo.toml` pulls in `serde`, `serde_json`,
//! `sha2`, `hex`, `regex`, `thiserror`, `tokio` — no `reqwest`, no HTML/CSS
//! parser, no CDP/WebSocket client). Those are reported as NOT-STARTED in
//! the packet report rather than forced into a stub that cannot make real
//! HTTP/browser calls.
//!
//! Two legacy scripts do have genuinely portable *pure* logic once the I/O
//! edges (a real HTTP POST, `ffprobe` exec, filesystem writes) are factored
//! out as caller-supplied inputs/outputs:
//!
//! - `huashu/scripts/tts-doubao.mjs` (Doubao/Volcengine TTS CLI): argument
//!   parsing, `.env` line parsing, the outbound JSON request-body shape,
//!   and the inbound JSON response envelope's success/error decoding.
//!   Ported in [`tts_doubao`].
//! - `huashu/scripts/fetch_images.py` (Wikimedia Commons image fetch CLI):
//!   the `_safe()` filename sanitizer and the derived output filename it
//!   feeds into. Ported in [`fetch_images`].
//!
//! Both keep the network call itself as a NOT-PORTED gap (needs `reqwest`,
//! not in this crate's `Cargo.toml` — see the packet report for the exact
//! patch) — see each module's doc comment for the precise remaining scope.

pub mod fetch_images;
pub mod tts_doubao;
