//! Chunk w2_007: port of `skills/designer/engine/huashu/scripts/`
//! (`export_deck_stage_pdf.mjs`, `fetch_images.py`, `gen_deck_thumbs.mjs`,
//! `html2pptx.js`, `mix-voiceover.sh`).
//!
//! Every script here drives at least one of a real browser (Playwright
//! Chromium), an image codec (`sharp`), or an external process (`ffmpeg`)
//! that this headless-engine crate cannot reach — none of `headless_chrome`,
//! `chromiumoxide`, or an `image`-equivalent crate is in `engine/Cargo.lock`.
//! Each submodule ports every deterministic computation around that
//! boundary faithfully (argument parsing, path/filename derivation, unit
//! conversion and CSS-value parsing, validation error text, log/summary
//! line formats, and — for `mix-voiceover.sh`, which needs no browser or
//! codec — the full `ffmpeg` argument-vector construction) and documents
//! exactly what remains out of reach and why. See `docs/pending`/the w2_007
//! report for the dependency patches a future chunk would need to finish
//! the browser/codec-backed halves.

pub mod export_deck_stage_pdf;
pub mod fetch_images;
pub mod gen_deck_thumbs;
pub mod html2pptx;
pub mod mix_voiceover;
pub mod render_narration;
