//! wf_port packet r00 (area `skills/designer/engine/huashu/scripts`,
//! target crate `legion-runtime`).
//!
//! Completes four huashu deck-export/asset scripts left `NOT-STARTED` /
//! `PORTED-PARTIAL` by the earlier `q_q0` packet, now that this packet's
//! porting brief allows adding `reqwest`, `headless_chrome`, and `image` to
//! `Cargo.toml`:
//!
//!   - `export_deck_pptx.mjs`   -> [`export_deck_pptx`]
//!   - `export_deck_stage_pdf.mjs` -> [`export_deck_stage_pdf`]
//!   - `fetch_images.py`        -> [`fetch_images`]
//!   - `gen_deck_thumbs.mjs`    -> [`gen_deck_thumbs`]
//!
//! All real I/O (filesystem slide discovery aside, which is deterministic)
//! sits behind a small trait per module so the orchestration/argument/
//! error-shape logic is unit-testable with fakes; no test in this packet
//! touches the network or launches a real browser.
//!
//! NOTE for the integrator: this module is not yet wired into
//! `wf_port::mod` (`pub mod r00;`) per the porting-packet rule against
//! editing `wf_port/mod.rs` in this pass — add that one line to register it.

pub mod export_deck_pptx;
pub mod export_deck_stage_pdf;
pub mod fetch_images;
pub mod gen_deck_thumbs;
