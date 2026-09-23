//! Port of the `skills/designer/engine/huashu` deck-authoring surface
//! (chunk w2_006):
//! - `assets/deck_stage.js` — the `<deck-stage>` web component
//! - `scripts/add-music.sh` — BGM mixing via ffmpeg
//! - `scripts/convert-formats.sh` — 60fps MP4 + palette GIF via ffmpeg
//! - `scripts/export_deck_pdf.mjs` — deck → merged vector PDF (Playwright + pdf-lib)
//! - `scripts/export_deck_pptx.mjs` — deck → editable PPTX (via `html2pptx.js`)
//!
//! All five sources are host-effect-heavy (DOM, shell processes, a headless
//! browser, file I/O). None of this chunk's ports spawn a process, touch the
//! filesystem, or drive a browser themselves — each module ports every
//! deterministic decision the original makes (argument parsing, path/URL
//! templating, command construction, progress and summary message
//! formatting, pass/fail policy) and leaves the actual effect to a host,
//! matching the injected-runner shape used elsewhere in `wf_port` (e.g.
//! `wf015`'s `ProcessRunner`). See each submodule's doc comment for the
//! specific boundary.

pub mod add_music;
pub mod convert_formats;
pub mod deck_stage;
pub mod export_deck_pdf;
pub mod export_deck_pptx;
