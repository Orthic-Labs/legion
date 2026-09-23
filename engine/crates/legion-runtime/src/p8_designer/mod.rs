//! Packet P8-designer: Rust port of `skills/designer/engine/**` logic.
//!
//! Ported so far (pure logic, no DOM/browser dependency):
//! - `target_args`: CLI `--target`/`-t` argument parsing
//!   (skills/designer/engine/scripts/lib/target-args.mjs)
//! - `is_generated`: heuristics for "generated file, unsafe to edit"
//!   (skills/designer/engine/scripts/lib/is-generated.mjs)
//! - `page`: full-page-vs-partial HTML detection
//!   (skills/designer/engine/scripts/detector/shared/page.mjs)
//! - `constants`: detector shared constants (safe tags, font lists, WCAG
//!   thresholds) (skills/designer/engine/scripts/detector/shared/constants.mjs)
//!
//! See the packet report (`full-P8-designer.md`) for the full per-file table
//! and the precise list of files not yet ported (browser/DOM-driven "live"
//! preview machinery, the detector rule engine, the huashu video/pptx
//! pipeline, and Membrane/Blueprint-only pieces which are dropped).

pub mod constants;
pub mod is_generated;
pub mod page;
pub mod target_args;

pub use constants::*;
pub use is_generated::{is_generated_file, IsGeneratedOptions};
pub use page::is_full_page;
pub use target_args::{parse_target_options, parse_target_path, TargetArgError};
