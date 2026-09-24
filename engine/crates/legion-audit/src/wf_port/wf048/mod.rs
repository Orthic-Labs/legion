//! Port of chunk wf048 (area `src/providers/runtime/web`, target crate
//! `legion-audit`):
//!   - `src/providers/runtime/web/backend/index.mjs`   -> `backend::inspect_web_backend`
//!   - `src/providers/runtime/web/capture/index.mjs`   -> `capture::capture_web_evidence`
//!   - `src/providers/runtime/web/data/index.mjs`      -> `data::verify_data_exercise`
//!   - `src/providers/runtime/web/discovery/index.mjs` -> `discovery::discover_web_surfaces`
//!   - `src/providers/runtime/web/index.mjs`           -> a barrel re-export
//!     of every `src/providers/runtime/web/*` submodule (including several
//!     outside this chunk, e.g. `actors`, `api`, `infrastructure`,
//!     `integration`, `matrix`, `operations`, `protocols`, `runner`,
//!     `scenario`, `third-party`). It has no logic of its own; there is
//!     nothing to port beyond wiring, which belongs to whichever crate
//!     entry point re-exports all `wf_port::wf0*` modules for
//!     `legion-audit` callers.
//!
//! No Rust coverage of any of the above existed before this port (checked
//! via `git grep` for the JS export names and their probable Rust
//! spellings across `engine/`).
//!
//! Membrane/Blueprint: none of the five files in this chunk reference
//! Membrane or Blueprint (`grep -i "membrane\|blueprint"` over the chunk's
//! files returned nothing), so nothing needed to be dropped here.

pub mod backend;
pub mod capture;
pub mod data;
pub mod discovery;
pub mod sanitize;
pub mod shared;

pub use backend::inspect_web_backend;
pub use capture::{capture_web_evidence, capture_web_evidence_production, WebJourneyRow};
pub use data::{verify_data_exercise, DataExerciseAdapter, MissingAdapter};
pub use discovery::discover_web_surfaces;
