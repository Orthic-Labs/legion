//! Packet P9-skill-scripts: Rust port of `skills/{seo,alchemist,brand-identity,covenant,
//! dispatch,handoff,qa,tasklist,ads}/**` script/hook JS (everything except `skills/designer`
//! and `skills/audit`, which are owned by other packets).
//!
//! Of those nine skill directories, four had no script/hook/engine JS files at all
//! (`skills/dispatch`, `skills/handoff`, `skills/tasklist`, `skills/ads` —
//! confirmed by exhaustive `find` for `*.js`/`*.mjs`/`*.cjs`/`*.ts`/`*.sh`); there is nothing to
//! port for them. See the packet report (`full-P9-skill-scripts.md`) for the exact per-file
//! table, including the JS that remains unported and why (raw-CDP browser automation in
//! `render_gap.mjs` and provider-IO orchestration in `covenant/lib/flows.mjs`).

pub mod alchemist;
pub mod alchemist_viewer;
pub mod brand_identity;
pub mod covenant;
pub mod qa;
pub mod render_gap;
pub mod seo;
