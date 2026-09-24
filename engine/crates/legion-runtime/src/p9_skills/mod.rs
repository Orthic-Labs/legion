//! Packet P9-skill-scripts: Rust port of `skills/{seo,alchemist,brand-identity,coder,covenant,
//! dispatch,handoff,qa,tasklist,ads}/**` script/hook JS (everything except `skills/designer`
//! and `skills/audit`, which are owned by other packets).
//!
//! Of those ten skill directories, five had no script/hook/engine JS files at all
//! (`skills/coder`, `skills/dispatch`, `skills/handoff`, `skills/tasklist`, `skills/ads` —
//! confirmed by exhaustive `find` for `*.js`/`*.mjs`/`*.cjs`/`*.ts`/`*.sh`); there is nothing to
//! port for them. See the packet report (`full-P9-skill-scripts.md`) for the exact per-file
//! table, including the JS that remains unported and why (raw-CDP browser automation in
//! `render_gap.mjs`, process/watchdog orchestration in `run-worker.sh`, and provider-IO
//! orchestration in `covenant/lib/flows.mjs`).
//!
//! `skills/coder` since grew Python hooks/scripts (not JS, so outside this doc note's original
//! scope): `hooks/enforce_cheap_review_routing.py` and `scripts/api-worker.py` are owned and
//! ported elsewhere (`wf_port::w2_044::routing`, `l1b_port::execution` respectively — the latter
//! reached unmodified via `scripts/api-worker.py`'s `runpy` delegation). `hooks/install.py`, the
//! per-machine hook registrar, had no home; it is ported here as [`coder_hooks_install`]
//! (packet U01).

pub mod alchemist;
pub mod alchemist_viewer;
pub mod brand_identity;
pub mod coder_hooks_install;
pub mod covenant;
pub mod qa;
pub mod render_gap;
pub mod seo;
