//! Port of `skills/designer/engine/scripts/detector/{registry,rules,shared}`
//! (chunk w2_014, area `skills/designer/engine/scripts`).
//!
//! Per-file status (see the chunk report for detail):
//! - `shared/constants.mjs` — already ported at `p8_designer::constants`
//!   (verified equivalent; not duplicated here).
//! - `shared/page.mjs` — already ported at `p8_designer::page::is_full_page`
//!   (verified equivalent; not duplicated here).
//! - `shared/color.mjs` — ported in full below (`color`): was confirmed
//!   absent from the tree at port time (see `l6_designer_checks`'s module
//!   docs, which call it out as "a separate, not-yet-ported foundation").
//! - `registry/antipatterns.mjs` — ported in full below (`antipatterns`):
//!   the `ANTIPATTERNS` registry and its lookup/filter helpers.
//! - `rules/checks.mjs` (2671 lines) — largely covered by the separate,
//!   already-landed `l6_designer_checks` packet (`css_color` +
//!   `pure_checks`), which is out of this chunk's owned paths (read-only).
//!   That packet's own docs record `checkColors`/`checkBorders`/`checkGlow`
//!   as deferred pending a `shared/color.mjs` port — this chunk now
//!   supplies that port (`color`, above), unblocking them. Porting the
//!   remaining `checks.mjs` rule functions themselves belongs to whichever
//!   packet owns `l6_designer_checks` (this chunk may not create files
//!   there); see the chunk report for the itemized remaining list.

pub mod antipatterns;
pub mod color;
