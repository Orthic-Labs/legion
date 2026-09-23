//! Chunk w2_036 (area `src/lib/cognitive`, target crate `legion-policy`).
//!
//! Rust port of:
//!   - `src/lib/cognitive/arcane/user-intent.mjs` — ALREADY-NATIVE-VERIFIED.
//!     `classify_latest_user_intent`, `latest_external_user_turn`,
//!     `admits_authority`, `classify_content_origin_hint` and
//!     `strip_non_authoritative_directive_text` are already ported, faithfully,
//!     at `crate::wf_port::wf007::user_intent` (wf007's report notes it ported
//!     exactly the subset `user-approval.mjs` needs). This chunk's own target
//!     file, `stop-shape.mjs`, imports only `classifyLatestUserIntent` and
//!     `latestExternalUserTurn` from `user-intent.mjs`, so no gap exists for
//!     this chunk's consumers. Gap for the record: `recentUserInstructions`,
//!     `userIntent`, `alreadyAuthorized`, and `explicitDirective` (the
//!     no-deferral-tone detector) remain unported anywhere in `engine/` — a
//!     future chunk should port `explicitDirective` in particular, since
//!     stop-shape's own `SCOPE_CUT` shape depends on evidence of that kind
//!     being supplied by a caller.
//!   - `src/lib/cognitive/arcane/stop-shape.mjs` -> ported below, in full,
//!     minus the Node CLI entry point (`main()`, which reads a `Stop` hook
//!     payload off stdin and is not portable library logic; `legion-hook`
//!     already carries an independent — and materially incomplete — subset of
//!     this same gate as `stop_shape_reason` in
//!     `engine/bins/legion-hook/src/main.rs`, which is exactly the "fourth
//!     hand-written stop gate" parity risk the JS source's own module comment
//!     warns about. That binary is outside this chunk's ownership; the gap is
//!     recorded in the w2_036 report for the integrator).
//!
//! This module is additive only: the JS files remain source of truth until CI
//! parity is proven and a later packet deletes them.
//!
//! NOTE for the integration owner: wire `pub mod wf_port;` (if not already
//! present) and `pub mod w2_036;` into
//! `engine/crates/legion-policy/src/wf_port/mod.rs`, alongside the existing
//! `pub mod wf007;` (already present).

pub mod stop_shape;
