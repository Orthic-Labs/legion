//! wf_port packet r04 (area `skills/designer/engine/scripts/context.mjs`,
//! target crate `legion-runtime`).
//!
//! `context.mjs`'s deterministic context-resolution core (PRODUCT.md /
//! DESIGN.md discovery, monorepo workspace-root detection, `## Register`
//! extraction) was already ported at
//! [`crate::wf_port::w2_010::context`]. This packet completes the file by
//! porting the two layers that module's header explicitly left out:
//!
//!   - the CLI entry point (`cli()` and its helpers: option parsing, the
//!     `RESOLVED_CONTEXT` / `MONOREPO_TARGET_REQUIRED` /
//!     `TARGET_SELECTION_REQUIRED` / `NO_PRODUCT_MD` output blocks, and the
//!     final `NEXT STEP` register directive) — see [`cli`];
//!   - the best-effort skill self-update check (`computeUpdateDirective`
//!     and friends: local-version read, throttled/cached version poll,
//!     anti-nag re-notify window, `UPDATE_AVAILABLE` directive text) — see
//!     [`update_check`].
//!
//! Both layers keep their I/O (filesystem cache, network fetch, argv) behind
//! small traits so the orchestration logic is unit-testable without a real
//! filesystem, network, or process.
//!
//! NOTE for the integrator: this module is not yet wired into
//! `wf_port::mod` (`pub mod r04;`) per the porting-packet rule against
//! editing `wf_port/mod.rs` in this pass — add that one line to register it.

pub mod cli;
pub mod update_check;
