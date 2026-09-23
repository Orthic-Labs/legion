//! wf064 — port of `tools/audit/audit-complete.mjs`, `audit-finalize.mjs`,
//! `audit-plan.mjs`, `audit-run.mjs`, and `audit-runtime.mjs`.
//!
//! Each submodule documents, at its top, which JS exports it ports
//! faithfully and which orchestration/IO/browser-automation portions of the
//! source file it deliberately leaves unported (see each module's doc
//! comment and `/private/tmp/.../scratchpad/loss/wf/wf064.md` for the full
//! accounting).

pub mod common;
pub mod complete;
pub mod finalize;
pub mod plan;
pub mod run;
pub mod runtime;
