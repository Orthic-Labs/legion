//! Chunk r64 (packet R64) — Rust port of
//! `src/lib/verification/arcane/{advisory-profile,completion-evidence,
//! completion-gate,current-user-risk-acceptance}.mjs` and
//! `src/lib/verification/arcane/s11-bindings/{eval-adversarial,
//! eval-concurrency-convergence,eval-review-security}.mjs`.
//!
//! Additive only: the JS remains the source of truth until CI parity is
//! proven and a later packet deletes it.
//!
//! `completion-evidence.mjs` was already ported in full at
//! `crate::wf_port::q_q4::completion_evidence` (packet Q4) — this packet
//! does not re-touch it.
//!
//! The three `s11-bindings/eval-*.mjs` files were already partially ported
//! at `crate::wf_port::wf074` (packet wf074), each with a documented
//! `BlockedOnDependency` case for a small pure-logic sibling module
//! (`architecture-router.mjs`, `src/lib/core/scheduler.mjs`,
//! `gate-validity.mjs`) that had no Rust port. Per this packet's mandate to
//! close every gap rather than report "already partial, no changes", those
//! three sibling modules are ported here (`architecture_router`,
//! `scheduler`, `gate_validity`) and `crate::wf_port::wf074`'s
//! `eval_adversarial`, `eval_concurrency_convergence`, and
//! `eval_review_security` modules are extended in place to call the real
//! logic instead of reporting `BlockedOnDependency`.
//!
//! `decision`: a small shared `Decision`/`decision(...)` helper mirroring
//! `src/lib/contracts/arcane/errors.mjs`'s `decision()` — used by every
//! module in this packet that returns Arcane's typed decision shape.
//!
//! GAP (documented per module): `advisory_profile` takes
//! `validateSkillBundle` (from `src/lib/skills/contracts.mjs`, not owned by
//! this packet) as an injected trait rather than a hard-wired port.
//! `completion_gate` takes `findCurrentAdvisoryCertification` (from
//! `src/lib/verification/arcane/advisory-certification.mjs`, 158 lines, not
//! owned by this packet, no Rust port anywhere in `engine/`) as an injected
//! trait for the same reason completion-evidence.mjs's own unported
//! collaborators were injected in packet Q4.

pub mod decision;
pub mod time;

pub mod architecture_router;
pub mod scheduler;
pub mod gate_validity;

pub mod advisory_profile;
pub mod current_user_risk_acceptance;
pub mod completion_gate;
