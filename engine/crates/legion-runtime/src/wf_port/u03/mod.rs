//! Packet U03 — faithful ports of files with no prior Rust coverage:
//!
//! - [`privacy`] — `src/lib/privacy/index.mjs`
//! - [`passport`] — `src/lib/provenance/passport.mjs`
//! - [`context_transport`] — `src/packages/context/lib/context.mjs` (the
//!   Membrane transport shim; distinct from `src/lib/design/context.mjs`,
//!   which is already ported in `p7_host::design`)
//! - [`version`] — `src/lib/version.mjs`
//! - [`kernel_barrel`] — the `KERNEL_TASK_ID_BRIDGE_DECISION` constant from
//!   `src/packages/kernel/index.mjs` (every other export of that barrel file
//!   is a re-export of a module already ported under `p5_core`)
//! - [`recipes_validate`] — `src/lib/recipes/validate.mjs`
//!
//! `src/lib/policy/compliance.mjs` and `src/lib/policy/org/index.mjs` are
//! already ported (`p7_host::policy::{map_evidence_to_controls,
//! organization_policy, apply_policy}`); `src/lib/skills/uri.mjs`,
//! `src/lib/skills/profile.mjs`, `src/lib/skills/skill-frontmatter.mjs`, and
//! `src/packages/kernel/lib/journal.mjs` are already ported under
//! `l5_skills` / `p5_core::kernel_journal`. `src/lib/pyio.py` has no Rust
//! equivalent: it exists only to work around Windows console code pages not
//! defaulting to UTF-8; Rust's `print!`/`println!` always write UTF-8
//! regardless of console code page, so the workaround is structurally
//! inapplicable (see `legion-review::wf_port::w2_053::quick_ask` for the
//! same conclusion reached when porting one of its five callers).

pub mod context_transport;
pub mod kernel_barrel;
pub mod passport;
pub mod privacy;
pub mod recipes_validate;
pub mod version;
