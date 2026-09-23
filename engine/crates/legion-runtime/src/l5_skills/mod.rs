//! L5 — packaged-skill primitives.
//!
//! Ports the pure, self-contained pieces of `src/lib/skills/**` (the JS skill
//! packaging spec) to Rust: package URI parsing, the compact `SKILL.md`
//! frontmatter grammar, bundle manifest contract validation, and audit/authoring
//! profile projection. See `docs/pending/README.md` L5 packet notes for the
//! filesystem- and registry-dependent modules (`resolver.mjs`, `loader.mjs`,
//! `verify.mjs`, `route-resources.mjs`, `dependency-closure.mjs`) intentionally
//! left out of this pass, and for the Python tasklist/dispatch validators.

pub mod contracts;
pub mod profile;
pub mod skill_frontmatter;
pub mod uri;

pub use contracts::validate_skill_bundle;
pub use profile::project_skill_text;
pub use skill_frontmatter::{parse_skill_frontmatter, FrontmatterValue, SkillFrontmatter};
pub use uri::{parse_skill_uri, skill_uri, ParsedSkillUri};
