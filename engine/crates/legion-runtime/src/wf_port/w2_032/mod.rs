//! Port of `skills/seo/scripts/{pagespeed_check,parse_html,provider_registry,
//! query_ownership,question_inventory}.py` (chunk w2_032).
//!
//! - `provider_registry`: fully ported (pure registry discovery/selection
//!   logic; no secret values are ever read or printed).
//! - `query_ownership`: fully ported (pure GSC query/page evidence
//!   classification).
//! - `question_inventory`: fully ported (pure AEO question-inventory
//!   build from GSC rows plus supplied extras).
//! - `pagespeed_check`: fully ported, including the live PSI/CrUX HTTP
//!   round trips and the CLI entry point, both behind a `PsiClient` trait
//!   so tests never hit the network (packet r41) — see the module doc.
//! - `parse_html`: fully ported (packet `r42`), including the DOM
//!   tag-finding via `scraper` and the CLI entrypoint (`parse_html::run`).

pub mod pagespeed_check;
pub mod parse_html;
pub mod provider_registry;
pub mod query_ownership;
pub mod question_inventory;
