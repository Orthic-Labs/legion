//! Port of `skills/seo/scripts/{indexing_notify,indexnow,keyword_planner,
//! nlp_analyze,page_engine}.py` (chunk w2_031).
//!
//! `page_engine` is a full, faithful port (pure logic, no network, no
//! external client). The other four scripts are third-party API wrappers
//! (IndexNow, Google Indexing API, Google Ads API, Google Cloud Natural
//! Language API); each is ported as its pure request-shaping /
//! response-classification / bookkeeping core, behind a small client trait
//! the caller implements with a real HTTP/OAuth transport. See the w2_031
//! report for what a full network port would need added to `Cargo.toml`
//! (this crate has no HTTP client or OAuth dependency today).

pub mod indexing_notify;
pub mod indexnow;
pub mod keyword_planner;
pub mod nlp_analyze;
pub mod page_engine;
