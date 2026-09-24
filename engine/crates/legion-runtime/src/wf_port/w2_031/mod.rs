//! Port of `skills/seo/scripts/{indexing_notify,indexnow,keyword_planner,
//! nlp_analyze,page_engine}.py` (chunk w2_031).
//!
//! `page_engine` is a full, faithful port (pure logic, no network, no
//! external client). `indexnow` and `indexing_notify` (packet r39) are
//! full ports including the real HTTP transport (`reqwest::blocking`) and
//! the `main()` CLI, behind a client trait so tests use fakes instead of
//! the network. `keyword_planner` and `nlp_analyze` (Google Ads API,
//! Google Cloud Natural Language API; packet r40) are likewise full ports:
//! real `reqwest`-backed clients (`keyword_planner::ReqwestAdsClient`,
//! `nlp_analyze::ReqwestNlpTransport`) plus each script's `main()` CLI as
//! `run()`, behind a client/transport trait so tests use fakes instead of
//! the network.

pub mod indexing_notify;
pub mod indexnow;
pub mod keyword_planner;
pub mod nlp_analyze;
pub mod page_engine;
