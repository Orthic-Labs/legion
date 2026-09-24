//! w2_034: Rust ports of the `skills/seo/scripts/` audit/freshness/metadata/YouTube
//! tools.
//!
//! Every script in this chunk is either a live-network crawler/API client
//! (`site_audit.py`, `youtube_search.py`) or a pure data transform
//! (`source_freshness.py`, `templated_metadata.py`). `site_audit.py` is fully ported
//! (packet `r43`), including the HTTP crawl driver (`site_audit::audit`, behind the
//! `site_audit::Fetcher` trait) and the `main()` CLI (`site_audit::run`). See each
//! submodule's doc comment for exactly what was ported vs. left to the host.

pub mod date_math;
pub mod site_audit;
pub mod source_freshness;
pub mod templated_metadata;
pub mod youtube_search;
