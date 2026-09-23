//! w2_034: Rust ports of the `skills/seo/scripts/` audit/freshness/metadata/YouTube
//! tools.
//!
//! Every script in this chunk is either a live-network crawler/API client
//! (`site_audit.py`, `youtube_search.py`) or a pure data transform
//! (`source_freshness.py`, `templated_metadata.py`). In every case, the pure,
//! independently testable core is ported faithfully; the network IO (HTTP fetches, the
//! YouTube Data API client, file reads) stays with a host wrapper that fetches/reads and
//! hands the resulting already-parsed data to these functions. See each submodule's doc
//! comment for exactly what was ported vs. left to the host.

pub mod date_math;
pub mod site_audit;
pub mod source_freshness;
pub mod templated_metadata;
pub mod youtube_search;
