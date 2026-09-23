//! Port of `skills/seo/scripts/{contracts,coverage,crux_history,fetch_page,ga4_report}.py`
//! (chunk w2_029, area `skills/seo/scripts`, target crate `legion-runtime`).
//!
//! Coverage check: `git grep` across `engine/` for `validate_bundle`,
//! `coverage_state`, `evidence_tiers`, `detect_trends`, `query_history`,
//! `CWV_THRESHOLDS`, `fetch_page`, `DEFAULT_USER_AGENT`,
//! `GOOGLEBOT_USER_AGENT`, `organic_traffic_report`, `ga4_property_id`,
//! `sessionDefaultChannelGroup`, and `validate_url` turned up nothing under
//! `engine/`. These are fresh ports.
//!
//! Kept at this crate's usual boundary: pure JSON-value-in/value-out and
//! string/number transforms are ported in full; real network I/O (Google
//! CrUX/GA4 HTTP calls, DNS resolution, file writes) is not — those stay
//! owned by the Python CLI surface / a future host-side effect. Membrane and
//! Blueprint are out of scope for this product direction and neither script
//! referenced them.
//!
//! - `contracts.py` -> [`contracts`] (`validate`, `validate_bundle`).
//! - `coverage.py` -> [`coverage`] (`rows`, `calculate`).
//! - `crux_history.py` -> [`crux_history`] (`detect_trends`, the CrUX
//!   History JSON-record parsing done in `query_history` after the HTTP
//!   call, and `validate_url` from `google_auth.py`, which `crux_history.py`
//!   imports).
//! - `fetch_page.py` -> [`fetch_page`] (URL scheme validation, the
//!   private/loopback/reserved IP block check, and header construction;
//!   `fetch_page()`'s actual `requests.Session` call is not ported).
//! - `ga4_report.py` -> [`ga4_report`] (`_resolve_property`, the
//!   start/end date-range computation, and the totals/slimming logic in
//!   `top_pages_report`; the `BetaAnalyticsDataClient` calls are not
//!   ported).

pub mod contracts;
pub mod coverage;
pub mod crux_history;
pub mod fetch_page;
pub mod ga4_report;
