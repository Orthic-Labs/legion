//! wf_port chunk w2_030 (area `skills/seo/scripts`, target crate `legion-runtime`).
//!
//! Source files assigned to this chunk:
//! - `skills/seo/scripts/google_auth.py`
//! - `skills/seo/scripts/google_report.py`
//! - `skills/seo/scripts/gsc_inspect.py`
//! - `skills/seo/scripts/gsc_query.py`
//! - `skills/seo/scripts/gsc_query_v2.py`
//!
//! No pre-existing native coverage was found for any of these five files (`git grep` across
//! `engine/` for their function/command names — `check_credentials`, `detect_tier`,
//! `normalize_result`, `inspect_url`, `list_sites`, etc. — returned nothing before this port).
//!
//! ## What is ported
//!
//! All five scripts are thin CLIs wrapped around live Google API calls (OAuth/service-account
//! HTTP requests via `googleapiclient`/`google-auth`). Per each file, this chunk ports the
//! deterministic, provider-I/O-free logic — the part that is mechanically portable and safely
//! unit-testable without live credentials or network access — and leaves the HTTP-calling glue
//! as a documented gap rather than porting it into dead code with nothing to call it:
//!
//! - [`google_auth`]: the `SCOPES`/`SERVICE_AUTH`/`SERVICE_NAMES` tables, `OAUTH_SCOPES` /
//!   `OAUTH_REDIRECT_URI`, `load_config()`'s file+env merge precedence, `validate_url()`
//!   (verbatim, including the blocked-host list and private/loopback/link-local IP checks), and
//!   `detect_tier()` / `check_credentials()`'s full branching logic. The latter two are ported
//!   over an already-resolved [`google_auth::CredentialState`] rather than re-implementing the
//!   Python functions' own OAuth-token-file / service-account-file reads — the branching (tier
//!   math, per-service error strings, the GA4-needs-property-id special case) is the actual
//!   ported behaviour; the file I/O around it is a thin, uninteresting wrapper appropriate for a
//!   future caller to supply.
//! - [`gsc_query_v2`]: `normalize_result()` ported verbatim (field names, `round(x, 4)` /
//!   `round(x, 3)` rounding, the divide-by-zero -> `null` coverage behavior) — this is the
//!   function the script's own docstring calls out as "pure and replayable", so it is the
//!   correct unit to port. Also ports the `--device`/`--country` -> `dimensionFilterGroups`
//!   filter-building from `main()`.
//! - `gsc_query.py`'s `main()` and `gsc_query_v2.py`'s `main()` share one piece of pure logic:
//!   the `end = end_date or now-3d`, `start = start_date or now-days` default date-range
//!   computation. Ported as [`date_util::default_date_range`], built on dependency-free
//!   Hinnant-algorithm civil-calendar arithmetic ([`date_util`]) since no date/time crate is a
//!   dependency of `legion-runtime` (see the report's dependency-patch note — this port
//!   deliberately does NOT add one).
//! - [`gsc_inspect`]: the `inspectionResult` JSON -> normalized-result field mapping done inline
//!   in `inspect_url()` (index status, canonical match, mobile usability, rich results), the
//!   `403`/`429`/`400` HTTP-error-string classification, `batch_inspect()`'s pass/fail/neutral/
//!   error summary tally, and the `DAILY_LIMIT` batch-truncation-with-warning behavior.
//!
//! ## What is NOT ported, and why
//!
//! - Packet r36 closed the `google_auth.py` half of this gap: `run_oauth_flow` (browser open +
//!   local `http.server`-equivalent TCP listener on `localhost:8085` catching the OAuth
//!   redirect), `_refresh_oauth_token`, `_exchange_code`, `_load_oauth_token`/`_save_oauth_token`,
//!   and real-filesystem resolution of service-account/OAuth-token state are all now ported in
//!   [`google_auth`] (network calls behind [`google_auth::TokenHttpClient`], browser launch
//!   behind [`google_auth::BrowserOpener`], both fakeable in tests), along with the full CLI
//!   dispatch (`google_auth::run`). What remains unported in `google_auth.py` is
//!   `get_service_account_credentials`/`get_oauth_credentials`/`build_service`'s construction of
//!   a live `googleapiclient` service object — those are owned entirely by the python
//!   `google-auth`/`google-api-python-client` libraries and the shipped script performs no JWT
//!   signing itself at that point, so there is nothing script-side left to port; a future caller
//!   that wants to actually call a Google API with service-account credentials would need to add
//!   `jsonwebtoken` for RS256 JWT-bearer signing.
//! - Packet r38 closed the `gsc_inspect.py`/`gsc_query.py`/`gsc_query_v2.py` half of this gap:
//!   the live GSC URL Inspection call ([`gsc_inspect::inspect_url_with`]/
//!   [`gsc_inspect::batch_inspect_with`], over [`gsc_inspect::InspectionTransport`]), the live
//!   Search Analytics call ([`gsc_query_v2::query_with`], over
//!   [`gsc_query_v2::SearchAnalyticsTransport`]), and the live `sites`/`sitemaps` calls
//!   ([`gsc_query::list_sites_with`]/[`gsc_query::list_sitemaps_with`], over
//!   [`gsc_query::SitesTransport`]) are all now ported, each backed for real by a
//!   `reqwest`-based transport and fakeable in tests. Bearer-token resolution
//!   ([`gsc_query_v2::resolve_bearer_token`]) wires the OAuth-token-file/refresh path through
//!   `google_auth`'s already-ported [`google_auth::TokenHttpClient`]/[`google_auth::OauthClient`]
//!   machinery. Each of the three scripts' `main()` is ported as a `run(args, out, err) -> i32`
//!   entry point ([`gsc_inspect::run`], [`gsc_query::run`], [`gsc_query_v2::run`]), with
//!   `gsc_query::run`'s `query` command delegating to `gsc_query_v2::query_with` exactly as the
//!   python original delegates to `gsc_query_v2.query()`.
//! - What remains unported, in all three: the service-account credential fallback
//!   (`get_service_account_credentials`/`build_service`'s live path in `google_auth.py`, which
//!   these scripts reach via `get_oauth_credentials()`'s "no OAuth token -> fall back to service
//!   account" branch). That needs an RSA-SHA256 JWT signed with the service account's private
//!   key, and no crate providing RSA signing is in this port's allowed dependency list (`reqwest`,
//!   `scraper`, `headless_chrome`, `image`) — the one genuinely-impossible piece; see the module
//!   header of [`gsc_query_v2`] for the full note. The OAuth-token path (the common case once
//!   `google_auth --auth` has been run once) is fully live.
//! - `google_report.py` (2461 lines): NOT started under this chunk's budget. It is a large report
//!   generator that formats/aggregates the same live GSC/PSI/CrUX/GA4/Indexing API responses this
//!   chunk's other four files fetch; a faithful port belongs in its own follow-up chunk. Flagged
//!   explicitly in the report rather than silently dropped.

pub mod date_util;
pub mod google_auth;
pub mod gsc_inspect;
pub mod gsc_query;
pub mod gsc_query_v2;
