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
//! - The live Google API calls themselves: `google_auth.py`'s `get_service_account_credentials`,
//!   `get_oauth_credentials`, `run_oauth_flow` (opens a browser + a local `http.server` on
//!   `localhost:8085` to catch the OAuth redirect), `_refresh_oauth_token`, `build_service`;
//!   `gsc_query.py`/`gsc_query_v2.py`'s `service()`/`_query()` (Search Console `searchanalytics`/
//!   `sites`/`sitemaps` HTTP calls); `gsc_inspect.py`'s `_build_inspection_service()` and the
//!   `urlInspection().index().inspect()` call. These require an HTTP client, OAuth token
//!   exchange, and a local callback server — none of which exist as dependencies of
//!   `legion-runtime` today, and porting them as unreachable dead code with no caller would
//!   violate the same "no second implementation with nothing driving it" principle documented in
//!   `wf_port::w2_004`. A future caller that wires up real Google API access should build on top
//!   of the deterministic pieces ported here.
//! - `google_report.py` (2461 lines): NOT started under this chunk's budget. It is a large report
//!   generator that formats/aggregates the same live GSC/PSI/CrUX/GA4/Indexing API responses this
//!   chunk's other four files fetch; a faithful port belongs in its own follow-up chunk once
//!   `gsc_query_v2`/`gsc_inspect`'s live-fetch layer (the gap above) exists for it to consume, so
//!   its pure formatting/aggregation logic isn't ported speculatively against an unported input
//!   shape. Flagged explicitly in the report rather than silently dropped.
//! - `gsc_query.py`'s `list_sites()`/`list_sitemaps()` and its `query` subcommand's delegation to
//!   `gsc_query_v2.query()`: these are thin wrappers with no logic beyond the live API call
//!   itself (already covered by the gap above) and response reshaping identical in kind to what
//!   [`gsc_query_v2::normalize_result`] already demonstrates is portable; not duplicated here.

pub mod date_util;
pub mod google_auth;
pub mod gsc_inspect;
pub mod gsc_query_v2;
