//! Port of `skills/seo/scripts/{pagespeed_check,parse_html,provider_registry,
//! query_ownership,question_inventory}.py` (chunk w2_032).
//!
//! - `provider_registry`: fully ported (pure registry discovery/selection
//!   logic; no secret values are ever read or printed).
//! - `query_ownership`: fully ported (pure GSC query/page evidence
//!   classification).
//! - `question_inventory`: fully ported (pure AEO question-inventory
//!   build from GSC rows plus supplied extras).
//! - `pagespeed_check`: the live PSI/CrUX HTTP round trips are not ported
//!   (no HTTP client dependency in this crate); CWV thresholds/rating, URL
//!   validation, the CrUX origin-vs-URL decision, and the full response-JSON
//!   parsing for both PSI and CrUX are ported in full — see the module doc.
//! - `parse_html`: BeautifulSoup-based DOM tag-finding is not ported (no
//!   HTML/DOM parsing dependency in this crate); every pure
//!   post-extraction transform (word count, link resolution/
//!   classification, JSON-LD parsing, Open Graph/Twitter Card filtering)
//!   is ported in full — see the module doc for the dependency this would
//!   need to close the remaining gap.

pub mod pagespeed_check;
pub mod parse_html;
pub mod provider_registry;
pub mod query_ownership;
pub mod question_inventory;
