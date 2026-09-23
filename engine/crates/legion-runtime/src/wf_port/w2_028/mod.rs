//! Port of `skills/seo/scripts/{ai_visibility_import,analyze_visual,
//! bing_webmaster,capture_screenshot,checklist_compiler}.py` (chunk
//! w2_028).
//!
//! - `ai_visibility_import`: fully ported (pure row normalization; see the
//!   module doc for the CLI/file-I/O boundary that stays unported).
//! - `checklist_compiler`: fully ported (pure text/JSON transformation).
//! - `bing_webmaster`: the live HTTPS round trip to the Bing Webmaster
//!   Tools API is not ported (no HTTP client dependency in this crate);
//!   every pure piece around it — key validation, method/subcommand
//!   mapping, request URL construction, response-envelope unwrap, dispatch
//!   resolution — is ported in full.
//! - `web_page_probe` (`capture_screenshot.py` + `analyze_visual.py`): the
//!   actual Playwright-driven page capture/analysis is not ported (no
//!   browser-automation dependency in this crate); the pure URL
//!   normalization, viewport table, SSRF guard, and output-path traversal
//!   guard both scripts share are ported in full.

pub mod ai_visibility_import;
pub mod bing_webmaster;
pub mod checklist_compiler;
pub mod web_page_probe;
