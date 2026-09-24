//! Port of `skills/seo/scripts/{ai_visibility_import,analyze_visual,
//! bing_webmaster,capture_screenshot,checklist_compiler}.py` (chunk
//! w2_028).
//!
//! - `ai_visibility_import`: fully ported (pure row normalization; see the
//!   module doc for the CLI/file-I/O boundary that stays unported).
//! - `checklist_compiler`: fully ported (pure text/JSON transformation).
//! - `bing_webmaster`: fully ported as of packet r33, including the live
//!   HTTPS round trip to the Bing Webmaster Tools API behind
//!   [`bing_webmaster::Transport`] ([`bing_webmaster::ReqwestTransport`] is
//!   the production impl) and the `main()` CLI dispatch
//!   ([`bing_webmaster::run`]).
//! - `web_page_probe` (`capture_screenshot.py` + `analyze_visual.py`):
//!   fully ported as of packet r33, including the live
//!   Chromium-driven page capture/analysis behind
//!   [`web_page_probe::PageBrowser`] ([`web_page_probe::ChromePageBrowser`]
//!   is the production impl) via [`web_page_probe::run_capture_screenshot`]
//!   and [`web_page_probe::run_analyze_visual`].

pub mod ai_visibility_import;
pub mod bing_webmaster;
pub mod checklist_compiler;
pub mod web_page_probe;
