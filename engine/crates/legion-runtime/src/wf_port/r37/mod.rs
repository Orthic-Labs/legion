//! wf_port packet r37 (target crate `legion-runtime`).
//!
//! Source file: `skills/seo/scripts/google_report.py` (2461 lines). Flagged
//! as explicitly NOT started in `wf_port::w2_030`'s module doc ("a faithful
//! port belongs in its own follow-up chunk"); this packet is that follow-up.
//!
//! Integrator note (this module is not yet wired into the crate -- mirroring
//! the same disclaimer `wf_port::w2_030`'s own module doc and test file
//! carry): add `pub mod r37;` to `wf_port::mod`'s module list to make
//! `legion_runtime::wf_port::r37::*` reachable. No other file needs editing.
//!
//! ## What is ported
//!
//! Every function in the Python file, faithfully, across five submodules:
//! - [`colors`]: `BRAND`, `_score_color`, `_rating_color`, `_score_class`,
//!   `_rating_css_class`.
//! - [`charts`]: `chart_lighthouse_gauges`, `chart_cwv_distributions`,
//!   `chart_cwv_timeline`, `chart_top_queries`, `chart_index_status` -- same
//!   data selection/sort/filter logic as the Python, rendered as SVG instead
//!   of a matplotlib PNG (see the module doc there for why: no charting
//!   crate is in this packet's allowed-crate list).
//! - [`css`]: `_build_css`, extracted brace-for-brace from the Python
//!   f-string.
//! - [`sections`]: `_img_tag`, `_chart_html`, `_metric_card`,
//!   `_build_title_page`, `_build_toc`, `_build_executive_summary`,
//!   `_build_cwv_section`, `_build_gsc_section`, `_build_indexation_section`,
//!   `_build_recommendations`, `_build_methodology_footer`.
//! - [`report`]: `generate_report`'s chart-generation and HTML-assembly
//!   blocks, and `_review_pdf`. PDF rendering is `weasyprint` in the Python
//!   vs. `headless_chrome::Tab::print_to_pdf` here (see [`report`]'s module
//!   doc for the documented Paged-Media-margin-box fidelity gap this implies).
//! - [`xlsx`]: `generate_xlsx`, `_severity_fill`, `_style_header`,
//!   `_auto_width` -- writes the `.xlsx` OOXML package directly with the
//!   `zip` crate (no spreadsheet crate is allowed; same approach as
//!   `wf_port::w2_007::html2pptx`'s `.pptx`).
//! - [`cli`]: `main()` / the `argparse` setup, as `parse_args` +
//!   `pub fn run(argv, timestamp) -> i32`.
//! - [`jget`]: shared `serde_json::Value` accessor helpers standing in for
//!   Python's `dict.get(key, default)` chains (not a port of any one
//!   function; a shim every other submodule here leans on).
//!
//! ## What is NOT ported, and why
//!
//! - Exact pixel-for-pixel chart rendering: matplotlib PNGs are ported as
//!   equivalent-data SVGs (documented in [`charts`]'s module doc as a
//!   deliberate format substitution, not a capability gap -- every function's
//!   data selection, sorting, filtering, and suppression logic is ported
//!   verbatim).
//! - PDF page-number/footer margin boxes from `@page` CSS (`@bottom-center`
//!   etc.): Chrome's print-to-PDF (`headless_chrome::Tab::print_to_pdf`) does
//!   not implement CSS Paged Media margin boxes the way WeasyPrint does; see
//!   [`report`]'s module doc. The HTML-format output is unaffected -- the
//!   full CSS (including these rules) is ported verbatim into it and renders
//!   correctly in any browser.
//! - `_review_pdf`'s `page_count` field: the Python's own value is `None`
//!   unless the optional `pypdf` import succeeds; no PDF-parsing crate is in
//!   this packet's allowed-crate list, so this port keeps the same
//!   "absent unless a PDF parser is available" behavior by omitting the
//!   field. See [`report::review_pdf`]'s doc comment.
//! - `_build_title_page`'s Google-logo lookup
//!   (`Path(__file__).parent.parent / "charts" / "google_logo.png"`), which
//!   resolves a path relative to the Python script's own on-disk location.
//!   Ported as a caller-supplied `Option<&Path>` parameter instead of
//!   hardcoding a developer-local skill-tree layout into the crate; see
//!   [`sections`]'s module doc.

pub mod charts;
pub mod cli;
pub mod colors;
pub mod css;
pub mod jget;
pub mod report;
pub mod sections;
pub mod xlsx;
