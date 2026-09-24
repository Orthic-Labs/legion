//! Adapts `wf_port::r05::real_detectors` (the production `detectText`/
//! `detectHtml` composition, ultimately backed by `hook-lib.mjs`'s sibling
//! `detect-antipatterns.mjs`) onto the [`super::Detector`] trait `run_hook`
//! (r14) and `r13::run` inject, so `legion script designer/hook` and
//! `designer/hook-before-edit` run the real detector instead of a fake.
//!
//! `ScanOptions`/`DesignSystemInfo` here only carry a `md_newer_than_json`
//! flag (used for the design-system-staleness note in the rendered
//! template), not the parsed `DesignSystem` itself, so this adapter loads
//! the real `DesignSystem` fresh per call via
//! `r05::design_system_loader::load_design_system_for_cwd`, matching
//! `detectText`/`detectHtml`'s own `cwd`-relative lookup in the JS.

use std::cell::RefCell;
use std::path::Path;

use super::{DesignSystemInfo, Detector as R14Detector, Finding, ScanOptions};
use crate::wf_port::r05::design_system_loader::load_design_system_for_cwd;
use crate::wf_port::r05::output::CliFinding;
use crate::wf_port::r05::real_detectors::{detect_html, detect_text};
use crate::wf_port::w2_011::design_system::DesignSystem;

fn cli_finding_to_finding(f: CliFinding) -> Finding {
    Finding {
        antipattern: f.antipattern,
        line: f.line as i64,
        ignore_value: f.ignore_value,
        value: None,
        detail: f.description.clone(),
        snippet: Some(f.snippet),
        name: f.name,
        description: f.description,
        file: Some(f.file),
    }
}

/// Production [`R14Detector`] wired to `r05::real_detectors::detect_text`/
/// `detect_html`. `run_hook`/`r13::run` always call
/// [`load_design_system_for_cwd`](R14Detector::load_design_system_for_cwd)
/// with the resolved project cwd before any `detect_text`/`detect_html`
/// call in the same scan (`design_system_options` runs first, and its
/// result is threaded into every subsequent `scan_options`), so this caches
/// the one real `DesignSystem` it loads there and reuses it for the scan,
/// matching `detectText`/`detectHtml`'s own single per-project lookup.
#[derive(Default)]
pub struct RealHookDetector {
    cached: RefCell<Option<DesignSystem>>,
}

impl RealHookDetector {
    pub fn new() -> Self {
        Self::default()
    }
}

impl R14Detector for RealHookDetector {
    fn detect_text(&self, content: &str, file_path: &str, scan_options: &ScanOptions) -> Vec<Finding> {
        let design_system = if scan_options.design_system.is_some() {
            self.cached.borrow().clone()
        } else {
            None
        };
        detect_text(content, file_path, design_system.as_ref())
            .into_iter()
            .map(cli_finding_to_finding)
            .collect()
    }

    fn detect_html(&self, file_path: &str, scan_options: &ScanOptions) -> Vec<Finding> {
        let design_system = if scan_options.design_system.is_some() {
            self.cached.borrow().clone()
        } else {
            None
        };
        detect_html(file_path, design_system.as_ref())
            .unwrap_or_default()
            .into_iter()
            .map(cli_finding_to_finding)
            .collect()
    }

    fn load_design_system_for_cwd(&self, project_cwd: &Path) -> Option<DesignSystemInfo> {
        let ds = load_design_system_for_cwd(project_cwd);
        let found = ds.is_some();
        *self.cached.borrow_mut() = ds;
        found.then_some(DesignSystemInfo { md_newer_than_json: false })
    }
}
