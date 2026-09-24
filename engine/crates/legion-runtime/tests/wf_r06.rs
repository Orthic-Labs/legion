//! Integration tests for wf_port packet r06
//! (`skills/designer/engine/scripts/detector/design-system.mjs`).
//!
//! `w2_011::design_system` already ports this file's pure core
//! (`parseFrontmatter` / `normalizeDesignSystem` / the allow-list checks /
//! `checkSourceDesignSystem`, unit-tested in that module). This packet
//! closed the two remaining gaps noted in `w2_011`'s module doc:
//! `loadDesignSystemForCwd`'s `fs` wrapper (`design_system_fs`, tested
//! there with a fake filesystem) and `collectStaticDesignSystemFindings`
//! (`design_system_dom`, tested there with a fake DOM evaluator). This
//! file adds end-to-end coverage that wires the fs loader's output
//! straight into the DOM-findings collector, the way `cli/main.mjs` does
//! in JS (load the design system for a cwd, then scan a page against it),
//! without touching a real filesystem or launching a real browser.

use std::cell::RefCell;
use std::collections::HashMap;

use legion_runtime::wf_port::w2_011::{
    collect_static_design_system_findings, load_design_system_for_cwd, DesignDomEvaluator,
    DesignFs, ElementStyleObservation,
};

#[derive(Default)]
struct FakeFs {
    files: RefCell<HashMap<String, (String, f64)>>,
}

impl FakeFs {
    fn put(&self, path: &str, content: &str, mtime_ms: f64) {
        self.files
            .borrow_mut()
            .insert(path.to_string(), (content.to_string(), mtime_ms));
    }
}

impl DesignFs for FakeFs {
    fn exists(&self, path: &str) -> bool {
        self.files.borrow().contains_key(path)
    }
    fn read_to_string(&self, path: &str) -> Option<String> {
        self.files.borrow().get(path).map(|(c, _)| c.clone())
    }
    fn mtime_ms(&self, path: &str) -> Option<f64> {
        self.files.borrow().get(path).map(|(_, m)| *m)
    }
}

struct FakeEvaluator(Vec<ElementStyleObservation>);
impl DesignDomEvaluator for FakeEvaluator {
    fn observe(&self, _html: &str) -> Result<Vec<ElementStyleObservation>, String> {
        Ok(self.0.clone())
    }
}

#[test]
fn loaded_design_system_flags_undeclared_font_and_color_in_a_scanned_page() {
    let fs = FakeFs::default();
    fs.put(
        "/repo/DESIGN.md",
        "---\ntypography:\n  body:\n    fontFamily: \"Inter, sans-serif\"\ncolors:\n  brand: \"#336699\"\n---\n",
        1000.0,
    );
    let ds = load_design_system_for_cwd(&fs, "/repo").expect("design system should load");

    let evaluator = FakeEvaluator(vec![ElementStyleObservation {
        tag: "div".to_string(),
        sample_text: "Sign up".to_string(),
        has_direct_text: true,
        font_family: Some("\"Comic Sans MS\", sans-serif".to_string()),
        color: Some("rgb(255, 0, 255)".to_string()),
        ..Default::default()
    }]);

    let findings = collect_static_design_system_findings(
        &evaluator,
        "<div>Sign up</div>",
        "index.html",
        Some(&ds),
    )
    .expect("evaluator should not fail");

    assert!(findings
        .iter()
        .any(|f| f.antipattern == "design-system-font" && f.ignore_value == "comic sans ms"));
    assert!(findings
        .iter()
        .any(|f| f.antipattern == "design-system-color" && f.ignore_value == "rgb(255, 0, 255)"));
}

#[test]
fn loaded_design_system_allows_colors_within_channel_tolerance() {
    let fs = FakeFs::default();
    fs.put(
        "/repo/DESIGN.md",
        "---\ncolors:\n  brand: \"#336699\"\n---\n",
        1000.0,
    );
    let ds = load_design_system_for_cwd(&fs, "/repo").expect("design system should load");

    let evaluator = FakeEvaluator(vec![ElementStyleObservation {
        tag: "div".to_string(),
        background_color: Some("rgb(51, 102, 154)".to_string()), // within tolerance of #336699
        ..Default::default()
    }]);

    let findings =
        collect_static_design_system_findings(&evaluator, "<div></div>", "index.html", Some(&ds))
            .unwrap();
    assert!(findings.is_empty());
}

#[test]
fn no_design_md_means_no_design_system_and_no_findings() {
    let fs = FakeFs::default();
    let evaluator = FakeEvaluator(vec![ElementStyleObservation {
        tag: "div".to_string(),
        background_color: Some("rgb(255, 0, 255)".to_string()),
        ..Default::default()
    }]);
    assert!(load_design_system_for_cwd(&fs, "/repo").is_none());
    let findings =
        collect_static_design_system_findings(&evaluator, "<div></div>", "index.html", None)
            .unwrap();
    assert!(findings.is_empty());
}
