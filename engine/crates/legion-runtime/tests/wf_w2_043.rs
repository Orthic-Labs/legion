//! Integration tests for the ported `wf_port::w2_043` module (production
//! entry point `run_design_gate`), mirroring `tests/design-gate.test.mjs`
//! against `src/lib/design-gate.mjs`.
//!
//! See `src/wf_port/w2_043/mod.rs` for what this chunk ports.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use legion_runtime::wf_port::w2_043::{
    load_banned_words, run_design_gate, GateOptions, Status, BREAKPOINTS,
};

/// The repository root, so `load_banned_words`/`run_design_gate` can read
/// the real `skills/designer/references/banned-words.md`, exactly like the
/// JS test suite does against its own repo root.
fn repo_root() -> PathBuf {
    // engine/crates/legion-runtime -> engine/crates -> engine -> repo root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

struct TempSurface {
    dir: PathBuf,
}

impl TempSurface {
    fn new() -> Self {
        // Windows' `SystemTime::now()` has coarse (~15ms) resolution, so two
        // `TempSurface`s created on different test threads within the same
        // tick can otherwise get an identical nanos value and collide on
        // the same directory — one test's fixture files then leak into the
        // other's "empty surface" case. An in-process atomic counter makes
        // each instance unique regardless of clock granularity.
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "legion-design-gate-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            unique
        ));
        fs::create_dir_all(&dir).unwrap();
        TempSurface { dir }
    }

    fn path(&self) -> &Path {
        &self.dir
    }
}

impl Drop for TempSurface {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Mirrors the JS test helper `surface({ html, motion })`.
fn surface(html: &str, motion: Option<&str>) -> TempSurface {
    let s = TempSurface::new();
    fs::write(s.path().join("index.html"), html).unwrap();
    fs::write(s.path().join("motion-plan.md"), "# motion\n").unwrap();
    if let Some(verdict) = motion {
        fs::write(
            s.path().join("motion-gate.json"),
            format!(r#"{{"verdict":"{verdict}"}}"#),
        )
        .unwrap();
    }
    s
}

fn default_surface() -> TempSurface {
    surface(
        "<html><body><p>Plain honest copy.</p></body></html>",
        Some("pass"),
    )
}

fn run(root: &Path, surface: &Path) -> legion_runtime::wf_port::w2_043::GateReport {
    run_design_gate(GateOptions {
        root,
        surface,
        env: HashMap::new(),
    })
}

fn find<'a>(
    report: &'a legion_runtime::wf_port::w2_043::GateReport,
    id: &str,
) -> &'a legion_runtime::wf_port::w2_043::Check {
    report
        .checks
        .iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("missing check {id}"))
}

#[test]
fn banned_vocabulary_is_read_from_the_documented_source_not_duplicated_in_code() {
    let root = repo_root();
    let banned = load_banned_words(&root);
    assert!(banned.available);
    assert!(banned.vocabulary.iter().any(|w| w == "leverage"));
    assert!(
        banned.vocabulary.len() >= 10,
        "expected a real term list, got {}",
        banned.vocabulary.len()
    );
    assert!(banned.structural.len() >= 3, "parses the structural table");
}

#[test]
fn banned_words_and_em_dashes_in_built_html_fail_the_gate() {
    let root = repo_root();
    let s = surface(
        "<p>We leverage synergy to unlock value \u{2014} truly revolutionary.</p>",
        Some("pass"),
    );
    let report = run(&root, s.path());
    assert_eq!(report.verdict, Status::Fail);
    let words = find(&report, "banned-words");
    assert_eq!(words.status, Status::Fail);
    let mut terms: Vec<String> = words.vocab_hits.iter().map(|h| h.term.clone()).collect();
    terms.sort();
    assert_eq!(
        terms,
        vec!["leverage", "revolutionary", "synergy", "unlock"]
    );
    assert_eq!(find(&report, "typography").status, Status::Fail, "em dash is caught");
}

#[test]
fn clean_copy_passes_text_checks_without_flagging_ascii_as_smart_quotes() {
    let root = repo_root();
    // banned-words.md carries a malformed escape for U+2019 that decodes to
    // a space; a naive decoder flags every space in the build.
    let s = surface(
        "<p>It's plain ASCII copy with 'quotes' and no tells.</p>",
        Some("pass"),
    );
    let report = run(&root, s.path());
    assert_eq!(find(&report, "banned-words").status, Status::Pass);
    assert_eq!(
        find(&report, "typography").status,
        Status::Pass,
        "ASCII apostrophes are not smart quotes"
    );
}

#[test]
fn a_missing_motion_gate_blocks_and_a_failed_motion_verdict_blocks() {
    let root = repo_root();
    let missing = surface("<p>ok</p>", None);
    let report = run(&root, missing.path());
    assert_eq!(find(&report, "motion-gate-verdict").status, Status::Fail);
    assert!(report.blocking.contains(&"motion-gate-verdict".to_string()));

    let failed = surface("<p>ok</p>", Some("fail"));
    let report = run(&root, failed.path());
    assert_eq!(find(&report, "motion-gate-verdict").status, Status::Fail);
}

#[test]
fn a_check_that_cannot_run_reports_unavailable_and_blocks_never_a_silent_pass() {
    let root = repo_root();
    let dir = TempSurface::new();
    let report = run(&root, dir.path());
    assert_eq!(
        find(&report, "banned-words").status,
        Status::Unavailable,
        "no text to scan is not a pass"
    );
    assert_eq!(find(&report, "lighthouse").status, Status::Unavailable);
    assert_eq!(report.verdict, Status::Fail, "unavailable required checks block the gate");
    assert!(report.counts.pass < report.counts.total);
}

#[test]
fn a_waiver_clears_a_check_only_when_it_carries_a_reason() {
    let root = repo_root();
    let s = surface("<p>We leverage synergy.</p>", Some("pass"));
    fs::create_dir_all(s.path().join("artifacts/qa")).unwrap();
    fs::write(
        s.path().join("artifacts/qa/gate-waivers.json"),
        r#"{"banned-words":"","lighthouse":"no CI browser"}"#,
    )
    .unwrap();
    let report = run(&root, s.path());
    assert_eq!(
        find(&report, "banned-words").waived,
        None,
        "empty reason does not waive"
    );
    assert_eq!(
        find(&report, "lighthouse").waived,
        Some(true),
        "reasoned waiver clears the check"
    );
    assert!(report.blocking.contains(&"banned-words".to_string()));
    assert!(!report.blocking.contains(&"lighthouse".to_string()));
}

#[test]
fn the_gate_reports_the_five_specified_breakpoints() {
    assert_eq!(BREAKPOINTS, [360, 768, 1024, 1440, 1920]);
}

#[test]
fn default_surface_helper_round_trips_through_the_gate() {
    let root = repo_root();
    let s = default_surface();
    let report = run(&root, s.path());
    assert!(!report.checks.is_empty());
}
