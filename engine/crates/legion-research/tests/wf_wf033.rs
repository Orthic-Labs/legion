//! Integration test for wf033
//! (`src/lib/research-core/workflows/legal/india/consumer/scripts/generate_pack.py`
//! + `src/lib/research-core/workflows/legal/india/criminal/__init__.py`), exercised
//! against the crate's public API.
//!
//! NOTE: this file depends on `pub mod wf_port;` and, inside it, `pub mod wf033;`
//! landing in `src/lib.rs` / `src/wf_port/mod.rs` — files this packet does not own.
//! The exact patch is in the packet report (`wf033.md`). Until the integrator
//! applies it, this file will not compile — the same prerequisite `tests/wf_wf030.rs`
//! already documents for its own sibling-module dependency. `engine/Cargo.toml`
//! also needs a `serde_yaml` dependency added to `legion-research`'s
//! `[dependencies]` (already present in `engine/Cargo.lock` at 0.9.34 for other
//! crates in the workspace) — see the report for the exact patch.
//!
//! `criminal/__init__.py` is an empty Python package marker with zero lines of
//! logic; it has no Rust equivalent to test (DROP, recorded in the packet report).

use std::fs;
use std::path::PathBuf;

use legion_research::wf_port::wf033::{
    annexure_range, complaint_para_count, file_names, summary_text, validate,
};

fn fixture_yaml() -> serde_yaml::Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/wf_wf033/case-template.yaml");
    let text = fs::read_to_string(path).expect("read case-template.yaml fixture");
    serde_yaml::from_str(&text).expect("parse case-template.yaml fixture")
}

// --- generate_pack.py (structure + cross-reference half; docx serialization
// is out of scope, see the module doc comment and the packet report) --------

#[test]
fn the_shipped_case_template_validates() {
    // case-template.yaml is the exact file matter-writers copy in production
    // (`src/lib/research-core/workflows/legal/india/consumer/scripts/case-template.yaml`).
    // It carries every REQUIRED_TOP_KEYS entry with placeholder values, so
    // validate() must accept it exactly as Python's validate() does.
    let case = fixture_yaml();
    assert!(validate(&case).is_ok());
}

#[test]
fn the_shipped_case_template_computes_a_consistent_complaint_para_count() {
    let case = fixture_yaml();
    // template.yaml: 3 complaint_paragraphs + 1 cause + 1 limitation
    // + 2 jurisdiction_paragraphs + 1 grounds intro = 8
    assert_eq!(complaint_para_count(&case).unwrap(), 8);
}

#[test]
fn the_shipped_case_template_has_a_single_annexure() {
    let case = fixture_yaml();
    assert_eq!(annexure_range(&case), Some("A-1 to A-1".to_string()));
}

#[test]
fn the_shipped_case_template_plans_six_files_in_order() {
    let case = fixture_yaml();
    let names = file_names(&case).unwrap();
    assert_eq!(
        names,
        vec![
            "01_Matter_Index.docx".to_string(),
            "02_Matter_Proforma.docx".to_string(),
            "03_Matter_Synopsis_and_Dates.docx".to_string(),
            "04_Matter_Memo_of_Parties.docx".to_string(),
            "05_Matter_Consumer_Complaint_with_Affidavit.docx".to_string(),
            "06_Matter_Party_In_Person_Declaration.docx".to_string(),
        ]
    );
}

#[test]
fn the_shipped_case_template_summary_matches_pythons_stdout_shape() {
    let case = fixture_yaml();
    let text = summary_text(&case, "/tmp/out").unwrap();
    assert!(text.starts_with("Generated 6 files in /tmp/out\n"));
    assert!(text.contains("complaint paragraphs: 1 to 8\n"));
    assert!(text.contains("annexures: A-1 to A-1\n"));
    assert!(text.contains(
        "NEXT: verify legal substance, confirm statute citations against\nreferences/cp-act-2019.md, then notarise file 05 and file on e-Jagriti.\n"
    ));
}

#[test]
fn removing_a_required_top_key_from_the_template_fails_validation() {
    let mut case = fixture_yaml();
    case.as_mapping_mut().unwrap().remove("commission");
    let err = validate(&case).unwrap_err();
    assert_eq!(err, "Case YAML is missing required keys: commission");
}
