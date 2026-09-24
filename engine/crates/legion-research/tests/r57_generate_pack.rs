//! Packet r57 tests: `legion_research::wf_port::r57`, ported from
//! `generate_pack.py` (India consumer-complaint filing pack generator).
//!
//! No network or browser I/O is involved (the legacy script only reads a
//! YAML file and writes .docx files), so these are plain filesystem tests
//! against isolated per-test temp directories.

use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use legion_research::wf_port::r57;
use legion_research::wf_port::r57::{builders, yaml_case};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_dir(label: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "r57-{}-{}-{}",
        std::process::id(),
        label,
        n
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

const CASE_YAML: &str = r##"
output:
  dir: "OUT_DIR_PLACEHOLDER"
  case_slug: "Doe_v_Acme"
  start_number: 1
filing:
  year: 2026
  signing_month: "March"
commission:
  name: "DISTRICT CONSUMER DISPUTES REDRESSAL COMMISSION"
  place: "New Delhi"
complainant:
  name: "Jane Doe"
  father_name: "Richard Doe"
  age: 34
  address: "12 Example Road, New Delhi"
  city: "New Delhi"
  email: "jane@example.com"
  mobile: "9999999999"
  faith: "the Hindu religion"
opposite_parties:
  - name: "Acme Retail Pvt. Ltd."
    operating_as: "Acme Store"
    is_individual: false
    cin: "U12345DL2020PTC000001"
    address: "1 Corporate Ave, New Delhi"
    email: "support@acme.example"
    phone: "1800-000-000"
consumer_status:
  narrative: "Yes, the Complainant purchased goods for consideration."
money:
  consideration_paid: 150000
  consideration_words: "One Lakh Fifty Thousand Rupees only"
  total_claim: 250000
  total_claim_words: "Two Lakh Fifty Thousand Rupees only"
complaint_paragraphs:
  - "That the Complainant purchased a product from OP-1."
  - "That the product was defective on delivery."
cause_of_action: "The cause of action arose on the date of delivery."
limitation: "The complaint is within limitation."
jurisdiction_paragraphs:
  - "This Commission has territorial jurisdiction."
grounds:
  - "Deficiency in service."
  - "Unfair trade practice."
prayer:
  - "Direct OP-1 to refund the consideration amount."
  - "Award compensation for mental agony."
annexures:
  - id: "A-1"
    description: "Tax invoice"
  - id: "A-2"
    description: "Email correspondence"
synopsis: "This is a brief synopsis of the dispute."
dates_and_events:
  - date: "01.01.2026"
    event: "Product purchased."
  - date: "05.01.2026"
    event: "Defect reported."
nch:
  docket: "NCH12345"
  date: "10.01.2026"
nature_of_complaint: "Deficiency in service and unfair trade practice."
brief_facts: "The Complainant purchased a defective product from OP-1."
territorial_jurisdiction: "Cause of action arose within the territorial limits of this Commission."
"##;

fn case_yaml_for(out_dir: &std::path::Path) -> String {
    CASE_YAML.replace("OUT_DIR_PLACEHOLDER", &out_dir.to_string_lossy())
}

fn zip_entry_names(path: &std::path::Path) -> Vec<String> {
    let file = std::fs::File::open(path).expect("open docx");
    let mut zip = zip::ZipArchive::new(file).expect("valid zip");
    (0..zip.len())
        .map(|i| zip.by_index(i).unwrap().name().to_string())
        .collect()
}

#[test]
fn validate_reports_missing_top_level_keys_like_python_sys_exit() {
    let case: serde_yaml::Value = serde_yaml::from_str("output:\n  dir: x\n").unwrap();
    let err = r57::validate(&case).unwrap_err();
    assert!(err.starts_with("Case YAML is missing required keys: "));
    assert!(err.contains("filing"));
    assert!(err.contains("opposite_parties"));
}

#[test]
fn validate_rejects_empty_opposite_parties() {
    let dir = temp_dir("empty-op");
    let yaml = case_yaml_for(&dir).replace(
        "opposite_parties:\n  - name: \"Acme Retail Pvt. Ltd.\"\n    operating_as: \"Acme Store\"\n    is_individual: false\n    cin: \"U12345DL2020PTC000001\"\n    address: \"1 Corporate Ave, New Delhi\"\n    email: \"support@acme.example\"\n    phone: \"1800-000-000\"\n",
        "opposite_parties: []\n",
    );
    let case: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
    let err = r57::validate(&case).unwrap_err();
    assert_eq!(err, "Case YAML has no opposite_parties.");
}

#[test]
fn validate_rejects_non_sequential_annexure_ids() {
    let dir = temp_dir("bad-annex");
    let yaml = case_yaml_for(&dir).replace("id: \"A-2\"", "id: \"A-9\"");
    let case: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
    let err = r57::validate(&case).unwrap_err();
    assert!(err.starts_with("Annexure ids must be sequential A-1, A-2, ...  found"));
    assert!(err.contains("'A-9'"));
}

#[test]
fn complaint_para_count_matches_body_plus_fixed_sections() {
    let dir = temp_dir("para-count");
    let yaml = case_yaml_for(&dir);
    let case: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
    // 2 body paragraphs + cause(1) + limitation(1) + jurisdiction(1) + grounds(1) = 6
    assert_eq!(builders::complaint_para_count(&case), 6);
}

#[test]
fn annexure_range_spans_first_to_last_id() {
    let dir = temp_dir("annex-range");
    let yaml = case_yaml_for(&dir);
    let case: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
    assert_eq!(builders::annexure_range(&case).as_deref(), Some("A-1 to A-2"));
}

#[test]
fn annexure_range_is_none_without_annexures() {
    let dir = temp_dir("annex-none");
    let yaml = case_yaml_for(&dir).replace(
        "annexures:\n  - id: \"A-1\"\n    description: \"Tax invoice\"\n  - id: \"A-2\"\n    description: \"Email correspondence\"\n",
        "annexures: []\n",
    );
    let case: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
    assert_eq!(builders::annexure_range(&case), None);
}

#[test]
fn comma_int_groups_by_three_digits() {
    assert_eq!(yaml_case::comma_int(0), "0");
    assert_eq!(yaml_case::comma_int(999), "999");
    assert_eq!(yaml_case::comma_int(1000), "1,000");
    assert_eq!(yaml_case::comma_int(150000), "150,000");
    assert_eq!(yaml_case::comma_int(-2500), "-2,500");
}

#[test]
fn op_label_singular_and_numbered() {
    assert_eq!(builders::op_label(1, 1), "… OPPOSITE PARTY");
    assert_eq!(builders::op_label(1, 2), "… OPPOSITE PARTY NO. 1");
    assert_eq!(builders::op_label(2, 2), "… OPPOSITE PARTY NO. 2");
}

#[test]
fn run_writes_six_docx_files_when_party_in_person_defaults_true() {
    let dir = temp_dir("run-six");
    let case_path = dir.join("case.yaml");
    std::fs::write(&case_path, case_yaml_for(&dir)).unwrap();

    let code = r57::run(&[case_path.to_string_lossy().to_string()]);
    assert_eq!(code, 0);

    let entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".docx"))
        .collect();
    assert_eq!(entries.len(), 6, "expected 6 docx files, got {:?}", entries);
    assert!(entries.iter().any(|n| n.starts_with("01_Doe_v_Acme_Index")));
    assert!(entries
        .iter()
        .any(|n| n.contains("Consumer_Complaint_with_Affidavit")));
    assert!(entries
        .iter()
        .any(|n| n.contains("Party_In_Person_Declaration")));

    // Every generated file must be a well-formed docx (zip with the parts
    // python-docx's Document.save() would also produce).
    for name in &entries {
        let names = zip_entry_names(&dir.join(name));
        assert!(names.contains(&"word/document.xml".to_string()));
        assert!(names.contains(&"[Content_Types].xml".to_string()));
        assert!(names.contains(&"word/styles.xml".to_string()));
    }
}

#[test]
fn run_skips_party_in_person_file_when_disabled() {
    let dir = temp_dir("run-five");
    let yaml = format!("{}\nparty_in_person: false\n", case_yaml_for(&dir));
    let case_path = dir.join("case.yaml");
    std::fs::write(&case_path, yaml).unwrap();

    let code = r57::run(&[case_path.to_string_lossy().to_string()]);
    assert_eq!(code, 0);

    let entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".docx"))
        .collect();
    assert_eq!(entries.len(), 5, "expected 5 docx files, got {:?}", entries);
    assert!(!entries
        .iter()
        .any(|n| n.contains("Party_In_Person_Declaration")));
}

#[test]
fn run_honours_out_override_over_output_dir_in_yaml() {
    let yaml_dir = temp_dir("run-out-yaml-dir");
    let override_dir = temp_dir("run-out-override-dir");
    let case_path = yaml_dir.join("case.yaml");
    // The YAML's own output.dir points at a directory we never use.
    std::fs::write(&case_path, case_yaml_for(&yaml_dir.join("unused"))).unwrap();

    let code = r57::run(&[
        case_path.to_string_lossy().to_string(),
        "--out".to_string(),
        override_dir.to_string_lossy().to_string(),
    ]);
    assert_eq!(code, 0);

    let entries: Vec<_> = std::fs::read_dir(&override_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .count();
    assert_eq!(entries, 6);
}

#[test]
fn run_reports_usage_error_without_case_yaml_argument() {
    let code = r57::run(&[]);
    assert_eq!(code, 2);
}

#[test]
fn run_reports_validation_error_for_malformed_case_yaml() {
    let dir = temp_dir("run-bad-case");
    let case_path = dir.join("case.yaml");
    std::fs::write(&case_path, "output:\n  dir: x\n").unwrap();
    let code = r57::run(&[case_path.to_string_lossy().to_string()]);
    assert_eq!(code, 1);
}

#[test]
fn docx_paragraph_and_table_roundtrip_contains_expected_text() {
    let dir = temp_dir("docx-roundtrip");
    let mut doc = r57::docx::Doc::new();
    doc.para(r57::docx::para("Hello, World.").bold(true));
    doc.table(
        Some(vec!["A".to_string(), "B".to_string()]),
        vec![vec!["1".to_string(), "2".to_string()]],
    );
    doc.page_break();
    let path = dir.join("sample.docx");
    doc.save(&path).unwrap();

    let file = std::fs::File::open(&path).unwrap();
    let mut zip = zip::ZipArchive::new(file).unwrap();
    let mut xml = String::new();
    zip.by_name("word/document.xml")
        .unwrap()
        .read_to_string(&mut xml)
        .unwrap();
    assert!(xml.contains("Hello, World."));
    assert!(xml.contains("w:type=\"page\""));
    assert!(xml.contains("<w:tbl>"));
}
