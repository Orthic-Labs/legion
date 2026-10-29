//! SQLFluff (PostgreSQL) scanner controls. Pure envelope controls always run; the
//! real-tool controls run only when a genuine `sqlfluff` is installed and otherwise
//! print `SQLFLUFF_UNAVAILABLE` and return (set `LEGION_REQUIRE_SQLFLUFF=1` to make
//! absence a failure). Constructed controls only: no population accuracy, no
//! production admission, no claim beyond the owned rule allowlist.

use legion_audit::{
    native_providers::security::{
        producer::{ArtifactProducer, Production, SandboxPolicy},
        scanners,
    },
    AuditProvider, InventoryEntry, InventoryEnvelope,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sqlfluff");

fn digest(bytes: &[u8]) -> String {
    format!(
        "sha256:{}",
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

fn record(path: &str, violations: Value) -> Value {
    json!({"filepath":path,"violations":violations,"statistics":{}})
}

fn violation(code: &str, line: u64) -> Value {
    json!({"code":code,"description":"finding","start_line_no":line,"start_line_pos":1,"warning":false,"name":"x","fixes":[]})
}

fn selected(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|p| (*p).to_owned()).collect()
}

// ---------- pure controls: always run ----------

#[test]
fn clean_report_is_clean_only_when_every_selected_file_has_a_record() {
    let report = json!([record("./a.sql", json!([])), record("b.sql", json!([]))]);
    let (examined, gaps) = scanners::sqlfluff_examined(&report, &selected(&["a.sql", "b.sql"]));
    assert_eq!(examined.len(), 2);
    assert!(gaps.is_empty());
    // One record short of the denominator: the absent file is a named gap.
    let (examined, gaps) =
        scanners::sqlfluff_examined(&report, &selected(&["a.sql", "b.sql", "c.sql"]));
    assert_eq!(examined.len(), 2);
    assert!(gaps
        .iter()
        .any(|g| g["kind"] == "scanner-file-record-missing" && g["path"] == "c.sql"));
}

#[test]
fn parse_lex_template_errors_never_count_as_examined() {
    for code in ["PRS", "LXR", "TMP"] {
        let report = json!([record("a.sql", json!([violation(code, 2)]))]);
        let (examined, _) = scanners::sqlfluff_examined(&report, &selected(&["a.sql"]));
        assert!(examined.is_empty(), "{code}");
        let normalized = scanners::normalize("sqlfluff", &report, Path::new("/repo"), "");
        assert!(
            normalized
                .gaps
                .iter()
                .any(|g| g["kind"] == "scanner-parser-failed"),
            "{code}"
        );
    }
}

#[test]
fn tool_error_shapes_are_schema_gaps_not_clean_output() {
    // What a crash, usage error or changed CLI would print instead of the envelope.
    for bad in [
        json!({"error":"x"}),
        json!(null),
        json!("text"),
        json!([{"filepath":"a.sql"}]),
        json!([{"filepath":"a.sql","violations":"none"}]),
    ] {
        let (examined, _) = scanners::sqlfluff_examined(&bad, &selected(&["a.sql"]));
        assert!(examined.is_empty(), "{bad}");
        let normalized = scanners::normalize("sqlfluff", &bad, Path::new("/repo"), "");
        assert!(
            normalized
                .gaps
                .iter()
                .any(|g| g["kind"] == "scanner-output-schema-invalid"),
            "{bad}"
        );
    }
}

#[test]
fn empty_array_with_nonempty_denominator_is_not_clean() {
    let (examined, gaps) = scanners::sqlfluff_examined(&json!([]), &selected(&["a.sql"]));
    assert!(examined.is_empty());
    assert!(gaps
        .iter()
        .any(|g| g["kind"] == "scanner-file-record-missing"));
}

#[test]
fn exit_status_and_report_must_agree() {
    let finding = json!([record("a.sql", json!([violation("AM02", 3)]))]);
    let clean = json!([record("a.sql", json!([]))]);
    assert!(scanners::sqlfluff_exit_mismatch(&finding, 0));
    assert!(scanners::sqlfluff_exit_mismatch(&clean, 1));
    assert!(!scanners::sqlfluff_exit_mismatch(&finding, 1));
    assert!(!scanners::sqlfluff_exit_mismatch(&clean, 0));
}

#[test]
fn planted_violation_is_one_candidate_with_known_rule_and_line() {
    let report = json!([record("m.sql", json!([violation("AM02", 3)]))]);
    let normalized = scanners::normalize("sqlfluff", &report, Path::new("/repo"), "");
    assert_eq!(normalized.candidates.len(), 1);
    assert_eq!(normalized.ledger.len(), 1);
    assert_eq!(normalized.candidates[0]["ruleId"], "AM02");
    assert_eq!(normalized.candidates[0]["path"], "m.sql");
    assert_eq!(normalized.candidates[0]["line"], 3);
    assert!(normalized.gaps.is_empty());
}

#[test]
fn command_is_postgres_isolated_and_not_nofail() {
    let args = scanners::sqlfluff_args("/owned/config", &["./a.sql".into()]).join(" ");
    for required in [
        "--dialect postgres",
        "--templater raw",
        "--ignore-local-config",
        "--disable-noqa",
        "--format json",
    ] {
        assert!(args.contains(required), "{required}");
    }
    assert!(!args.contains("--nofail"));
}

#[test]
fn registry_entry_is_unproven_until_qualified() {
    let registry: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/registry/providers.json"
    )))
    .unwrap();
    let entry = registry["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == "security.scanner-sqlfluff")
        .expect("sqlfluff provider registered");
    assert_eq!(entry["selector"], scanners::selector("sqlfluff"));
    assert_eq!(entry["benchmark"]["status"], "unproven");
    assert_eq!(entry["benchmark"]["qualificationDigest"], Value::Null);
    assert_eq!(entry["cleanClaim"], "evidence-only");
}

// ---------- producer controls ----------

struct Repo(PathBuf);
impl Repo {
    fn new(label: &str) -> Self {
        let base = std::env::var_os("LEGION_SQLFLUFF_SCRATCH")
            .map(PathBuf::from)
            .filter(|p| p.is_dir())
            .or_else(|| Some(PathBuf::from("/Volumes/D/scratch")).filter(|p| p.is_dir()))
            .unwrap_or_else(std::env::temp_dir);
        let path = base.join(format!(
            "legion-sqlfluff-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(path.join("repo")).unwrap();
        Self(fs::canonicalize(path).unwrap())
    }
    fn root(&self) -> PathBuf {
        self.0.join("repo")
    }
    fn put(&self, fixture: &str, name: &str) -> InventoryEntry {
        let bytes = fs::read(Path::new(FIXTURES).join(fixture)).unwrap();
        fs::write(self.root().join(name), &bytes).unwrap();
        InventoryEntry {
            path: name.into(),
            symbols: vec![],
            dependencies: vec![],
            package_scripts: vec![],
            source_file: true,
            digest: Some(digest(&bytes)),
        }
    }
}
impl Drop for Repo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn provider() -> AuditProvider {
    serde_json::from_value(json!({"id":"security.scanner-sqlfluff","version":"1.0.0","role":"candidate-generator","phase":"source","dependencies":[],"kind":"rust-algorithm","configuration":{"selector":scanners::selector("sqlfluff")},"cleanClaim":"evidence-only","benchmarkStatus":"unproven","benchmarkRequiredForCleanClaim":false,"qualificationDigest":null,"required":true})).unwrap()
}

fn producer(root: &Path, search: Vec<PathBuf>) -> ArtifactProducer {
    let policy = legion_effects::StaticPolicy {
        decision: legion_effects::PolicyDecision {
            allowed: true,
            policy_id: "sqlfluff-fixture".into(),
            policy_version: 1,
            policy_digest: format!("sha256:{}", "f".repeat(64)),
            reason: None,
        },
    };
    let producer = ArtifactProducer::new(root)
        .with_policy_authorizer(Arc::new(policy))
        .with_search_path(search);
    if cfg!(target_os = "macos") {
        producer
    } else {
        producer.with_sandbox(SandboxPolicy::Disabled)
    }
}

fn evidence(repo: &Repo, entries: Vec<InventoryEntry>, search: Vec<PathBuf>) -> Value {
    let inventory = InventoryEnvelope::new("sqlfluff-controls", "fixture", entries).unwrap();
    match producer(&repo.root(), search).produce(&provider(), &inventory) {
        Production::Artifact(input) => input,
        other => panic!("expected retained scanner evidence, got {other:?}"),
    }
}

fn gap_kinds(input: &Value) -> Vec<String> {
    input["artifacts"]["scannerEvidence"]["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|g| g["kind"].as_str().map(str::to_owned))
        .collect()
}

#[test]
fn absent_sqlfluff_is_a_typed_gap_never_clean() {
    let repo = Repo::new("absent");
    let entry = repo.put("clean.sql.txt", "clean.sql");
    let input = evidence(&repo, vec![entry], vec![]);
    assert!(input["artifacts"]["scannerEvidence"]["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g["reason"] == "tool-missing:sqlfluff"));
    let verdict = scanners::analyze(&input);
    assert_eq!(verdict["complete"], false);
    assert_ne!(verdict["status"], "pass");
}

#[test]
fn inline_config_directive_file_is_refused_not_linted() {
    let repo = Repo::new("directive");
    let entry = repo.put("inline_directive.sql.txt", "directive.sql");
    let input = evidence(&repo, vec![entry], vec![]);
    assert!(gap_kinds(&input).contains(&"scanner-inline-config-directive".to_owned()));
    let verdict = scanners::analyze(&input);
    assert_eq!(verdict["complete"], false);
    assert_ne!(verdict["status"], "pass");
}

// ---------- real tool controls: skip explicitly when sqlfluff is absent ----------

fn sqlfluff_dir() -> Option<PathBuf> {
    let explicit = std::env::var_os("LEGION_SQLFLUFF_BIN").map(PathBuf::from);
    let dirs: Vec<PathBuf> = explicit
        .into_iter()
        .chain(
            std::env::var_os("PATH")
                .map(|p| std::env::split_paths(&p).collect::<Vec<_>>())
                .unwrap_or_default(),
        )
        .collect();
    dirs.into_iter().find(|d| d.join("sqlfluff").is_file())
}

fn require_sqlfluff() -> Option<PathBuf> {
    let found = sqlfluff_dir();
    if found.is_none() {
        assert!(
            std::env::var_os("LEGION_REQUIRE_SQLFLUFF").is_none(),
            "LEGION_REQUIRE_SQLFLUFF set but sqlfluff is not installed"
        );
        eprintln!(
            "SQLFLUFF_UNAVAILABLE: sqlfluff not found; real-tool controls skipped, not passed"
        );
    }
    found
}

#[test]
fn real_sqlfluff_negative_control_with_hostile_repository_config_is_clean() {
    let Some(dir) = require_sqlfluff() else {
        return;
    };
    let repo = Repo::new("clean");
    let entry = repo.put("clean.sql.txt", "clean.sql");
    // A repository config that would break PostgreSQL parsing if it were honored.
    fs::copy(
        Path::new(FIXTURES).join("hostile.sqlfluff.txt"),
        repo.root().join(".sqlfluff"),
    )
    .unwrap();
    let input = evidence(&repo, vec![entry], vec![dir]);
    let found = &input["artifacts"]["scannerEvidence"];
    assert_eq!(found["gaps"], json!([]), "{found}");
    assert_eq!(found["candidates"], json!([]), "{found}");
    assert_eq!(found["examinedPaths"], json!(["clean.sql"]));
}

#[test]
fn real_sqlfluff_positive_control_reports_planted_ambiguity() {
    let Some(dir) = require_sqlfluff() else {
        return;
    };
    let repo = Repo::new("planted");
    let entry = repo.put("planted_am02.sql.txt", "planted.sql");
    let input = evidence(&repo, vec![entry], vec![dir]);
    let found = &input["artifacts"]["scannerEvidence"];
    let candidates = found["candidates"].as_array().unwrap();
    assert!(
        candidates
            .iter()
            .any(|c| c["ruleId"] == "AM02" && c["path"] == "planted.sql"),
        "{found}"
    );
    assert_eq!(found["examinedPaths"], json!(["planted.sql"]));
    assert_eq!(scanners::analyze(&input)["status"], "candidates");
}

#[test]
fn real_sqlfluff_parse_failure_is_a_named_gap_never_clean() {
    let Some(dir) = require_sqlfluff() else {
        return;
    };
    let repo = Repo::new("parse");
    let broken = repo.put("parse_error.sql.txt", "broken.sql");
    let good = repo.put("clean.sql.txt", "good.sql");
    let input = evidence(&repo, vec![broken, good], vec![dir]);
    let found = &input["artifacts"]["scannerEvidence"];
    assert!(
        gap_kinds(&input).contains(&"scanner-parser-failed".to_owned()),
        "{found}"
    );
    // The unparsable file is not examined; the valid one still is.
    assert_eq!(found["examinedPaths"], json!(["good.sql"]));
    let verdict = scanners::analyze(&input);
    assert_eq!(verdict["complete"], false);
    assert_ne!(verdict["status"], "pass");
}
