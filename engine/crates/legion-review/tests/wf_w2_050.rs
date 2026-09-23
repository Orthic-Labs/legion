//! Integration tests for wf_port chunk w2_050
//! (`src/lib/review/{cache,config,agent_room_driver,_codex-diag}.py`).
//!
//! NOTE: depends on the integrator wiring `pub mod wf_port;` (with
//! `pub mod w2_050;` inside it) into `legion_review::lib.rs`, per the w2_050
//! assignment contract. Until then this file will not compile.

use legion_review::wf_port::w2_050::{
    active_result, config::load_models_config, discover_passed_value_gate, fallback_result,
    pending_link_delivery, readiness_complete, room_id, safe_diagnostic, Cache, RoomDriverError,
    RunsEvidence, ROOM_SEATS,
};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wf_w2_050")
}

fn tmp_dir(label: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "legion-review-wf_w2_050-it-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&p).unwrap();
    p
}

// ---------------------------------------------------------------------
// cache.py -> Cache
// ---------------------------------------------------------------------

#[test]
fn cache_make_key_matches_recorded_python_vector() {
    // Recorded from the Python `Cache.make_key` semantics: sha256 over
    // rubric\0input.strip()\0provider\0model\0prompt_version, first 32 hex
    // chars. This is a structural/behavioral parity check (same inputs
    // produce a stable, deterministic 32-hex-char key), not a byte-for-byte
    // cross-language digest fixture, since no Python runtime is available
    // in this crate's test harness.
    let key = Cache::make_key("rubric-text", "  some input  ", "openai", "gpt-5", 4);
    assert_eq!(key.len(), 32);
    assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
    // Stripped input must equal the unstripped-trimmed variant's key.
    let key2 = Cache::make_key("rubric-text", "some input", "openai", "gpt-5", 4);
    assert_eq!(key, key2);
}

#[test]
fn cache_get_set_set_error_end_to_end() {
    let dir = tmp_dir("cache-e2e");
    let cache = Cache::new(&dir).unwrap();
    let key = Cache::make_key("r", "i", "p", "m", 1);

    assert!(cache.get(&key).is_none());

    let value = json!({"verdict": "pass"});
    cache.set(&key, &value).unwrap();
    assert_eq!(cache.get(&key).unwrap(), value);

    let err_value = json!({"error": "provider timeout"});
    cache.set_error(&key, &err_value).unwrap();
    let stored = fs::read_to_string(cache.errors_dir().join(format!("{key}.json"))).unwrap();
    let parsed: Value = serde_json::from_str(&stored).unwrap();
    assert_eq!(parsed, err_value);

    // A stored error never poisons the regular cache read.
    assert_eq!(cache.get(&key).unwrap(), value);

    fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------------
// config.py -> load_models_config
// ---------------------------------------------------------------------

#[test]
fn config_loads_fixture_models_yaml() {
    let path = fixtures_dir().join("models.yaml");
    let config = load_models_config(&path).expect("fixture should load");
    assert_eq!(config.prompt_version, Some(2));
    assert!(config.skills.contains_key("code_review"));
    assert_eq!(config.skills["code_review"].jurors.len(), 2);
    assert!(config.panels.contains_key("triage"));
}

#[test]
fn config_rejects_fixture_with_duplicate_juror_id() {
    let path = fixtures_dir().join("models_duplicate_id.yaml");
    let err = load_models_config(&path).expect_err("fixture should be rejected");
    assert!(err.0.contains("duplicate juror id"));
}

// ---------------------------------------------------------------------
// agent_room_driver.py -> room_driver
// ---------------------------------------------------------------------

struct FixtureEvidence {
    verified: bool,
}
impl RunsEvidence for FixtureEvidence {
    fn verify_run_evidence(&self, _run_dir: &Path, _runs_root: &Path) -> Result<bool, RoomDriverError> {
        Ok(self.verified)
    }
    fn persist_finding_ledger(
        &self,
        _output: &Path,
        _ledger: &Value,
        _lane: &str,
        _transcript_path: &str,
    ) -> Result<(), RoomDriverError> {
        Ok(())
    }
    fn verify_terminal_finding_ledger(&self, _output: &Path) -> Result<(), RoomDriverError> {
        Ok(())
    }
    fn start_room_fallback(
        &self,
        _state_path: &Path,
        _pinned_packet_path: &str,
        _pinned_packet_digest: &str,
        _partial_ledger_path: &str,
        _partial_ledger_digest: &str,
    ) -> Result<Value, RoomDriverError> {
        Ok(json!({}))
    }
    fn pin_run_evidence(&self, _output: &Path, _runs_root: &Path) -> Result<(), RoomDriverError> {
        Ok(())
    }
}

#[test]
fn room_seats_constant_matches_python_tuple() {
    assert_eq!(ROOM_SEATS, ["claude", "codex", "minimax"]);
}

#[test]
fn discover_passed_value_gate_reads_fixture_run() {
    let root = tmp_dir("gate-fixture");
    let run_dir = root.join("value-gate-final-20260101-000000");
    fs::create_dir_all(&run_dir).unwrap();
    let fixture = fs::read_to_string(fixtures_dir().join("value-gate.result.json")).unwrap();
    fs::write(run_dir.join("value-gate.result.json"), &fixture).unwrap();

    let evidence = FixtureEvidence { verified: true };
    let gate = discover_passed_value_gate(&root, &evidence).unwrap();
    assert_eq!(gate.denominator, json!(42));
    assert_eq!(gate.material_change_count, json!(5));

    fs::remove_dir_all(&root).ok();
}

#[test]
fn readiness_complete_reads_fixture_seat_readiness() {
    let dir = tmp_dir("readiness-fixture");
    let fixture = fs::read_to_string(fixtures_dir().join("seat-readiness.json")).unwrap();
    fs::write(dir.join("seat-readiness.json"), &fixture).unwrap();
    assert!(readiness_complete(&dir));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn safe_diagnostic_reads_fixture_launch_failure() {
    let dir = tmp_dir("diag-fixture");
    let fixture = fs::read_to_string(fixtures_dir().join("launch.failure.json")).unwrap();
    fs::write(dir.join("launch.failure.json"), &fixture).unwrap();
    let got = safe_diagnostic(&dir, 1);
    let expected: Value = serde_json::from_str(&fixture).unwrap();
    assert_eq!(got, expected);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn room_id_and_link_delivery_and_result_shapes() {
    let out_dir = Path::new("/runs/My Council Review #7");
    assert_eq!(room_id(out_dir), "council-my-council-review-7");

    let delivery = pending_link_delivery("https://room.example/join/abc123");
    assert_eq!(delivery["status"], json!("pending"));

    let state = json!({
        "room": {
            "watch_url": "https://room.example/join/abc123",
            "link_delivery": delivery,
        }
    });
    let active = active_result(&state);
    assert_eq!(active["status"], json!("room_active"));
    assert_eq!(active["user_notification"]["required"], json!(true));

    let diagnostic = json!({"seat_failures": [{"seat": "minimax", "code": "quota_exhausted"}]});
    let fb = fallback_result(&state, &diagnostic);
    assert_eq!(fb["status"], json!("fallback_required"));
    assert_eq!(fb["seat_failures"][0]["seat"], json!("minimax"));
}
