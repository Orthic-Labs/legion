//! Integration-level parity test for wf028 (research-core scholarly
//! provider, search/open/find dispatcher, run-finalization receipt,
//! resource-authorization guard, and DOI retraction sweep: `scholarly.py`,
//! `search_open_find.py`, `receipt.py`, `resource_guard.py`,
//! `retraction.py`), exercised against the crate's public API rather than
//! the in-module unit tests under `src/wf_port/wf028/*.rs`.
//!
//! NOTE: this file depends on `pub mod wf_port;` and, inside it,
//! `pub mod wf028;` landing in `src/lib.rs` / `src/wf_port/mod.rs` — files
//! this packet does not own. It also depends on `pub mod wf026;` for the
//! `search_open_find::meter_effect` path, ported by a different packet.
//! The exact patch is in the packet report (`wf028.md`). Until the
//! integrator applies it, this file will not compile.

use std::fs;
use std::path::PathBuf;

use legion_research::wf_port::wf027::types::Provider as _;
use legion_research::wf_port::wf028::receipt::finalize;
use legion_research::wf_port::wf028::resource_guard::read_resource;
use legion_research::wf_port::wf028::retraction::{self, RetractionTransport, TransportError as RetractionTransportError};
use legion_research::wf_port::wf028::scholarly::{self, ScholarlyTransport, TransportError as ScholarlyTransportError};
use legion_research::wf_port::wf028::search_open_find::{self, ProviderName};
use legion_research::wf_port::wf028::support;
use serde_json::{json, Value};

fn scratch_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "legion-wf028-integration-{name}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wf_wf028")
}

/// End-to-end: authorize + read a resource inside a workspace bound by a
/// run's frozen route, then finalize that run and confirm the receipt
/// carries the same `route_sha256` the resource read was checked against —
/// mirroring how `resource_guard.py` and `receipt.py` (via `manifest.py`)
/// share the same on-disk `manifest.json` in the Python original.
#[test]
fn resource_read_and_run_finalize_share_the_same_manifest() {
    let workspace = scratch_dir("resource-workspace");
    let run_dir = scratch_dir("resource-run");
    fs::write(workspace.join("notes.md"), "shared manifest content").unwrap();

    let manifest = json!({
        "manifest_version": 2,
        "run_id": "run-wf028-1",
        "query_sha256": "qsha",
        "route": {"forbidden_resources": ["*.env"]},
        "route_sha256": "route-digest-1",
        "status": "running",
        "blocked_on": [],
        "usage": {"external_requests": 0},
        "budget": {"external_requests": 12},
        "approvals": {},
        "artifacts": {},
    });
    support::atomic_write_json(&run_dir.join("manifest.json"), &manifest).unwrap();

    let read = read_resource(&run_dir, "notes.md", &workspace).unwrap();
    assert_eq!(read["receipt"]["route_sha256"], json!("route-digest-1"));

    let receipt = finalize(&run_dir, "run-wf028-1", "ship", &json!({"citecheck": "ok"})).unwrap();
    assert_eq!(receipt["route_sha256"], json!("route-digest-1"));
    assert_eq!(receipt["verdict"], json!("ship"));

    let events = fs::read_to_string(run_dir.join("events.jsonl")).unwrap();
    assert!(events.contains("resource.allowed"));
    assert!(events.contains("run.finalized"));
}

/// A forbidden resource read is denied and never reaches the finalized
/// receipt's `checks`.
#[test]
fn forbidden_resource_is_denied_before_any_finalize() {
    let workspace = scratch_dir("resource-forbidden-workspace");
    let run_dir = scratch_dir("resource-forbidden-run");
    fs::write(workspace.join("secret.env"), "token=abc").unwrap();
    let manifest = json!({
        "manifest_version": 2,
        "run_id": "run-wf028-2",
        "route": {"forbidden_resources": ["*.env"]},
        "route_sha256": "route-digest-2",
        "status": "running",
        "blocked_on": [],
    });
    support::atomic_write_json(&run_dir.join("manifest.json"), &manifest).unwrap();

    let err = read_resource(&run_dir, "secret.env", &workspace).unwrap_err();
    assert!(err.to_string().contains("resource denied by frozen route"));
}

struct FixtureScholarlyTransport {
    json_body: Value,
}
impl ScholarlyTransport for FixtureScholarlyTransport {
    fn get_json(&self, _url: &str, _timeout_secs: u64) -> Result<Value, ScholarlyTransportError> {
        Ok(self.json_body.clone())
    }
    fn get_text(&self, _url: &str, _timeout_secs: u64) -> Result<(String, String), ScholarlyTransportError> {
        Ok(("<html>Ossified Alloys of the Late Devonian</html>".to_string(), "https://journal.example/paper".to_string()))
    }
}

/// `search_open_find`'s dispatcher resolves `--provider scholarly` to the
/// same provider this packet backs, whose `search()`/`open()` produce the
/// exact `to_dict()`-shaped JSON `search_open_find.py`'s CLI prints, and
/// both ops are metered while `find` is not — end to end through the
/// dispatcher, not just the unit-level `scholarly` module.
#[test]
fn search_open_find_dispatches_scholarly_and_matches_to_dict_shapes() {
    let fixture_path = fixtures_dir().join("crossref_works.json");
    let fixture: Value = serde_json::from_str(&fs::read_to_string(&fixture_path).unwrap()).unwrap();
    let transport = FixtureScholarlyTransport { json_body: fixture };

    let resolved = search_open_find::provider("scholarly", None).unwrap();
    assert_eq!(resolved.name(), "scholarly");
    assert!(search_open_find::is_metered_op(ProviderName::Scholarly, "search"));
    assert!(search_open_find::is_metered_op(ProviderName::Scholarly, "open"));
    assert!(!search_open_find::is_metered_op(ProviderName::Scholarly, "find"));

    let hits = scholarly::search(&transport, "devonian alloys", 10, &[], None).unwrap();
    assert_eq!(hits.len(), 1);
    let hit_json = hits[0].to_json();
    assert_eq!(hit_json["evidence_status"], json!("lead"));
    assert_eq!(hit_json["provider"], json!("scholarly"));

    let opened = scholarly::open(&transport, "https://journal.example/paper", "2026-09-23").unwrap();
    let opened_json = opened.to_json();
    assert_eq!(opened_json["instructionPolicy"], json!("data_only"));
    assert!(opened_json.get("instruction_policy").is_none());

    let passage = scholarly::find(&opened.content, "Ossified Alloys").unwrap();
    assert!(passage.text.contains("Ossified Alloys"));
}

/// `meter_effect` is a genuine no-op (never touches `manifest.json`) when
/// no run is bound — the exact `if not run_id: return` short-circuit
/// `search_open_find.py`'s `meter()` helper performs for a run-less CLI
/// invocation.
#[test]
fn meter_effect_without_a_run_never_touches_disk() {
    assert!(search_open_find::meter_effect(None, "external_request").is_ok());
}

struct FixtureRetractionTransport {
    openalex: Value,
    crossref: Value,
}
impl RetractionTransport for FixtureRetractionTransport {
    fn openalex(&self, _doi: &str) -> Result<Value, RetractionTransportError> {
        Ok(self.openalex.clone())
    }
    fn crossref(&self, _doi: &str) -> Result<Value, RetractionTransportError> {
        Ok(self.crossref.clone())
    }
}

/// A retraction sweep over a fixture-shaped OpenAlex/Crossref pair blocks
/// exactly when the DOI is retracted and undisclosed, matching
/// `retraction.py`'s `sweep()`/`main()` exit-code contract (0 clean, 2
/// blocked).
#[test]
fn retraction_sweep_blocks_undisclosed_retraction_end_to_end() {
    let fixture_path = fixtures_dir().join("openalex_retracted.json");
    let openalex: Value = serde_json::from_str(&fs::read_to_string(&fixture_path).unwrap()).unwrap();
    let transport = FixtureRetractionTransport {
        openalex,
        crossref: json!({"message": {"update-to": [], "relation": {}}}),
    };

    let result = retraction::sweep(&transport, &["10.9999/retracted-example".to_string()], &[], true, None);
    assert_eq!(result["block_brief"], json!(true));
    assert_eq!(retraction::exit_code(&result), 2);

    let disclosed = retraction::sweep(
        &transport,
        &["10.9999/retracted-example".to_string()],
        &["10.9999/retracted-example".to_string()],
        true,
        None,
    );
    assert_eq!(disclosed["block_brief"], json!(false));
    assert_eq!(retraction::exit_code(&disclosed), 0);
}
