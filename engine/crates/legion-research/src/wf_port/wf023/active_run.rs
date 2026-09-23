//! Port of `research-core/active_run.py`: durable workspace pointer for the
//! Research run subject to hooks.
//!
//! `active_run.py` reads/writes its pointer file through `manifest.py`
//! (`manifest.load_run`, `manifest.default_run_root`, `manifest.record_event`),
//! which is not yet ported under `legion-research` (no `manifest` module
//! exists in this crate or engine-wide, per a `git grep` at port time). This
//! module ports the pointer/selection *decision logic* faithfully against a
//! `RunManifest` trait rather than assuming a concrete manifest
//! implementation, so it compiles and is fully tested today; when
//! `manifest.py`'s port lands, wire a `RunManifest` impl over it (see the
//! wf023 report) instead of duplicating manifest state here.

use serde_json::{json, Value};

use crate::research_port::utc_now;

/// One run's fields relevant to `active_run.py`, i.e. `manifest.load_run`'s
/// result restricted to what `_executable`/`activate`/`_pointed` read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRecord {
    pub run_id: String,
    pub status: String,
    pub route_sha256: String,
    /// `bool(run.get('route', {}).get('allowed_effects'))`.
    pub route_allows_effects: bool,
}

/// The persisted pointer value, mirroring the dict `activate()` builds and
/// writes to `.active-run.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerValue {
    pub pointer_version: u32,
    pub run_id: String,
    pub route_sha256: String,
    pub activated_at: String,
}

/// Abstracts `manifest.py`'s run store and pointer file so this module's
/// decision logic (`_executable`, `activate`, `_pointed`, `executable_runs`,
/// `selection`, `clear`) is faithful and testable without a concrete
/// manifest port.
pub trait RunManifest {
    /// `manifest.load_run(run_id)`. `Err` mirrors any lookup failure the
    /// Python raises (missing run, corrupt manifest, etc.).
    fn load_run(&self, run_id: &str) -> Result<RunRecord, String>;
    /// Every run id under `manifest.default_run_root()` that has a
    /// `manifest.json` readable as JSON — mirrors the
    /// `root.glob('run-*/manifest.json')` scan in `executable_runs`,
    /// already filtered to files that parsed. `_executable` filtering is
    /// applied by this module, not the store.
    fn candidate_run_ids(&self) -> Vec<String>;
    /// Reads the pointer file's `{run_id, route_sha256}`, or `None` if it
    /// does not exist or fails to parse — mirrors `_pointed`'s try/except.
    fn read_pointer(&self) -> Option<(String, String)>;
    /// Writes the pointer file (`common.atomic_write_json(pointer_path(), value)`).
    fn write_pointer(&self, value: &PointerValue);
    /// Deletes the pointer file (`path.unlink(missing_ok=True)`).
    fn delete_pointer(&self);
    /// `manifest.record_event(run_id, kind, detail)`.
    fn record_event(&self, run_id: &str, kind: &str, detail: Value);
}

/// `_executable`.
fn executable(run: &RunRecord) -> bool {
    !matches!(run.status.as_str(), "failed" | "done" | "aborted") && run.route_allows_effects
}

/// `activate`. Returns the same error message the Python raises when the
/// run is not executable.
pub fn activate(store: &impl RunManifest, run_id: &str) -> Result<PointerValue, String> {
    let run = store.load_run(run_id)?;
    if !executable(&run) {
        return Err("Research run is not executable or route effects are not granted".to_string());
    }
    let value = PointerValue {
        pointer_version: 1,
        run_id: run_id.to_string(),
        route_sha256: run.route_sha256,
        activated_at: utc_now(),
    };
    store.write_pointer(&value);
    store.record_event(run_id, "run.activated", json!({"pointer": "active-run-pointer"}));
    Ok(value)
}

/// `_pointed`.
fn pointed(store: &impl RunManifest) -> Option<String> {
    let (run_id, route_sha256) = store.read_pointer()?;
    let run = store.load_run(&run_id).ok()?;
    if run.route_sha256 != route_sha256 || !executable(&run) {
        return None;
    }
    Some(run_id)
}

/// `executable_runs`.
pub fn executable_runs(store: &impl RunManifest) -> Vec<String> {
    let mut candidates: Vec<String> = store
        .candidate_run_ids()
        .into_iter()
        .filter(|run_id| store.load_run(run_id).map(|r| executable(&r)).unwrap_or(false))
        .collect();
    // `glob` returns paths in filesystem order which, per `sorted(...)` in
    // the Python, is normalized to sorted order before filtering.
    candidates.sort();
    candidates
}

/// Mirrors the dict `selection()` returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    pub run_id: Option<String>,
    pub ambiguous: bool,
    pub candidates: Vec<String>,
    pub source: &'static str,
}

/// `selection`.
pub fn selection(store: &impl RunManifest) -> Selection {
    if let Some(run_id) = pointed(store) {
        return Selection {
            candidates: vec![run_id.clone()],
            run_id: Some(run_id),
            ambiguous: false,
            source: "pointer",
        };
    }
    let candidates = executable_runs(store);
    if candidates.len() == 1 {
        return Selection {
            run_id: Some(candidates[0].clone()),
            ambiguous: false,
            candidates,
            source: "single",
        };
    }
    let ambiguous = candidates.len() > 1;
    Selection { run_id: None, ambiguous, candidates, source: "none" }
}

/// `current`.
pub fn current(store: &impl RunManifest) -> Option<String> {
    selection(store).run_id
}

/// `clear`. Returns `false` for "nothing to clear" the same way the Python
/// returns `False` (no pointer file, or pointer points at a different run).
pub fn clear(store: &impl RunManifest, run_id: &str) -> bool {
    let Some((pointed_run_id, _)) = store.read_pointer() else {
        return false;
    };
    if pointed_run_id != run_id {
        return false;
    }
    store.delete_pointer();
    store.record_event(run_id, "run.deactivated", json!({"pointer": "active-run-pointer"}));
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct MockStore {
        runs: BTreeMap<String, RunRecord>,
        pointer: RefCell<Option<(String, String)>>,
        events: RefCell<Vec<(String, String, Value)>>,
    }

    impl RunManifest for MockStore {
        fn load_run(&self, run_id: &str) -> Result<RunRecord, String> {
            self.runs.get(run_id).cloned().ok_or_else(|| format!("no such run: {run_id}"))
        }
        fn candidate_run_ids(&self) -> Vec<String> {
            self.runs.keys().cloned().collect()
        }
        fn read_pointer(&self) -> Option<(String, String)> {
            self.pointer.borrow().clone()
        }
        fn write_pointer(&self, value: &PointerValue) {
            *self.pointer.borrow_mut() = Some((value.run_id.clone(), value.route_sha256.clone()));
        }
        fn delete_pointer(&self) {
            *self.pointer.borrow_mut() = None;
        }
        fn record_event(&self, run_id: &str, kind: &str, detail: Value) {
            self.events.borrow_mut().push((run_id.to_string(), kind.to_string(), detail));
        }
    }

    fn executable_run(run_id: &str, sha: &str) -> RunRecord {
        RunRecord {
            run_id: run_id.to_string(),
            status: "acquiring".to_string(),
            route_sha256: sha.to_string(),
            route_allows_effects: true,
        }
    }

    #[test]
    fn activate_rejects_non_executable_run() {
        let mut store = MockStore::default();
        store.runs.insert(
            "run-1".into(),
            RunRecord { run_id: "run-1".into(), status: "done".into(), route_sha256: "sha".into(), route_allows_effects: true },
        );
        let err = activate(&store, "run-1").unwrap_err();
        assert_eq!(err, "Research run is not executable or route effects are not granted");
    }

    #[test]
    fn activate_rejects_run_with_no_allowed_effects() {
        let mut store = MockStore::default();
        store.runs.insert(
            "run-1".into(),
            RunRecord { run_id: "run-1".into(), status: "acquiring".into(), route_sha256: "sha".into(), route_allows_effects: false },
        );
        assert!(activate(&store, "run-1").is_err());
    }

    #[test]
    fn activate_writes_pointer_and_records_event() {
        let mut store = MockStore::default();
        store.runs.insert("run-1".into(), executable_run("run-1", "sha-1"));
        let value = activate(&store, "run-1").unwrap();
        assert_eq!(value.run_id, "run-1");
        assert_eq!(value.route_sha256, "sha-1");
        assert_eq!(store.read_pointer(), Some(("run-1".into(), "sha-1".into())));
        assert_eq!(store.events.borrow().last().unwrap().1, "run.activated");
    }

    #[test]
    fn selection_prefers_a_valid_pointer_over_candidates() {
        let mut store = MockStore::default();
        store.runs.insert("run-1".into(), executable_run("run-1", "sha-1"));
        store.runs.insert("run-2".into(), executable_run("run-2", "sha-2"));
        activate(&store, "run-1").unwrap();
        let sel = selection(&store);
        assert_eq!(sel.run_id.as_deref(), Some("run-1"));
        assert_eq!(sel.source, "pointer");
        assert!(!sel.ambiguous);
    }

    #[test]
    fn selection_falls_back_to_single_candidate_when_pointer_is_stale() {
        let mut store = MockStore::default();
        store.runs.insert("run-1".into(), executable_run("run-1", "sha-1"));
        // Pointer references a route sha that no longer matches the run.
        *store.pointer.borrow_mut() = Some(("run-1".into(), "stale-sha".into()));
        let sel = selection(&store);
        assert_eq!(sel.run_id.as_deref(), Some("run-1"));
        assert_eq!(sel.source, "single");
    }

    #[test]
    fn selection_is_ambiguous_with_multiple_executable_candidates_and_no_pointer() {
        let mut store = MockStore::default();
        store.runs.insert("run-1".into(), executable_run("run-1", "sha-1"));
        store.runs.insert("run-2".into(), executable_run("run-2", "sha-2"));
        let sel = selection(&store);
        assert_eq!(sel.run_id, None);
        assert!(sel.ambiguous);
        assert_eq!(sel.candidates, vec!["run-1".to_string(), "run-2".to_string()]);
        assert_eq!(sel.source, "none");
    }

    #[test]
    fn selection_reports_no_run_when_no_candidates_are_executable() {
        let mut store = MockStore::default();
        store.runs.insert(
            "run-1".into(),
            RunRecord { run_id: "run-1".into(), status: "done".into(), route_sha256: "sha".into(), route_allows_effects: true },
        );
        let sel = selection(&store);
        assert_eq!(sel.run_id, None);
        assert!(!sel.ambiguous);
        assert!(sel.candidates.is_empty());
        assert_eq!(sel.source, "none");
    }

    #[test]
    fn clear_removes_matching_pointer_and_reports_false_otherwise() {
        let mut store = MockStore::default();
        store.runs.insert("run-1".into(), executable_run("run-1", "sha-1"));
        activate(&store, "run-1").unwrap();
        assert!(!clear(&store, "run-2"));
        assert!(store.read_pointer().is_some());
        assert!(clear(&store, "run-1"));
        assert!(store.read_pointer().is_none());
        assert!(!clear(&store, "run-1"));
    }

    #[test]
    fn current_delegates_to_selection() {
        let mut store = MockStore::default();
        store.runs.insert("run-1".into(), executable_run("run-1", "sha-1"));
        assert_eq!(current(&store), Some("run-1".to_string()));
    }
}
