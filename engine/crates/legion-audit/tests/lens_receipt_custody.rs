//! The lens receipt MAC key (epoch key) lives in host custody beside the plan
//! key, never in the run directory. A planted `<run>/epoch.key` is ignored for
//! new runs; a legacy run that only has a run-directory key still loads, as
//! weak custody.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

use legion_audit::native_providers::reasoning::ingest::{
    create_epoch, epoch_digest, load_epoch, load_epoch_with_source, EpochKeySource, EPOCH_KEY_DIR,
    EPOCH_KEY_FILE,
};
use serde_json::json;

static ENV_LOCK: Mutex<()> = Mutex::new(());

struct Sandbox {
    base: PathBuf,
    run: PathBuf,
    state: PathBuf,
    saved: Option<std::ffi::OsString>,
}

impl Sandbox {
    fn new(name: &str) -> Self {
        let base = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("legion-lens-custody-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let run = base.join("run");
        let state = base.join("state");
        fs::create_dir_all(&run).unwrap();
        fs::create_dir_all(&state).unwrap();
        let saved = std::env::var_os("LEGION_STATE_ROOT");
        std::env::set_var("LEGION_STATE_ROOT", &state);
        Self {
            base,
            run,
            state,
            saved,
        }
    }
    fn key_files(&self) -> Vec<PathBuf> {
        fs::read_dir(self.state.join(EPOCH_KEY_DIR))
            .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
            .unwrap_or_default()
    }
    fn write_plan(&self, value: serde_json::Value) {
        fs::write(
            self.run.join("plan.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        match &self.saved {
            Some(value) => std::env::set_var("LEGION_STATE_ROOT", value),
            None => std::env::remove_var("LEGION_STATE_ROOT"),
        }
        let _ = fs::remove_dir_all(&self.base);
    }
}

fn plant(run: &Path, key: &[u8]) {
    let path = run.join(EPOCH_KEY_FILE);
    fs::write(&path, hex::encode(key)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[test]
fn new_run_epoch_key_is_in_host_custody_not_the_run_directory() {
    let _turn = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let sandbox = Sandbox::new("new-run");
    let digest = create_epoch(&sandbox.run).unwrap();
    assert!(
        !sandbox.run.join(EPOCH_KEY_FILE).exists(),
        "new run wrote epoch.key into the run dir"
    );
    let keys = sandbox.key_files();
    assert_eq!(keys.len(), 1, "{keys:?}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&keys[0]).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    // The key material appears nowhere in the run tree.
    let hex_key = fs::read_to_string(&keys[0]).unwrap();
    for entry in fs::read_dir(&sandbox.run).unwrap().flatten() {
        let text = fs::read_to_string(entry.path()).unwrap_or_default();
        assert!(!text.contains(hex_key.trim()));
    }
    let (key, loaded, source) = load_epoch_with_source(&sandbox.run).unwrap();
    assert_eq!(loaded, digest);
    assert_eq!(epoch_digest(&key), digest);
    assert_eq!(source, EpochKeySource::HostState);
}

#[test]
fn planted_epoch_key_is_ignored_for_new_runs() {
    let _turn = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let sandbox = Sandbox::new("planted");
    let digest = create_epoch(&sandbox.run).unwrap();
    let (host_key, _) = load_epoch(&sandbox.run).unwrap();
    sandbox.write_plan(json!({
        "epoch": {"digest": digest},
        "planKey": {"runId": "run-x", "keyId": "sha256:00", "custody": "host-state"},
    }));
    let forged = [0x42u8; 32];
    plant(&sandbox.run, &forged);
    let (key, loaded, source) = load_epoch_with_source(&sandbox.run).unwrap();
    assert_eq!(key, host_key, "planted key replaced the host key");
    assert_eq!(loaded, digest);
    assert_eq!(source, EpochKeySource::HostState);

    // Host key gone: a host-custody run never falls back to the planted key,
    // even when the planted key's digest is written into the (unsigned) plan.
    for path in sandbox.key_files() {
        fs::remove_file(path).unwrap();
    }
    assert!(load_epoch(&sandbox.run).is_err());
    sandbox.write_plan(json!({
        "epoch": {"digest": epoch_digest(&forged)},
        "planKey": {"runId": "run-x", "keyId": "sha256:00", "custody": "host-state"},
    }));
    assert!(load_epoch(&sandbox.run).is_err());
}

#[test]
fn legacy_run_with_only_a_run_directory_key_still_loads_as_weak_custody() {
    let _turn = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let sandbox = Sandbox::new("legacy");
    let key = [0x07u8; 32];
    plant(&sandbox.run, &key);
    sandbox.write_plan(json!({"epoch": {"digest": epoch_digest(&key)}}));
    let (loaded, digest, source) = load_epoch_with_source(&sandbox.run).unwrap();
    assert_eq!(loaded, key);
    assert_eq!(digest, epoch_digest(&key));
    assert_eq!(source, EpochKeySource::LegacyRunDir);
}

#[test]
fn creating_an_epoch_removes_a_stale_run_directory_key() {
    let _turn = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let sandbox = Sandbox::new("stale");
    plant(&sandbox.run, &[0x01u8; 32]);
    create_epoch(&sandbox.run).unwrap();
    assert!(!sandbox.run.join(EPOCH_KEY_FILE).exists());
}
