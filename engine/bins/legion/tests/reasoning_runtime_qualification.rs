//! Genuine production planning over source-owned controls; no host or model call.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

struct Fixture {
    base: PathBuf,
    corpus: PathBuf,
    source: PathBuf,
    run: PathBuf,
    home: PathBuf,
}

fn copy_source(from: &Path, to: &Path) {
    assert!(!fs::symlink_metadata(from).unwrap().file_type().is_symlink());
    if from.is_dir() {
        fs::create_dir_all(to).unwrap();
        for entry in fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            copy_source(&entry.path(), &to.join(entry.file_name()));
        }
    } else {
        fs::copy(from, to).unwrap();
    }
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let base = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "legion-reasoning-production-no-call-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        assert!(!base.exists(), "production no-call output must be fresh");
        let fixture = Self {
            corpus: base.join("corpus"),
            source: base.join("fixture-source"),
            run: base.join("run"),
            home: base.join("home"),
            base,
        };
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../scripts/ci/fixtures/audit-reasoning-runtime-accuracy");
        copy_source(&source, &fixture.corpus);
        copy_source(&fixture.corpus.join("fixtures"), &fixture.source);
        fs::create_dir_all(&fixture.home).unwrap();
        // Audit requires Git top-level source. Keep answer keys & proposed
        // grouping outside audited Git tree, exactly as live runner expects.
        for args in [
            vec!["init", "-q"],
            vec!["add", "--all"],
            vec!["commit", "-q", "-m", "source-owned reasoning controls"],
        ] {
            let output = Command::new("git")
                .current_dir(&fixture.source)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env(
                    "GIT_CONFIG_GLOBAL",
                    if cfg!(windows) { "NUL" } else { "/dev/null" },
                )
                .args([
                    "-c",
                    "core.hooksPath=",
                    "-c",
                    "commit.gpgsign=false",
                    "-c",
                    "core.autocrlf=false",
                    "-c",
                    "user.name=Reasoning no-call control",
                    "-c",
                    "user.email=reasoning-no-call@example.invalid",
                ])
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "fixture Git failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        fixture
    }

    fn command(&self, args: &[String]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_legion"))
            .current_dir(&self.corpus)
            .env("GIT_CEILING_DIRECTORIES", &self.base)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("LOCALAPPDATA", self.home.join("AppData/Local"))
            .env("XDG_DATA_HOME", self.home.join(".local/share"))
            .env(
                "LEGION_PROVIDER_REGISTRY",
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../src/registry/providers.json"),
            )
            .env_remove("AUDIT_PLAN_SIGNING_KEY")
            .env_remove("LEGION_NATIVE_APPLICATION_CONFIG")
            .env_remove("CLAUDECODE")
            .env_remove("CLAUDE_CODE_SESSION_ID")
            .args(args)
            .output()
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

#[test]
fn reasoning_runtime_production_no_call_contract() {
    let fixture = Fixture::new();
    let controls: Value =
        serde_json::from_slice(&fs::read(fixture.corpus.join("cases.json")).unwrap()).unwrap();
    let mut args: Vec<String> = [
        "audit".into(),
        fixture.source.to_string_lossy().into_owned(),
        "--json".into(),
        "--coverage".into(),
        "exhaustive".into(),
        "--seat-token-budget".into(),
        "10000".into(),
        "--run-token-budget".into(),
        "440000".into(),
        "--max-total-seats".into(),
        "44".into(),
        "--max-lens-seats".into(),
        "1".into(),
        "--out".into(),
        fixture.run.to_string_lossy().into_owned(),
    ]
    .into();
    for provider in controls["providers"].as_array().unwrap() {
        args.extend(["--only".into(), provider.as_str().unwrap().into()]);
    }
    args.extend(["--only".into(), "security.misuse-resistance".into()]);
    let planned = fixture.command(&args);
    assert!(
        matches!(planned.status.code(), Some(0 | 2)),
        "production planner failed: {}",
        String::from_utf8_lossy(&planned.stderr)
    );
    let dispatch_path = fixture.run.join("lens-dispatch.json");
    let dispatch: Value =
        serde_json::from_slice(&fs::read(&dispatch_path).unwrap_or_else(|error| {
            panic!(
                "production dispatch missing ({error}): {}",
                String::from_utf8_lossy(&planned.stderr)
            )
        }))
        .unwrap();
    let seats = dispatch["seats"]
        .as_array()
        .expect("production seat inventory");
    let binary_sha256 = format!(
        "sha256:{}",
        Sha256::digest(fs::read(env!("CARGO_BIN_EXE_legion")).unwrap())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    println!(
        "REASONING_RUNTIME_PRODUCTION_DISPATCH {}",
        json!({"requiredSeats":seats.len(),"bundles":dispatch["bundles"],"withinLimits":dispatch["withinLimits"],"binarySha256":binary_sha256})
    );
    let checked = fixture.command(&[
        "audit".into(),
        "check-reasoning-dispatch".into(),
        "--run".into(),
        fixture.run.to_string_lossy().into_owned(),
    ]);
    assert!(
        checked.status.success(),
        "genuine production preflight rejected {} author seats: {}",
        seats.len(),
        String::from_utf8_lossy(&checked.stderr)
    );
    let proof: Value = serde_json::from_slice(&checked.stdout).unwrap();
    assert_eq!(proof["productionDispatchValidated"], true);
    assert_eq!(proof["modelCalls"], 0);
    assert_eq!(proof["qualification"], false);
    assert_eq!(proof["dispatch"], dispatch);
    assert!((1..=8).contains(&seats.len()));
    assert_eq!(dispatch["requiredSeats"], seats.len());
    assert_eq!(
        dispatch.pointer("/reasoningBudget/maxSeats"),
        Some(&json!(44))
    );
    assert_eq!(
        dispatch.pointer("/reasoningBudget/perCallTokens"),
        Some(&json!(10000))
    );
    assert_eq!(
        dispatch.pointer("/reasoningBudget/totalTokens"),
        Some(&json!(440000))
    );
    assert_eq!(dispatch.pointer("/limits/waveWidth"), Some(&json!(1)));
    assert!(
        !fixture.run.join("runtime-calls").exists()
            || fs::read_dir(fixture.run.join("runtime-calls"))
                .unwrap()
                .next()
                .is_none()
    );
    println!("REASONING_RUNTIME_PRODUCTION_NO_CALL {proof}");
}
