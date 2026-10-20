//! Genuine production planning over source-owned controls; no host or model call.
use legion_audit::review_runtime::qualification::{
    MAX_RESERVED_TOKENS, MEMBER_PROVIDERS, PER_CALL_TOKENS,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

#[derive(Clone)]
struct TestedBinary {
    path: PathBuf,
    sha256: String,
    bytes: u64,
    runner: Option<Value>,
}

impl TestedBinary {
    fn prepare() -> Self {
        let source = PathBuf::from(env!("CARGO_BIN_EXE_legion"));
        let metadata = fs::symlink_metadata(&source).unwrap();
        assert!(metadata.is_file() && !metadata.file_type().is_symlink());
        let original = fs::read(&source).unwrap();
        let mut binary = Self {
            path: source.clone(),
            sha256: digest(&original),
            bytes: original.len() as u64,
            runner: None,
        };
        if let Some(directory) = std::env::var_os("LEGION_REASONING_NATIVE_RUNNER_DIR") {
            let directory = PathBuf::from(directory);
            assert!(
                directory.is_absolute(),
                "retained runner path must be absolute"
            );
            // Fresh output & rename-only admission: EXDEV or any other move
            // failure stops this proof, never falls back to a partial copy.
            fs::create_dir(&directory).expect("retained runner directory must be fresh");
            let retained = directory.join(source.file_name().unwrap());
            fs::rename(&source, &retained)
                .expect("exact built CLI must move atomically on the same filesystem");
            binary.path = retained;
            binary.assert_identity();
            let revision = std::env::var("GITHUB_SHA").expect("CI source revision required");
            assert!(
                revision.len() == 40
                    && revision
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            );
            let platform = std::env::var("RUNNER_OS").expect("CI platform required");
            assert_eq!(
                platform,
                if cfg!(target_os = "macos") {
                    "macOS"
                } else if cfg!(windows) {
                    "Windows"
                } else {
                    panic!("unsupported retained runner platform")
                }
            );
            let architecture = std::env::var("RUNNER_ARCH").expect("CI architecture required");
            assert_eq!(
                architecture,
                match std::env::consts::ARCH {
                    "aarch64" => "ARM64",
                    "x86_64" => "X64",
                    _ => panic!("unsupported retained runner architecture"),
                }
            );
            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt;
                fs::metadata(&binary.path).unwrap().permissions().mode() & 0o777
            };
            #[cfg(windows)]
            let mode = if fs::metadata(&binary.path).unwrap().permissions().readonly() {
                0o555
            } else {
                0o777
            };
            binary.runner = Some(
                json!({"schema":"legion-reasoning-native-runner/1","sourceRevision":revision,
                "platform":{"os":platform,"architecture":architecture},
                "binary":{"path":binary.path.file_name().unwrap().to_str().unwrap(),"sha256":binary.sha256,"bytes":binary.bytes,"mode":mode},
                "modelCalls":0,"qualification":false}),
            );
        }
        binary.assert_identity();
        binary
    }

    fn assert_identity(&self) {
        let metadata = fs::symlink_metadata(&self.path).expect("tested CLI missing");
        assert!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "tested CLI must stay regular"
        );
        let actual = fs::read(&self.path).unwrap();
        assert_eq!(actual.len() as u64, self.bytes, "tested CLI length changed");
        assert_eq!(digest(&actual), self.sha256, "tested CLI bytes changed");
    }

    fn publish(&self) {
        self.assert_identity();
        if let Some(record) = &self.runner {
            let directory = self.path.parent().unwrap();
            let pending = directory.join("runner.json.pending");
            fs::write(&pending, serde_json::to_vec(record).unwrap()).unwrap();
            fs::rename(pending, directory.join("runner.json")).unwrap();
        }
    }
}

struct Fixture {
    binary: TestedBinary,
    base: PathBuf,
    corpus: PathBuf,
    source: PathBuf,
    run: PathBuf,
    home: PathBuf,
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
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
    fn new(member_index: usize, binary: &TestedBinary) -> Self {
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
            binary: binary.clone(),
            corpus: base.join("corpus"),
            source: base.join("fixture-source"),
            run: base.join("run"),
            home: base.join("home"),
            base,
        };
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../scripts/ci/fixtures/audit-reasoning-runtime-accuracy");
        copy_source(&source, &fixture.corpus);
        let controls: Value =
            serde_json::from_slice(&fs::read(fixture.corpus.join("cases.json")).unwrap()).unwrap();
        let providers = MEMBER_PROVIDERS[member_index];
        let mut case_ids = Vec::new();
        for case in controls["cases"].as_array().unwrap() {
            if providers.contains(&case["providerIds"][0].as_str().unwrap()) {
                let relative = case["fixtureRoot"]
                    .as_str()
                    .unwrap()
                    .strip_prefix("fixtures/")
                    .unwrap();
                copy_source(
                    &fixture.corpus.join("fixtures").join(relative),
                    &fixture.source.join(relative),
                );
                case_ids.push(case["caseId"].as_str().unwrap().to_owned());
            }
        }
        case_ids.sort();
        fn hashes(root: &Path, current: &Path, files: &mut serde_json::Map<String, Value>) {
            for entry in fs::read_dir(current).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    hashes(root, &path, files);
                } else {
                    files.insert(
                        path.strip_prefix(root)
                            .unwrap()
                            .to_string_lossy()
                            .replace('\\', "/"),
                        json!(digest(&fs::read(path).unwrap())),
                    );
                }
            }
        }
        let mut files = serde_json::Map::new();
        hashes(&fixture.source, &fixture.source, &mut files);
        let manifest = json!({"schema":"legion-reasoning-qualification-member/1","memberId":format!("run-{:02}",member_index+1),"memberIndex":member_index,"corpusRoot":fixture.corpus,"providerIds":providers,"caseIds":case_ids,"sourceRoot":fixture.source,"sourceFiles":files,"casesDigest":digest(&fs::read(fixture.corpus.join("cases.json")).unwrap())});
        fs::write(
            fixture.base.join("qualification-member.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
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
        self.binary.assert_identity();
        let output = Command::new(&self.binary.path)
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
            .unwrap();
        self.binary.assert_identity();
        output
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

#[test]
fn reasoning_runtime_production_no_call_contract() {
    let binary = TestedBinary::prepare();
    let mut author_seats = 0;
    for member_index in 0..MEMBER_PROVIDERS.len() {
        let fixture = Fixture::new(member_index, &binary);
        let mut args: Vec<String> = [
            "audit".into(),
            fixture.source.to_string_lossy().into_owned(),
            "--json".into(),
            "--coverage".into(),
            "exhaustive".into(),
            "--seat-token-budget".into(),
            PER_CALL_TOKENS.to_string(),
            "--run-token-budget".into(),
            MAX_RESERVED_TOKENS.to_string(),
            "--max-total-seats".into(),
            "44".into(),
            "--max-lens-seats".into(),
            "1".into(),
            "--out".into(),
            fixture.run.to_string_lossy().into_owned(),
        ]
        .into();
        for provider in MEMBER_PROVIDERS[member_index] {
            args.extend(["--only".into(), (*provider).into()]);
        }
        args.extend(["--only".into(), "security.misuse-resistance".into()]);
        let planned = fixture.command(&args);
        assert!(
            matches!(planned.status.code(), Some(0 | 2)),
            "production planner failed: {}",
            String::from_utf8_lossy(&planned.stderr)
        );
        // Exit 2 also covers a pre-execution size refusal. A dispatch-only
        // diagnostic is not a prepared production run & cannot prove preflight.
        for artifact in ["plan.json", "execution.json", "report.json"] {
            assert!(
                fixture.run.join(artifact).is_file(),
                "full production audit did not prepare {artifact}: {}",
                String::from_utf8_lossy(&planned.stderr)
            );
        }
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
        fixture.binary.assert_identity();
        let binary_sha256 = &binary.sha256;
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
            Some(&json!(PER_CALL_TOKENS))
        );
        assert_eq!(
            dispatch.pointer("/reasoningBudget/totalTokens"),
            Some(&json!(MAX_RESERVED_TOKENS))
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
        assert_eq!(proof["memberIndex"], member_index);
        assert_eq!(
            proof["expectedVerifierItems"],
            MEMBER_PROVIDERS[member_index].len()
        );
        assert!(proof["expectedVerifierItems"].as_u64().unwrap() <= 8);
        assert!(proof["logicalPendingRequestCount"].as_u64().unwrap() <= 8);
        // A real prepared run cannot be relabelled as a different member.
        let manifest_path = fixture.base.join("qualification-member.json");
        let mut changed: Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        changed["caseIds"][0] = json!("unbound-case");
        fs::write(&manifest_path, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(
            !fixture
                .command(&[
                    "audit".into(),
                    "check-reasoning-dispatch".into(),
                    "--run".into(),
                    fixture.run.to_string_lossy().into_owned(),
                ])
                .status
                .success(),
            "prepared run must reject member/case drift"
        );
        author_seats += seats.len();
    }
    assert!(
        author_seats + 3 <= 44,
        "authors plus one native fresh batch verifier per member must fit shared quota"
    );
    // Commit metadata only after every production/member/cumulative assertion.
    binary.publish();
    println!(
        "REASONING_RUNTIME_CUMULATIVE_NO_CALL {}",
        json!({"members":3,"plannedAuthorSeats":author_seats,"plannedFreshBatchVerifierAdmissions":3,"expectedVerifierItems":[6,6,5],"physicalAdmissionCap":44,"modelCalls":0,"qualification":false})
    );
}

#[test]
fn tested_binary_rejects_same_length_replacement() {
    let path = std::env::temp_dir().join(format!("legion-tested-binary-{}", std::process::id()));
    assert!(!path.exists());
    fs::write(&path, b"original").unwrap();
    let binary = TestedBinary {
        path: path.clone(),
        sha256: digest(b"original"),
        bytes: 8,
        runner: None,
    };
    binary.assert_identity();
    fs::write(&path, b"mutated!").unwrap();
    let rejected = std::panic::catch_unwind(|| binary.assert_identity()).is_err();
    fs::remove_file(path).unwrap();
    assert!(
        rejected,
        "same-length replacement must invalidate tested binary identity"
    );
}
