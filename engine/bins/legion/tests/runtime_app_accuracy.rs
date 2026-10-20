//! Constructed frozen runtime SDK controls with actual Legion QA & native receipts.
//! Only test adapter maps resolved test executable to digest-attested Legion CLI.
//! No production admission, unmodified resolver or whole-provider clean claim.
#![cfg(target_os = "macos")]

use async_trait::async_trait;
use legion_audit::native_providers::legacy_checks::{
    runtime_inputs, AuditExternalProjectTool, AuditScratch,
};
use legion_audit::{
    execute_with_cancellation, AuditPlan, FilesystemInventorySource, InventorySource,
    NativeProviderRegistry,
};
use legion_contracts::ProviderSpec;
use legion_effects::{ExternalToolRequest, PolicyAuthorizer, PolicyDecision, ToolOrigin};
use legion_provider_sdk::{ExecutionReceipt, ExternalProjectTool};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};
use tokio_util::sync::CancellationToken;

const ID: &str = "legacy.runtime.app";
const SOURCE: &str = "engine/bins/legion/tests/runtime_app_accuracy.rs";
const PLAN: &str = "bench/runtime-app-accuracy-plan.json";
const POLICY: &str = "legion-runtime-app-constructed-sdk-v1";
const SCOPE: &str = "Constructed live URL/surface SDK controls via explicit attested fixture executable mapping; not production admission, unmodified resolver identity or whole-provider clean";

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
fn canonical(value: &Value) -> Vec<u8> {
    fn ordered(value: &Value) -> Value {
        match value {
            Value::Object(items) => {
                let sorted: BTreeMap<_, _> = items.iter().collect();
                let mut out = serde_json::Map::new();
                for (k, v) in sorted {
                    out.insert(k.clone(), ordered(v));
                }
                Value::Object(out)
            }
            Value::Array(items) => Value::Array(items.iter().map(ordered).collect()),
            _ => value.clone(),
        }
    }
    serde_json::to_vec(&ordered(value)).unwrap()
}
fn source_root() -> PathBuf {
    fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")).unwrap()
}
fn sources(root: &Path) -> BTreeMap<String, String> {
    fn walk(root: &Path, path: &Path, out: &mut BTreeMap<String, String>) {
        assert!(!path.is_symlink(), "source symlink refused");
        if path.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                walk(root, &entry.unwrap().path(), out);
            }
        } else {
            out.insert(
                path.strip_prefix(root)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .replace('\\', "/"),
                digest(&fs::read(path).unwrap()),
            );
        }
    }
    let mut out = BTreeMap::new();
    for name in [
        "engine/crates/legion-runtime/src/lib.rs",
        "engine/crates/legion-runtime/src/wf_port/mod.rs",
        "scripts/ci/tests/test_audit_runtime_app_accuracy.py",
    ] {
        walk(root, &root.join(name), &mut out);
    }
    for name in [
        "engine/crates/legion-audit/src",
        "engine/crates/legion-audit/assets",
        "engine/crates/legion-runtime/src/wf_port/r54",
        "engine/crates/legion-effects/src",
        "engine/crates/legion-provider-sdk/src",
        "engine/crates/legion-contracts/src",
        "engine/crates/legion-rules/src",
        "engine/bins/legion/src",
        "src/registry/rules",
        "src/registry/controls",
        "bench/fixtures/runtime-app",
        PLAN,
        SOURCE,
        "scripts/ci/audit-runtime-app-accuracy.py",
        "engine/Cargo.toml",
        "engine/Cargo.lock",
        "engine/bins/legion/Cargo.toml",
        "engine/crates/legion-runtime/Cargo.toml",
        "engine/crates/legion-audit/Cargo.toml",
        "engine/crates/legion-effects/Cargo.toml",
        "engine/crates/legion-provider-sdk/Cargo.toml",
        "engine/crates/legion-contracts/Cargo.toml",
        "engine/crates/legion-rules/Cargo.toml",
    ] {
        walk(root, &root.join(name), &mut out);
    }
    out
}
fn retain(output: &Path, native: &Path, name: &str) -> Value {
    assert!(!native.is_symlink());
    let bytes = fs::read(native).unwrap();
    let path = format!("evidence/{name}");
    let target = output.join(&path);
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::write(target, &bytes).unwrap();
    json!({"path":path,"nativePath":native,"sha256":digest(&bytes),"bytes":bytes.len()})
}
fn request_json(req: &ExternalToolRequest) -> Value {
    json!({"schemaVersion":req.schema_version,"requestId":req.request_id,"providerId":req.provider_id,"planId":req.plan_id,"policyId":req.policy_id,"taskId":req.task_id,"executable":req.executable,"expectedDigest":req.expected_digest,"args":req.args,"cwd":req.cwd,"origin":format!("{:?}",req.origin),"shell":req.shell,"acceptedExitCodes":req.accepted_exit_codes,"versionArgs":req.version_args,"skipVersionProbe":req.skip_version_probe,"versionRequirement":req.version_requirement,"environment":req.environment,"environmentAllowlist":req.environment_allowlist,"sensitiveArgumentIndexes":req.sensitive_argument_indexes,"sensitiveEnvironmentNames":req.sensitive_environment_names,"requiresNetworkSandbox":req.requires_network_sandbox,"sandbox":req.sandbox.as_ref().map(|s|json!({"id":s.id,"network":s.network,"filesystemScope":s.filesystem_scope})),"timeoutMs":req.timeout_ms,"stdoutLimit":req.stdout_limit,"stderrLimit":req.stderr_limit})
}
fn browser_tree(root: &Path) -> Value {
    fn visit(root: &Path, path: &Path, rows: &mut Vec<Value>) {
        let relative = path.strip_prefix(root).unwrap().to_str().unwrap();
        let metadata = fs::symlink_metadata(path).unwrap();
        if metadata.file_type().is_symlink() {
            let resolved = fs::canonicalize(path).unwrap();
            assert!(resolved.starts_with(root));
            rows.push(json!({"path":relative,"kind":"symlink","target":fs::read_link(path).unwrap(),"resolved":resolved.strip_prefix(root).unwrap()}));
        } else if metadata.is_dir() {
            let mut files: Vec<_> = fs::read_dir(path)
                .unwrap()
                .map(|e| e.unwrap().path())
                .collect();
            files.sort();
            for file in files {
                visit(root, &file, rows);
            }
        } else {
            assert!(metadata.is_file());
            let bytes = fs::read(path).unwrap();
            rows.push(
                json!({"path":relative,"kind":"file","digest":digest(&bytes),"bytes":bytes.len()}),
            );
        }
    }
    let mut rows = Vec::new();
    visit(root, root, &mut rows);
    json!({"files":rows,"digest":digest(&canonical(&json!(rows)))})
}

struct Server {
    origin: String,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
    requests: Arc<Mutex<Vec<Value>>>,
}
impl Server {
    fn new(clean: Vec<u8>, planted: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let log = requests.clone();
        let handle = thread::spawn(move || {
            while !done.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut data = [0; 8192];
                        let count = stream.read(&mut data).unwrap_or(0);
                        let text = String::from_utf8_lossy(&data[..count]);
                        let path = text
                            .lines()
                            .next()
                            .and_then(|l| l.split_whitespace().nth(1))
                            .unwrap_or("");
                        let (status, body): (u16, &[u8]) = match path {
                            "/clean/entry.html" | "/clean/secondary.html" => (200, &clean),
                            "/planted/entry.html" | "/planted/secondary.html" => (200, &planted),
                            "/favicon.ico" => (204, b""),
                            _ => (404, b"not found"),
                        };
                        log.lock().unwrap().push(json!({"path":path,"status":status,"bodySha256":digest(body),"bodyBytes":body.len()}));
                        let header = format!("HTTP/1.1 {status} {}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",if status==200 {"OK"} else {"Not Found"},body.len());
                        let _ = stream.write_all(header.as_bytes());
                        let _ = stream.write_all(body);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => panic!("fixture server: {e}"),
                }
            }
        });
        Self {
            origin,
            stop,
            thread: Some(handle),
            requests,
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.take().unwrap().join().unwrap();
    }
}

#[derive(Clone)]
struct ExactPolicy {
    request: ExternalToolRequest,
    decision: Value,
}
impl PolicyAuthorizer for ExactPolicy {
    fn authorize(&self, req: &ExternalToolRequest) -> PolicyDecision {
        PolicyDecision {
            allowed: req == &self.request,
            policy_id: POLICY.into(),
            policy_version: 1,
            policy_digest: digest(&canonical(&self.decision)),
            reason: Some(
                "exact constructed runtime fixture request; no production admission".into(),
            ),
        }
    }
}
struct MappingTool {
    output: PathBuf,
    scratch: Arc<AuditScratch>,
    plan: String,
    urls: Vec<String>,
    test: PathBuf,
    test_digest: String,
    cli: PathBuf,
    cli_digest: String,
    browser: PathBuf,
    browser_digest: String,
    rows: Arc<Mutex<Vec<Value>>>,
}
#[async_trait]
impl ExternalProjectTool for MappingTool {
    async fn execute(
        &self,
        mut req: ExternalToolRequest,
        cancellation: CancellationToken,
    ) -> ExecutionReceipt {
        // Original production adapter resolved exactly current_exe before this explicit test-only seam.
        assert_eq!(req.executable, self.test.to_str().unwrap());
        assert_eq!(
            req.expected_digest.as_deref(),
            Some(self.test_digest.as_str())
        );
        assert_eq!(digest(&fs::read(&self.test).unwrap()), self.test_digest);
        assert_eq!(digest(&fs::read(&self.cli).unwrap()), self.cli_digest);
        assert_eq!(
            digest(&fs::read(&self.browser).unwrap()),
            self.browser_digest
        );
        assert_eq!(req.provider_id, ID);
        assert_eq!(req.plan_id, self.plan);
        assert_eq!(req.task_id.as_deref(), Some("runtime"));
        assert_eq!(req.origin, ToolOrigin::LegionOwned);
        assert!(!req.shell);
        assert!(!req.requires_network_sandbox);
        assert!(req.sandbox.is_none());
        assert_eq!(req.args.len(), 10);
        assert_eq!(&req.args[..3], ["script", "qa/qa-functional", "--url"]);
        assert!(self.urls.contains(&req.args[3]));
        assert_eq!(&req.args[4..5], ["--actions"]);
        assert_eq!(&req.args[6..], ["--width", "640", "--height", "480"]);
        let cwd = Path::new(&req.cwd);
        assert!(cwd.starts_with(self.scratch.root()));
        let actions_path = Path::new(&req.args[5]);
        assert_eq!(actions_path, cwd.join("actions.json"));
        let actions: Value = serde_json::from_slice(&fs::read(actions_path).unwrap()).unwrap();
        let items = actions.as_array().unwrap();
        assert_eq!(items.len(), 4);
        assert_eq!(items[0]["type"], "eval");
        assert_eq!(items[1]["type"], "screenshot");
        assert_eq!(items[2]["type"], "eval");
        assert_eq!(items[3]["type"], "eval");
        assert!(Path::new(items[1]["out"].as_str().unwrap()).starts_with(self.scratch.root()));
        let owner = fs::read_to_string(source_root().join(
            "engine/crates/legion-audit/src/native_providers/legacy_checks/runtime_capture.rs",
        ))
        .unwrap();
        for (index, name) in [(0, "LOAD_CHECK"), (2, "PERFORMANCE_METRICS")] {
            let line = owner
                .lines()
                .find(|line| line.starts_with(&format!("const {name}: &str = ")))
                .unwrap();
            let literal = line.split_once(" = ").unwrap().1.trim_end_matches(';');
            assert_eq!(
                items[index]["expression"],
                serde_json::from_str::<Value>(literal).unwrap()
            );
        }
        let axe = fs::read_to_string(
            source_root().join("engine/crates/legion-audit/assets/axe-core-4.14.0.min.js"),
        )
        .unwrap();
        assert!(items[3]["expression"].as_str().unwrap().contains(&axe));
        assert_eq!(
            req.environment.get("CHROME_PATH"),
            Some(&self.browser.to_string_lossy().into_owned())
        );
        assert_eq!(req.timeout_ms, 120000);
        assert_eq!(req.stdout_limit, 8388608);
        assert_eq!(req.stderr_limit, 8388608);
        assert_eq!(req.accepted_exit_codes, BTreeSet::from([0]));
        assert!(!req.skip_version_probe);
        assert_eq!(req.version_args, vec!["--version"]);
        let original = request_json(&req);
        req.executable = self.cli.to_string_lossy().into_owned();
        req.expected_digest = Some(self.cli_digest.clone());
        let mapped = request_json(&req);
        let policy = ExactPolicy {
            request: req.clone(),
            decision: json!({"original":original,"mapped":mapped,"actionsDigest":digest(&canonical(&actions))}),
        };
        let effects = legion_effects::EffectExecutor::new(
            legion_effects::platform::unix::UnixProcess::new(),
            legion_effects::ArtifactWriter::new(self.scratch.artifacts_dir()),
            policy.clone(),
        );
        let receipt = effects.execute_with_cancellation(&req, cancellation).await;
        let number = self.rows.lock().unwrap().len();
        let mut row = json!({"originalRequest":original,"mappedRequest":mapped,"admission":policy.decision,
            "actions":retain(&self.output,actions_path,&format!("{}-{number}-actions.json",self.plan.trim_start_matches("sha256:"))),
            "policyDigest":digest(&canonical(&policy.decision))});
        for (name, artifact) in [
            ("stdout", receipt.stdout.as_ref()),
            ("stderr", receipt.stderr.as_ref()),
        ] {
            if let Some(artifact) = artifact {
                let mut retained = retain(
                    &self.output,
                    &self.scratch.artifacts_dir().join(&artifact.path),
                    &format!(
                        "{}-{number}-{name}.bin",
                        self.plan.trim_start_matches("sha256:")
                    ),
                );
                retained["nativePath"] = json!(artifact.path);
                row[name] = retained;
            }
        }
        self.rows.lock().unwrap().push(row);
        receipt
    }
}

#[test]
#[ignore = "requires managed mac-arm64 pinned Chrome, real Legion binary & retained CI evidence"]
fn real_runtime_app_accuracy() {
    assert_eq!(std::env::consts::ARCH, "aarch64");
    let root = source_root();
    let output = PathBuf::from(
        std::env::var_os("LEGION_RUNTIME_APP_RECEIPTS").expect("retained runtime output"),
    );
    fs::create_dir_all(&output).unwrap();
    let output = fs::canonicalize(output).unwrap();
    let runner = fs::canonicalize(PathBuf::from(std::env::var_os("RUNNER_TEMP").unwrap())).unwrap();
    assert!(output.starts_with(&runner));
    let cli = fs::canonicalize(env!("CARGO_BIN_EXE_legion")).unwrap();
    let test = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
    let browser = fs::canonicalize(PathBuf::from(
        std::env::var_os("RIGHTKIT_CHROME_FOR_TESTING").unwrap(),
    ))
    .unwrap();
    let installed = fs::canonicalize(
        PathBuf::from(std::env::var_os("RIGHTKIT_CHROME_FOR_TESTING_ROOT").unwrap())
            .join("current"),
    )
    .unwrap();
    assert!(installed.starts_with(&runner));
    assert!(browser.starts_with(&installed));
    let marker: Value =
        serde_json::from_slice(&fs::read(installed.join("install.json")).unwrap()).unwrap();
    let definition: Value = serde_json::from_slice(&fs::read(root.join(PLAN)).unwrap()).unwrap();
    assert_eq!(definition["scope"], SCOPE);
    assert_eq!(marker["version"], definition["browser"]["version"]);
    assert_eq!(marker["platform"], "mac-arm64");
    assert_eq!(
        marker["files"],
        json!([{"kind":"chrome","url":definition["browser"]["archiveUrl"],"sha256":definition["browser"]["archiveSha256"]}])
    );
    std::env::set_var("CHROME_PATH", &browser);
    std::env::remove_var("QA_BROWSER");
    let browser_version = std::process::Command::new(&browser)
        .arg("--version")
        .output()
        .unwrap();
    assert!(browser_version.status.success());
    let browser_banner = String::from_utf8(browser_version.stdout).unwrap();
    assert!(browser_banner.contains("155.0.8059.39"));
    let clean = fs::read(root.join("bench/fixtures/runtime-app/clean.html")).unwrap();
    let planted = fs::read(root.join("bench/fixtures/runtime-app/planted.html")).unwrap();
    let server = Server::new(clean, planted);
    let mut cases = Vec::new();
    let registry: Value =
        serde_json::from_slice(&fs::read(root.join("src/registry/providers.json")).unwrap())
            .unwrap();
    let spec = registry["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == ID)
        .unwrap();
    let mut shipped = spec.clone();
    shipped.as_object_mut().unwrap().remove("benchmark");
    for case in definition["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let fixture = output.join(format!("fixture-{id}"));
        fs::create_dir_all(&fixture).unwrap();
        fs::write(
            fixture.join("package.json"),
            "{\"scripts\":{\"dev\":\"unused\"}}",
        )
        .unwrap();
        let scratch = Arc::new(
            AuditScratch::with_scratch_dir(&fixture, output.join(format!("run-{id}"))).unwrap(),
        );
        let route = if id == "owner-denied" { "clean" } else { id };
        let url = format!("{}/{route}/entry.html", server.origin);
        let extra = if matches!(id, "clean" | "planted") {
            vec![(
                "secondary".to_owned(),
                format!("{}/{route}/secondary.html", server.origin),
            )]
        } else {
            vec![]
        };
        let inventory = FilesystemInventorySource::new(&fixture)
            .unwrap()
            .inventory(fixture.to_str().unwrap())
            .unwrap();
        let mut configured = spec.clone();
        configured["runner"]["runtime"] =
            runtime_inputs(&url, &extra, &[], 640, 480, None).unwrap();
        let configured: ProviderSpec = serde_json::from_value(configured).unwrap();
        let frozen = AuditPlan::compile(&inventory, &[configured])
            .unwrap()
            .freeze(Some(b"runtime-app-constructed-sdk-only"))
            .unwrap();
        let rows = Arc::new(Mutex::new(Vec::new()));
        let native = if id == "owner-denied" {
            NativeProviderRegistry::new(&fixture)
                .with_scratch(scratch.clone())
                .with_external_project_tool(Arc::new(legion_effects::EffectExecutor::new(
                    legion_effects::platform::unix::UnixProcess::new(),
                    legion_effects::ArtifactWriter::new(scratch.artifacts_dir()),
                    legion_audit::execution_policy::OwnerAdmissionRequired,
                )))
        } else {
            let tool = MappingTool {
                output: output.clone(),
                scratch: scratch.clone(),
                plan: frozen.digest().into(),
                urls: std::iter::once(url.clone())
                    .chain(extra.iter().map(|(_, u)| u.clone()))
                    .collect(),
                test: test.clone(),
                test_digest: digest(&fs::read(&test).unwrap()),
                cli: cli.clone(),
                cli_digest: digest(&fs::read(&cli).unwrap()),
                browser: browser.clone(),
                browser_digest: digest(&fs::read(&browser).unwrap()),
                rows: rows.clone(),
            };
            NativeProviderRegistry::new(&fixture)
                .with_scratch(scratch.clone())
                .with_external_project_tool(Arc::new(AuditExternalProjectTool::new(tool)))
        };
        let report = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(execute_with_cancellation(
                &frozen,
                &inventory,
                &native,
                CancellationToken::new(),
            ))
            .unwrap();
        assert_eq!(report.results.len(), 1);
        let result = &report.results[0].result;
        assert_eq!(result.provider.as_str(), ID);
        assert!(!result.complete);
        let runtime = &result.details["runtime"];
        let mut shots = Vec::new();
        for receipt in result.details["executionReceipts"].as_array().unwrap() {
            if receipt["processTree"]["started"] == true {
                assert_eq!(receipt["processTree"]["terminated"], true);
                assert_eq!(receipt["processTree"]["reaped"], true);
            }
        }
        if matches!(id, "clean" | "planted") {
            assert_eq!(runtime["surfaces"].as_array().unwrap().len(), 2);
            assert_eq!(runtime["a11y_axe"], "ran");
            for (index, surface) in runtime["surfaces"].as_array().unwrap().iter().enumerate() {
                assert_eq!(surface["status"], "captured");
                assert_eq!(surface["gaps"], json!([]));
                assert!(!surface["performance"].is_null());
                assert_eq!(surface["accessibility"]["status"], "ran");
                assert_eq!(surface["accessibility"]["truncated"], false);
                let rules: Vec<_> = surface["accessibility"]["violations"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v["id"].clone())
                    .collect();
                assert_eq!(rules, case["axeRuleIds"].as_array().unwrap().clone());
                if id == "clean" {
                    assert_eq!(surface["consoleErrors"], json!([]));
                } else {
                    assert!(surface["consoleErrors"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|v| v.as_str().unwrap().contains("legion-runtime-planted")));
                }
                let shot = Path::new(surface["screenshot"]["path"].as_str().unwrap());
                let bytes = fs::read(shot).unwrap();
                assert!(bytes.starts_with(b"\x89PNG\r\n\x1a\n"));
                assert_eq!(surface["screenshot"]["sha256"], digest(&bytes));
                shots.push(retain(&output, shot, &format!("{id}-{index}.png")));
            }
            if id == "clean" {
                assert!(result.findings.is_empty());
            } else {
                assert_eq!(result.findings.len(), 4);
            }
            for receipt in result.details["executionReceipts"].as_array().unwrap() {
                assert_eq!(receipt["state"], "completed");
                assert_eq!(receipt["complete"], true);
                assert_eq!(receipt["exitCode"], 0);
                assert_eq!(receipt["processTree"]["reaped"], true);
            }
        } else if id == "http-failure" {
            assert!(runtime["surfaces"][0]["gaps"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v.as_str().unwrap().contains("runtime-surface-load")));
        } else {
            let receipt = &result.details["executionReceipt"];
            assert_eq!(receipt["state"], "unauthorized_effect");
            assert_eq!(receipt["processTree"]["started"], false);
            assert_eq!(
                receipt["policy"]["reason"],
                "native-owner-admission-unavailable"
            );
            assert!(rows.lock().unwrap().is_empty());
        }
        cases.push(json!({"caseId":id,"fixtureRoot":fixture,"scratchRoot":scratch.root(),"url":url,"extraSurfaces":extra,"frozenPlan":frozen.plan(),"planDigest":frozen.digest(),"inventory":inventory,"actualProviderResult":result,"mappings":rows.lock().unwrap().clone(),"screenshots":shots}));
    }
    let requests = server.requests.lock().unwrap().clone();
    drop(server);
    let files = sources(&root);
    let mut row = json!({"schema":"legion-runtime-app-sdk-accuracy/1","provider":ID,"family":"runtime-app-sdk","stage":"finding","scope":SCOPE,"productionQualification":false,"wholeProviderQualified":false,"unmodifiedResolverQualified":false,"productionAdmissionQualified":false,"qualificationEligible":true,"status":"pass","modelCalls":0,"binding":{"providerSpec":shipped,"sources":files,"sourcesDigest":digest(&canonical(&serde_json::to_value(&files).unwrap())),"plan":definition,"planDigest":digest(&canonical(&definition)),"originalExecutable":{"path":test,"sha256":digest(&fs::read(&test).unwrap())},"mappedExecutable":{"path":cli,"sha256":digest(&fs::read(&cli).unwrap())},"browser":{"path":browser,"sha256":digest(&fs::read(&browser).unwrap()),"versionOutput":browser_banner,"installerMarker":marker,"installedRoot":installed,"installedTree":browser_tree(&installed)},"axeDigest":digest(&fs::read(root.join("engine/crates/legion-audit/assets/axe-core-4.14.0.min.js")).unwrap())},"retainedRoot":output,"origin":cases[0]["url"].as_str().unwrap().trim_end_matches("/clean/entry.html"),"cases":cases,"serverRequests":requests,"cleanup":{"fixtureServerStopped":true,"nativeProcessTreesReaped":true,"retainedEvidence":true}});
    row["qualificationDigest"] = json!(digest(&canonical(&row)));
    fs::write(
        output.join("legacy_runtime_app.json"),
        serde_json::to_vec_pretty(&row).unwrap(),
    )
    .unwrap();
    println!(
        "RUNTIME_APP_SDK_ACCURACY {}",
        serde_json::to_string(&row).unwrap()
    );
}
