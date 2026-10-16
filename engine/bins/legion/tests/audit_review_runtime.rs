//! Deterministic host integration simulation. This custom test executable is
//! also the fake Claude subprocess; it contains no model/network client.
//! `harness=false` lets it accept native --help/--print protocol arguments.
use legion_audit::{
    canonical_report, execute,
    native_providers::reasoning::{
        ingest::{
            create_epoch, load_epoch, write_lens_dispatch, write_lens_packets, DispatchLimits,
            EPOCH_KEY_FILE,
        },
        pending_lens_work, ReasoningProviderExecutor,
    },
    review_runtime::{self, RuntimeOptions},
    scope::{ResolvedScope, ScopeSpec},
    snapshot::FrozenSnapshot,
    AuditPlan, FilesystemInventorySource, InventorySource,
};
use legion_contracts::{ProviderId, ProviderSpec};
use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

const PROVIDER: &str = "reasoning.naming";
const SOURCE_LINE: &str = "    a - b";
// Keep these exact markers inside the executable for the bounded capability
// probe. This is simulated capability evidence, never Claude qualification.
const HELP: &str = "SIMULATED Claude: --tools --strict-mcp-config --mcp-config --safe-mode --restricted --disable-slash-commands --no-chrome --no-session-persistence --permission-prompts --json-schema --system-prompt --max-turns CLAUDE_CODE_MAX_OUTPUT_TOKENS";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--help") {
        println!("{HELP}");
    } else if args.iter().any(|arg| arg == "--print") {
        install_simulation_diagnostics();
        simulate_native(&args);
    } else {
        completes_after_host_tool_round_and_recovers_stale_lock_file();
        completes_with_eager_selected_skeleton_source_in_one_call();
        preserves_finding_after_fresh_verifier_success();
        refusal_and_missing_usage_remain_incomplete();
        rejects_unadvertised_native_tool();
        live_runtime_lock_excludes_another_controller();
        println!("SIMULATION PASS: Audit native host integration (no real model call)");
    }
}

fn install_simulation_diagnostics() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // Fake-provider-only diagnostic: these inputs contain synthetic source
        // & no credential client. Never change real native stderr handling.
        let message = info.to_string().chars().take(4096).collect::<String>();
        if let Ok(directory) = std::env::current_dir() {
            let _ = fs::write(
                directory.join(format!("simulation-failure-{}.txt", std::process::id())),
                message,
            );
        }
        previous(info);
    }));
}

fn value_after<'a>(args: &'a [String], flag: &str) -> &'a str {
    args.iter()
        .position(|arg| arg == flag)
        .and_then(|index| args.get(index + 1))
        .map(String::as_str)
        .unwrap_or_else(|| panic!("simulation missing native argument {flag}"))
}
fn simulate_native(args: &[String]) {
    assert_eq!(value_after(args, "--tools"), "");
    assert_eq!(value_after(args, "--mcp-config"), r#"{"mcpServers":{}}"#);
    assert_eq!(value_after(args, "--max-turns"), "1");
    let schema: Value = serde_json::from_str(value_after(args, "--json-schema")).unwrap();
    for unsupported in ["oneOf", "allOf", "anyOf"] {
        assert!(
            schema.get(unsupported).is_none(),
            "simulation rejects native-unsupported top-level {unsupported}"
        );
    }
    for flag in [
        "--strict-mcp-config",
        "--safe-mode",
        "--restricted",
        "--disable-slash-commands",
        "--no-chrome",
        "--no-session-persistence",
    ] {
        assert!(
            args.iter().any(|arg| arg == flag),
            "missing boundary flag {flag}"
        );
    }
    let cap = std::env::var("CLAUDE_CODE_MAX_OUTPUT_TOKENS")
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert!(cap > 0);
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).unwrap();
    let frame: Value = serde_json::from_str(&input).unwrap();
    assert_eq!(frame["type"], "user");
    let prompt: Value =
        serde_json::from_str(frame["message"]["content"].as_str().unwrap()).unwrap();
    let prompt_text = prompt.to_string();
    assert!(
        prompt_text.contains("runtime-simulation:"),
        "fixture source marker absent"
    );
    let reviewer = prompt.get("finding").is_some();
    if !reviewer && prompt_text.contains("runtime-simulation:clean-eager") {
        assert!(prompt["initialContext"]["deliveries"].is_array());
        assert!(prompt["initialContext"].to_string().contains(SOURCE_LINE));
        assert!(prompt["initialContext"]
            .to_string()
            .contains("audit.read_file"));
        assert!(prompt["initialContext"].to_string().contains("replyDigest"));
        assert!(!prompt["request"]["packet"]["excerpts"]
            .to_string()
            .contains(SOURCE_LINE));
        assert!(prompt.get("findingSchema").is_none());
        assert_eq!(
            prompt["findingSchemaRef"],
            "request.packet.reportSchemaBody"
        );
    }
    let tool_round = !reviewer
        && prompt_text.contains("runtime-simulation:clean-tool")
        && prompt["conversation"].as_array().is_some_and(Vec::is_empty);
    let directory = std::env::current_dir().unwrap();
    write_json(
        &directory.join(format!("simulation-call-{}.json", std::process::id())),
        &json!({"simulation":true,"args":args,"prompt":prompt,"outputTokenLimit":cap,"reviewer":reviewer,"toolRound":tool_round}),
    );
    if !reviewer && prompt_text.contains("runtime-simulation:wait-for-release") {
        fs::write(directory.join("simulation-ready"), b"ready").unwrap();
        wait_for(&directory.join("simulation-release"));
    }
    let reply = if reviewer {
        json!({"verdict":"upheld","reason":"Simulation: add(5,2) follows subtraction source trace","evidence":[{"path":"src/lib.rs","line":2,"text":SOURCE_LINE,"sourceSide":"selected"}],"concreteCase":"Simulation: add(5,2) returns3 while name promises addition7"})
    } else if tool_round {
        json!({"toolRequest":{"tool":"audit.read_file","arguments":{"path":"src/lib.rs","startLine":1,"endLine":4}}})
    } else {
        if prompt_text.contains("runtime-simulation:clean-tool") {
            assert!(prompt_text.contains("hostToolReply"));
            assert!(prompt_text.contains("replyDigest"));
            assert!(prompt_text.contains(SOURCE_LINE));
        }
        let findings = if prompt_text.contains("runtime-simulation:clean-tool")
            || prompt_text.contains("runtime-simulation:clean-eager")
            || prompt_text.contains("runtime-simulation:wait-for-release")
        {
            json!([])
        } else {
            json!([finding()])
        };
        json!({"finalResult":{"complete":true,"findings":findings,"withdrawn":[],"details":{}}})
    };
    println!(
        "{}",
        json!({"type":"system","subtype":"init","session_id":format!("simulation-context-{}",std::process::id()),"tools":["StructuredOutput"]})
    );
    if prompt_text.contains("runtime-simulation:unexpected-tool") {
        println!(
            "{}",
            json!({"type":"assistant","message":{"content":[{"type":"tool_use","id":"forbidden","name":"Bash","input":{"command":"must never execute"}}]}})
        );
    } else {
        println!(
            "{}",
            json!({"type":"assistant","message":{"content":[{"type":"tool_use","id":"structured","name":"StructuredOutput","input":reply}]}})
        );
    }
    let mut terminal =
        json!({"type":"result","subtype":"success","is_error":false,"structured_output":reply});
    if reviewer && prompt_text.contains("runtime-simulation:refusal") {
        terminal = json!({"type":"result","subtype":"error_during_execution","is_error":true,"errors":["SIMULATED refusal"]});
    }
    if !(reviewer && prompt_text.contains("runtime-simulation:missing-usage")) {
        terminal["usage"] = json!({"input_tokens":100,"cache_read_input_tokens":0,"cache_creation_input_tokens":0,"output_tokens":20});
    }
    println!("{terminal}");
    std::io::stdout().flush().unwrap();
}

fn finding() -> Value {
    json!({"id":"simulation-naming-1","title":"Simulation: add subtracts","lens":"naming","severity":"medium","confidence":"likely","evidence":["src/lib.rs:2"],"failureScenario":"Simulation: add(5,2) returns3 while its name promises addition","action":"rename or implement addition","verifyStatus":"unverified","anchor":{"path":"src/lib.rs","line":2,"text":SOURCE_LINE,"sourceSide":"selected"}})
}
fn write_json(path: &Path, value: &Value) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}
fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}
fn wait_for(path: &Path) {
    let start = Instant::now();
    while !path.exists() {
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "simulation wait timed out: {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

struct Fixture {
    base: PathBuf,
    repo: PathBuf,
    run: PathBuf,
    home: PathBuf,
}
impl Fixture {
    fn new(mode: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let base = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "legion-runtime-simulation-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(&base).unwrap();
        let fixture = Self {
            repo: base.join("repo"),
            run: base.join("run"),
            home: base.join("home"),
            base,
        };
        fs::create_dir_all(fixture.repo.join("src")).unwrap();
        fs::create_dir_all(&fixture.home).unwrap();
        // Naming uses skeleton excerpts, which omit ordinary comments. Keep
        // mode selection in valid frozen source retained by that projection.
        fs::write(fixture.repo.join("src/lib.rs"),format!("pub fn add(a:i32,b:i32)->i32 {{\n{SOURCE_LINE}\n}}\npub const RUNTIME_SIMULATION: &str = \"runtime-simulation:{mode}\";\n")).unwrap();
        fixture.git(&["init", "-q"]);
        fixture.git(&["config", "user.name", "Runtime Simulation"]);
        fixture.git(&["config", "user.email", "simulation@example.invalid"]);
        fixture.git(&["add", "src"]);
        fixture.git(&[
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=",
            "commit",
            "-qm",
            "simulated runtime source",
        ]);
        fixture.prepare();
        fixture
    }
    fn git(&self, args: &[&str]) {
        let output = Command::new("git")
            .current_dir(&self.repo)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "fixture Git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    fn prepare(&self) {
        let snapshot = FrozenSnapshot::capture(
            ResolvedScope::resolve(&self.repo, ScopeSpec::Repo, None).unwrap(),
        )
        .unwrap();
        let root = &snapshot.manifest.execution_root;
        let repository = root.to_string_lossy().into_owned();
        let inventory = FilesystemInventorySource::new(root)
            .unwrap()
            .inventory(&repository)
            .unwrap();
        let epoch = create_epoch(&self.run).unwrap();
        let (key, _) = load_epoch(&self.run).unwrap();
        let context = json!({"snapshotManifest":snapshot.manifest_path,"snapshotKey":snapshot.manifest.key,"sourceRepository":self.repo});
        let spec = ProviderSpec {
            schema_version: 2,
            id: ProviderId::new(PROVIDER).unwrap(),
            provider_version: "1".into(),
            family: "simulation".into(),
            lens_ids: vec!["naming".into()],
            role: "adjudicator".into(),
            phase: "source".into(),
            depends_on: Vec::new(),
            consumes: vec!["repository-inventory".into()],
            produces: vec!["provider-result".into()],
            selector: json!({"op":"always"}),
            denominator_kind: "first-party-source-files".into(),
            runner: json!({"kind":"reasoning-contract","contract":"runtime-simulation-v1"}),
            host_capabilities: Vec::new(),
            execution: json!({}),
            reasoning: json!({"reviewContext":context}),
            benchmark: json!({"status":"unproven","requiredForCleanClaim":false}),
            clean_claim: "evidence-only".into(),
            control_ids: Vec::new(),
            scopes: Vec::new(),
            selectable: true,
        };
        let plan = AuditPlan::compile_with_root(Some(root), &inventory, &[spec])
            .unwrap()
            .freeze(Some(&key))
            .unwrap();
        let execution = execute(
            &plan,
            &inventory,
            &ReasoningProviderExecutor::unavailable(root),
        )
        .unwrap();
        assert_eq!(execution.pending_host, vec![PROVIDER]);
        let report = canonical_report(&repository, &execution).unwrap();
        let work = pending_lens_work(root, &plan, &inventory).unwrap();
        assert_eq!(work.len(), 1);
        assert!(
            work[0].request.packet["excerpts"]
                .to_string()
                .contains("runtime-simulation:"),
            "simulation mode must survive frozen source excerpt projection"
        );
        write_lens_packets(&self.run.join("lens-packets"), &work).unwrap();
        write_lens_dispatch(&self.run, &work, &DispatchLimits::default()).unwrap();
        write_json(
            &self.run.join("inventory.json"),
            &serde_json::to_value(&inventory).unwrap(),
        );
        write_json(
            &self.run.join("execution.json"),
            &serde_json::to_value(&execution).unwrap(),
        );
        write_json(
            &self.run.join("report.json"),
            &serde_json::to_value(
                legion_audit::lift_report_v2(
                    &report,
                    legion_contracts::ReportScope {
                        spec: "repo".into(),
                        base_ref_oid: None,
                        merge_base_oid: None,
                        head: snapshot.manifest.scope.selected_oid.clone(),
                        snapshot_key: Some(snapshot.manifest.key.clone()),
                        index_schema_version: Some(legion_audit::scope::SCOPE_SCHEMA_VERSION),
                    },
                )
                .unwrap(),
            )
            .unwrap(),
        );
        write_json(
            &self.run.join("plan.json"),
            &json!({"schemaVersion":1,"kind":"audit-provider-plan","repository":repository,"reviewContext":context,"snapshotManifest":snapshot.manifest_path,"nativePlan":{"schemaVersion":1,"digest":plan.digest(),"signature":plan.signature(),"plan":plan.plan()},"binding":{"repositoryRevision":execution.generation,"inventoryDigest":execution.inventory_digest},"seal":{"digest":plan.digest(),"signature":plan.signature(),"authenticity":"hmac-sha256"},"providers":execution.planned_providers,"epoch":{"digest":epoch,"keyFile":EPOCH_KEY_FILE}}),
        );
    }
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_legion"));
        command
            .current_dir(&self.repo)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("LOCALAPPDATA", self.home.join("AppData/Local"))
            .env("XDG_DATA_HOME", self.home.join(".local/share"))
            .env_remove("AUDIT_PLAN_SIGNING_KEY")
            .env_remove("LEGION_NATIVE_APPLICATION_CONFIG")
            .args(["audit", "run-reasoning", "--run"])
            .arg(&self.run)
            .arg("--claude")
            .arg(std::env::current_exe().unwrap());
        command
    }
    fn run(&self) -> (Output, Value, Value) {
        let output = self.command().output().unwrap();
        let result = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "runtime simulation output invalid:{error}; stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
        let report = read_json(&self.run.join("report.json"));
        (output, result, report)
    }
    fn calls(&self) -> Vec<Value> {
        let mut calls = fs::read_dir(self.run.join("runtime-host"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("simulation-call-")
            })
            .map(|path| read_json(&path))
            .collect::<Vec<_>>();
        calls.sort_by_key(|call| call["reviewer"].as_bool());
        calls
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("simulation artifacts retained: {}", self.base.display());
            if let Ok(entries) = fs::read_dir(self.run.join("runtime-host")) {
                for entry in entries
                    .flatten()
                    .filter(|entry| {
                        entry
                            .file_name()
                            .to_string_lossy()
                            .starts_with("simulation-failure-")
                    })
                    .take(8)
                {
                    if let Ok(file) = fs::File::open(entry.path()) {
                        let mut message = String::new();
                        let _ = file.take(4096).read_to_string(&mut message);
                        eprintln!(
                            "SIMULATED provider stderr {}: {message}",
                            entry.file_name().to_string_lossy()
                        );
                    }
                }
            }
        } else {
            let _ = fs::remove_dir_all(&self.base);
        }
    }
}

fn completes_after_host_tool_round_and_recovers_stale_lock_file() {
    let fixture = Fixture::new("clean-tool");
    fs::write(fixture.run.join("review-runtime.lock"), b"99999999").unwrap();
    let (output, result, report) = fixture.run();
    assert!(output.status.success(), "simulation runtime:{result}");
    assert_eq!(result["complete"], true);
    assert_eq!(result["status"], "done");
    assert_eq!(result["calls"], 2);
    assert_eq!(result["callAttempts"], 2);
    assert_eq!(report["status"], "clean");
    assert!(report["gaps"].as_array().unwrap().is_empty());
    assert!(fixture
        .run
        .join(format!("lens-receipts/{PROVIDER}.json"))
        .is_file());
    assert_eq!(fixture.calls().len(), 2);
    assert!(fixture.calls().iter().any(|call| call["toolRound"] == true));
    let budget = read_json(&fixture.run.join("next-state.json"));
    assert_eq!(
        budget["reservations"]
            .as_object()
            .unwrap()
            .values()
            .filter(|reservation| reservation["transportAuthorized"] == true)
            .count(),
        2
    );
    assert!(fixture.run.join("report.sarif").is_file());
    assert!(!fixture.repo.join("must-never-execute").exists());
}
fn completes_with_eager_selected_skeleton_source_in_one_call() {
    let fixture = Fixture::new("clean-eager");
    let (output, result, report) = fixture.run();
    assert!(output.status.success(), "simulation eager runtime:{result}");
    assert_eq!(result["complete"], true);
    assert_eq!(report["status"], "clean");
    assert_eq!(result["calls"], 1);
    assert_eq!(result["callAttempts"], 1);
    assert_eq!(fixture.calls().len(), 1);
    let receipts: Vec<_> = fs::read_dir(fixture.run.join("runtime-calls"))
        .unwrap()
        .map(|entry| read_json(&entry.unwrap().path()))
        .collect();
    assert_eq!(receipts.len(), 1);
    let receipt = legion_audit::native_providers::reasoning::ingest::verify_runtime_call(
        &fixture.run,
        &receipts[0],
    )
    .unwrap();
    assert_eq!(receipt["modelAction"]["kind"], "finalResult");
    assert_eq!(receipt["requestAccounting"]["nativeFramingIncluded"], false);
    assert!(receipt["requestAccounting"]["providerInputTokenCountBeforeSend"].is_null());
    assert!(receipt["initialContext"].to_string().contains(SOURCE_LINE));
    assert!(receipt["initialContext"].to_string().len() <= 32 * 1024);
    let mut changed = receipts[0].clone();
    changed["modelAction"]["kind"] = json!("toolRequest");
    assert!(
        legion_audit::native_providers::reasoning::ingest::verify_runtime_call(
            &fixture.run,
            &changed
        )
        .is_err()
    );
}
fn preserves_finding_after_fresh_verifier_success() {
    let fixture = Fixture::new("upheld");
    let (output, result, report) = fixture.run();
    assert!(
        output.status.success(),
        "simulation verified runtime:{result}"
    );
    assert_eq!(result["complete"], true);
    assert_eq!(report["status"], "findings");
    assert_eq!(report["findings"].as_array().unwrap().len(), 1);
    assert_eq!(fixture.calls().len(), 2);
    assert_eq!(
        fixture
            .calls()
            .iter()
            .filter(|call| call["reviewer"] == true)
            .count(),
        1
    );
    let receipt = read_json(&fixture.run.join(format!("lens-receipts/{PROVIDER}.json")));
    let evidence = &receipt["result"]["details"]["verificationEvidence"]["findings"][0];
    assert_eq!(evidence["verdict"], "upheld");
    assert_ne!(
        evidence["author"]["contextId"],
        evidence["reviewer"]["contextId"]
    );
    assert_ne!(
        evidence["author"]["processId"],
        evidence["reviewer"]["processId"]
    );
}
fn refusal_and_missing_usage_remain_incomplete() {
    for mode in ["refusal", "missing-usage"] {
        let fixture = Fixture::new(mode);
        let (output, result, report) = fixture.run();
        assert_eq!(output.status.code(), Some(2), "simulation {mode}:{result}");
        assert_eq!(result["complete"], false);
        assert_eq!(report["status"], "incomplete");
        assert!(!report["gaps"].as_array().unwrap().is_empty());
        assert_eq!(
            report["findings"].as_array().unwrap().len(),
            1,
            "paid finding lost:{report}"
        );
        assert_eq!(fixture.calls().len(), 2);
        if mode == "missing-usage" {
            let state = read_json(&fixture.run.join("next-state.json"));
            assert!(
                state["reservations"]
                    .as_object()
                    .unwrap()
                    .values()
                    .any(|reservation| reservation.pointer("/usage/inputTokens")
                        == Some(&Value::Null))
            );
        }
    }
}
fn rejects_unadvertised_native_tool() {
    let fixture = Fixture::new("unexpected-tool");
    let (output, result, report) = fixture.run();
    assert_eq!(
        output.status.code(),
        Some(2),
        "simulation forbidden tool:{result}"
    );
    assert_eq!(report["status"], "incomplete");
    assert!(!fixture
        .run
        .join(format!("lens-receipts/{PROVIDER}.json"))
        .exists());
    assert_eq!(fixture.calls().len(), 1);
}
fn live_runtime_lock_excludes_another_controller() {
    let fixture = Fixture::new("wait-for-release");
    let child = fixture
        .command()
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for(&fixture.run.join("runtime-host/simulation-ready"));
    let contender = review_runtime::run(
        &fixture.run,
        &RuntimeOptions {
            claude: Some(std::env::current_exe().unwrap()),
            ..Default::default()
        },
    );
    assert!(contender
        .unwrap_err()
        .to_string()
        .contains("runtime-already-active"));
    fs::write(
        fixture.run.join("runtime-host/simulation-release"),
        b"release",
    )
    .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "simulation lock holder failed:{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(
        fixture.calls().len(),
        1,
        "contender launched a model process"
    );
}
