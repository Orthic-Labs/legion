//! `legacy.runtime.app`: runtime capture through the running Legion
//! executable's browser route, exercised with a fake external tool that plays
//! the route's stdout/stderr and files. Every result goes through
//! `execute_with_cancellation`, so the external-receipt validator and the
//! frozen-denominator checks run on it too.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use legion_audit::{
    native_providers::legacy_checks::{resolve_request, runtime_inputs},
    AuditPlan, InventoryEntry, InventoryEnvelope, NativeProviderRegistry,
};
use legion_provider_sdk::{
    ExecutionReceipt, ExecutionState, ExternalProjectTool, ExternalToolRequest,
};
use serde_json::{json, Value};
use sha2::Digest;
use tokio_util::sync::CancellationToken;

const PROVIDER: &str = "legacy.runtime.app";
const PNG: &[u8] = b"\x89PNG\r\n\x1a\nfake-image-bytes";

static ROOT_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn root() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "legion-runtime-capture-{}-{nonce}-{}",
        std::process::id(),
        ROOT_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("package.json"), "{}").unwrap();
    root
}

fn inventory() -> InventoryEnvelope {
    InventoryEnvelope::new(
        "repo",
        "generation",
        vec![InventoryEntry {
            path: "package.json".into(),
            symbols: vec![],
            dependencies: vec![],
            package_scripts: vec!["dev".into()],
            source_file: false,
            digest: None,
        }],
    )
    .unwrap()
}

fn plan_with(inventory: &InventoryEnvelope, runtime: Option<Value>) -> legion_audit::FrozenPlan {
    let mut runner = json!({"kind": "legacy-check", "check": "runtime"});
    if let Some(runtime) = runtime {
        runner["runtime"] = runtime;
    }
    AuditPlan::compile(
        inventory,
        &[serde_json::from_value(json!({
            "schemaVersion": 2, "id": PROVIDER, "providerVersion": "2.0.0",
            "family": "performance", "role": "deterministic", "phase": "runtime",
            "lensIds": ["runtime"], "dependsOn": [], "consumes": [],
            "produces": ["provider-result"], "selector": {"op": "always"},
            "denominatorKind": "runnable app", "runner": runner,
            "hostCapabilities": [], "execution": {}, "reasoning": {},
            "benchmark": {"status": "unproven", "requiredForCleanClaim": false},
            "cleanClaim": "evidence-only", "controlIds": [], "scopes": [],
            "selectable": true
        }))
        .unwrap()],
    )
    .unwrap()
    .freeze(Some(b"test-key"))
    .unwrap()
}

#[derive(Clone)]
enum Mode {
    /// Page loads; `entries` are printed as console output, `total` is the
    /// count the route reports (defaults to the entry count).
    Good {
        entries: Vec<String>,
        total: Option<usize>,
    },
    /// The route reports a screenshot but no file exists.
    NoScreenshot,
    /// The load check fails (browser error page / HTTP error).
    LoadFailed,
    /// No browser on the host.
    BrowserMissing,
}

struct RuntimeFake {
    mode: Mode,
    calls: Arc<Mutex<Vec<ExternalToolRequest>>>,
}

fn artifact(path: &Path, body: &[u8]) -> legion_effects::ArtifactRecord {
    fs::write(path, body).unwrap();
    legion_effects::ArtifactRecord {
        path: path.to_string_lossy().into_owned(),
        digest: format!("sha256:{}", hex::encode(sha2::Sha256::digest(body))),
        bytes: body.len(),
        immutable: true,
    }
}

fn arg_after<'a>(args: &'a [String], flag: &str) -> &'a str {
    let at = args.iter().position(|arg| arg == flag).unwrap();
    &args[at + 1]
}

#[async_trait]
impl ExternalProjectTool for RuntimeFake {
    async fn execute(
        &self,
        request: ExternalToolRequest,
        _cancellation: CancellationToken,
    ) -> ExecutionReceipt {
        self.calls.lock().unwrap().push(request.clone());
        let cwd = PathBuf::from(&request.cwd);
        let actions_path = arg_after(&request.args, "--actions").to_owned();
        let actions: Value = serde_json::from_slice(&fs::read(&actions_path).unwrap()).unwrap();
        let shot = actions[1]["out"].as_str().unwrap().to_owned();
        let mut receipt = ExecutionReceipt::failure(&request, ExecutionState::Failed, "exit 1");
        receipt.process_tree.started = true;
        receipt.process_tree.terminated = true;
        receipt.process_tree.reaped = true;
        match &self.mode {
            Mode::Good { entries, total } => {
                fs::write(&shot, PNG).unwrap();
                let mut out = format!(
                    "[qa] 1:eval ok\n[qa] screenshot {shot}\n[qa] 2:screenshot ok\n[qa] actions complete {actions_path}\n"
                );
                if entries.is_empty() {
                    out.push_str("[qa] no console errors or warnings\n");
                } else {
                    out.push_str(&format!(
                        "[qa] {} console error/warning(s) \u{2014} see x\n",
                        total.unwrap_or(entries.len())
                    ));
                    for entry in entries {
                        out.push_str(&format!("[qa]   {entry}\n"));
                    }
                }
                receipt.state = ExecutionState::Completed;
                receipt.complete = true;
                receipt.gaps.clear();
                receipt.exit_code = Some(0);
                receipt.stdout = Some(artifact(&cwd.join("stdout.txt"), out.as_bytes()));
            }
            Mode::NoScreenshot => {
                let out = format!(
                    "[qa] 1:eval ok\n[qa] screenshot {shot}\n[qa] actions complete x\n[qa] no console errors or warnings\n"
                );
                receipt.state = ExecutionState::Completed;
                receipt.complete = true;
                receipt.gaps.clear();
                receipt.exit_code = Some(0);
                receipt.stdout = Some(artifact(&cwd.join("stdout.txt"), out.as_bytes()));
            }
            Mode::LoadFailed => {
                receipt.exit_code = Some(1);
                receipt.stderr = Some(artifact(
                    &cwd.join("stderr.txt"),
                    b"[qa] 1:eval eval returned not ok: {\"ok\":false,\"href\":\"chrome-error://chromewebdata/\"}\n",
                ));
            }
            Mode::BrowserMissing => {
                receipt.exit_code = Some(1);
                receipt.stderr = Some(artifact(
                    &cwd.join("stderr.txt"),
                    b"[qa] No Chrome/Edge executable found.\n",
                ));
            }
        }
        receipt
    }
}

struct Run {
    result: legion_contracts::ProviderResult,
    calls: Vec<ExternalToolRequest>,
    root: PathBuf,
    /// Keeps the audit scratch (and its screenshots) alive for assertions.
    _registry: NativeProviderRegistry,
}

fn run(runtime: Option<Value>, mode: Mode, with_tool: bool) -> Run {
    let root = root();
    let inventory = inventory();
    let plan = plan_with(&inventory, runtime);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut registry = NativeProviderRegistry::new(&root);
    if with_tool {
        registry = registry.with_external_project_tool(Arc::new(RuntimeFake {
            mode,
            calls: calls.clone(),
        }));
    }
    let report = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(legion_audit::execute_with_cancellation(
            &plan,
            &inventory,
            &registry,
            CancellationToken::new(),
        ))
        .unwrap();
    let result = report.results[0].result.clone();
    let calls = calls.lock().unwrap().clone();
    Run {
        result,
        calls,
        root,
        _registry: registry,
    }
}

fn url_inputs(extra: &[(&str, &str)], unsupported: &[&str]) -> Value {
    runtime_inputs(
        "http://127.0.0.1:1422/?qa=1",
        &extra
            .iter()
            .map(|(label, url)| (label.to_string(), url.to_string()))
            .collect::<Vec<_>>(),
        &unsupported
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>(),
        390,
        844,
        None,
    )
    .unwrap()
}

fn assert_valid_not_rejected(result: &legion_contracts::ProviderResult) {
    assert!(
        !result
            .coverage_gaps
            .iter()
            .any(|gap| gap.starts_with("invalid-provider-result")),
        "{:?}",
        result.coverage_gaps
    );
}

#[test]
fn good_capture_records_screenshot_digest_console_findings_and_stays_incomplete() {
    let run = run(
        Some(url_inputs(
            &[("settings", "http://127.0.0.1:1422/settings")],
            &[],
        )),
        Mode::Good {
            entries: vec![
                "console.error: \"boom\"".into(),
                "console.warning: \"careful\"".into(),
            ],
            total: None,
        },
        true,
    );
    let result = &run.result;
    assert_valid_not_rejected(result);
    assert!(!result.complete, "performance and a11y are not captured");
    assert_eq!(result.status, legion_contracts::ProviderStatus::Partial);
    for gap in [
        "runtime-lens-not-captured:performance:qa-eval-result-not-reported",
        "runtime-lens-not-captured:a11y:axe-core-not-shipped",
    ] {
        assert!(
            result.coverage_gaps.contains(&gap.to_owned()),
            "missing named lens gap {gap}"
        );
    }
    // The bare, reasonless gap names are gone: every lens gap names its
    // missing dependency.
    assert!(!result
        .coverage_gaps
        .iter()
        .any(|gap| gap == "runtime-lens-not-captured:performance"
            || gap == "runtime-lens-not-captured:a11y"));
    assert_eq!(run.calls.len(), 2, "one invocation per surface");

    // The request is the running executable's own browser route, argv-only,
    // in a scratch directory outside the audited tree.
    let first = &run.calls[0];
    assert_eq!(first.executable, "legion-qa-shot");
    assert_eq!(&first.args[..2], ["script", "qa/qa-functional"]);
    assert_eq!(
        arg_after(&first.args, "--url"),
        "http://127.0.0.1:1422/?qa=1"
    );
    assert_eq!(arg_after(&first.args, "--width"), "390");
    assert_eq!(arg_after(&first.args, "--height"), "844");
    assert_eq!(
        arg_after(&run.calls[1].args, "--url"),
        "http://127.0.0.1:1422/settings"
    );
    assert!(!first.shell && !first.requires_network_sandbox);
    assert_eq!(first.origin, legion_effects::ToolOrigin::LegionOwned);
    assert!(Path::new(&first.cwd).is_absolute());
    assert!(!Path::new(&first.cwd).starts_with(&run.root));

    let runtime = &result.details["runtime"];
    assert_eq!(runtime["kind"], "audit-runtime");
    assert_eq!(runtime["viewport"], json!({"width": 390, "height": 844}));
    let surfaces = runtime["surfaces"].as_array().unwrap();
    assert_eq!(surfaces.len(), 2);
    for (index, surface) in surfaces.iter().enumerate() {
        assert_eq!(surface["status"], "captured", "{surface}");
        let path = surface["screenshot"]["path"].as_str().unwrap();
        let bytes = fs::read(path).unwrap();
        assert_eq!(
            surface["screenshot"]["sha256"],
            format!("sha256:{}", hex::encode(sha2::Sha256::digest(&bytes)))
        );
        assert_eq!(surface["screenshot"]["bytes"], bytes.len());
        assert!(!Path::new(path).starts_with(&run.root));
        assert_eq!(surface["consoleErrors"].as_array().unwrap().len(), 1);
        assert_eq!(surface["consoleWarnings"].as_array().unwrap().len(), 1);
        assert_eq!(surface["processState"], "completed");
        assert_eq!(surface["index"], index);
    }
    assert_eq!(surfaces[0]["label"], "entry");
    assert_eq!(surfaces[1]["label"], "settings");
    assert_eq!(
        runtime["denominator"],
        json!({"kind": "runtime-surfaces", "expected": 2, "examined": 2})
    );

    // Console errors become findings, one per surface; warnings stay evidence.
    assert_eq!(result.findings.len(), 2);
    assert_eq!(result.coverage.as_ref().unwrap().examined, 1);
    assert_eq!(
        result.details["executionReceipt"]["processTree"]["started"],
        true
    );
    assert_eq!(
        result.details["executionReceipts"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(result.details["processState"], "completed");

    // Nothing was written into the audited tree.
    let names: Vec<_> = fs::read_dir(&run.root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["package.json".to_owned()]);
}

#[test]
fn clean_console_makes_no_findings() {
    let run = run(
        Some(url_inputs(&[], &[])),
        Mode::Good {
            entries: vec![],
            total: None,
        },
        true,
    );
    assert_valid_not_rejected(&run.result);
    assert!(run.result.findings.is_empty());
    assert_eq!(
        run.result.details["runtime"]["surfaces"][0]["status"],
        "captured"
    );
    assert!(!run.result.complete);
}

#[test]
fn truncated_console_output_is_a_named_gap() {
    let run = run(
        Some(url_inputs(&[], &[])),
        Mode::Good {
            entries: vec!["console.error: \"a\"".into()],
            total: Some(25),
        },
        true,
    );
    assert!(run
        .result
        .coverage_gaps
        .contains(&"runtime-console-truncated:entry:25".to_owned()));
}

#[test]
fn tool_failure_to_load_the_page_is_a_failed_provider_with_a_named_gap() {
    let run = run(Some(url_inputs(&[], &[])), Mode::LoadFailed, true);
    let result = &run.result;
    assert_valid_not_rejected(result);
    assert!(!result.complete);
    assert_eq!(result.status, legion_contracts::ProviderStatus::Failed);
    assert!(result
        .coverage_gaps
        .contains(&"runtime-surface-load-failed:entry".to_owned()));
    let surface = &result.details["runtime"]["surfaces"][0];
    assert_eq!(surface["status"], "failed");
    assert_eq!(surface["screenshot"], Value::Null);
    assert!(surface["failure"]
        .as_str()
        .unwrap()
        .contains("eval returned not ok"));
    assert_eq!(result.coverage.as_ref().unwrap().examined, 0);
    assert_eq!(result.details["executionReceipt"]["state"], "failed");
    assert!(result.findings.is_empty());
}

#[test]
fn missing_browser_is_typed_unavailable() {
    let run = run(Some(url_inputs(&[], &[])), Mode::BrowserMissing, true);
    let result = &run.result;
    assert_valid_not_rejected(result);
    assert!(!result.complete);
    assert_eq!(result.status, legion_contracts::ProviderStatus::Partial);
    assert!(result
        .coverage_gaps
        .contains(&"unavailable:browser-not-found".to_owned()));
    assert_eq!(
        result.details["availability"]["reason"],
        "browser-not-found"
    );
}

#[test]
fn reported_screenshot_without_a_file_is_never_a_capture() {
    let run = run(Some(url_inputs(&[], &[])), Mode::NoScreenshot, true);
    let result = &run.result;
    assert_valid_not_rejected(result);
    assert!(result
        .coverage_gaps
        .contains(&"runtime-screenshot-missing:entry".to_owned()));
    assert_eq!(result.details["runtime"]["surfaces"][0]["status"], "failed");
    assert_eq!(result.coverage.as_ref().unwrap().examined, 0);
}

#[test]
fn click_only_surfaces_are_named_unsupported_gaps() {
    let run = run(
        Some(url_inputs(&[], &["editor"])),
        Mode::Good {
            entries: vec![],
            total: None,
        },
        true,
    );
    assert!(run
        .result
        .coverage_gaps
        .contains(&"runtime-surface-unsupported:editor".to_owned()));
    assert_eq!(
        run.result.details["runtime"]["unsupportedSurfaces"][0],
        "editor"
    );
    assert_eq!(
        run.result.details["runtime"]["denominator"],
        json!({"kind": "runtime-surfaces", "expected": 2, "examined": 1})
    );
}

#[test]
fn without_a_url_the_provider_is_unavailable_and_starts_nothing() {
    let run = run(None, Mode::LoadFailed, true);
    let result = &run.result;
    assert_valid_not_rejected(result);
    assert!(run.calls.is_empty(), "no process may start without a URL");
    assert!(!result.complete);
    assert_eq!(result.status, legion_contracts::ProviderStatus::Partial);
    assert!(result
        .coverage_gaps
        .contains(&"unavailable:runtime-url-not-supplied".to_owned()));
    assert_eq!(
        result.details["availability"]["reason"],
        "runtime-url-not-supplied"
    );
    assert_eq!(
        result.details["executionReceipt"]["processTree"]["started"],
        false
    );
}

#[test]
fn invalid_frozen_inputs_are_unavailable_not_executed() {
    let run = run(
        Some(json!({"url": "ftp://127.0.0.1/", "width": 800, "height": 600})),
        Mode::LoadFailed,
        true,
    );
    assert!(run.calls.is_empty());
    assert!(run
        .result
        .coverage_gaps
        .contains(&"unavailable:runtime-inputs-invalid:url-scheme-not-http".to_owned()));
}

#[test]
fn without_the_external_tool_capability_nothing_is_claimed() {
    let run = run(Some(url_inputs(&[], &[])), Mode::LoadFailed, false);
    assert!(!run.result.complete);
    assert!(run
        .result
        .coverage_gaps
        .contains(&"unavailable:external-project-tool-capability-unavailable".to_owned()));
}

#[test]
fn runtime_inputs_validate_what_the_plan_will_freeze() {
    assert!(runtime_inputs("ftp://x/", &[], &[], 800, 600, None).is_err());
    assert!(runtime_inputs("http://x/", &[], &[], 0, 600, None).is_err());
    assert!(runtime_inputs("http://x/", &[], &[], 800, 600, Some("relative")).is_err());
    let value = runtime_inputs("http://x/", &[], &[], 800, 600, Some("/tmp/out/runtime")).unwrap();
    assert_eq!(value["artifactDir"], "/tmp/out/runtime");
}

#[test]
fn runtime_tool_resolves_to_the_running_executable() {
    let root = root();
    let args = vec!["script".to_owned(), "qa/qa-functional".to_owned()];
    let resolved = resolve_request(&root, "legion-qa-shot", &args).unwrap();
    let current = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
    assert_eq!(resolved.executable, current);
    assert_eq!(resolved.args, args);
    assert!(resolved.digest.starts_with("sha256:"));
    fs::remove_dir_all(root).unwrap();
}
