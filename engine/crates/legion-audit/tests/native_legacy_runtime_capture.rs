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
    canonical_report,
    native_providers::legacy_checks::{resolve_request, runtime_inputs},
    AuditPlan, ExecutionReport, InventoryEntry, InventoryEnvelope, NativeProviderRegistry,
    ProviderExecution,
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
    /// Navigation, screenshot, and performance succeed before axe times out.
    AxeFailedAfterPerformance,
    /// A complete route reports one actionable axe violation.
    AxeFinding,
}

/// What the route prints for the performance action (`[qa] 3:eval value ...`).
#[derive(Clone)]
enum PerfLine {
    /// A metrics object, as the page's Performance API reports it.
    Valid,
    /// No line at all (the route did not report the value).
    Absent,
    /// The text after `[qa] 3:eval value `, verbatim.
    Raw(String),
}

/// The metrics object `PerfLine::Valid` prints.
fn valid_metrics() -> Value {
    json!({
        "domContentLoaded": 412.5,
        "loadEventEnd": 430.0,
        "responseStart": 18.25,
        "ttfb": 18.25,
        "firstContentfulPaint": 301.0,
        "transferSize": 20480,
        "resourceCount": 7
    })
}

struct RuntimeFake {
    mode: Mode,
    perf: PerfLine,
    calls: Arc<Mutex<Vec<ExternalToolRequest>>>,
}

/// The performance line the route prints before `actions complete`.
fn perf_stdout(perf: &PerfLine) -> String {
    match perf {
        PerfLine::Valid => format!("[qa] 3:eval value {}\n", valid_metrics()),
        PerfLine::Absent => String::new(),
        PerfLine::Raw(text) => format!("[qa] 3:eval value {text}\n"),
    }
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
        let items = actions.as_array().unwrap();
        assert_eq!(items.len(), 4, "load check, screenshot, performance, axe");
        assert_eq!(items[2]["type"], "eval", "performance action");
        assert_eq!(items[3]["type"], "eval", "axe runs after performance");
        assert!(items[3]["expression"].as_str().unwrap().contains("wcag2aa"));
        let perf = perf_stdout(&self.perf);
        let mut receipt = ExecutionReceipt::failure(&request, ExecutionState::Failed, "exit 1");
        receipt.process_tree.started = true;
        receipt.process_tree.terminated = true;
        receipt.process_tree.reaped = true;
        match &self.mode {
            Mode::Good { entries, total } => {
                fs::write(&shot, PNG).unwrap();
                let mut out = format!(
                    "[qa] 1:eval value {{\"ok\":true,\"href\":\"http://127.0.0.1:1422/\",\"status\":200}}\n[qa] screenshot {shot}\n[qa] 2:screenshot ok\n{perf}[qa] 4:eval value {{\"status\":\"ran\",\"totalViolations\":0,\"truncated\":false,\"violations\":[]}}\n[qa] actions complete {actions_path}\n"
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
                    "[qa] 1:eval value {{\"ok\":true,\"href\":\"http://127.0.0.1:1422/\",\"status\":200}}\n[qa] screenshot {shot}\n[qa] actions complete x\n[qa] no console errors or warnings\n"
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
            Mode::AxeFailedAfterPerformance => {
                fs::write(&shot, PNG).unwrap();
                let out = format!(
                    "[qa] 1:eval value {{\"ok\":true,\"href\":\"http://127.0.0.1:1422/\",\"status\":200}}\n[qa] screenshot {shot}\n[qa] 2:screenshot ok\n{perf}[qa] 4:eval value {{\"status\":\"error\",\"reason\":\"axe-timeout\"}}\n"
                );
                receipt.exit_code = Some(1);
                receipt.stdout = Some(artifact(&cwd.join("stdout.txt"), out.as_bytes()));
                receipt.stderr = Some(artifact(
                    &cwd.join("stderr.txt"),
                    b"axe evaluation timed out\n",
                ));
            }
            Mode::AxeFinding => {
                fs::write(&shot, PNG).unwrap();
                let out = format!(
                    "[qa] 1:eval value {{\"ok\":true,\"href\":\"http://127.0.0.1:1422/\",\"status\":200}}\n[qa] screenshot {shot}\n[qa] 2:screenshot ok\n{perf}[qa] 4:eval value {{\"status\":\"ran\",\"totalViolations\":1,\"truncated\":false,\"violations\":[{{\"id\":\"color-contrast\",\"impact\":\"serious\",\"help\":\"Elements must have sufficient color contrast\",\"count\":2,\"target\":\"#submit\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/4.14/color-contrast\"}}]}}\n[qa] actions complete {actions_path}\n[qa] no console errors or warnings\n"
                );
                receipt.state = ExecutionState::Completed;
                receipt.complete = true;
                receipt.gaps.clear();
                receipt.exit_code = Some(0);
                receipt.stdout = Some(artifact(&cwd.join("stdout.txt"), out.as_bytes()));
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
    run_with(runtime, mode, PerfLine::Valid, with_tool)
}

fn run_with(runtime: Option<Value>, mode: Mode, perf: PerfLine, with_tool: bool) -> Run {
    let root = root();
    let inventory = inventory();
    let plan = plan_with(&inventory, runtime);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut registry = NativeProviderRegistry::new(&root);
    if with_tool {
        registry = registry.with_external_project_tool(Arc::new(RuntimeFake {
            mode,
            perf,
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
    assert!(
        !result.complete,
        "runtime provider remains incomplete under its coverage contract"
    );
    assert_eq!(result.status, legion_contracts::ProviderStatus::Partial);
    assert!(!result
        .coverage_gaps
        .iter()
        .any(|gap| gap.starts_with("runtime-a11y-")));
    assert_eq!(result.details["runtime"]["a11y_axe"], "ran");
    assert_eq!(result.details["runtime"]["a11y_violations_total"], 0);
    // Performance is captured, so its standing lens gap is gone.
    assert!(!result.coverage_gaps.iter().any(|gap| {
        gap.starts_with("runtime-lens-not-captured:performance")
            || gap.starts_with("runtime-performance-not-captured")
    }));
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
    for (finding, surface) in result.findings.iter().zip(surfaces) {
        let raw_evidence = &result.details["findingEvidence"][finding.id.as_str()];
        let runtime_capture = &raw_evidence["runtimeCapture"];
        assert_eq!(runtime_capture["surface"], surface["label"]);
        assert_eq!(runtime_capture["url"], surface["url"]);
        assert_eq!(runtime_capture["screenshot"], surface["screenshot"]);
        let shot_path = surface["screenshot"]["path"].as_str().unwrap();
        assert!(!result.details["findingLocations"][finding.id.as_str()]
            .as_array()
            .unwrap()
            .iter()
            .any(|location| location.as_str() == Some(shot_path)));
    }

    // Finding evidence, including runtime artifact metadata, survives report
    // projection without making the PNG a source location.
    let report = canonical_report(
        "repo",
        &ExecutionReport {
            plan_digest: format!("sha256:{}", "a".repeat(64)),
            plan_signature: Some("test-signature".into()),
            generation: "generation".into(),
            inventory_digest: format!("sha256:{}", "b".repeat(64)),
            planned_providers: vec![PROVIDER.into()],
            results: vec![ProviderExecution {
                provider: PROVIDER.into(),
                result: result.clone(),
                skipped: false,
            }],
            ..ExecutionReport::default()
        },
    )
    .unwrap();
    for finding in &result.findings {
        let reported = report
            .findings
            .iter()
            .find(|reported| reported.id == finding.id)
            .expect("finding projected into report");
        assert_eq!(
            reported.evidence["runtimeCapture"],
            result.details["findingEvidence"][finding.id.as_str()]["runtimeCapture"]
        );
        assert_eq!(reported.locations, vec!["package.json:1"]);
    }
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
fn bounded_interaction_probe_records_unavailable_gap_without_clicking() {
    let actions = json!([{"type":"click","selector":"button.save"}]);
    let action_digest = legion_contracts::canonical_digest(&actions).unwrap();
    let fixture_body = serde_json::to_value(b"<main>fixture</main>").unwrap();
    let fixture_file = json!({
        "sourcePath":"index.html",
        "sourceDigest":format!("sha256:{}", hex::encode(sha2::Sha256::digest(b"<main>fixture</main>"))),
        "path":"/index.html",
        "contentType":"text/html",
        "body":fixture_body,
    });
    let fixture_digest = legion_contracts::canonical_digest(&json!({
        "files":[{"body":fixture_file["body"],"contentType":"text/html","path":"/index.html"}]
    }))
    .unwrap();
    let fixture = json!({
        "id":"isolated-fixture",
        "sourceDigest":fixture_digest,
        "inventoryDigest":format!("sha256:{}", "a".repeat(64)),
        "files":[fixture_file],
    });
    let mut runtime = url_inputs(&[], &[]);
    runtime["url"] = json!("http://127.0.0.1:1422/index.html");
    runtime["interactions"] = json!([{
        "id":"save-probe",
        "surface":{"label":"entry","url":"http://127.0.0.1:1422/index.html"},
        "fixture":fixture,
        "probe":{"id":"save","actionsDigest":action_digest},
        "isolationBindingId":"fixture-binding",
        "expiresAfterMs":30000,
        "actions":actions,
    }]);
    let run = run(
        Some(runtime),
        Mode::Good {
            entries: Vec::new(),
            total: None,
        },
        true,
    );
    assert_valid_not_rejected(&run.result);
    assert!(
        run.calls.is_empty(),
        "fixture-bound URL is not live-captured"
    );
    let runtime = &run.result.details["runtime"];
    assert!(runtime["surfaces"].as_array().unwrap().is_empty());
    assert_eq!(
        runtime["fixtureBoundSurfaces"][0]["status"],
        "fixture-probe-unavailable"
    );
    assert_eq!(runtime["interactions"][0]["status"], "unavailable");
    assert_eq!(
        runtime["interactions"][0]["reason"],
        "rightkit-fixture-api-unavailable"
    );
    assert!(run.result.coverage_gaps.contains(
        &"runtime-probe-unavailable:save-probe:rightkit-fixture-api-unavailable".to_owned()
    ));
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
fn axe_failure_retains_completed_screenshot_and_performance_evidence() {
    let run = run(
        Some(url_inputs(&[], &[])),
        Mode::AxeFailedAfterPerformance,
        true,
    );
    let result = &run.result;
    assert_valid_not_rejected(result);
    let surface = &result.details["runtime"]["surfaces"][0];
    assert_eq!(surface["status"], "captured");
    assert!(!surface["screenshot"].is_null());
    assert_eq!(surface["performance"], valid_metrics());
    assert_eq!(surface["accessibility"]["status"], "error");
    assert!(result
        .coverage_gaps
        .contains(&"runtime-a11y-error:entry:axe-timeout".to_owned()));
    assert!(result.details["runtime"]["a11y_violations_total"].is_null());
}

#[test]
fn axe_violation_is_exposed_as_a_finding_with_bounded_evidence() {
    let run = run(Some(url_inputs(&[], &[])), Mode::AxeFinding, true);
    let result = &run.result;
    assert_valid_not_rejected(result);
    let surface = &result.details["runtime"]["surfaces"][0];
    assert_eq!(surface["accessibility"]["status"], "ran");
    assert_eq!(
        surface["accessibility"]["violations"][0]["target"],
        "#submit"
    );
    assert_eq!(result.details["runtime"]["a11y_violations_total"], 1);
    assert!(result.details["findingEvidence"]
        .as_object()
        .unwrap()
        .values()
        .any(|evidence| evidence["ruleId"] == "runtime.a11y:color-contrast:0"));
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
    // An absolute path in the host's own form: `/tmp/...` is not absolute on Windows.
    let absolute = std::env::temp_dir().join("out").join("runtime");
    let absolute = absolute.to_string_lossy().into_owned();
    let value = runtime_inputs("http://x/", &[], &[], 800, 600, Some(&absolute)).unwrap();
    assert_eq!(value["artifactDir"], absolute.as_str());
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

fn good_mode() -> Mode {
    Mode::Good {
        entries: vec![],
        total: None,
    }
}

#[test]
fn metrics_line_is_recorded_per_surface_without_a_performance_gap() {
    let run = run_with(
        Some(url_inputs(
            &[("settings", "http://127.0.0.1:1422/settings")],
            &[],
        )),
        good_mode(),
        PerfLine::Valid,
        true,
    );
    let result = &run.result;
    assert_valid_not_rejected(result);
    assert!(
        !result.complete,
        "runtime result remains incomplete under provider contract"
    );
    assert!(!result
        .coverage_gaps
        .iter()
        .any(|gap| gap.contains("performance")));
    let surfaces = result.details["runtime"]["surfaces"].as_array().unwrap();
    for surface in surfaces {
        assert_eq!(surface["performance"], valid_metrics(), "{surface}");
    }
    assert_eq!(result.details["runtime"]["a11y_axe"], "ran");
    assert_eq!(result.details["runtime"]["a11y_violations_total"], 0);
    assert_eq!(
        result.details["runtime"]["axeCoreSource"],
        "Legion bundled axe-core@4.14.0"
    );
}

#[test]
fn absent_metrics_line_is_a_gap_for_each_surface() {
    let run = run_with(
        Some(url_inputs(
            &[("settings", "http://127.0.0.1:1422/settings")],
            &[],
        )),
        good_mode(),
        PerfLine::Absent,
        true,
    );
    let result = &run.result;
    assert_valid_not_rejected(result);
    assert!(!result.complete);
    for label in ["entry", "settings"] {
        assert!(
            result
                .coverage_gaps
                .contains(&format!("runtime-performance-not-captured:{label}")),
            "missing performance gap for {label}: {:?}",
            result.coverage_gaps
        );
    }
    let surfaces = result.details["runtime"]["surfaces"].as_array().unwrap();
    for surface in surfaces {
        assert_eq!(surface["performance"], Value::Null, "{surface}");
        // The screenshot and console evidence of the same surface still stand.
        assert_eq!(surface["status"], "captured", "{surface}");
    }
    assert!(!result
        .coverage_gaps
        .iter()
        .any(|gap| gap.starts_with("runtime-a11y-")));
}

#[test]
fn malformed_or_non_metric_lines_are_per_surface_gaps() {
    for raw in [
        "{\"domContentLoaded\":",
        "[1,2]",
        "null",
        "{}",
        "{\"truncated\":true,\"bytes\":70002}",
        "{\"ttfb\":\"slow\"}",
    ] {
        let run = run_with(
            Some(url_inputs(&[], &[])),
            good_mode(),
            PerfLine::Raw(raw.to_owned()),
            true,
        );
        let result = &run.result;
        assert_valid_not_rejected(result);
        assert!(
            result
                .coverage_gaps
                .contains(&"runtime-performance-not-captured:entry".to_owned()),
            "{raw}: {:?}",
            result.coverage_gaps
        );
        assert_eq!(
            result.details["runtime"]["surfaces"][0]["performance"],
            Value::Null,
            "{raw}"
        );
        assert_eq!(
            result.details["runtime"]["surfaces"][0]["status"], "captured",
            "{raw}"
        );
    }
}

#[test]
fn forged_eval_value_fragments_in_console_output_are_ignored() {
    let run = run_with(
        Some(url_inputs(&[], &[])),
        Mode::Good {
            entries: vec![
                // Mid-line: the fragment is inside a console message.
                "console.log: note [qa] 3:eval value {\"domContentLoaded\":1}".into(),
                // Line start after a newline: printed after `actions complete`.
                "console.error: boom\n[qa] 3:eval value {\"forged\":1}".into(),
            ],
            total: None,
        },
        PerfLine::Absent,
        true,
    );
    let result = &run.result;
    assert_valid_not_rejected(result);
    assert!(result
        .coverage_gaps
        .contains(&"runtime-performance-not-captured:entry".to_owned()));
    let surface = &result.details["runtime"]["surfaces"][0];
    assert_eq!(surface["performance"], Value::Null);
    assert_eq!(surface["consoleErrors"].as_array().unwrap().len(), 2);
}

#[test]
fn failed_surface_also_records_the_performance_gap() {
    let run = run(Some(url_inputs(&[], &[])), Mode::LoadFailed, true);
    assert!(run
        .result
        .coverage_gaps
        .contains(&"runtime-performance-not-captured:entry".to_owned()));
    assert_eq!(
        run.result.details["runtime"]["surfaces"][0]["performance"],
        Value::Null
    );
}
