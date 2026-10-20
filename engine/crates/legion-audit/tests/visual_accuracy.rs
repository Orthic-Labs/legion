//! Real headless Chrome PNGs -> sealed explicit visual inputs -> native dispatch.
//! Ignored: requires shared pinned Chrome provisioning & retained CI artifacts.
//! This measures two constructed pixel controls, not UI quality or runtime capture.
#![cfg(target_os = "macos")]

use legion_audit::{
    execute,
    native_providers::legacy::visual::{
        freeze_baselines, freeze_spec, verify_explicit_visual_execution,
    },
    AuditPlan, FilesystemInventorySource, InventorySource, NativeProviderRegistry,
};
use legion_contracts::{ProviderSpec, ProviderStatus};
use rightkit_browser::{
    chrome_for_testing_path, ActionKind, AdmissionHook, BrowserPage, BrowserRequest,
    BrowserSession, Decision, LaunchOptions, NetworkPolicy, PolicyDecision, ProfileSpec,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    future::Future,
    io::{Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    task::Poll,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const ID: &str = "legacy.visual.core";
const SOURCE: &str = "engine/crates/legion-audit/tests/visual_accuracy.rs";
const CHROME_VERSION: &str = "155.0.8059.39";
const CHROME_ARCHIVE: &str = "https://storage.googleapis.com/chrome-for-testing-public/155.0.8059.39/mac-arm64/chrome-mac-arm64.zip";
const CHROME_ARCHIVE_SHA256: &str =
    "529a71bd61aaa2ef266a4d4bd300ae9572ba6a3468a8d55c3023ffeffb5b6b4e";
const WIDTH: u32 = 64;
const HEIGHT: u32 = 48;
const READY: &str = "document.readyState === 'complete'";
const START_ANIMATION_FRAMES: &str = "(() => { const state = {rafAvailable: typeof window.requestAnimationFrame === 'function', frameCallbacks: 0, frameProbeComplete: false}; window.__legionVisualFrames = state; if (state.rafAvailable) requestAnimationFrame(() => { state.frameCallbacks += 1; requestAnimationFrame(() => { state.frameCallbacks += 1; state.frameProbeComplete = true; }); }); return true; })()";
const ANIMATION_STATE: &str = "Object.assign({}, window.__legionVisualFrames, {visibilityState: document.visibilityState, readyState: document.readyState, hasFocus: document.hasFocus()})";
const HIGH_ENTROPY_UA: &str =
    "(async () => await navigator.userAgentData.getHighEntropyValues(['fullVersionList']))()";
const OBSERVE_DOM: &str = "({ready:document.readyState,background:getComputedStyle(document.documentElement).backgroundColor,width:innerWidth,height:innerHeight,devicePixelRatio:devicePixelRatio,userAgent:navigator.userAgent})";
const LABEL: &str = "visual.regression|viewport|shots/viewport.png|artifact";
const OPERATION_TIMEOUT: Duration = Duration::from_secs(20);
const LAUNCH_TIMEOUT: Duration = Duration::from_secs(60);
const CAPTURE_TIMEOUT: Duration = Duration::from_secs(180);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(20);
const CANCEL_TIMEOUT: Duration = Duration::from_secs(10);

fn lifecycle(stage: &str, state: &str, detail: Value) {
    eprintln!(
        "REAL_VISUAL_LIFECYCLE {}",
        json!({"stage": stage, "state": state, "detail": detail})
    );
}

/// Owner request deadlines do not cover every composite page await. Bound the
/// caller too, preserving the exact operation that returned an error or stalled.
async fn bounded<T, E: std::fmt::Display>(
    stage: &str,
    limit: Duration,
    operation: impl Future<Output = Result<T, E>>,
) -> Result<T, String> {
    lifecycle(stage, "begin", json!({"timeoutMs": limit.as_millis()}));
    let result = match tokio::time::timeout(limit, operation).await {
        Ok(Ok(value)) => {
            lifecycle(stage, "pass", json!({}));
            return Ok(value);
        }
        Ok(Err(error)) => format!("{stage}: {error}"),
        Err(_) => format!("{stage}: deadline exceeded after {} ms", limit.as_millis()),
    };
    lifecycle(stage, "fail", json!({"error": result}));
    Err(result)
}

/// Bind sequential observation phases to one deadline, including phase logging overhead.
async fn bounded_until<T, E: std::fmt::Display>(
    stage: &str,
    deadline: Instant,
    operation: impl Future<Output = Result<T, E>>,
) -> Result<T, String> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    lifecycle(stage, "begin", json!({"timeoutMs": remaining.as_millis()}));
    tokio::pin!(operation);
    // Tokio timeout polls its inner future before testing expiry. Guard every
    // poll so a ready or resumed renderer operation cannot begin after expiry.
    let guarded = std::future::poll_fn(|cx| {
        if Instant::now() >= deadline {
            return Poll::Ready(Err(format!(
                "{stage}: shared observation deadline exceeded before operation"
            )));
        }
        match operation.as_mut().poll(cx) {
            Poll::Ready(_) if Instant::now() >= deadline => Poll::Ready(Err(format!(
                "{stage}: shared observation deadline exceeded on completion"
            ))),
            Poll::Ready(result) => Poll::Ready(result.map_err(|error| format!("{stage}: {error}"))),
            Poll::Pending => Poll::Pending,
        }
    });
    let result =
        match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), guarded).await {
            Ok(Ok(value)) => {
                lifecycle(stage, "pass", json!({}));
                return Ok(value);
            }
            Ok(Err(error)) => error,
            Err(_) => format!("{stage}: shared observation deadline exceeded"),
        };
    lifecycle(stage, "fail", json!({"error": result}));
    Err(result)
}

async fn animation_frames(
    page: &BrowserPage,
    name: &str,
    deadline: Instant,
) -> Result<Value, String> {
    // Schedule actual renderer callbacks without keeping a CDP awaitPromise
    // request open across frame scheduling. Poll only synchronous observations.
    bounded_until(
        &format!("{name}.animation-start"),
        deadline,
        page.eval(START_ANIMATION_FRAMES),
    )
    .await?;
    loop {
        let state = bounded_until(
            &format!("{name}.animation-frames"),
            deadline,
            page.eval(ANIMATION_STATE),
        )
        .await?;
        lifecycle(
            &format!("{name}.animation-frames"),
            "observed",
            state.clone(),
        );
        if state["rafAvailable"] != true {
            return Err(format!(
                "{name}: renderer requestAnimationFrame unavailable"
            ));
        }
        if state["frameCallbacks"] == 2 && state["frameProbeComplete"] == true {
            return Ok(state);
        }
        tokio::time::sleep_until(tokio::time::Instant::from_std(
            (Instant::now() + Duration::from_millis(50)).min(deadline),
        ))
        .await;
    }
}

#[test]
fn expired_observation_never_polls_ready_renderer_operation() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let polled = AtomicBool::new(false);
    let operation = async {
        polled.store(true, Ordering::SeqCst);
        Ok::<_, String>(true)
    };
    let result = runtime.block_on(bounded_until(
        "expired-control",
        Instant::now() - Duration::from_millis(1),
        operation,
    ));
    assert!(result.is_err());
    assert!(
        !polled.load(Ordering::SeqCst),
        "expired renderer operation must remain unpolled"
    );
}

async fn stop_browser(session: &BrowserSession, cancel: bool) -> Result<(), String> {
    let (stage, limit) = if cancel {
        ("browser.cancel", CANCEL_TIMEOUT)
    } else {
        ("browser.shutdown", SHUTDOWN_TIMEOUT)
    };
    bounded(stage, limit, async {
        if cancel {
            session.cancel().await;
        } else {
            session.shutdown().await;
        }
        Ok::<(), String>(())
    })
    .await
}

fn digest(bytes: &[u8]) -> String {
    format!(
        "sha256:{}",
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

fn html(planted: bool) -> String {
    format!(
        "<!doctype html><html style=\"background:rgb({});width:100%;height:100%;margin:0\"><head><meta charset=\"utf-8\"><link rel=\"icon\" href=\"data:,\"></head><body style=\"margin:0\"></body></html>",
        if planted { "255,0,0" } else { "0,0,255" }
    )
}

/// Read every installed file & link without following directory links. Archive
/// verification belongs to shared installer; marker alone is never byte proof.
fn tree_binding(root: &Path) -> Value {
    fn visit(root: &Path, path: &Path, rows: &mut Vec<Value>) {
        let relative = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let metadata = fs::symlink_metadata(path).unwrap();
        if metadata.file_type().is_symlink() {
            let resolved = fs::canonicalize(path).unwrap();
            assert!(
                resolved.starts_with(root),
                "installed link escapes pinned tree"
            );
            rows.push(
                json!({"path": relative, "kind": "symlink", "target": fs::read_link(path).unwrap(),
                "resolved": resolved.strip_prefix(root).unwrap()}),
            );
        } else if metadata.is_dir() {
            let mut entries: Vec<_> = fs::read_dir(path)
                .unwrap()
                .map(|e| e.unwrap().path())
                .collect();
            entries.sort();
            for entry in entries {
                visit(root, &entry, rows);
            }
        } else {
            assert!(metadata.is_file(), "unexpected special file");
            let bytes = fs::read(path).unwrap();
            rows.push(json!({"path": relative, "kind": "file", "digest": digest(&bytes), "bytes": bytes.len()}));
        }
    }
    let mut files = vec![];
    visit(root, root, &mut files);
    json!({"digest": digest(&serde_json::to_vec(&files).unwrap()), "files": files})
}

fn implementation_binding(repo: &Path) -> Value {
    let roots: Vec<_> = [
        "engine/crates/legion-audit/src",
        "engine/crates/legion-provider-sdk/src",
        "engine/crates/legion-contracts/src",
        "engine/crates/legion-effects/src",
        "engine/crates/legion-rules/src",
        "src/registry/rules",
        "src/registry/controls",
    ]
    .into_iter()
    .map(|path| json!({"path":path,"tree":tree_binding(&repo.join(path))}))
    .collect();
    json!({"digest":digest(&serde_json::to_vec(&roots).unwrap()),"roots":roots})
}

fn provisioned_chrome(scratch: &Path) -> (PathBuf, PathBuf, Value) {
    assert_eq!(
        std::env::consts::ARCH,
        "aarch64",
        "reviewed pin is mac-arm64"
    );
    let installed = fs::canonicalize(
        PathBuf::from(
            std::env::var_os("RIGHTKIT_CHROME_FOR_TESTING_ROOT")
                .expect("provision shared pinned Chrome root"),
        )
        .join("current"),
    )
    .unwrap();
    assert!(
        installed.starts_with(scratch),
        "CI must provision browser under RUNNER_TEMP"
    );
    let chrome =
        fs::canonicalize(chrome_for_testing_path(None).expect("shared Chrome is required"))
            .unwrap();
    assert!(
        chrome.starts_with(&installed),
        "system/previous/unrelated Chrome cannot qualify"
    );
    let marker: Value =
        serde_json::from_slice(&fs::read(installed.join("install.json")).unwrap()).unwrap();
    assert_eq!(marker["version"], CHROME_VERSION);
    assert_eq!(marker["platform"], "mac-arm64");
    assert_eq!(
        marker["files"],
        json!([{"kind":"chrome", "url":CHROME_ARCHIVE, "sha256":CHROME_ARCHIVE_SHA256}])
    );
    let binding = json!({"versionPin": CHROME_VERSION, "archiveUrl": CHROME_ARCHIVE, "archiveSha256": CHROME_ARCHIVE_SHA256,
        "executable": chrome.strip_prefix(&installed).unwrap(), "executableDigest": digest(&fs::read(&chrome).unwrap()),
        "installerMarker": marker, "installedTree": tree_binding(&installed),
        "provenance": "shared RightKit provisioner verifies pinned official archive before extraction; test binds observed installed bytes"});
    (chrome, installed, binding)
}

/// Actual loopback server, serving only retained fixture bytes. No response
/// interception, network replay, screenshots or serialized observations supplied.
struct Server {
    origin: String,
    stop: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<Value>>>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Server {
    fn start(files: BTreeMap<String, PathBuf>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let requests = Arc::new(Mutex::new(vec![]));
        let log = requests.clone();
        let worker = thread::spawn(move || {
            while !done.load(Ordering::Acquire) {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Err(error) => panic!("fixture accept: {error}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut header = vec![];
                let mut byte = [0u8; 1];
                let deadline = Instant::now() + Duration::from_secs(2);
                while header.len() < 8192 && !header.ends_with(b"\r\n\r\n") {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() || done.load(Ordering::Acquire) {
                        break;
                    }
                    stream.set_read_timeout(Some(remaining)).unwrap();
                    match stream.read(&mut byte) {
                        Ok(1) => header.push(byte[0]),
                        _ => break,
                    }
                }
                // Browser may close an unused speculative connection.
                if header.is_empty() {
                    continue;
                }
                let request = String::from_utf8(header).unwrap();
                let first = request.lines().next().unwrap();
                let words: Vec<_> = first.split_whitespace().collect();
                let path = words.get(1).copied().unwrap_or("");
                let accepted = words.first() == Some(&"GET") && files.contains_key(path);
                let body = if accepted {
                    fs::read(&files[path]).unwrap()
                } else {
                    vec![]
                };
                log.lock().unwrap().push(
                    json!({"method": words.first(), "path": path, "accepted": accepted,
                    "bodyDigest": digest(&body), "bytes": body.len()}),
                );
                let response = format!(
                    "HTTP/1.1 {}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
                    if accepted { "200 OK" } else { "404 Not Found" },
                    body.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
                stream.write_all(&body).unwrap();
            }
        });
        Self {
            origin,
            stop,
            requests,
            worker: Some(worker),
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

async fn capture(
    session: &BrowserSession,
    origin: &str,
    root: &Path,
    name: &str,
    planted: bool,
) -> Value {
    let url = format!("{origin}/{name}/index.html");
    let page = bounded(
        &format!("{name}.new-page"),
        OPERATION_TIMEOUT,
        session.new_page(&url),
    )
    .await
    .unwrap();
    bounded(
        &format!("{name}.viewport"),
        OPERATION_TIMEOUT,
        page.set_viewport(WIDTH, HEIGHT, 1.0),
    )
    .await
    .unwrap();
    // A logically current target is not necessarily foregrounded. Keep real
    // animation-frame waits active for every capture, including headless tabs.
    bounded(
        &format!("{name}.foreground"),
        OPERATION_TIMEOUT,
        page.bring_to_front(),
    )
    .await
    .unwrap();

    bounded(
        &format!("{name}.ready"),
        OPERATION_TIMEOUT,
        page.wait_eval(READY, Duration::from_secs(10)),
    )
    .await
    .unwrap();
    let observe_deadline = Instant::now() + OPERATION_TIMEOUT;
    let frames = animation_frames(&page, name, observe_deadline)
        .await
        .unwrap();
    let user_agent = bounded_until(
        &format!("{name}.high-entropy-user-agent"),
        observe_deadline,
        page.eval(HIGH_ENTROPY_UA),
    )
    .await
    .unwrap();
    let mut observed = bounded_until(
        &format!("{name}.observe-dom"),
        observe_deadline,
        page.eval(OBSERVE_DOM),
    )
    .await
    .unwrap();
    observed["fullVersionList"] = user_agent["fullVersionList"].clone();
    observed["animationFrames"] = frames;
    assert_eq!(observed["ready"], "complete");
    assert_eq!(
        observed["background"],
        if planted {
            "rgb(255, 0, 0)"
        } else {
            "rgb(0, 0, 255)"
        }
    );
    assert_eq!(observed["width"], WIDTH);
    assert_eq!(observed["height"], HEIGHT);
    assert_eq!(observed["devicePixelRatio"].as_f64(), Some(1.0));
    // UA strings reduce minor versions; use actual high-entropy browser data
    // for exact pinned version, never substitute installer marker text.
    assert!(observed["userAgent"]
        .as_str()
        .unwrap()
        .contains("HeadlessChrome/155."));
    assert!(observed["fullVersionList"]
        .as_array()
        .unwrap()
        .iter()
        .any(|brand| brand["brand"] == "Chromium" && brand["version"] == CHROME_VERSION));
    let png = bounded(
        &format!("{name}.screenshot"),
        OPERATION_TIMEOUT,
        page.screenshot(),
    )
    .await
    .unwrap();
    // Independent byte decode verifies actual capture before native comparison.
    let decoded = image::load_from_memory_with_format(&png, image::ImageFormat::Png)
        .unwrap()
        .to_rgba8();
    assert_eq!(decoded.dimensions(), (WIDTH, HEIGHT));
    let expected = if planted {
        [255, 0, 0, 255]
    } else {
        [0, 0, 255, 255]
    };
    assert!(
        decoded.pixels().all(|p| p.0 == expected),
        "every captured pixel must match real rendered control"
    );
    let path = root.join("shots/viewport.png");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, &png).unwrap();
    json!({"captureId": "viewport", "sourcePath": "index.html", "sourceDigest": digest(&fs::read(root.join("index.html")).unwrap()),
        "path": "shots/viewport.png", "digest": digest(&png), "bytes": png.len(), "width": WIDTH, "height": HEIGHT,
        "pixelDigest": digest(decoded.as_raw()), "rendererObservation": observed,
        "sessionId": session.id(), "pageId": page.id(), "url": url})
}

fn shipped_spec() -> (ProviderSpec, Value) {
    let registry: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/registry/providers.json"
    )))
    .unwrap();
    let entry = registry["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == ID)
        .unwrap()
        .clone();
    (serde_json::from_value(entry.clone()).unwrap(), entry)
}

fn case(root: &Path, baselines: &Path, capture: &Value, baseline: &Value, planted: bool) -> Value {
    let inventory = FilesystemInventorySource::new(root)
        .unwrap()
        .inventory("real-visual-accuracy")
        .unwrap();
    let (spec, _) = shipped_spec();
    let denominator = inventory.denominator_entries(&spec.selector).unwrap();
    assert_eq!(denominator.entries.len(), 1);
    assert_eq!(denominator.entries[0].path, "index.html");
    let visual_spec = json!({"expected":{"cases":[{"route":"/", "state":"default", "viewport":"64x48"}]},
        "captures":[{"id":"viewport", "path":"shots/viewport.png", "baseline":"viewport.png", "route":"/", "state":"default", "viewport":"64x48"}]});
    let spec_bytes = serde_json::to_vec(&visual_spec).unwrap();
    let mut visual = freeze_spec(&spec_bytes).unwrap();
    visual["baselines"] = freeze_baselines(baselines).unwrap();
    let mut plan = AuditPlan::compile_with_root(Some(root), &inventory, &[spec]).unwrap();
    assert_eq!(plan.providers.len(), 1);
    plan.providers[0].configuration.get_mut("runner").unwrap()["visual"] = visual.clone();
    let frozen = plan
        .freeze(Some(b"real-visual-accuracy-fixture-signing-key"))
        .unwrap();
    let execution = execute(&frozen, &inventory, &NativeProviderRegistry::new(root)).unwrap();
    assert_eq!(execution.planned_providers, vec![ID]);
    assert_eq!(execution.results.len(), 1);
    let entry = &execution.results[0];
    let result = &entry.result;
    eprintln!(
        "REAL_VISUAL_CASE_DIAGNOSTIC {}",
        json!({"planted":planted,"result":result})
    );
    assert_eq!(entry.provider, ID);
    assert!(!entry.skipped && result.applicable && result.complete);
    assert_eq!(result.status, ProviderStatus::Complete);
    assert!(result.details.get("availability").is_none());
    assert!(result.coverage_gaps.is_empty() && result.degradation.is_empty());
    let coverage = result.coverage.as_ref().unwrap();
    assert_eq!(coverage.denominator_digest, denominator.digest);
    assert_eq!((coverage.expected, coverage.examined), (1, 1));
    assert!(coverage.gaps.is_empty());
    assert_eq!(
        denominator.entries[0].digest.as_deref(),
        capture["sourceDigest"].as_str()
    );
    let provider = frozen.provider(ID).unwrap();
    assert_eq!(
        provider.configuration["denominatorDigest"],
        coverage.denominator_digest
    );
    assert_eq!(provider.configuration["denominatorCount"], 1);
    verify_explicit_visual_execution(root, provider, &inventory.generation, result).unwrap();
    let analysis = &result.details["analysis"];
    assert_eq!(analysis["complete"], true);
    assert_eq!(analysis["reviewRequired"], false);
    assert_eq!(analysis["coverageGaps"], json!([]));
    assert_eq!(analysis["status"], if planted { "fail" } else { "pass" });
    assert_eq!(analysis["coverage"]["expectedCount"], 1);
    assert_eq!(analysis["coverage"]["coveredCount"], 1);
    assert_eq!(analysis["coverage"]["missingCount"], 0);
    assert_eq!(analysis["coverage"]["complete"], true);
    assert_eq!(analysis["coverage"]["cases"].as_array().unwrap().len(), 1);
    assert_eq!(analysis["coverage"]["cases"][0]["covered"], true);
    assert_eq!(
        analysis["denominator"],
        json!({"kind":"visual-artifacts","expected":1,"examined":1})
    );
    let rows = analysis["captures"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row["id"], "viewport");
    assert_eq!(row["path"], "shots/viewport.png");
    assert_eq!(row["baseline"], "viewport.png");
    assert_eq!(row["status"], if planted { "different" } else { "match" });
    let diff = &row["diff"];
    assert_eq!(diff["width"], WIDTH);
    assert_eq!(diff["height"], HEIGHT);
    assert_eq!(diff["compared_pixels"], WIDTH as u64 * HEIGHT as u64);
    assert_eq!(
        diff["changed_pixels"],
        if planted {
            WIDTH as u64 * HEIGHT as u64
        } else {
            0
        }
    );
    assert_eq!(diff["changed_ratio"], if planted { 1.0 } else { 0.0 });
    assert_eq!(diff["max_channel_delta"], if planted { 255 } else { 0 });
    assert_eq!(
        diff["mean_channel_delta"],
        if planted { 127.5 } else { 0.0 }
    );
    assert_eq!(diff["channel_threshold"], 0.0);
    assert_eq!(diff["max_changed_ratio"], 0.0);
    assert_eq!(diff["masks"], json!([]));
    let findings = analysis["findings"].as_array().unwrap();
    assert_eq!(findings.len(), usize::from(planted));
    assert_eq!(result.findings.len(), findings.len());
    assert_eq!(
        result.details["findingEvidence"].as_object().unwrap().len(),
        findings.len()
    );
    assert_eq!(
        result.details["findingLocations"]
            .as_object()
            .unwrap()
            .len(),
        findings.len()
    );
    // Preserve every actual emission; artifact locus is not a source line.
    let actual: Vec<String> = result.findings.iter().map(|finding| {
        let id = finding.id.to_string();
        let evidence = &result.details["findingEvidence"][&id];
        assert_eq!(result.details["findingLocations"][&id], json!([]));
        assert_eq!(findings[0]["ruleId"], "visual.regression");
        assert_eq!(evidence["kind"], "visual-artifact-difference");
        assert_eq!(evidence["captureId"], "viewport");
        assert_eq!(evidence["actual"], json!({"path":"shots/viewport.png","digest":capture["digest"],"bytes":capture["bytes"]}));
        assert_eq!(evidence["baseline"], json!({"path":"viewport.png","digest":baseline["digest"],"bytes":baseline["bytes"]}));
        assert_eq!(evidence["specDigest"], digest(&spec_bytes));
        assert_eq!(evidence["diff"], *diff);
        format!("{}|{}|{}|artifact", findings[0]["ruleId"].as_str().unwrap(), evidence["captureId"].as_str().unwrap(), evidence["actual"]["path"].as_str().unwrap())
    }).collect();
    let expected: Vec<&str> = if planted { vec![LABEL] } else { vec![] };
    assert_eq!(actual, expected);
    assert_eq!(
        fs::read(root.join("index.html")).unwrap(),
        html(planted).as_bytes()
    );
    assert_eq!(
        digest(&fs::read(root.join("shots/viewport.png")).unwrap()),
        capture["digest"]
    );
    assert_eq!(
        digest(&fs::read(baselines.join("viewport.png")).unwrap()),
        baseline["digest"]
    );
    json!({"caseId":if planted {"planted"}else{"clean"}, "stage":"finding", "expected":expected,"actual":actual,
        "controlMatched":true,"coverageContractMatched":true,"complete":result.complete,"coverageGaps":[],
        "source":{"path":"index.html","digest":capture["sourceDigest"]},"capture":capture,
        "visualSpec":visual,"planDigest":frozen.digest(),"frozenPlan":frozen.plan(),"inventoryDigest":inventory.digest,
        "selectedDenominator":{"digest":denominator.digest,"entries":denominator.entries},"coverage":coverage,"observedDiffDigest":digest(&serde_json::to_vec(diff).unwrap()),
        "actualProviderResult":result})
}

#[test]
#[ignore = "requires provisioned shared mac-arm64 Chrome pin; retain real PNGs & report under RUNNER_TEMP"]
fn real_browser_accuracy_visual_regression() {
    let scratch = fs::canonicalize(PathBuf::from(
        std::env::var_os("RUNNER_TEMP").expect("managed CI scratch required"),
    ))
    .unwrap();
    assert!(
        fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .starts_with(&scratch),
        "set TMPDIR under RUNNER_TEMP before starting test process"
    );
    let output = PathBuf::from(
        std::env::var_os("LEGION_PROVIDER_BENCHMARK_DIR")
            .expect("retained benchmark directory required"),
    );
    fs::create_dir_all(&output).unwrap();
    let output = fs::canonicalize(output).unwrap();
    assert!(output.starts_with(&scratch));
    let root = output.join(format!(
        "visual-artifacts-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let (chrome, installed, browser_binding) = provisioned_chrome(&scratch);
    let mut files = BTreeMap::new();
    for (name, planted) in [("baseline", false), ("clean", false), ("planted", true)] {
        let directory = root.join(name);
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("index.html"), html(planted)).unwrap();
        files.insert(format!("/{name}/index.html"), directory.join("index.html"));
    }
    let server = Server::start(files);
    let admissions = Arc::new(Mutex::new(vec![]));
    let log = admissions.clone();
    let urls: Vec<_> = ["baseline", "clean", "planted"]
        .into_iter()
        .map(|n| format!("{}/{n}/index.html", server.origin))
        .collect();
    let admission: AdmissionHook = Arc::new(move |request| {
        let allowed = request.url.as_ref().is_some_and(|url| urls.contains(url))
            && match request.action {
                ActionKind::Navigate => true,
                ActionKind::Eval => {
                    matches!(
                        request.detail.as_deref(),
                        Some(READY)
                            | Some(START_ANIMATION_FRAMES)
                            | Some(ANIMATION_STATE)
                            | Some(HIGH_ENTROPY_UA)
                            | Some(OBSERVE_DOM)
                    )
                }
                _ => false,
            };
        log.lock().unwrap().push(json!({"sessionId":request.session_id,"pageId":request.page_id,
            "action":format!("{:?}",request.action),"url":request.url,"detail":request.detail,"allowed":allowed}));
        Box::pin(async move {
            if allowed {
                Decision::Allow
            } else {
                Decision::Deny("outside exact visual benchmark actions".into())
            }
        })
    });
    let network_log = Arc::new(Mutex::new(vec![]));
    let log = network_log.clone();
    let origin = server.origin.clone();
    let network = NetworkPolicy::default().allow_with(move |request: &BrowserRequest| {
        // Proxy connection checks use an origin URL; HTTP server only serves
        // three exact files & navigation admission pins their complete URLs.
        let allowed = request.scheme == "http"
            && request.host == "127.0.0.1"
            && request.url.starts_with(&format!("{origin}/"));
        log.lock().unwrap().push(
            json!({"url":request.url,"resourceType":request.resource_type,"allowed":allowed}),
        );
        if allowed {
            PolicyDecision::Allow
        } else {
            PolicyDecision::Deny("outside isolated loopback fixture origin".into())
        }
    });
    let events = Arc::new(Mutex::new(vec![]));
    let log = events.clone();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let captured = runtime.block_on(async {
        let session = Arc::new(
            bounded(
                "browser.launch",
                LAUNCH_TIMEOUT,
                BrowserSession::launch(LaunchOptions {
                    chrome_path: Some(chrome.clone()),
                    headless: true,
                    allow_system_chrome: false,
                    use_system_chrome_only: false,
                    profile: ProfileSpec::Temporary,
                    // Outer window must leave visible content for frame callbacks.
                    // Renderer & PNG dimensions remain pinned by set_viewport.
                    viewport: (800, 600),
                    launch_timeout: Duration::from_secs(30),
                    request_timeout: Duration::from_secs(10),
                    admission: Some(admission),
                    network,
                    on_event: Some(Arc::new(move |event| {
                        let event = event.to_json();
                        lifecycle("browser.event", "observed", event.clone());
                        log.lock().unwrap().push(event)
                    })),
                    ..LaunchOptions::default()
                }),
            )
            .await?,
        );
        let profile = session.profile_dir().to_path_buf();
        let session_id = session.id().to_owned();
        let capture_session = session.clone();
        let capture_root = root.clone();
        let origin = server.origin.clone();
        // Keep session ownership outside this task: assertion panics & timed-out
        // operations must still reach explicit shared-owner cleanup.
        let mut task = tokio::spawn(async move {
            let baseline = capture(
                &capture_session,
                &origin,
                &capture_root.join("baseline"),
                "baseline",
                false,
            )
            .await;
            let clean = capture(
                &capture_session,
                &origin,
                &capture_root.join("clean"),
                "clean",
                false,
            )
            .await;
            let planted = capture(
                &capture_session,
                &origin,
                &capture_root.join("planted"),
                "planted",
                true,
            )
            .await;
            (baseline, clean, planted)
        });
        let captures = match tokio::time::timeout(CAPTURE_TIMEOUT, &mut task).await {
            Ok(Ok(values)) => Ok(values),
            Ok(Err(error)) => Err(format!("capture task: {error}")),
            Err(_) => {
                task.abort();
                let _ = task.await;
                Err("capture task: overall deadline exceeded".to_string())
            }
        };
        let stopped = stop_browser(&session, captures.is_err()).await;
        if stopped.is_err() {
            // Cancellation is containment only. A failed graceful shutdown still
            // fails this harness even if a later cancel happens to return.
            let _ = stop_browser(&session, true).await;
        }
        drop(session);
        let profile_removed = !profile.exists();
        let terminal = json!({"sessionId":session_id,"captureComplete":captures.is_ok(),
            "captureError":captures.as_ref().err(),"stopComplete":stopped.is_ok(),
            "stopError":stopped.as_ref().err(),"profileRemoved":profile_removed});
        lifecycle(
            "browser.terminal",
            if captures.is_ok() && stopped.is_ok() && profile_removed {
                "pass"
            } else {
                "fail"
            },
            terminal.clone(),
        );
        fs::write(
            output.join("visual-lifecycle.json"),
            serde_json::to_vec_pretty(&terminal).unwrap(),
        )
        .unwrap();
        stopped?;
        let (baseline, clean, planted) = captures?;
        Ok::<_, String>((baseline, clean, planted, session_id, profile_removed))
    });
    // Owner cleanup can spawn blocking OS waits. Runtime Drop must not turn a
    // failed cleanup into an unlimited wait that suppresses later CI controls.
    runtime.shutdown_timeout(Duration::from_secs(5));
    let (baseline, clean, planted, session_id, profile_removed) = captured.unwrap();
    assert!(profile_removed, "temporary browser profile must be removed");
    let events = events.lock().unwrap().clone();
    for kind in ["start", "stop"] {
        assert_eq!(events.iter().filter(|e| e["event"] == kind).count(), 1);
    }
    assert!(!events.iter().any(|e| e["event"] == "crash"));
    assert!(events.iter().all(|e| e["session_id"] == session_id));
    let started = events.iter().find(|e| e["event"] == "start").unwrap();
    let stopped = events.iter().find(|e| e["event"] == "stop").unwrap();
    assert_eq!(started["reason"], "launched (headless)");
    assert_eq!(stopped["reason"], "shutdown");
    assert!(started["pid"].as_u64().is_some_and(|pid| pid > 0));
    assert_eq!(stopped["pid"], started["pid"]);
    assert!(started["ts_ms"].as_u64().unwrap() <= stopped["ts_ms"].as_u64().unwrap());
    let admissions = admissions.lock().unwrap().clone();
    assert!(admissions
        .iter()
        .all(|admission| [&baseline, &clean, &planted]
            .iter()
            .any(|captured| admission["pageId"] == captured["pageId"])));
    assert!(admissions.iter().all(|a| a["allowed"] == true));
    assert!(admissions.iter().all(|a| a["sessionId"] == session_id));
    assert_ne!(baseline["pageId"], clean["pageId"]);
    assert_ne!(baseline["pageId"], planted["pageId"]);
    assert_ne!(clean["pageId"], planted["pageId"]);
    let requests = server.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 3);
    assert!(requests.iter().all(|r| r["accepted"] == true));
    let network_decisions = network_log.lock().unwrap().clone();
    for (name, captured) in [
        ("baseline", &baseline),
        ("clean", &clean),
        ("planted", &planted),
    ] {
        assert_eq!(captured["sessionId"], session_id);
        let page_admissions: Vec<_> = admissions
            .iter()
            .filter(|a| a["pageId"] == captured["pageId"])
            .collect();
        let frame_polls = page_admissions
            .iter()
            .filter(|a| a["action"] == "Eval" && a["detail"] == ANIMATION_STATE)
            .count();
        assert!(frame_polls > 0);
        assert_eq!(page_admissions.len(), 5 + frame_polls);
        assert!(page_admissions.iter().all(|a| a["url"] == captured["url"]));
        assert_eq!(
            page_admissions
                .iter()
                .filter(|a| a["action"] == "Navigate")
                .count(),
            1
        );
        for expression in [READY, START_ANIMATION_FRAMES, HIGH_ENTROPY_UA, OBSERVE_DOM] {
            assert_eq!(
                page_admissions
                    .iter()
                    .filter(|a| a["action"] == "Eval" && a["detail"] == expression)
                    .count(),
                1
            );
        }
        let path = format!("/{name}/index.html");
        let served: Vec<_> = requests.iter().filter(|r| r["path"] == path).collect();
        assert_eq!(served.len(), 1);
        assert_eq!(served[0]["bodyDigest"], captured["sourceDigest"]);
        assert!(network_decisions
            .iter()
            .any(|decision| { decision["allowed"] == true && decision["url"] == captured["url"] }));
    }
    assert_eq!(baseline["sourceDigest"], clean["sourceDigest"]);
    assert_eq!(baseline["pixelDigest"], clean["pixelDigest"]);
    assert_ne!(baseline["sourceDigest"], planted["sourceDigest"]);
    assert_ne!(baseline["pixelDigest"], planted["pixelDigest"]);
    // Include server teardown in terminal harness success. A retained JSON row
    // printed earlier is never a substitute for successful test termination.
    drop(server);
    let baselines = root.join("baselines");
    fs::create_dir(&baselines).unwrap();
    fs::copy(
        root.join("baseline/shots/viewport.png"),
        baselines.join("viewport.png"),
    )
    .unwrap();
    let cases = vec![
        case(&root.join("planted"), &baselines, &planted, &baseline, true),
        case(&root.join("clean"), &baselines, &clean, &baseline, false),
    ];
    assert_eq!(
        tree_binding(&installed),
        browser_binding["installedTree"],
        "installed browser bytes changed during capture"
    );
    let repo = fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")).unwrap();
    let (_, mut provider) = shipped_spec();
    provider.as_object_mut().unwrap().remove("benchmark");
    let bindings: Vec<_> = [
        "engine/Cargo.lock",
        "engine/Cargo.toml",
        "engine/crates/legion-audit/Cargo.toml",
        "engine/crates/legion-provider-sdk/Cargo.toml",
        "engine/crates/legion-contracts/Cargo.toml",
        "engine/crates/legion-effects/Cargo.toml",
        "engine/crates/legion-rules/Cargo.toml",
        SOURCE,
    ]
    .into_iter()
    .map(|path| json!({"path":path,"digest":digest(&fs::read(repo.join(path)).unwrap())}))
    .collect();
    let mut true_positives = 0usize;
    let mut false_positives = 0usize;
    let mut false_negatives = 0usize;
    for case in &cases {
        let expected = case["expected"].as_array().unwrap();
        let actual = case["actual"].as_array().unwrap();
        let mut unmatched = actual.clone();
        for label in expected {
            if let Some(index) = unmatched.iter().position(|a| a == label) {
                unmatched.remove(index);
                true_positives += 1;
            } else {
                false_negatives += 1;
            }
        }
        false_positives += unmatched.len();
    }
    let complete = cases
        .iter()
        .all(|case| case["complete"] == true && case["coverageGaps"] == json!([]));
    let eligible = complete && false_positives == 0 && false_negatives == 0;
    assert!(eligible && true_positives == 1);
    let mut record = json!({"schema":"legion-external-provider-accuracy/1","provider":ID,"stage":"finding","outputKind":"findings",
        "executionPath":"native-sdk-frozen-plan-real-rightkit-browser-png","modelCalls":0,
        "scope":"Two flat-color constructed controls; explicit sealed PNG comparison only, not UI quality, runtime capture, population accuracy or production admission",
        "qualificationEligible":eligible,"status":"pass","coverageState":"complete","coverageGaps":[],
        "binding":{"providerSpecDigest":digest(&serde_json::to_vec(&provider).unwrap()),"providerSpec":provider,
            "harnessPath":SOURCE,"harnessDigest":digest(&fs::read(repo.join(SOURCE)).unwrap()),"files":bindings,
            "implementation":implementation_binding(&repo),"browser":browser_binding},
        "metrics":{"truePositives":true_positives,"falsePositives":false_positives,"falseNegatives":false_negatives,
            "precision":true_positives as f64/(true_positives+false_positives) as f64,"recall":true_positives as f64/(true_positives+false_negatives) as f64,"positiveCases":1,"cleanCases":1},
        "browserEvidence":{"sessionId":session_id,"events":events,"admissionDecisions":admissions,"networkDecisions":network_decisions,
            "servedRequests":requests,"profileRemoved":profile_removed,"fixtureServerJoined":true,"baseline":baseline,
            "processTerminationEvidence":"Actual RightKit shutdown lifecycle event only; no authenticated process-tree receipt is exposed by BrowserSession::shutdown",
            "receiptBoundary":"RightKit BrowserSession supplies actual lifecycle/admission/network records, not EffectExecutor process receipts; native explicit visual provider supplies actual comparison result"},
        "artifactDirectory":root,"cases":cases});
    record["qualificationDigest"] = json!(digest(&serde_json::to_vec(&record).unwrap()));
    fs::write(
        output.join("legacy_visual-core.json"),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();
    println!(
        "EXTERNAL_PROVIDER_ACCURACY {}",
        serde_json::to_string(&record).unwrap()
    );
}
