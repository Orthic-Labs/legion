//! Native Apple development operations.
//!
//! This module deliberately uses typed argv plans.  It does not invoke a
//! shell, a Node daemon, or the upstream MobileBuildMCP implementation.

use serde_json::{json, Value};
use std::{collections::BTreeMap, env, future::Future, path::{Path, PathBuf}, pin::Pin, process::Stdio, time::Duration};
use tokio::{io::{AsyncRead, AsyncReadExt}, process::{Child, Command}, time};

const SOURCE_COMMIT: &str = "d13ff0c707b0681769cf31da0eb42c4f94ceafff";
const DEFAULT_TIMEOUT_MS: u64 = 120_000;
const MAX_TIMEOUT_MS: u64 = 300_000;
const DEFAULT_OUTPUT_BYTES: usize = 1_048_576;
const MAX_OUTPUT_BYTES: usize = 8 * 1_048_576;
const XCODEBUILD: &str = "/usr/bin/xcodebuild";
const XCRUN: &str = "/usr/bin/xcrun";
const SWIFT: &str = "/usr/bin/swift";
const LLDB: &str = "/usr/bin/lldb";

#[derive(Clone, Debug)]
struct Plan {
    operation: String,
    executable: String,
    args: Vec<String>,
    cwd: String,
    effects: Vec<String>,
    env: BTreeMap<String, String>,
}

#[derive(Debug)]
struct ProcessOutput {
    status: Option<i32>,
    stdout: String,
    stderr: String,
    timed_out: bool,
    truncated: bool,
    cleanup_ok: Option<bool>,
    cleanup_error: Option<String>,
}

type TransportFuture<'a> = Pin<Box<dyn Future<Output = Result<ProcessOutput, String>> + Send + 'a>>;

trait Transport: Send + Sync {
    fn run<'a>(&'a self, plan: &'a Plan, timeout: Duration, max_output: usize) -> TransportFuture<'a>;
}

struct NativeTransport;

struct ChildGuard {
    child: Child,
    process_group: Option<u32>,
    armed: bool,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { process_group: child.id(), child, armed: true }
    }

    fn terminate_group(&self) -> Result<(), String> {
        #[cfg(unix)]
        if let Some(pid) = self.process_group {
            // Tokio exposes process_group on Unix, while Rust's standard
            // library has no portable process-group signal API.  `/bin/kill`
            // is invoked with typed argv so descendants receive termination.
            let group = format!("-{pid}");
            let term = std::process::Command::new("/bin/kill")
                .args(["-TERM", group.as_str()])
                .status()
                .map_err(|error| format!("TERM process group failed: {error}"))?;
            let kill = std::process::Command::new("/bin/kill")
                .args(["-KILL", group.as_str()])
                .status()
                .map_err(|error| format!("KILL process group failed: {error}"))?;
            if !term.success() || !kill.success() {
                return Err(format!("process-group cleanup exited TERM={} KILL={}", term, kill));
            }
        }
        Ok(())
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.terminate_group();
        }
    }
}

impl Transport for NativeTransport {
    fn run<'a>(&'a self, plan: &'a Plan, timeout: Duration, max_output: usize) -> TransportFuture<'a> {
        Box::pin(async move {
            let mut command = Command::new(&plan.executable);
            command.args(&plan.args)
                .current_dir(&plan.cwd)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            #[cfg(unix)]
            command.process_group(0);
            for (key, value) in &plan.env {
                command.env(key, value);
            }
            let mut guard = ChildGuard::new(command.spawn().map_err(|error| format!("failed to start {}: {error}", plan.executable))?);
            match time::timeout(timeout, capture_child(&mut guard.child, max_output)).await {
                Ok(result) => {
                    if result.is_ok() { guard.armed = false; }
                    result
                }
                Err(_) => {
                    let mut cleanup_errors = Vec::new();
                    if let Err(error) = guard.terminate_group() { cleanup_errors.push(error); }
                    if let Err(error) = guard.child.kill().await { cleanup_errors.push(format!("child kill failed: {error}")); }
                    let _ = guard.child.wait().await;
                    guard.armed = false;
                    Ok(ProcessOutput {
                        status: None,
                        stdout: String::new(),
                        stderr: String::new(),
                        timed_out: true,
                        truncated: false,
                        cleanup_ok: Some(cleanup_errors.is_empty()),
                        cleanup_error: (!cleanup_errors.is_empty()).then(|| cleanup_errors.join("; ")),
                    })
                }
            }
        })
    }
}

async fn capture_child(child: &mut Child, max_output: usize) -> Result<ProcessOutput, String> {
    let mut stdout = child.stdout.take().ok_or_else(|| "child stdout was not piped".to_string())?;
    let mut stderr = child.stderr.take().ok_or_else(|| "child stderr was not piped".to_string())?;
    let stdout_future = read_limited(&mut stdout, max_output);
    let stderr_future = read_limited(&mut stderr, max_output);
    let wait_future = child.wait();
    let (stdout, stderr, status) = tokio::join!(stdout_future, stderr_future, wait_future);
    let (stdout, stdout_truncated) = stdout?;
    let (stderr, stderr_truncated) = stderr?;
    let status = status.map_err(|error| format!("failed waiting for child: {error}"))?;
    Ok(ProcessOutput {
        status: status.code(),
        stdout,
        stderr,
        timed_out: false,
        truncated: stdout_truncated || stderr_truncated,
        cleanup_ok: Some(true),
        cleanup_error: None,
    })
}

async fn read_limited<R: AsyncRead + Unpin>(reader: &mut R, limit: usize) -> Result<(String, bool), String> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];
    let mut truncated = false;
    loop {
        let count = reader.read(&mut buffer).await.map_err(|error| format!("failed reading child output: {error}"))?;
        if count == 0 {
            break;
        }
        if bytes.len() < limit {
            let keep = (limit - bytes.len()).min(count);
            bytes.extend_from_slice(&buffer[..keep]);
            if keep < count {
                truncated = true;
            }
        } else {
            truncated = true;
        }
    }
    Ok((String::from_utf8_lossy(&bytes).into_owned(), truncated))
}

/// Return a native operation plan and, when explicitly requested, execute it.
/// Plans are always available on every host; execution is supported only on macOS.
pub async fn invoke(operation: &str, arguments: &Value) -> Result<Value, String> {
    if operation == "catalog" {
        return Ok(catalog());
    }
    let object = arguments.as_object().ok_or_else(|| "arguments must be a JSON object".to_string())?;
    let execute = optional_bool(object, "execute")?.unwrap_or(false);
    let plan = build_plan(operation, arguments, execute)?;
    if !execute {
        return Ok(plan_json(&plan, "plan"));
    }
    if !cfg!(target_os = "macos") {
        return Err("unsupported host: native Apple execution requires macOS".to_string());
    }
    let timeout = Duration::from_millis(optional_u64(object, "timeout_ms")?.unwrap_or(DEFAULT_TIMEOUT_MS));
    let max_output = optional_usize(object, "max_output_bytes")?.unwrap_or(DEFAULT_OUTPUT_BYTES);
    let output = run_with_transport(&plan, timeout, max_output, &NativeTransport).await?;
    let status = if output.timed_out {
        "timeout"
    } else if output.status == Some(0) {
        "success"
    } else {
        "failed"
    };
    let mut result = plan_json(&plan, "result");
    if let Some(map) = result.as_object_mut() {
        map.insert("status".to_string(), json!(status));
        map.insert("success".to_string(), json!(status == "success"));
        map.insert("exit_status".to_string(), output.status.map(Value::from).unwrap_or(Value::Null));
        map.insert("stdout".to_string(), Value::String(output.stdout));
        map.insert("stderr".to_string(), Value::String(output.stderr));
        map.insert("truncated".to_string(), Value::Bool(output.truncated));
        map.insert("cleanup_ok".to_string(), output.cleanup_ok.map(Value::Bool).unwrap_or(Value::Null));
        map.insert("cleanup_error".to_string(), output.cleanup_error.map(Value::String).unwrap_or(Value::Null));
    }
    Ok(result)
}

async fn run_with_transport<T: Transport + ?Sized>(plan: &Plan, timeout: Duration, max_output: usize, transport: &T) -> Result<ProcessOutput, String> {
    match time::timeout(timeout, transport.run(plan, timeout, max_output)).await {
        Ok(result) => result,
        Err(_) => Ok(ProcessOutput {
            status: None,
            stdout: String::new(),
            stderr: String::new(),
            timed_out: true,
            truncated: false,
            cleanup_ok: None,
            cleanup_error: Some("transport timeout; cleanup status unavailable".to_string()),
        }),
    }
}

fn plan_json(plan: &Plan, kind: &str) -> Value {
    let mut value = json!({
        "kind": kind,
        "operation": plan.operation,
        "executable": plan.executable,
        "args": plan.args,
        "cwd": plan.cwd,
        "effects": plan.effects,
    });
    if !plan.env.is_empty() {
        value["env"] = json!(plan.env);
    }
    value
}

fn build_plan(operation: &str, arguments: &Value, execute: bool) -> Result<Plan, String> {
    let object = arguments.as_object().ok_or_else(|| "arguments must be a JSON object".to_string())?;
    validate_controls(object)?;
    let operation = canonical_operation(operation)?;
    let cwd = selected_cwd(object)?;
    let developer_dir = selected_developer_dir(object, execute)?;
    let common = ["execute", "cwd", "developer_dir", "timeout_ms", "max_output_bytes"];
    let mut plan = match operation {
        "project.inspect" | "project.schemes" | "project.discover" => {
            ensure_allowed(object, &common, &["project", "project_path", "workspace", "workspace_path"])?;
            let mut args = xcode_context(object, &cwd, execute)?;
            args.push("-list".to_string());
            args.push("-json".to_string());
            Plan::new(operation, XCODEBUILD, args, cwd, vec!["read project metadata".to_string()])
        }
        "project.settings" => {
            ensure_allowed(object, &common, &["project", "project_path", "workspace", "workspace_path", "scheme", "configuration"])?;
            let mut args = xcode_context(object, &cwd, execute)?;
            args.push("-showBuildSettings".to_string());
            args.push("-json".to_string());
            args.push("-scheme".to_string());
            args.push(required_string(object, "scheme")?);
            optional_arg(&mut args, object, "configuration", "-configuration")?;
            Plan::new(operation, XCODEBUILD, args, cwd, vec!["read build settings".to_string()])
        }
        "project.destinations" => {
            ensure_allowed(object, &common, &["project", "project_path", "workspace", "workspace_path", "scheme"])?;
            let mut args = xcode_context(object, &cwd, execute)?;
            args.push("-showdestinations".to_string());
            args.push("-scheme".to_string());
            args.push(required_string(object, "scheme")?);
            Plan::new(operation, XCODEBUILD, args, cwd, vec!["read available destinations".to_string()])
        }
        "project.build" | "project.test" => {
            ensure_allowed(object, &common, &["project", "project_path", "workspace", "workspace_path", "scheme", "configuration", "destination", "derived_data_path", "result_bundle_path"])?;
            let mut args = xcode_context(object, &cwd, execute)?;
            args.push("-scheme".to_string());
            args.push(required_string(object, "scheme")?);
            optional_arg(&mut args, object, "configuration", "-configuration")?;
            optional_arg(&mut args, object, "destination", "-destination")?;
            optional_path_arg(&mut args, object, "derived_data_path", "-derivedDataPath", &cwd, execute, true)?;
            optional_path_arg(&mut args, object, "result_bundle_path", "-resultBundlePath", &cwd, execute, true)?;
            args.push(operation.strip_prefix("project.").unwrap().to_string());
            Plan::new(operation, XCODEBUILD, args, cwd, vec![if operation == "project.build" { "compile project" } else { "run project tests" }.to_string()])
        }
        "project.clean" => {
            ensure_allowed(object, &common, &["project", "project_path", "workspace", "workspace_path", "scheme", "configuration"])?;
            let mut args = xcode_context(object, &cwd, execute)?;
            if let Some(scheme) = optional_string(object, "scheme")? { args.extend(["-scheme".to_string(), scheme]); }
            optional_arg(&mut args, object, "configuration", "-configuration")?;
            args.push("clean".to_string());
            Plan::new(operation, XCODEBUILD, args, cwd, vec!["FileDelete".to_string(), "delete Xcode build artifacts".to_string()])
        }
        "project.archive" => {
            ensure_allowed(object, &common, &["project", "project_path", "workspace", "workspace_path", "scheme", "configuration", "destination", "archive_path"])?;
            let mut args = xcode_context(object, &cwd, execute)?;
            args.push("-scheme".to_string());
            args.push(required_string(object, "scheme")?);
            optional_arg(&mut args, object, "configuration", "-configuration")?;
            optional_arg(&mut args, object, "destination", "-destination")?;
            let archive = required_path_arg(&cwd, object, "archive_path", execute, true)?;
            args.push("-archivePath".to_string());
            args.push(archive);
            args.push("archive".to_string());
            Plan::new(operation, XCODEBUILD, args, cwd, vec!["write Xcode archive".to_string()])
        }
        "project.export" => {
            ensure_allowed(object, &common, &["archive_path", "export_path", "export_options_plist"])?;
            let archive = required_path_arg(&cwd, object, "archive_path", execute, false)?;
            let export_path = required_path_arg(&cwd, object, "export_path", execute, true)?;
            let plist = required_path_arg(&cwd, object, "export_options_plist", execute, false)?;
            Plan::new(operation, XCODEBUILD, vec!["-exportArchive".to_string(), "-archivePath".to_string(), archive, "-exportPath".to_string(), export_path, "-exportOptionsPlist".to_string(), plist], cwd, vec!["export archive products".to_string()])
        }
        "swiftpm.build" | "swiftpm.test" | "swiftpm.run" => {
            ensure_allowed(object, &common, &["package_path", "product", "configuration"])?;
            let package = optional_path_arg_value(&PathBuf::from(&cwd), object, "package_path", execute, false)?.unwrap_or_else(|| cwd.clone());
            let mut args = vec![operation.strip_prefix("swiftpm.").unwrap().to_string(), "--package-path".to_string(), package.clone()];
            optional_arg(&mut args, object, "configuration", "-c")?;
            if operation == "swiftpm.run" {
                if let Some(product) = optional_string(object, "product")? {
                    args.push(product);
                }
            }
            Plan::new(operation, SWIFT, args, cwd, vec![format!("run SwiftPM {}", operation.strip_prefix("swiftpm.").unwrap())])
        }
        "swiftpm.clean" => {
            ensure_allowed(object, &common, &["package_path"])?;
            let package = optional_path_arg_value(&PathBuf::from(&cwd), object, "package_path", execute, false)?.unwrap_or_else(|| cwd.clone());
            Plan::new(operation, SWIFT, vec!["package".to_string(), "clean".to_string(), "--package-path".to_string(), package], cwd, vec!["FileDelete".to_string(), "delete SwiftPM build artifacts".to_string()])
        }
        "simulator.list" => {
            ensure_allowed(object, &common, &[])?;
            Plan::new(operation, XCRUN, vec!["simctl".to_string(), "list".to_string(), "devices".to_string(), "-j".to_string()], cwd, vec!["read simulator inventory".to_string()])
        }
        "simulator.boot" | "simulator.bootstatus" => {
            ensure_allowed(object, &common, &["simulator_id"])?;
            let id = required_id(object, "simulator_id", "simulator")?;
            let action = if operation == "simulator.boot" { "boot" } else { "bootstatus" };
            let mut args = vec!["simctl".to_string(), action.to_string(), id];
            if operation == "simulator.bootstatus" { args.push("-b".to_string()); }
            Plan::new(operation, XCRUN, args, cwd, vec![if operation == "simulator.boot" { "boot simulator" } else { "wait for simulator boot" }.to_string()])
        }
        "simulator.install" => {
            ensure_allowed(object, &common, &["simulator_id", "app_path"])?;
            let id = required_id(object, "simulator_id", "simulator")?;
            let app = required_path_arg(&cwd, object, "app_path", execute, false)?;
            Plan::new(operation, XCRUN, vec!["simctl".to_string(), "install".to_string(), id, app], cwd, vec!["install app in simulator".to_string()])
        }
        "simulator.launch" | "simulator.terminate" => {
            ensure_allowed(object, &common, &["simulator_id", "bundle_id"])?;
            let id = required_id(object, "simulator_id", "simulator")?;
            let bundle = required_bundle_id(object)?;
            let action = if operation == "simulator.launch" { "launch" } else { "terminate" };
            Plan::new(operation, XCRUN, vec!["simctl".to_string(), action.to_string(), id, bundle], cwd, vec![if operation == "simulator.launch" { "launch app in simulator" } else { "terminate app in simulator" }.to_string()])
        }
        "simulator.screenshot" | "simulator.record_video" => {
            ensure_allowed(object, &common, &["simulator_id", "output", "path"])?;
            let id = required_id(object, "simulator_id", "simulator")?;
            let output = optional_string(object, "output")?.or(optional_string(object, "path")?).ok_or_else(|| "missing output or path".to_string())?;
            validate_output_path(&cwd, &output, execute)?;
            let action = if operation == "simulator.screenshot" { "screenshot" } else { "recordVideo" };
            Plan::new(operation, XCRUN, vec!["simctl".to_string(), "io".to_string(), id, action.to_string(), resolve_path(&PathBuf::from(&cwd), &output).display().to_string()], cwd, vec![if operation == "simulator.screenshot" { "write simulator screenshot" } else { "record simulator video" }.to_string()])
        }
        "simulator.location" => {
            ensure_allowed(object, &common, &["simulator_id", "latitude", "longitude"])?;
            let id = required_id(object, "simulator_id", "simulator")?;
            let latitude = coordinate(object, "latitude")?;
            let longitude = coordinate(object, "longitude")?;
            Plan::new(operation, XCRUN, vec!["simctl".to_string(), "location".to_string(), id, "set".to_string(), latitude, longitude], cwd, vec!["change simulator location".to_string()])
        }
        "simulator.location_reset" => {
            ensure_allowed(object, &common, &["simulator_id"])?;
            let id = required_id(object, "simulator_id", "simulator")?;
            Plan::new(operation, XCRUN, vec!["simctl".to_string(), "location".to_string(), id, "clear".to_string()], cwd, vec!["external:simulator state mutation".to_string(), "clear simulator location".to_string()])
        }
        "simulator.appearance" => {
            ensure_allowed(object, &common, &["simulator_id", "appearance"])?;
            let id = required_id(object, "simulator_id", "simulator")?;
            let appearance = required_string(object, "appearance")?;
            if !matches!(appearance.as_str(), "light" | "dark") { return Err("appearance must be light or dark".to_string()); }
            Plan::new(operation, XCRUN, vec!["simctl".to_string(), "ui".to_string(), id, "appearance".to_string(), appearance], cwd, vec!["change simulator appearance".to_string()])
        }
        "simulator.statusbar" => {
            ensure_allowed(object, &common, &["simulator_id", "time"])?;
            let id = required_id(object, "simulator_id", "simulator")?;
            let time_value = optional_string(object, "time")?.unwrap_or_else(|| "09:41".to_string());
            if !time_value.chars().all(|character| character.is_ascii_digit() || character == ':') { return Err("status bar time must contain only digits and colons".to_string()); }
            Plan::new(operation, XCRUN, vec!["simctl".to_string(), "status_bar".to_string(), id, "override".to_string(), "--time".to_string(), time_value], cwd, vec!["change simulator status bar".to_string()])
        }
        "simulator.logs" => {
            ensure_allowed(object, &common, &["simulator_id", "predicate", "duration"])?;
            let id = required_id(object, "simulator_id", "simulator")?;
            let duration = bounded_log_duration(object)?;
            let mut args = vec!["simctl".to_string(), "spawn".to_string(), id, "log".to_string(), "show".to_string(), "--last".to_string(), duration, "--style".to_string(), "compact".to_string(), "--level".to_string(), "debug".to_string()];
            if let Some(predicate) = optional_string(object, "predicate")? {
                args.push("--predicate".to_string());
                args.push(predicate);
            }
            Plan::new(operation, XCRUN, args, cwd, vec!["read bounded simulator logs".to_string()])
        }
        "device.list" => {
            ensure_allowed(object, &common, &[])?;
            Plan::new(operation, XCRUN, vec!["devicectl".to_string(), "list".to_string(), "devices".to_string()], cwd, vec!["read physical device inventory".to_string()])
        }
        "device.install" => {
            ensure_allowed(object, &common, &["device_id", "app_path"])?;
            let id = required_id(object, "device_id", "device")?;
            let app = required_path_arg(&cwd, object, "app_path", execute, false)?;
            Plan::new(operation, XCRUN, vec!["devicectl".to_string(), "device".to_string(), "install".to_string(), "app".to_string(), "--device".to_string(), id, app], cwd, vec!["install app on physical device".to_string()])
        }
        "device.launch" => {
            ensure_allowed(object, &common, &["device_id", "bundle_id"])?;
            let id = required_id(object, "device_id", "device")?;
            let bundle = required_bundle_id(object)?;
            Plan::new(operation, XCRUN, vec!["devicectl".to_string(), "device".to_string(), "process".to_string(), "launch".to_string(), "--device".to_string(), id, bundle], cwd, vec!["launch app on physical device".to_string()])
        }
        "device.terminate" => {
            ensure_allowed(object, &common, &["device_id", "bundle_id"])?;
            let id = required_id(object, "device_id", "device")?;
            let bundle = required_bundle_id(object)?;
            Plan::new(operation, XCRUN, vec!["devicectl".to_string(), "device".to_string(), "process".to_string(), "terminate".to_string(), "--device".to_string(), id, bundle], cwd, vec!["terminate app on physical device".to_string()])
        }
        "mac.launch" => {
            ensure_allowed(object, &common, &["app_path"])?;
            let app = required_path_arg(&cwd, object, "app_path", execute, false)?;
            Plan::new(operation, "/usr/bin/open", vec!["-a".to_string(), app], cwd, vec!["launch macOS app".to_string()])
        }
        "mac.stop" => {
            ensure_allowed(object, &common, &["process_name"])?;
            let process = required_string(object, "process_name")?;
            if process.starts_with('-') || process.len() > 128 || !process.chars().all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.' | ' ')) { return Err("process_name must contain only ASCII letters, digits, spaces, '.', '_' or '-' and cannot start with '-'".to_string()); }
            let process = process.replace('.', "\\.");
            Plan::new(operation, "/usr/bin/pkill", vec!["-x".to_string(), process], cwd, vec!["terminate matching macOS app processes".to_string()])
        }
        "bundle.inspect" => {
            ensure_allowed(object, &common, &["app_path"])?;
            let app = required_path_arg(&cwd, object, "app_path", execute, false)?;
            let plist = resolve_path(&PathBuf::from(&cwd), &app).join("Contents/Info.plist");
            let plist = if app.ends_with(".app") { plist } else { resolve_path(&PathBuf::from(&cwd), &app).join("Info.plist") };
            Plan::new(operation, "/usr/bin/plutil", vec!["-extract".to_string(), "CFBundleIdentifier".to_string(), "raw".to_string(), "-o".to_string(), "-".to_string(), plist.display().to_string()], cwd, vec!["read bundle identifier".to_string()])
        }
        "simulator.app_container" => {
            ensure_allowed(object, &common, &["simulator_id", "bundle_id", "container"])?;
            let id = required_id(object, "simulator_id", "simulator")?;
            let bundle = required_bundle_id(object)?;
            let container = optional_string(object, "container")?.unwrap_or_else(|| "app".to_string());
            if !matches!(container.as_str(), "app" | "data" | "groups") { return Err("container must be app, data, or groups".to_string()); }
            Plan::new(operation, XCRUN, vec!["simctl".to_string(), "get_app_container".to_string(), id, bundle, container], cwd, vec!["read simulator app container path".to_string()])
        }
        "ui.button" => {
            ensure_allowed(object, &common, &["axe_path", "simulator_id", "udid", "button", "duration"])?;
            let axe = axe_executable(object, execute)?;
            let id = required_simulator_id(object)?;
            let button = required_string(object, "button")?;
            if !matches!(button.as_str(), "home" | "lock" | "side-button" | "siri" | "apple-pay") { return Err("button must be home, lock, side-button, siri, or apple-pay".to_string()); }
            let mut args = vec!["button".to_string(), button];
            optional_bounded_float_arg(&mut args, object, "duration", 0.01, 30.0)?;
            args.extend(["--udid".to_string(), id]);
            Plan::new(operation, &axe, args, cwd, vec!["send simulator button event".to_string()])
        }
        "ui.drag" => {
            ensure_allowed(object, &common, &["axe_path", "simulator_id", "udid", "start_x", "start_y", "end_x", "end_y", "duration", "steps"])?;
            let axe = axe_executable(object, execute)?;
            let id = required_simulator_id(object)?;
            let mut args = vec!["drag".to_string(), "--start-x".to_string(), coordinate_value(object, "start_x", 0.0, 100_000.0)?, "--start-y".to_string(), coordinate_value(object, "start_y", 0.0, 100_000.0)?, "--end-x".to_string(), coordinate_value(object, "end_x", 0.0, 100_000.0)?, "--end-y".to_string(), coordinate_value(object, "end_y", 0.0, 100_000.0)?];
            optional_bounded_float_arg(&mut args, object, "duration", 0.01, 30.0)?;
            if object.contains_key("steps") { let steps = required_positive_u64(object, "steps")?; if steps > 10_000 { return Err("steps must be 1..10000".to_string()); } args.extend(["--steps".to_string(), steps.to_string()]); }
            args.extend(["--udid".to_string(), id]);
            Plan::new(operation, &axe, args, cwd, vec!["send simulator drag".to_string()])
        }
        "ui.gesture" => {
            ensure_allowed(object, &common, &["axe_path", "simulator_id", "udid", "gesture", "duration", "delta"])?;
            let axe = axe_executable(object, execute)?;
            let id = required_simulator_id(object)?;
            let gesture = required_string(object, "gesture")?;
            if !matches!(gesture.as_str(), "scroll-up" | "scroll-down" | "scroll-left" | "scroll-right" | "swipe-from-left-edge" | "swipe-from-right-edge" | "swipe-from-top-edge" | "swipe-from-bottom-edge") { return Err("unsupported gesture preset".to_string()); }
            let mut args = vec!["gesture".to_string(), gesture];
            optional_bounded_float_arg(&mut args, object, "duration", 0.01, 30.0)?;
            optional_bounded_float_arg(&mut args, object, "delta", 0.0, 10_000.0)?;
            args.extend(["--udid".to_string(), id]);
            Plan::new(operation, &axe, args, cwd, vec!["send simulator gesture".to_string()])
        }
        "ui.key_sequence" => {
            ensure_allowed(object, &common, &["axe_path", "simulator_id", "udid", "keycodes", "delay"])?;
            let axe = axe_executable(object, execute)?;
            let id = required_simulator_id(object)?;
            let keycodes = object.get("keycodes").and_then(Value::as_array).ok_or_else(|| "keycodes must be an array".to_string())?;
            if keycodes.is_empty() { return Err("keycodes must not be empty".to_string()); }
            let mut values = Vec::new();
            for keycode in keycodes { let keycode = keycode.as_u64().ok_or_else(|| "keycodes must be positive integers".to_string())?; if keycode > 255 { return Err("keycodes must be 1..255".to_string()); } values.push(keycode.to_string()); }
            let mut args = vec!["key-sequence".to_string(), "--keycodes".to_string(), values.join(",")];
            optional_bounded_float_arg(&mut args, object, "delay", 0.0, 30.0)?;
            args.extend(["--udid".to_string(), id]);
            Plan::new(operation, &axe, args, cwd, vec!["send simulator key sequence".to_string()])
        }
        "ui.touch" | "ui.long_press" => {
            ensure_allowed(object, &common, &["axe_path", "simulator_id", "udid", "x", "y", "down", "up", "delay"])?;
            let axe = axe_executable(object, execute)?;
            let id = required_simulator_id(object)?;
            let mut args = vec!["touch".to_string(), "-x".to_string(), coordinate_value(object, "x", 0.0, 100_000.0)?, "-y".to_string(), coordinate_value(object, "y", 0.0, 100_000.0)?];
            let down = optional_bool(object, "down")?.unwrap_or(operation == "ui.long_press");
            let up = optional_bool(object, "up")?.unwrap_or(operation == "ui.long_press");
            if !down && !up { return Err("touch requires down or up".to_string()); }
            if down { args.push("--down".to_string()); }
            if up { args.push("--up".to_string()); }
            optional_bounded_float_arg(&mut args, object, "delay", 0.0, 30.0)?;
            args.extend(["--udid".to_string(), id]);
            Plan::new(operation, &axe, args, cwd, vec!["send simulator touch event".to_string()])
        }
        "ui.read" => {
            ensure_allowed(object, &common, &["axe_path", "simulator_id", "udid", "point"])?;
            let axe = axe_executable(object, execute)?;
            let id = required_simulator_id(object)?;
            let mut args = vec!["describe-ui".to_string(), "--udid".to_string(), id];
            if let Some(point) = optional_string(object, "point")? { validate_point(&point)?; args.extend(["--point".to_string(), point]); }
            Plan::new(operation, &axe, args, cwd, vec!["read simulator accessibility tree".to_string()])
        }
        "ui.tap" => {
            ensure_allowed(object, &common, &["axe_path", "simulator_id", "udid", "id", "label", "x", "y", "tap_style"])?;
            let axe = axe_executable(object, execute)?;
            let id = required_simulator_id(object)?;
            let mut args = vec!["tap".to_string()];
            let selector_count = object.contains_key("id") as u8 + object.contains_key("label") as u8 + (object.contains_key("x") && object.contains_key("y")) as u8;
            if selector_count != 1 { return Err("tap requires exactly one id, label, or x+y selector".to_string()); }
            if let Some(value) = optional_string(object, "id")? { args.extend(["--id".to_string(), value]); }
            if let Some(value) = optional_string(object, "label")? { args.extend(["--label".to_string(), value]); }
            if object.contains_key("x") && object.contains_key("y") { args.extend(["-x".to_string(), coordinate_value(object, "x", 0.0, 100_000.0)?, "-y".to_string(), coordinate_value(object, "y", 0.0, 100_000.0)?]); }
            if let Some(style) = optional_string(object, "tap_style")? { if !matches!(style.as_str(), "automatic" | "physical" | "simulator") { return Err("tap_style must be automatic, physical, or simulator".to_string()); } args.extend(["--tap-style".to_string(), style]); }
            args.extend(["--udid".to_string(), id]);
            Plan::new(operation, &axe, args, cwd, vec!["send simulator tap".to_string()])
        }
        "ui.type" => {
            ensure_allowed(object, &common, &["axe_path", "simulator_id", "udid", "text", "file"])?;
            let axe = axe_executable(object, execute)?;
            let id = required_simulator_id(object)?;
            let text = optional_string(object, "text")?;
            let file = optional_path_arg_value(&PathBuf::from(&cwd), object, "file", execute, false)?;
            if text.is_some() == file.is_some() { return Err("type requires exactly one text or file".to_string()); }
            let mut args = vec!["type".to_string()];
            if let Some(text) = text { args.push(text); } else { args.extend(["--file".to_string(), file.unwrap()]); }
            args.extend(["--udid".to_string(), id]);
            Plan::new(operation, &axe, args, cwd, vec!["send simulator text input".to_string()])
        }
        "ui.swipe" => {
            ensure_allowed(object, &common, &["axe_path", "simulator_id", "udid", "start_x", "start_y", "end_x", "end_y", "duration", "delta"])?;
            let axe = axe_executable(object, execute)?;
            let id = required_simulator_id(object)?;
            let mut args = vec!["swipe".to_string(), "--start-x".to_string(), coordinate_value(object, "start_x", 0.0, 100_000.0)?, "--start-y".to_string(), coordinate_value(object, "start_y", 0.0, 100_000.0)?, "--end-x".to_string(), coordinate_value(object, "end_x", 0.0, 100_000.0)?, "--end-y".to_string(), coordinate_value(object, "end_y", 0.0, 100_000.0)?];
            optional_bounded_float_arg(&mut args, object, "duration", 0.01, 30.0)?;
            optional_bounded_float_arg(&mut args, object, "delta", 0.0, 10_000.0)?;
            args.extend(["--udid".to_string(), id]);
            Plan::new(operation, &axe, args, cwd, vec!["send simulator swipe".to_string()])
        }
        "ui.key" => {
            ensure_allowed(object, &common, &["axe_path", "simulator_id", "udid", "keycode", "duration"])?;
            let axe = axe_executable(object, execute)?;
            let id = required_simulator_id(object)?;
            let keycode = required_positive_u64(object, "keycode")?;
            if keycode > 255 { return Err("keycode must be 1..255".to_string()); }
            let mut args = vec!["key".to_string(), keycode.to_string()];
            optional_bounded_float_arg(&mut args, object, "duration", 0.01, 30.0)?;
            args.extend(["--udid".to_string(), id]);
            Plan::new(operation, &axe, args, cwd, vec!["send simulator key event".to_string()])
        }
        "debug.batch" => {
            ensure_allowed(object, &common, &["pid", "actions"])?;
            let pid = required_pid(object)?;
            let actions = object.get("actions").and_then(Value::as_array).ok_or_else(|| "actions must be an array".to_string())?;
            if actions.is_empty() { return Err("actions must not be empty".to_string()); }
            let mut args = vec!["--batch".to_string(), "-p".to_string(), pid.to_string()];
            let mut mutates_process = false;
            for action in actions {
                let action = action.as_str().ok_or_else(|| "each debug action must be a string".to_string())?;
                let command = match action {
                    "backtrace" => "thread backtrace all",
                    "threads" => "thread list",
                    "registers" => "register read",
                    "frame" => "frame info",
                    "variables" => "frame variable",
                    "continue" => { mutates_process = true; "process continue" },
                    _ => return Err(format!("unsupported debug action: {action}")),
                };
                args.push("-o".to_string());
                args.push(command.to_string());
            }
            Plan::new(operation, LLDB, args, cwd, vec![if mutates_process { "continue process execution" } else { "read process state" }.to_string()])
        }
        "debug.breakpoint" | "debug.breakpoint.add" | "debug.breakpoint.remove" => {
            ensure_allowed(object, &common, &["pid", "action", "file", "line", "breakpoint_id"])?;
            let pid = required_pid(object)?;
            let action = optional_string(object, "action")?.unwrap_or_else(|| if operation.ends_with(".add") { "add".to_string() } else if operation.ends_with(".remove") { "remove".to_string() } else { String::new() });
            let command = match action.as_str() {
                "add" => {
                    let file = required_path_arg(&cwd, object, "file", execute, false)?;
                    let line = required_positive_u64(object, "line")?;
                    format!("breakpoint set --file {} --line {line}", lldb_quote(&file)?)
                }
                "remove" => format!("breakpoint delete {}", required_positive_u64(object, "breakpoint_id")?),
                _ => return Err("breakpoint action must be add or remove".to_string()),
            };
            Plan::new(operation, LLDB, vec!["--batch".to_string(), "-p".to_string(), pid.to_string(), "-o".to_string(), command], cwd, vec!["change scoped LLDB breakpoint state".to_string()])
        }
        "swiftpm.list" => {
            ensure_allowed(object, &common, &["package_path"])?;
            let package = optional_path_arg_value(&PathBuf::from(&cwd), object, "package_path", execute, false)?.unwrap_or_else(|| cwd.clone());
            Plan::new(operation, SWIFT, vec!["package".to_string(), "describe".to_string(), "--type".to_string(), "json".to_string(), "--package-path".to_string(), package], cwd, vec!["read SwiftPM package graph".to_string()])
        }
        "swiftpm.stop" => {
            ensure_allowed(object, &common, &["pid"])?;
            let pid = required_pid(object)?;
            Plan::new(operation, "/bin/kill", vec!["-TERM".to_string(), pid.to_string()], cwd, vec!["terminate selected SwiftPM process".to_string()])
        }
        "profile.export" => {
            ensure_allowed(object, &common, &["trace_path", "output_path"])?;
            let trace = required_path_arg(&cwd, object, "trace_path", execute, false)?;
            let output = required_path_arg(&cwd, object, "output_path", execute, true)?;
            Plan::new(operation, XCRUN, vec!["xctrace".to_string(), "export".to_string(), "--input".to_string(), trace, "--output".to_string(), output], cwd, vec!["write exported profile data".to_string()])
        }
        "profile.templates" | "profile.devices" => {
            ensure_allowed(object, &common, &[])?;
            let item = if operation == "profile.templates" { "templates" } else { "devices" };
            Plan::new(operation, XCRUN, vec!["xctrace".to_string(), "list".to_string(), item.to_string()], cwd, vec![format!("read xctrace {item}")])
        }
        "profile.toc" => {
            ensure_allowed(object, &common, &["trace_path"])?;
            let trace = required_path_arg(&cwd, object, "trace_path", execute, false)?;
            Plan::new(operation, XCRUN, vec!["xctrace".to_string(), "export".to_string(), "--input".to_string(), trace, "--toc".to_string()], cwd, vec!["read trace table of contents".to_string()])
        }
        "memory.inspect" => {
            ensure_allowed(object, &common, &["memgraph_path", "mode"])?;
            let memgraph = required_path_arg(&cwd, object, "memgraph_path", execute, false)?;
            let mode = optional_string(object, "mode")?.unwrap_or_else(|| "list".to_string());
            if !matches!(mode.as_str(), "list" | "traceTree" | "groupByType") { return Err("memory mode must be list, traceTree, or groupByType".to_string()); }
            Plan::new(operation, "/usr/bin/leaks", vec![format!("--{mode}"), memgraph], cwd, vec!["read memory graph".to_string()])
        }
        "symbolicate" => {
            ensure_allowed(object, &common, &["binary_path", "arch", "load_address", "addresses"])?;
            let binary = required_path_arg(&cwd, object, "binary_path", execute, false)?;
            let arch = required_string(object, "arch")?;
            let load_address = required_hex_token(object, "load_address")?;
            let addresses = object.get("addresses").and_then(Value::as_array).ok_or_else(|| "addresses must be an array".to_string())?;
            if addresses.is_empty() { return Err("addresses must not be empty".to_string()); }
            let mut args = vec!["-o".to_string(), binary, "-arch".to_string(), arch, "-l".to_string(), load_address];
            for address in addresses {
                let address = address.as_str().ok_or_else(|| "each address must be a string".to_string())?;
                args.push(validate_hex(address, "address")?);
            }
            Plan::new(operation, "/usr/bin/atos", args, cwd, vec!["read symbol information".to_string()])
        }
        "profile" => {
            ensure_allowed(object, &common, &["template", "output", "bundle_id", "device_id"])?;
            let template = required_string(object, "template")?;
            let output = required_path_arg(&cwd, object, "output", execute, true)?;
            let mut args = vec!["xctrace".to_string(), "record".to_string(), "--template".to_string(), template, "--output".to_string(), resolve_path(&PathBuf::from(&cwd), &output).display().to_string()];
            if let Some(bundle) = optional_string(object, "bundle_id")? { args.extend(["--launch".to_string(), bundle]); }
            if let Some(device) = optional_string(object, "device_id")? { args.extend(["--device".to_string(), device]); }
            Plan::new(operation, XCRUN, args, cwd, vec!["write bounded xctrace profile".to_string()])
        }
        _ => return Err(format!("unsupported Apple operation: {operation}")),
    };
    if let Some(developer_dir) = developer_dir {
        plan.env.insert("DEVELOPER_DIR".to_string(), developer_dir);
    }
    Ok(plan)
}

impl Plan {
    fn new(operation: &str, executable: &str, args: Vec<String>, cwd: String, effects: Vec<String>) -> Self {
        Self { operation: operation.to_string(), executable: executable.to_string(), args, cwd, effects, env: BTreeMap::new() }
    }
}

fn canonical_operation(operation: &str) -> Result<&str, String> {
    let operation = match operation {
        "inspect.project" => "project.inspect",
        "list_schemes" => "project.schemes",
        "show_build_settings" => "project.settings",
        "list_destinations" => "project.destinations",
        "build" => "project.build",
        "test" => "project.test",
        "clean" => "project.clean",
        "build_sim" | "build_device" | "build_macos" => "project.build",
        "test_sim" | "test_device" | "test_macos" => "project.test",
        "archive" => "project.archive",
        "export" => "project.export",
        "swift_package_build" => "swiftpm.build",
        "swift_package_test" => "swiftpm.test",
        "swift_package_run" => "swiftpm.run",
        "swift_package_clean" => "swiftpm.clean",
        "simulator.list_devices" => "simulator.list",
        "simulator.list_sims" => "simulator.list",
        "simulator.install_app" => "simulator.install",
        "simulator.launch_app" => "simulator.launch",
        "simulator.stop_app" => "simulator.terminate",
        "simulator.set_location" => "simulator.location",
        "simulator.set_appearance" => "simulator.appearance",
        "simulator.set_statusbar" => "simulator.statusbar",
        "reset_sim_location" => "simulator.location_reset",
        "set_sim_location" => "simulator.location",
        "set_sim_appearance" => "simulator.appearance",
        "sim_statusbar" => "simulator.statusbar",
        "record_sim_video" => "simulator.record_video",
        "boot_sim" => "simulator.boot",
        "list_sims" => "simulator.list",
        "install_app_sim" => "simulator.install",
        "launch_app_sim" => "simulator.launch",
        "stop_app_sim" => "simulator.terminate",
        "device.list_devices" => "device.list",
        "device.install_app" => "device.install",
        "device.launch_app" => "device.launch",
        "device.stop_app" => "device.terminate",
        "launch_mac_app" => "mac.launch",
        "stop_mac_app" => "mac.stop",
        "stop_app_device" => "device.terminate",
        "install_app_device" => "device.install",
        "launch_app_device" => "device.launch",
        "swift_package_list" => "swiftpm.list",
        "swift_package_stop" => "swiftpm.stop",
        "tap" => "ui.tap",
        "type_text" => "ui.type",
        "swipe" => "ui.swipe",
        "key_press" => "ui.key",
        "button" => "ui.button",
        "drag" => "ui.drag",
        "gesture" => "ui.gesture",
        "key_sequence" => "ui.key_sequence",
        "long_press" => "ui.long_press",
        "touch" => "ui.touch",
        "snapshot_ui" => "ui.read",
        "get_app_bundle_id" | "get_mac_bundle_id" => "bundle.inspect",
        "get_sim_app_path" => "simulator.app_container",
        "debug_breakpoint_add" => "debug.breakpoint.add",
        "debug_breakpoint_remove" => "debug.breakpoint.remove",
        "symbolicate.atos" => "symbolicate",
        other => other,
    };
    Ok(operation)
}

fn validate_controls(object: &serde_json::Map<String, Value>) -> Result<(), String> {
    for key in ["command", "shell", "raw_args", "args", "script"] {
        if object.contains_key(key) { return Err(format!("unsupported unsafe argument: {key}")); }
    }
    let _ = optional_bool(object, "execute")?;
    let timeout = optional_u64(object, "timeout_ms")?.unwrap_or(DEFAULT_TIMEOUT_MS);
    if !(1..=MAX_TIMEOUT_MS).contains(&timeout) { return Err(format!("timeout_ms must be between 1 and {MAX_TIMEOUT_MS}")); }
    let output = optional_usize(object, "max_output_bytes")?.unwrap_or(DEFAULT_OUTPUT_BYTES);
    if !(1..=MAX_OUTPUT_BYTES).contains(&output) { return Err(format!("max_output_bytes must be between 1 and {MAX_OUTPUT_BYTES}")); }
    Ok(())
}

fn ensure_allowed(object: &serde_json::Map<String, Value>, common: &[&str], specific: &[&str]) -> Result<(), String> {
    for key in object.keys() {
        if !common.contains(&key.as_str()) && !specific.contains(&key.as_str()) {
            return Err(format!("unsupported argument for operation: {key}"));
        }
    }
    Ok(())
}

fn selected_cwd(object: &serde_json::Map<String, Value>) -> Result<String, String> {
    let path = if let Some(value) = object.get("cwd") { PathBuf::from(value.as_str().ok_or_else(|| "cwd must be a string".to_string())?) } else { env::current_dir().map_err(|error| format!("cannot determine cwd: {error}"))? };
    if !path.is_absolute() { return Err("cwd must be an absolute path".to_string()); }
    if !path.is_dir() { return Err(format!("cwd is not an existing directory: {}", path.display())); }
    Ok(path.display().to_string())
}

fn selected_developer_dir(object: &serde_json::Map<String, Value>, execute: bool) -> Result<Option<String>, String> {
    let Some(value) = object.get("developer_dir") else { return Ok(None); };
    let path = PathBuf::from(value.as_str().ok_or_else(|| "developer_dir must be a string".to_string())?);
    if !path.is_absolute() { return Err("developer_dir must be an absolute path".to_string()); }
    if execute && !path.is_dir() { return Err(format!("developer_dir is not an existing directory: {}", path.display())); }
    Ok(Some(path.display().to_string()))
}

fn xcode_context(object: &serde_json::Map<String, Value>, cwd: &str, execute: bool) -> Result<Vec<String>, String> {
    let project = optional_path_arg_value(&PathBuf::from(cwd), object, "project_path", execute, false)?.or(optional_path_arg_value(&PathBuf::from(cwd), object, "project", execute, false)?);
    let workspace = optional_path_arg_value(&PathBuf::from(cwd), object, "workspace_path", execute, false)?.or(optional_path_arg_value(&PathBuf::from(cwd), object, "workspace", execute, false)?);
    match (project, workspace) {
        (Some(_), Some(_)) => Err("choose project or workspace, not both".to_string()),
        (Some(project), None) => Ok(vec!["-project".to_string(), project]),
        (None, Some(workspace)) => Ok(vec!["-workspace".to_string(), workspace]),
        (None, None) => Err("missing project or workspace".to_string()),
    }
}

fn required_path_arg(cwd: &str, object: &serde_json::Map<String, Value>, key: &str, execute: bool, output: bool) -> Result<String, String> {
    optional_path_arg_value(&PathBuf::from(cwd), object, key, execute, output)?.ok_or_else(|| format!("missing required path: {key}"))
}

fn optional_path_arg(args: &mut Vec<String>, object: &serde_json::Map<String, Value>, key: &str, flag: &str, cwd: &str, execute: bool, output: bool) -> Result<(), String> {
    if let Some(path) = optional_path_arg_value(&PathBuf::from(cwd), object, key, execute, output)? {
        args.push(flag.to_string());
        args.push(path);
    }
    Ok(())
}

fn optional_path_arg_value(cwd: &Path, object: &serde_json::Map<String, Value>, key: &str, execute: bool, output: bool) -> Result<Option<String>, String> {
    let Some(value) = object.get(key) else { return Ok(None); };
    let value = value.as_str().ok_or_else(|| format!("{key} must be a string"))?;
    if value.is_empty() || value.contains('\0') { return Err(format!("{key} is invalid")); }
    let path = resolve_path(cwd, value);
    if output && path == Path::new("/") { return Err(format!("{key} is too broad")); }
    if execute && output {
        let parent = path.parent().unwrap_or(cwd);
        if !parent.is_dir() { return Err(format!("{key} parent directory does not exist: {}", parent.display())); }
    }
    if execute && !output && !path.is_file() && !path.is_dir() { return Err(format!("{key} path does not exist: {}", path.display())); }
    Ok(Some(path.display().to_string()))
}

fn resolve_path(cwd: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() { path } else { cwd.join(path) }
}

fn validate_output_path(cwd: &str, value: &str, execute: bool) -> Result<(), String> {
    if value.is_empty() || value.contains('\0') { return Err("output path is invalid".to_string()); }
    let path = resolve_path(&PathBuf::from(cwd), value);
    if path == Path::new("/") { return Err("output path is too broad".to_string()); }
    if execute && !path.parent().unwrap_or(Path::new(cwd)).is_dir() { return Err(format!("output parent directory does not exist: {}", path.parent().unwrap_or(Path::new(cwd)).display())); }
    Ok(())
}

fn bounded_log_duration(object: &serde_json::Map<String, Value>) -> Result<String, String> {
    let value = optional_string(object, "duration")?.unwrap_or_else(|| "30s".to_string());
    let (number, suffix) = if let Some(number) = value.strip_suffix('s') { (number, "s") }
        else if let Some(number) = value.strip_suffix('m') { (number, "m") }
        else if let Some(number) = value.strip_suffix('h') { (number, "h") }
        else { return Err("duration must be an integer followed by s, m, or h".to_string()); };
    let amount = number.parse::<u64>().map_err(|_| "duration must be an integer followed by s, m, or h".to_string())?;
    let seconds = match suffix {
        "s" => amount,
        "m" => amount.saturating_mul(60),
        "h" => amount.saturating_mul(3_600),
        _ => 0,
    };
    if seconds == 0 || seconds > 300 {
        return Err("duration must be between 1s and 300s".to_string());
    }
    Ok(value)
}

fn required_bundle_id(object: &serde_json::Map<String, Value>) -> Result<String, String> {
    let value = required_string(object, "bundle_id")?;
    if value.is_empty() || value.chars().any(char::is_whitespace) || value.starts_with('-') || !value.contains('.') {
        return Err("bundle_id must be a dotted identifier".to_string());
    }
    Ok(value)
}

fn required_id(object: &serde_json::Map<String, Value>, key: &str, label: &str) -> Result<String, String> {
    let value = required_string(object, key)?;
    if value.is_empty() || value.starts_with('-') || value.contains(char::is_whitespace) { return Err(format!("{label} id is invalid")); }
    Ok(value)
}

fn required_simulator_id(object: &serde_json::Map<String, Value>) -> Result<String, String> {
    let simulator = object.get("simulator_id").or_else(|| object.get("udid")).ok_or_else(|| "missing simulator_id or udid".to_string())?;
    let value = simulator.as_str().ok_or_else(|| "simulator_id must be a string".to_string())?;
    if value.is_empty() || value.starts_with('-') || value.chars().any(char::is_whitespace) { return Err("simulator id is invalid".to_string()); }
    Ok(value.to_string())
}

fn required_pid(object: &serde_json::Map<String, Value>) -> Result<u32, String> {
    let value = object.get("pid").ok_or_else(|| "missing pid".to_string())?;
    let pid = value.as_u64().ok_or_else(|| "pid must be a positive integer".to_string())?;
    if pid == 0 || pid > u32::MAX as u64 { return Err("pid must be a positive 32-bit integer".to_string()); }
    Ok(pid as u32)
}

fn required_positive_u64(object: &serde_json::Map<String, Value>, key: &str) -> Result<u64, String> {
    let value = object.get(key).and_then(Value::as_u64).ok_or_else(|| format!("{key} must be a positive integer"))?;
    if value == 0 { return Err(format!("{key} must be positive")); }
    Ok(value)
}

fn coordinate(object: &serde_json::Map<String, Value>, key: &str) -> Result<String, String> {
    let value = object.get(key).and_then(Value::as_f64).ok_or_else(|| format!("{key} must be a number"))?;
    let valid = if key == "latitude" { (-90.0..=90.0).contains(&value) } else { (-180.0..=180.0).contains(&value) };
    if !valid || !value.is_finite() { return Err(format!("{key} is out of range")); }
    Ok(value.to_string())
}

fn coordinate_value(object: &serde_json::Map<String, Value>, key: &str, minimum: f64, maximum: f64) -> Result<String, String> {
    let value = object.get(key).and_then(Value::as_f64).ok_or_else(|| format!("{key} must be a number"))?;
    if !value.is_finite() || value < minimum || value > maximum { return Err(format!("{key} is out of range")); }
    Ok(value.to_string())
}

fn validate_point(value: &str) -> Result<(), String> {
    let mut parts = value.split(',');
    let x = parts.next().ok_or_else(|| "point must be X,Y".to_string())?.parse::<f64>().map_err(|_| "point must be X,Y".to_string())?;
    let y = parts.next().ok_or_else(|| "point must be X,Y".to_string())?.parse::<f64>().map_err(|_| "point must be X,Y".to_string())?;
    if parts.next().is_some() || !x.is_finite() || !y.is_finite() || x < 0.0 || y < 0.0 { return Err("point must be nonnegative X,Y".to_string()); }
    Ok(())
}

fn optional_bounded_float_arg(args: &mut Vec<String>, object: &serde_json::Map<String, Value>, key: &str, minimum: f64, maximum: f64) -> Result<(), String> {
    if object.contains_key(key) {
        let value = coordinate_value(object, key, minimum, maximum)?;
        args.extend([format!("--{key}"), value]);
    }
    Ok(())
}

fn axe_executable(object: &serde_json::Map<String, Value>, execute: bool) -> Result<String, String> {
    let Some(path) = optional_string(object, "axe_path")? else { return Ok("axe".to_string()); };
    let path = PathBuf::from(path);
    if !path.is_absolute() { return Err("axe_path must be absolute".to_string()); }
    if execute && !path.is_file() { return Err(format!("AXe executable is not installed at {}", path.display())); }
    Ok(path.display().to_string())
}

fn required_hex_token(object: &serde_json::Map<String, Value>, key: &str) -> Result<String, String> {
    let value = required_string(object, key)?;
    validate_hex(&value, key)
}

fn validate_hex(value: &str, label: &str) -> Result<String, String> {
    let digits = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")).unwrap_or(value);
    if digits.is_empty() || !digits.chars().all(|character| character.is_ascii_hexdigit()) {
        return Err(format!("{label} must be a hexadecimal address"));
    }
    Ok(value.to_string())
}

fn lldb_quote(value: &str) -> Result<String, String> {
    if value.chars().any(|character| character.is_control() || character == '\x60') { return Err("LLDB path cannot contain control characters or backticks".to_string()); }
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    Ok(format!("\"{escaped}\""))
}

fn required_string(object: &serde_json::Map<String, Value>, key: &str) -> Result<String, String> {
    let value = object.get(key).ok_or_else(|| format!("missing required argument: {key}"))?;
    let value = value.as_str().ok_or_else(|| format!("{key} must be a string"))?;
    if value.is_empty() || value.contains('\0') || value.starts_with('-') { return Err(format!("{key} is invalid")); }
    Ok(value.to_string())
}

fn optional_string(object: &serde_json::Map<String, Value>, key: &str) -> Result<Option<String>, String> {
    let Some(value) = object.get(key) else { return Ok(None); };
    let value = value.as_str().ok_or_else(|| format!("{key} must be a string"))?;
    if value.is_empty() || value.contains('\0') { return Err(format!("{key} is invalid")); }
    Ok(Some(value.to_string()))
}

fn optional_bool(object: &serde_json::Map<String, Value>, key: &str) -> Result<Option<bool>, String> {
    let Some(value) = object.get(key) else { return Ok(None); };
    value.as_bool().map(Some).ok_or_else(|| format!("{key} must be boolean"))
}

fn optional_u64(object: &serde_json::Map<String, Value>, key: &str) -> Result<Option<u64>, String> {
    let Some(value) = object.get(key) else { return Ok(None); };
    value.as_u64().map(Some).ok_or_else(|| format!("{key} must be an unsigned integer"))
}

fn optional_usize(object: &serde_json::Map<String, Value>, key: &str) -> Result<Option<usize>, String> {
    optional_u64(object, key)?.map(|value| usize::try_from(value).map_err(|_| format!("{key} is too large"))).transpose()
}

fn optional_arg(args: &mut Vec<String>, object: &serde_json::Map<String, Value>, key: &str, flag: &str) -> Result<(), String> {
    if let Some(value) = optional_string(object, key)? {
        args.extend([flag.to_string(), value]);
    }
    Ok(())
}

/// Describe native operations and disposition of every upstream MobileBuildMCP tool.
fn operation_schema(name: &str, command: &str, arguments: &[(&str, &str, bool)], exemplar: Value, effects: &[&str]) -> Value {
    json!({
        "name": name,
        "command": command,
        "args": arguments.iter().map(|(name, kind, required)| json!({"name": name, "type": kind, "required": required})).collect::<Vec<_>>(),
        "example": exemplar,
        "effects": effects,
    })
}

pub fn catalog() -> Value {
    let operations = vec![
        operation_schema("project.inspect", "xcodebuild -list -json", &[("project|workspace", "string path", true)], json!({"project": "Demo.xcodeproj"}), &["read"]),
        operation_schema("project.schemes", "xcodebuild -list -json", &[("project|workspace", "string path", true)], json!({"workspace": "Demo.xcworkspace"}), &["read"]),
        operation_schema("project.settings", "xcodebuild -showBuildSettings -json", &[("project|workspace", "string path", true), ("scheme", "string", true)], json!({"project": "Demo.xcodeproj", "scheme": "Demo"}), &["read"]),
        operation_schema("project.destinations", "xcodebuild -showdestinations", &[("project|workspace", "string path", true), ("scheme", "string", true)], json!({"project": "Demo.xcodeproj", "scheme": "Demo"}), &["read"]),
        operation_schema("project.build", "xcodebuild build", &[("project|workspace", "string path", true), ("scheme", "string", true), ("destination", "string", false)], json!({"project": "Demo.xcodeproj", "scheme": "Demo", "destination": "platform=iOS Simulator,name=iPhone 16"}), &["write build products"]),
        operation_schema("project.test", "xcodebuild test", &[("project|workspace", "string path", true), ("scheme", "string", true), ("destination", "string", false)], json!({"project": "Demo.xcodeproj", "scheme": "Demo", "destination": "platform=iOS Simulator,name=iPhone 16"}), &["write test products", "run tests"]),
        operation_schema("project.clean", "xcodebuild clean", &[("project|workspace", "string path", true), ("scheme", "string", false)], json!({"project": "Demo.xcodeproj", "scheme": "Demo"}), &["FileDelete", "delete build artifacts"]),
        operation_schema("project.archive", "xcodebuild archive", &[("project|workspace", "string path", true), ("scheme", "string", true), ("archive_path", "string path", true)], json!({"project": "Demo.xcodeproj", "scheme": "Demo", "archive_path": "build/Demo.xcarchive"}), &["write archive"]),
        operation_schema("project.export", "xcodebuild -exportArchive", &[("archive_path", "string path", true), ("export_path", "string path", true), ("export_options_plist", "string path", true)], json!({"archive_path": "build/Demo.xcarchive", "export_path": "build/export", "export_options_plist": "ExportOptions.plist"}), &["write exported products"]),
        operation_schema("swiftpm.build", "swift build", &[("package_path", "string path", false)], json!({"package_path": "."}), &["write SwiftPM products"]),
        operation_schema("swiftpm.test", "swift test", &[("package_path", "string path", false)], json!({"package_path": "."}), &["write SwiftPM products", "run tests"]),
        operation_schema("swiftpm.run", "swift run", &[("package_path", "string path", false), ("product", "string", false)], json!({"package_path": ".", "product": "Demo"}), &["run package product"]),
        operation_schema("swiftpm.clean", "swift package clean", &[("package_path", "string path", false)], json!({"package_path": "."}), &["FileDelete", "delete package artifacts"]),
        operation_schema("simulator.list", "xcrun simctl list devices -j", &[], json!({}), &["read"]),
        operation_schema("simulator.boot", "xcrun simctl boot", &[("simulator_id", "string identifier", true)], json!({"simulator_id": "SIMULATOR-UDID"}), &["change simulator state"]),
        operation_schema("simulator.bootstatus", "xcrun simctl bootstatus -b", &[("simulator_id", "string identifier", true)], json!({"simulator_id": "SIMULATOR-UDID"}), &["read", "wait"]),
        operation_schema("simulator.install", "xcrun simctl install", &[("simulator_id", "string identifier", true), ("app_path", "string path", true)], json!({"simulator_id": "SIMULATOR-UDID", "app_path": "build/Demo.app"}), &["change simulator app state"]),
        operation_schema("simulator.launch", "xcrun simctl launch", &[("simulator_id", "string identifier", true), ("bundle_id", "string", true)], json!({"simulator_id": "SIMULATOR-UDID", "bundle_id": "com.example.Demo"}), &["launch app"]),
        operation_schema("simulator.terminate", "xcrun simctl terminate", &[("simulator_id", "string identifier", true), ("bundle_id", "string", true)], json!({"simulator_id": "SIMULATOR-UDID", "bundle_id": "com.example.Demo"}), &["terminate app"]),
        operation_schema("simulator.screenshot", "xcrun simctl io screenshot", &[("simulator_id", "string identifier", true), ("output|path", "string path", true)], json!({"simulator_id": "SIMULATOR-UDID", "output": "artifacts/screen.png"}), &["write screenshot"]),
        operation_schema("simulator.record_video", "xcrun simctl io recordVideo", &[("simulator_id", "string identifier", true), ("output|path", "string path", true)], json!({"simulator_id": "SIMULATOR-UDID", "output": "artifacts/screen.mov"}), &["write video"]),
        operation_schema("simulator.location", "xcrun simctl location set", &[("simulator_id", "string identifier", true), ("latitude", "number -90..90", true), ("longitude", "number -180..180", true)], json!({"simulator_id": "SIMULATOR-UDID", "latitude": 37.3349, "longitude": -122.0090}), &["change simulator state"]),
        operation_schema("simulator.location_reset", "xcrun simctl location clear", &[("simulator_id", "string identifier", true)], json!({"simulator_id": "SIMULATOR-UDID"}), &["external:simulator state mutation"]),
        operation_schema("simulator.appearance", "xcrun simctl ui appearance", &[("simulator_id", "string identifier", true), ("appearance", "light|dark", true)], json!({"simulator_id": "SIMULATOR-UDID", "appearance": "dark"}), &["change simulator state"]),
        operation_schema("simulator.statusbar", "xcrun simctl status_bar override", &[("simulator_id", "string identifier", true), ("time", "digits and colons", false)], json!({"simulator_id": "SIMULATOR-UDID", "time": "09:41"}), &["change simulator state"]),
        operation_schema("simulator.logs", "xcrun simctl spawn log show --last", &[("simulator_id", "string identifier", true), ("duration", "bounded interval string", false), ("predicate", "string", false)], json!({"simulator_id": "SIMULATOR-UDID", "duration": "30s"}), &["read bounded logs"]),
        operation_schema("device.list", "xcrun devicectl list devices", &[], json!({}), &["read"]),
        operation_schema("device.install", "xcrun devicectl device install app", &[("device_id", "string identifier", true), ("app_path", "string path", true)], json!({"device_id": "DEVICE-UDID", "app_path": "build/Demo.app"}), &["change device app state"]),
        operation_schema("device.launch", "xcrun devicectl device process launch", &[("device_id", "string identifier", true), ("bundle_id", "string", true)], json!({"device_id": "DEVICE-UDID", "bundle_id": "com.example.Demo"}), &["launch app"]),
        operation_schema("device.terminate", "xcrun devicectl device process terminate", &[("device_id", "string identifier", true), ("bundle_id", "string", true)], json!({"device_id": "DEVICE-UDID", "bundle_id": "com.example.Demo"}), &["terminate app"]),
        operation_schema("mac.launch", "open -a", &[("app_path", "string path", true)], json!({"app_path": "/Applications/Demo.app"}), &["launch app"]),
        operation_schema("mac.stop", "pkill -x", &[("process_name", "plain process name", true)], json!({"process_name": "Demo"}), &["terminate matching processes"]),
        operation_schema("bundle.inspect", "plutil -extract CFBundleIdentifier", &[("app_path", "string .app path", true)], json!({"app_path": "build/Demo.app"}), &["read bundle metadata"]),
        operation_schema("simulator.app_container", "xcrun simctl get_app_container", &[("simulator_id", "string identifier", true), ("bundle_id", "string", true), ("container", "app|data|groups", false)], json!({"simulator_id": "SIMULATOR-UDID", "bundle_id": "com.example.Demo", "container": "data"}), &["read container path"]),
        operation_schema("ui.read", "axe describe-ui", &[("simulator_id|udid", "string identifier", true), ("point", "X,Y", false), ("axe_path", "absolute executable path", false)], json!({"udid": "SIMULATOR-UDID"}), &["read accessibility tree"]),
        operation_schema("ui.tap", "axe tap", &[("simulator_id|udid", "string identifier", true), ("id|label|x+y", "selector", true), ("tap_style", "automatic|physical|simulator", false), ("axe_path", "absolute executable path", false)], json!({"udid": "SIMULATOR-UDID", "label": "Continue"}), &["send UI event"]),
        operation_schema("ui.type", "axe type", &[("simulator_id|udid", "string identifier", true), ("text|file", "exactly one", true), ("axe_path", "absolute executable path", false)], json!({"udid": "SIMULATOR-UDID", "text": "Hello"}), &["send UI event"]),
        operation_schema("ui.swipe", "axe swipe", &[("simulator_id|udid", "string identifier", true), ("start_x", "number", true), ("start_y", "number", true), ("end_x", "number", true), ("end_y", "number", true), ("duration", "number", false), ("delta", "number", false)], json!({"udid": "SIMULATOR-UDID", "start_x": 100, "start_y": 300, "end_x": 300, "end_y": 100}), &["send UI event"]),
        operation_schema("ui.key", "axe key", &[("simulator_id|udid", "string identifier", true), ("keycode", "1..255", true), ("duration", "number", false)], json!({"udid": "SIMULATOR-UDID", "keycode": 40}), &["send UI event"]),
        operation_schema("ui.button", "axe button", &[("simulator_id|udid", "string identifier", true), ("button", "home|lock|side-button|siri|apple-pay", true), ("duration", "number", false)], json!({"udid": "SIMULATOR-UDID", "button": "home"}), &["send UI event"]),
        operation_schema("ui.drag", "axe drag", &[("simulator_id|udid", "string identifier", true), ("start_x", "number", true), ("start_y", "number", true), ("end_x", "number", true), ("end_y", "number", true), ("duration", "number", false), ("steps", "1..10000", false)], json!({"udid": "SIMULATOR-UDID", "start_x": 100, "start_y": 300, "end_x": 300, "end_y": 100}), &["send UI event"]),
        operation_schema("ui.gesture", "axe gesture", &[("simulator_id|udid", "string identifier", true), ("gesture", "bounded preset", true), ("duration", "number", false), ("delta", "number", false)], json!({"udid": "SIMULATOR-UDID", "gesture": "scroll-up"}), &["send UI event"]),
        operation_schema("ui.key_sequence", "axe key-sequence", &[("simulator_id|udid", "string identifier", true), ("keycodes", "array 1..255", true), ("delay", "number", false)], json!({"udid": "SIMULATOR-UDID", "keycodes": [11, 8, 15]}), &["send UI event"]),
        operation_schema("ui.touch", "axe touch", &[("simulator_id|udid", "string identifier", true), ("x", "number", true), ("y", "number", true), ("down", "boolean", false), ("up", "boolean", false), ("delay", "number", false)], json!({"udid": "SIMULATOR-UDID", "x": 150, "y": 250, "down": true, "up": true}), &["send UI event"]),
        operation_schema("debug.batch", "lldb --batch", &[("pid", "positive integer", true), ("actions", "array of bounded action names", true)], json!({"pid": 1234, "actions": ["backtrace", "variables"]}), &["read process state", "continue is stateful; expressions are unsupported"]),
        operation_schema("debug.breakpoint", "lldb --batch", &[("pid", "positive integer", true), ("action", "add|remove", true), ("file|breakpoint_id", "validated path or positive integer", true)], json!({"pid": 1234, "action": "add", "file": "Sources/Demo.swift", "line": 42}), &["change scoped breakpoint state"]),
        operation_schema("swiftpm.list", "swift package describe --type json", &[("package_path", "string path", false)], json!({"package_path": "."}), &["read package graph"]),
        operation_schema("swiftpm.stop", "/bin/kill -TERM", &[("pid", "positive integer", true)], json!({"pid": 1234}), &["terminate selected process"]),
        operation_schema("profile", "xcrun xctrace record", &[("template", "string", true), ("output", "string path", true)], json!({"template": "Time Profiler", "output": "artifacts/profile.trace", "bundle_id": "com.example.Demo"}), &["write profile"]),
        operation_schema("profile.templates", "xcrun xctrace list templates", &[], json!({}), &["read"]),
        operation_schema("profile.devices", "xcrun xctrace list devices", &[], json!({}), &["read"]),
        operation_schema("profile.toc", "xcrun xctrace export --toc", &[("trace_path", "string path", true)], json!({"trace_path": "artifacts/profile.trace"}), &["read trace"]),
        operation_schema("profile.export", "xcrun xctrace export", &[("trace_path", "string path", true), ("output_path", "string path", true)], json!({"trace_path": "artifacts/profile.trace", "output_path": "artifacts/profile.json"}), &["read trace", "write export"]),
        operation_schema("memory.inspect", "leaks", &[("memgraph_path", "string path", true), ("mode", "list|traceTree|groupByType", false)], json!({"memgraph_path": "artifacts/memory.memgraph", "mode": "groupByType"}), &["read memory graph"]),
        operation_schema("symbolicate", "atos", &[("binary_path", "string path", true), ("arch", "string", true), ("load_address", "hex address", true), ("addresses", "array of hex addresses", true)], json!({"binary_path": "Demo.app/Demo", "arch": "arm64", "load_address": "0x100000000", "addresses": ["0x100001000"]}), &["read symbols"]),
    ];
    let ported = [
        "list_schemes", "show_build_settings", "build_sim", "test_sim", "build_device", "test_device", "build_macos", "test_macos", "list_sims", "boot_sim", "install_app_sim", "launch_app_sim", "stop_app_sim", "screenshot", "record_sim_video", "set_sim_location", "set_sim_appearance", "sim_statusbar", "reset_sim_location", "list_devices", "install_app_device", "launch_app_device", "stop_app_device", "launch_mac_app", "stop_mac_app", "swift_package_build", "swift_package_test", "swift_package_run", "swift_package_list", "swift_package_stop", "swift_package_clean", "clean", "debug_stack", "debug_variables", "debug_continue", "debug_breakpoint_add", "debug_breakpoint_remove", "get_app_bundle_id", "get_mac_bundle_id", "get_sim_app_path", "tap", "type_text", "swipe", "key_press", "snapshot_ui", "button", "drag", "gesture", "key_sequence", "long_press", "touch",
    ];
    let composed = ["discover_projs", "build_run_sim", "build_run_device", "build_run_macos"];
    let mapped = [
        "get_device_app_path", "get_mac_app_path", "get_coverage_report", "get_file_coverage",
    ];
    let excluded = [
        "batch", "debug_attach_sim", "debug_detach", "debug_lldb_command", "doctor", "erase_sims", "manage_workflows", "open_sim", "scaffold_ios_project", "scaffold_macos_project", "session_clear_defaults", "session_set_defaults", "session_show_defaults", "session_use_defaults_profile", "sync_xcode_defaults", "toggle_connect_hardware_keyboard", "toggle_software_keyboard", "wait_for_ui", "xcode_ide_call_tool", "xcode_ide_list_tools", "xcode_tools_bridge_disconnect", "xcode_tools_bridge_status", "xcode_tools_bridge_sync",
    ];
    let excluded_reasons = [
        ("batch", "generic batch semantics would allow unbounded composition"),
        ("debug_attach_sim", "requires PID discovery and debugger session ownership"),
        ("debug_detach", "debugger session lifecycle is not owned by bounded batch"),
        ("debug_lldb_command", "upstream accepts arbitrary LLDB commands; native surface is bounded actions only"),
        ("doctor", "upstream daemon/environment probe rather than one native operation"),
        ("erase_sims", "destructive simulator data deletion"),
        ("manage_workflows", "mutates upstream daemon workflow state"),
        ("open_sim", "desktop activation is outside simulator device control"),
        ("scaffold_ios_project", "file generation is outside native build control"),
        ("scaffold_macos_project", "file generation is outside native build control"),
        ("session_clear_defaults", "mutates hidden upstream session state"),
        ("session_set_defaults", "mutates hidden upstream session state"),
        ("session_show_defaults", "depends on upstream daemon session state"),
        ("session_use_defaults_profile", "mutates hidden upstream session state"),
        ("sync_xcode_defaults", "mutates IDE defaults outside selected project"),
        ("toggle_connect_hardware_keyboard", "requires simulator UI preference mutation"),
        ("toggle_software_keyboard", "requires simulator UI preference mutation"),
        ("wait_for_ui", "AXe exposes waiting only as a batch selector precondition; no standalone read-only wait operation"),
        ("xcode_ide_call_tool", "depends on upstream IDE bridge daemon"),
        ("xcode_ide_list_tools", "depends on upstream IDE bridge daemon"),
        ("xcode_tools_bridge_disconnect", "depends on upstream IDE bridge daemon"),
        ("xcode_tools_bridge_status", "depends on upstream IDE bridge daemon"),
        ("xcode_tools_bridge_sync", "depends on upstream IDE bridge daemon"),
    ];
    json!({
        "native": true,
        "source": {"name": "MobileBuildMCP", "commit": SOURCE_COMMIT, "daemon": false},
        "optional_dependencies": {"axe": {"binary": "axe", "provider": "Cameron Cooke", "commit": "30f4bfa9bc81817906a60fadedbc913d7314b7e1", "required_for": ["ui.read", "ui.tap", "ui.type", "ui.swipe", "ui.key", "ui.button", "ui.drag", "ui.gesture", "ui.key_sequence", "ui.long_press", "ui.touch"], "status": "optional; native core never auto-installs and reports missing executable"}},
        "execution": {"plan_by_default": true, "non_macos": "plan_only", "shell": false, "process_group_cleanup": "best_effort_with_status", "max_timeout_ms": MAX_TIMEOUT_MS, "max_output_bytes": MAX_OUTPUT_BYTES},
        "common_args": {"cwd": {"type": "absolute directory", "required": false}, "developer_dir": {"type": "absolute directory", "required": false}, "execute": {"type": "boolean", "required": false, "default": false}, "timeout_ms": {"type": "integer", "required": false, "max": MAX_TIMEOUT_MS}, "max_output_bytes": {"type": "integer", "required": false, "max": MAX_OUTPUT_BYTES}},
        "operations": operations,
        "upstream": {"ported": ported.as_slice(), "composed": composed.as_slice(), "mapped": mapped.as_slice(), "excluded": excluded.as_slice(), "mapping_note": "Composed entries retain workflow semantics through multiple native operations; mapped entries have only a partial native route and are not claimed absorbed.", "excluded_reasons": excluded_reasons.iter().map(|(name, reason)| json!({"name": name, "reason": reason})).collect::<Vec<_>>()},
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    struct FakeTransport { delay: Duration, output: ProcessOutput }
    impl Transport for FakeTransport {
        fn run<'a>(&'a self, _plan: &'a Plan, _timeout: Duration, _max_output: usize) -> TransportFuture<'a> {
            let delay = self.delay;
            let output = ProcessOutput { status: self.output.status, stdout: self.output.stdout.clone(), stderr: self.output.stderr.clone(), timed_out: self.output.timed_out, truncated: self.output.truncated, cleanup_ok: self.output.cleanup_ok, cleanup_error: self.output.cleanup_error.clone() };
            Box::pin(async move { time::sleep(delay).await; Ok(output) })
        }
    }

    #[tokio::test]
    async fn plan_uses_typed_argv_and_selected_developer_dir() {
        let cwd = env::current_dir().unwrap();
        let developer_dir = cwd.join("SelectedXcode/Contents/Developer");
        let args = json!({"project": "Package.swift", "scheme": "Demo", "cwd": cwd, "developer_dir": developer_dir});
        let value = invoke("project.settings", &args).await.unwrap();
        assert_eq!(value["kind"], "plan");
        assert_eq!(value["executable"], XCODEBUILD);
        assert!(value["args"].as_array().unwrap().iter().all(|item| item.as_str().unwrap() != "sh"));
        assert_eq!(value["env"]["DEVELOPER_DIR"], developer_dir.to_str().unwrap());
    }

    #[tokio::test]
    async fn rejects_shell_and_option_injection() {
        let args = json!({"project": "Demo.xcodeproj", "scheme": "-bad", "shell": "xcodebuild"});
        assert!(invoke("project.build", &args).await.is_err());
        let args = json!({"project": "Demo.xcodeproj", "scheme": "Demo", "raw_args": ["-destination"]});
        assert!(invoke("project.build", &args).await.is_err());
    }

    #[tokio::test]
    async fn validates_required_scope() {
        let args = json!({});
        let error = invoke("project.build", &args).await.unwrap_err();
        assert!(error.contains("project or workspace"));
        let args = json!({"simulator_id": "abc"});
        assert!(invoke("simulator.install", &args).await.unwrap_err().contains("app_path"));
    }

    #[tokio::test]
    async fn non_macos_execute_fails_closed() {
        if cfg!(target_os = "macos") { return; }
        let cwd = env::current_dir().unwrap();
        // Execute-mode validates input paths before applying host capability
        // gating, so use an existing portable directory as fixture input.
        let args = json!({"project": cwd.clone(), "scheme": "Demo", "cwd": cwd, "execute": true});
        let error = invoke("project.build", &args).await.unwrap_err();
        assert!(error.contains("requires macOS"));
    }

    #[tokio::test]
    async fn log_plan_is_finite_and_output_destinations_are_fresh() {
        let cwd = env::current_dir().unwrap();
        let log = invoke("simulator.logs", &json!({"cwd": cwd.clone(), "simulator_id": "SIMULATOR-UDID"})).await.unwrap();
        let args = log["args"].as_array().unwrap().iter().map(|item| item.as_str().unwrap()).collect::<Vec<_>>();
        assert!(args.windows(2).any(|window| window == ["log", "show"]));
        assert!(args.windows(2).any(|window| window == ["--last", "30s"]));
        assert!(!args.iter().any(|arg| *arg == "stream"));
        let build = invoke("project.build", &json!({"cwd": cwd.clone(), "project": "Demo.xcodeproj", "scheme": "Demo", "derived_data_path": "new/DerivedData", "result_bundle_path": "new/Result.xcresult"})).await.unwrap();
        let args = build["args"].as_array().unwrap().iter().map(|item| item.as_str().unwrap()).collect::<Vec<_>>();
        assert!(args.windows(2).any(|window| window == ["-derivedDataPath", cwd.join("new/DerivedData").to_str().unwrap()]));
    }

    #[tokio::test]
    async fn axe_plans_require_scoped_target_and_preserve_typed_selectors() {
        let cwd = env::current_dir().unwrap();
        let axe = cwd.join("axe");
        let value = invoke("ui.tap", &json!({"cwd": cwd, "axe_path": axe, "udid": "SIMULATOR-UDID", "label": "Continue", "tap_style": "physical"})).await.unwrap();
        assert_eq!(value["executable"], axe.to_str().unwrap());
        let args = value["args"].as_array().unwrap().iter().map(|item| item.as_str().unwrap()).collect::<Vec<_>>();
        assert!(args.windows(2).any(|window| window == ["--label", "Continue"]));
        assert!(args.windows(2).any(|window| window == ["--udid", "SIMULATOR-UDID"]));
        assert!(invoke("ui.tap", &json!({"cwd": env::current_dir().unwrap(), "udid": "SIMULATOR-UDID", "label": "A", "x": 1, "y": 2})).await.is_err());
    }

    #[tokio::test]
    async fn process_and_lldb_tokens_are_bounded() {
        assert!(invoke("mac.stop", &json!({"process_name": ".*"})).await.is_err());
        assert!(invoke("mac.stop", &json!({"process_name": "-Demo"})).await.is_err());
        let process = invoke("mac.stop", &json!({"process_name": "My App"})).await.unwrap();
        assert_eq!(process["args"][1], "My App");
        let helper = invoke("mac.stop", &json!({"process_name": "Foo.Helper"})).await.unwrap();
        assert_eq!(helper["args"][1], "Foo\\.Helper");
        let value = invoke("debug.breakpoint", &json!({"pid": 1234, "action": "add", "file": "Sources/My App.swift", "line": 42})).await.unwrap();
        let args = value["args"].as_array().unwrap().iter().map(|item| item.as_str().unwrap()).collect::<Vec<_>>();
        assert!(args.iter().any(|arg| arg.contains("breakpoint set --file \"") && arg.contains("My App.swift\" --line 42")));
        assert!(invoke("debug.breakpoint", &json!({"pid": 1234, "action": "add", "file": "bad\npath.swift", "line": 42})).await.is_err());
        assert!(invoke("debug.breakpoint", &json!({"pid": 1234, "action": "add", "file": "bad\x60path.swift", "line": 42})).await.is_err());
    }

    #[tokio::test]
    async fn transport_preserves_result_and_timeout() {
        let plan = Plan::new("test", "true", Vec::new(), env::current_dir().unwrap().display().to_string(), vec!["test".to_string()]);
        let transport = FakeTransport { delay: Duration::from_millis(1), output: ProcessOutput { status: Some(7), stdout: "out".to_string(), stderr: "err".to_string(), timed_out: false, truncated: false, cleanup_ok: Some(true), cleanup_error: None } };
        let output = run_with_transport(&plan, Duration::from_secs(1), 100, &transport).await.unwrap();
        assert_eq!(output.status, Some(7));
        assert_eq!(output.stdout, "out");
        let slow = FakeTransport { delay: Duration::from_millis(100), output: ProcessOutput { status: Some(0), stdout: String::new(), stderr: String::new(), timed_out: false, truncated: false, cleanup_ok: Some(true), cleanup_error: None } };
        let output = run_with_transport(&plan, Duration::from_millis(1), 100, &slow).await.unwrap();
        assert!(output.timed_out);
    }

    #[test]
    fn catalog_exposes_schema_and_complete_upstream_disposition() {
        let value = catalog();
        assert!(value["operations"].as_array().unwrap().iter().all(|item| item["args"].is_array() && item["example"].is_object()));
        let upstream = &value["upstream"];
        let count = upstream["ported"].as_array().unwrap().len()
            + upstream["composed"].as_array().unwrap().len()
            + upstream["mapped"].as_array().unwrap().len()
            + upstream["excluded"].as_array().unwrap().len();
        assert_eq!(count, 82);
    }
}
