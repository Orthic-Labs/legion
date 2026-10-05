//! Diagnostic inventory for every native Legion entry point.
//!
//! This test is intentionally ignored.  The dedicated CI workflow builds the
//! three binaries first, then runs this probe and uploads its JSON receipt.
//! Probe outcomes are observations, never functional PASS claims.

use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SCRIPT_COUNT: usize = 77;
const ROOT_COUNT: usize = 43;
const DEV_COUNT: usize = 27;
const XTASK_COUNT: usize = 16;
const CHILD_TIMEOUT: Duration = Duration::from_secs(5);
const OUTPUT_LIMIT: usize = 8 * 1024;

#[derive(Clone, Copy)]
enum ProbeMode {
    Help,
    Precondition,
}

impl ProbeMode {
    fn label(self) -> &'static str {
        match self {
            Self::Help => "help",
            Self::Precondition => "precondition",
        }
    }
}

#[derive(Clone, Copy)]
struct ScriptProbe {
    key: &'static str,
    mode: ProbeMode,
    args: &'static [&'static str],
    reason: Option<&'static str>,
}

const HELP: &[&str] = &["--help"];
const EMPTY: &[&str] = &[];
const PALETTE: &[&str] = &["--id", "seed-200"];
const SAFE_UNKNOWN: &[&str] = &["__legion_entrypoint_missing__"];

// Every current `legion script --list` key must have one explicit audit row.
// Probes run only inside the CI workflow's isolated network namespace.
// Missing-input/browser/service failures are observations, not functional passes.
const SCRIPT_PROBES: &[ScriptProbe] = &[
    ScriptProbe {
        key: "alchemist/parse_events",
        mode: ProbeMode::Help,
        args: HELP,
        reason: None,
    },
    ScriptProbe {
        key: "alchemist/viewer",
        mode: ProbeMode::Help,
        args: HELP,
        reason: None,
    },
    ScriptProbe {
        key: "brand-identity/color-check",
        mode: ProbeMode::Help,
        args: HELP,
        reason: None,
    },
    ScriptProbe {
        key: "coder/api-worker",
        mode: ProbeMode::Help,
        args: HELP,
        reason: None,
    },
    ScriptProbe {
        key: "covenant/validate-external-review-packet",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "designer/context",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "designer/context-signals",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "designer/critique-storage",
        mode: ProbeMode::Precondition,
        args: SAFE_UNKNOWN,
        reason: None,
    },
    ScriptProbe {
        key: "designer/detect",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: Some("would construct a real browser driver when one is installed"),
    },
    ScriptProbe {
        key: "designer/detect-csp",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "designer/export-deck-pdf",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "designer/export-deck-pptx",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "designer/export-deck-stage-pdf",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "designer/fetch-images",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "designer/gen-deck-thumbs",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: Some("argument parser accepts empty input and then launches headless Chrome"),
    },
    ScriptProbe {
        key: "designer/hook",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "designer/hook-admin",
        mode: ProbeMode::Precondition,
        args: SAFE_UNKNOWN,
        reason: None,
    },
    ScriptProbe {
        key: "designer/hook-before-edit",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "designer/live",
        mode: ProbeMode::Help,
        args: HELP,
        reason: None,
    },
    ScriptProbe {
        key: "designer/live-accept",
        mode: ProbeMode::Help,
        args: HELP,
        reason: None,
    },
    ScriptProbe {
        key: "designer/live-commit-manual-edits",
        mode: ProbeMode::Help,
        args: HELP,
        reason: None,
    },
    ScriptProbe {
        key: "designer/live-complete",
        mode: ProbeMode::Help,
        args: HELP,
        reason: None,
    },
    ScriptProbe {
        key: "designer/live-inject",
        mode: ProbeMode::Help,
        args: HELP,
        reason: None,
    },
    ScriptProbe {
        key: "designer/live-insert",
        mode: ProbeMode::Help,
        args: HELP,
        reason: None,
    },
    ScriptProbe {
        key: "designer/live-poll",
        mode: ProbeMode::Help,
        args: HELP,
        reason: None,
    },
    ScriptProbe {
        key: "designer/live-resume",
        mode: ProbeMode::Help,
        args: HELP,
        reason: None,
    },
    ScriptProbe {
        key: "designer/live-server",
        mode: ProbeMode::Help,
        args: HELP,
        reason: None,
    },
    ScriptProbe {
        key: "designer/live-status",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "designer/live-target",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "designer/live-wrap",
        mode: ProbeMode::Help,
        args: HELP,
        reason: None,
    },
    ScriptProbe {
        key: "designer/mix-voiceover",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "designer/narrate-pipeline",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "designer/palette",
        mode: ProbeMode::Precondition,
        args: PALETTE,
        reason: None,
    },
    ScriptProbe {
        key: "designer/render-narration",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "designer/render-video",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: Some("would launch headless Chrome before validating input"),
    },
    ScriptProbe {
        key: "designer/render-video-seek",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "designer/tts-doubao",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "designer/verify",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: Some("would launch headless Chrome before validating input"),
    },
    ScriptProbe {
        key: "dispatch/validate-dispatch",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "foundation/validate-atom-report",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "handoff/transcript-handoff",
        mode: ProbeMode::Help,
        args: HELP,
        reason: None,
    },
    ScriptProbe {
        key: "handoff/validate-handoff",
        mode: ProbeMode::Help,
        args: HELP,
        reason: None,
    },
    ScriptProbe {
        key: "ios-development/tool_preflight",
        mode: ProbeMode::Help,
        args: HELP,
        reason: None,
    },
    ScriptProbe {
        key: "macos-development/tool_preflight",
        mode: ProbeMode::Help,
        args: HELP,
        reason: None,
    },
    ScriptProbe {
        key: "qa/qa-functional",
        mode: ProbeMode::Help,
        args: HELP,
        reason: None,
    },
    ScriptProbe {
        key: "qa/qa-shot",
        mode: ProbeMode::Help,
        args: HELP,
        reason: None,
    },
    ScriptProbe {
        key: "seo/banana-cost-tracker",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "seo/banana-generate",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: Some("would call an image-generation service and write under HOME"),
    },
    ScriptProbe {
        key: "seo/banana-presets",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "seo/bing_webmaster",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "seo/crux_history",
        mode: ProbeMode::Help,
        args: HELP,
        reason: None,
    },
    ScriptProbe {
        key: "seo/edit",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "seo/fetch_page",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "seo/ga4_report",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "seo/google_auth",
        mode: ProbeMode::Help,
        args: HELP,
        reason: None,
    },
    ScriptProbe {
        key: "seo/google_report",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "seo/gsc_inspect",
        mode: ProbeMode::Help,
        args: HELP,
        reason: None,
    },
    ScriptProbe {
        key: "seo/gsc_query",
        mode: ProbeMode::Help,
        args: HELP,
        reason: None,
    },
    ScriptProbe {
        key: "seo/gsc_query_v2",
        mode: ProbeMode::Help,
        args: HELP,
        reason: None,
    },
    ScriptProbe {
        key: "seo/indexing_notify",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "seo/indexnow",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "seo/keyword_planner",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "seo/nlp_analyze",
        mode: ProbeMode::Help,
        args: HELP,
        reason: None,
    },
    ScriptProbe {
        key: "seo/pagespeed_check",
        mode: ProbeMode::Help,
        args: HELP,
        reason: None,
    },
    ScriptProbe {
        key: "seo/parse_html",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "seo/provider_registry",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "seo/question_inventory",
        mode: ProbeMode::Help,
        args: HELP,
        reason: None,
    },
    ScriptProbe {
        key: "seo/query_ownership",
        mode: ProbeMode::Help,
        args: HELP,
        reason: None,
    },
    ScriptProbe {
        key: "seo/rank_tracker",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "seo/render_gap",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "seo/search_ops",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "seo/seo_closure",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "seo/seo_project",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "seo/site_audit",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "seo/templated_metadata",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
    ScriptProbe {
        key: "seo/youtube_search",
        mode: ProbeMode::Help,
        args: HELP,
        reason: None,
    },
    ScriptProbe {
        key: "tasklist/validate-tasklist",
        mode: ProbeMode::Precondition,
        args: EMPTY,
        reason: None,
    },
];

const ROOT_COMMANDS: &[&str] = &[
    "apple",
    "status",
    "serve",
    "init",
    "doctor",
    "bind",
    "inspect",
    "targets",
    "components",
    "stacks",
    "controls",
    "governance",
    "skills",
    "languages",
    "providers",
    "rules",
    "schedule",
    "plan",
    "audit",
    "verify",
    "explain",
    "report",
    "fix",
    "hooks",
    "mcp",
    "run",
    "budget",
    "contract",
    "assurance",
    "completion",
    "host",
    "harness",
    "authority",
    "state",
    "minimize",
    "catalog",
    "policy",
    "decision",
    "handoff",
    "research",
    "review",
    "setup",
    "script",
];

const DEV_COMMANDS: &[&str] = &[
    "check-portability",
    "check-version-parity",
    "check-publication-surface",
    "check-authority-parity",
    "evaluate-authority-replay",
    "generate-catalogs",
    "check-canonical-names",
    "check-blueprint-config",
    "check-publication-policy",
    "check-distribution-contract",
    "check-release-obligations",
    "generate-schemas",
    "generate-manifest",
    "normalize-provider-result",
    "native-cli-inventory",
    "check-native-cli-surface",
    "generate-host-projection",
    "generate-skill-catalog",
    "generate-codex-skill-sidecars",
    "refresh-local-skill-manifests",
    "verify-plugin-parity",
    "report-to-sarif",
    "plugin-dev",
    "check-dependency-closure",
    "check-packed-import-closure",
    "native-cli-parity-installed",
    "native-cli-capture-rust",
];

const XTASK_COMMANDS: &[&str] = &[
    "verify-release",
    "assemble-native-release",
    "package-windows-release",
    "prepare-unsigned-candidate",
    "prepare-windows-candidate-finalization",
    "finalize-macos-candidate",
    "qualify-windows-release",
    "release-admission",
    "release-stage-summary",
    "release-evidence-verification",
    "release-finalize-windows",
    "release-finalize-macos",
    "release-qualify-installed",
    "release-publish-qualified",
    "release-local-windows-development",
    "native-installed-smoke",
];

#[derive(Default)]
struct OutputCapture {
    text: String,
    truncated: bool,
}

struct ProbeResult {
    exit_code: Option<i32>,
    timed_out: bool,
    stdout: OutputCapture,
    stderr: OutputCapture,
    launch_error: Option<String>,
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn bounded_reader<R: Read>(mut reader: R) -> OutputCapture {
    let mut bytes = Vec::new();
    let mut truncated = false;
    let mut buf = [0u8; 4096];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if bytes.len() < OUTPUT_LIMIT {
                    let keep = n.min(OUTPUT_LIMIT - bytes.len());
                    bytes.extend_from_slice(&buf[..keep]);
                    if keep < n {
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }
            Err(_) => {
                truncated = true;
                break;
            }
        }
    }
    OutputCapture {
        text: String::from_utf8_lossy(&bytes).into_owned(),
        truncated,
    }
}

fn terminate_probe_tree(child: &mut Child) {
    #[cfg(unix)]
    let _ = Command::new("/bin/kill")
        .args(["-KILL", "--", &format!("-{}", child.id())])
        .stdout(Stdio::null()).stderr(Stdio::null()).status();
    #[cfg(windows)]
    let _ = Command::new("taskkill")
        .args(["/PID", &child.id().to_string(), "/T", "/F"])
        .stdout(Stdio::null()).stderr(Stdio::null()).status();
    let _ = child.kill();
}

fn wait_bounded(child: &mut Child) -> (Option<ExitStatus>, bool) {
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                terminate_probe_tree(child);
                return (Some(status), false);
            }
            Ok(None) if started.elapsed() >= CHILD_TIMEOUT => {
                terminate_probe_tree(child);
                let status = child.wait().ok();
                return (status, true);
            }
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(_) => return (None, false),
        }
    }
}

fn keep_environment(key: &OsStr) -> bool {
    matches!(
        key.to_string_lossy().to_ascii_lowercase().as_str(),
        "path"
            | "pathext"
            | "systemroot"
            | "comspec"
            | "windir"
            | "tmp"
            | "temp"
            | "tmpdir"
            | "ld_library_path"
            | "dyld_library_path"
            | "dyld_fallback_library_path"
            | "os"
            | "processor_architecture"
            | "processor_architew6432"
            | "programfiles"
            | "programfiles(x86)"
            | "commonprogramfiles"
            | "commonprogramfiles(x86)"
            | "number_of_processors"
    )
}

fn run_probe(binary: Option<&Path>, args: &[String], root: &Path, row_id: usize) -> ProbeResult {
    let Some(binary) = binary else {
        return ProbeResult {
            exit_code: None,
            timed_out: false,
            stdout: OutputCapture::default(),
            stderr: OutputCapture::default(),
            launch_error: Some("executable unavailable".to_string()),
        };
    };
    let row_root = root.join(format!("row-{row_id}"));
    let dirs = [
        "home",
        "userprofile",
        "localappdata",
        "appdata",
        "xdg-config",
        "xdg-data",
        "xdg-cache",
        "xdg-runtime",
    ];
    for dir in dirs {
        if let Err(error) = std::fs::create_dir_all(row_root.join(dir)) {
            return ProbeResult {
                exit_code: None,
                timed_out: false,
                stdout: OutputCapture::default(),
                stderr: OutputCapture::default(),
                launch_error: Some(format!("sandbox setup failed: {error}")),
            };
        }
    }

    let mut command = Command::new(binary);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    command
        .args(args)
        .current_dir(&row_root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();
    for (key, value) in std::env::vars_os().filter(|(key, _)| keep_environment(key)) {
        command.env(key, value);
    }
    command
        .env("HOME", row_root.join("home"))
        .env("USERPROFILE", row_root.join("userprofile"))
        .env("LOCALAPPDATA", row_root.join("localappdata"))
        .env("APPDATA", row_root.join("appdata"))
        .env("XDG_CONFIG_HOME", row_root.join("xdg-config"))
        .env("XDG_DATA_HOME", row_root.join("xdg-data"))
        .env("XDG_CACHE_HOME", row_root.join("xdg-cache"))
        .env("XDG_RUNTIME_DIR", row_root.join("xdg-runtime"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", row_root.join("missing-git-config"))
        .env("NO_COLOR", "1");

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return ProbeResult {
                exit_code: None,
                timed_out: false,
                stdout: OutputCapture::default(),
                stderr: OutputCapture::default(),
                launch_error: Some(error.to_string()),
            };
        }
    };
    let stdout_thread = child
        .stdout
        .take()
        .map(|stdout| thread::spawn(|| bounded_reader(stdout)));
    let stderr_thread = child
        .stderr
        .take()
        .map(|stderr| thread::spawn(|| bounded_reader(stderr)));
    let (status, timed_out) = wait_bounded(&mut child);
    let stdout = stdout_thread
        .and_then(|thread| thread.join().ok())
        .unwrap_or_default();
    let stderr = stderr_thread
        .and_then(|thread| thread.join().ok())
        .unwrap_or_default();
    ProbeResult {
        exit_code: status.and_then(|s| s.code()),
        timed_out,
        stdout,
        stderr,
        launch_error: None,
    }
}

fn executable(env_name: &str, fallback: &str) -> Option<PathBuf> {
    if let Some(path) = std::env::var_os(env_name).filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(path));
    }
    let current = std::env::current_exe().ok()?;
    let target = current.parent()?.parent()?;
    let path = target.join(if cfg!(windows) {
        format!("{fallback}.exe")
    } else {
        fallback.to_string()
    });
    path.is_file().then_some(path)
}

fn output_value(result: &ProbeResult) -> Value {
    json!({
        "stdout": result.stdout.text,
        "stderr": result.stderr.text,
        "truncated": result.stdout.truncated || result.stderr.truncated,
    })
}

fn outcome(result: &ProbeResult, skipped: bool) -> &'static str {
    if skipped {
        return "NOT_EXERCISED";
    }
    if result.launch_error.is_some() {
        return "LAUNCH_FAILURE_OBSERVED";
    }
    if result.timed_out {
        return "TIMED_OUT";
    }
    if result.exit_code == Some(0) {
        "EXIT_ZERO_OBSERVED"
    } else {
        "EXIT_NONZERO_OBSERVED"
    }
}

fn row(
    group: &str,
    key: &str,
    binary_label: &str,
    binary: Option<&Path>,
    args: &[String],
    mode: &str,
    reason: Option<String>,
    root: &Path,
    row_id: usize,
) -> Value {
    let mut invocation = vec![binary
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| binary_label.to_string())];
    invocation.extend(args.iter().cloned());
    let reason = reason.or_else(|| {
        binary
            .is_none()
            .then(|| "executable unavailable".to_string())
    });
    let skipped = reason.is_some();
    let result = if skipped {
        ProbeResult {
            exit_code: None,
            timed_out: false,
            stdout: OutputCapture::default(),
            stderr: OutputCapture::default(),
            launch_error: None,
        }
    } else {
        run_probe(binary, args, root, row_id)
    };
    let reason = reason.or_else(|| result.launch_error.clone());
    json!({
        "group": group,
        "key": key,
        "invocation": invocation,
        "exit_code": result.exit_code,
        "timed_out": result.timed_out,
        "output": output_value(&result),
        "state": mode,
        "outcome": outcome(&result, skipped),
        "reason": reason,
    })
}

fn discovery_row(
    group: &str,
    binary_label: &str,
    binary: Option<&Path>,
    args: &[String],
    root: &Path,
    row_id: usize,
) -> (Value, String) {
    let value = row(
        group,
        "--help",
        binary_label,
        binary,
        args,
        "help",
        None,
        root,
        row_id,
    );
    let text = value["output"]["stdout"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let stderr = value["output"]["stderr"].as_str().unwrap_or_default();
    let merged = format!("{text}\n{stderr}");
    (value, merged)
}

fn command_names_from_help(text: &str) -> Vec<String> {
    let mut in_commands = false;
    let mut names = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "Commands:" {
            in_commands = true;
            continue;
        }
        if in_commands && trimmed == "Options:" {
            break;
        }
        if in_commands && !trimmed.is_empty() && !trimmed.starts_with('-') {
            if let Some(name) = trimmed.split_whitespace().next() {
                if name
                    .chars()
                    .all(|c| c == '-' || c.is_ascii_lowercase() || c.is_ascii_digit())
                {
                    names.push(name.to_string());
                }
            }
        }
    }
    names
}

fn script_names(value: &str) -> Option<Vec<String>> {
    serde_json::from_str::<Value>(value)
        .ok()?
        .get("scripts")?
        .as_array()
        .map(|scripts| {
            scripts
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
}

fn args_for(probe: &ScriptProbe) -> Vec<String> {
    probe.args.iter().map(|arg| (*arg).to_string()).collect()
}

#[test]
#[ignore = "diagnostic inventory; run only from entrypoint-inventory CI workflow"]
fn entrypoint_inventory() {
    let original_network = std::env::var("LEGION_ENTRYPOINT_ORIGINAL_NET")
        .expect("diagnostic requires workflow-created network namespace");
    let isolated_network = std::fs::read_link("/proc/self/ns/net")
        .expect("diagnostic requires Linux network namespace evidence")
        .display().to_string();
    assert_ne!(original_network, isolated_network, "network namespace was not isolated");
    let routes = std::fs::read_to_string("/proc/net/route").expect("read isolated IPv4 routes");
    assert!(routes.lines().skip(1).all(|line| line.trim().is_empty()),
        "isolated namespace unexpectedly contains network routes");
    let root = std::env::temp_dir().join(format!(
        "legion-entrypoint-inventory-{}-{}",
        std::process::id(),
        now_millis()
    ));
    std::fs::create_dir_all(&root).expect("create isolated inventory root");
    let legion = executable("LEGION_BIN", "legion");
    let dev = executable("LEGION_DEV_BIN", "legion-dev");
    let xtask = executable("XTASK_BIN", "xtask");
    let mut rows = Vec::new();
    let mut structural_errors = Vec::new();
    let mut row_id = 0usize;

    let list_args = vec!["script".to_string(), "--list".to_string()];
    let (list_row, list_text) = discovery_row(
        "script-list",
        "legion",
        legion.as_deref(),
        &list_args,
        &root,
        row_id,
    );
    row_id += 1;
    let actual_scripts = script_names(&list_text).unwrap_or_default();
    rows.push(list_row);
    if legion.is_some() && actual_scripts.len() != SCRIPT_COUNT {
        structural_errors.push(format!(
            "script --list returned {} keys, expected {SCRIPT_COUNT}",
            actual_scripts.len()
        ));
    }
    let actual_script_set: BTreeSet<_> = actual_scripts.iter().cloned().collect();
    if actual_script_set.len() != actual_scripts.len() {
        structural_errors.push("script --list returned duplicate keys".to_string());
    }

    let probe_set: BTreeSet<_> = SCRIPT_PROBES.iter().map(|probe| probe.key).collect();
    for probe in SCRIPT_PROBES {
        if !actual_script_set.contains(probe.key) && !actual_scripts.is_empty() {
            rows.push(row(
                "script-mapping",
                probe.key,
                "legion",
                legion.as_deref(),
                &vec!["script".into(), probe.key.into()],
                "NOT_EXERCISED",
                Some("dispatch key absent from actual --list response".to_string()),
                &root,
                row_id,
            ));
            row_id += 1;
        }
    }
    for name in &actual_scripts {
        let Some(probe) = SCRIPT_PROBES.iter().find(|probe| probe.key == name) else {
            structural_errors.push(format!("missing probe mapping for script key {name}"));
            rows.push(row(
                "script-mapping",
                name,
                "legion",
                legion.as_deref(),
                &vec!["script".into(), name.clone()],
                "NOT_EXERCISED",
                Some("actual --list key has no safe probe mapping".to_string()),
                &root,
                row_id,
            ));
            row_id += 1;
            continue;
        };
        let args = args_for(probe);
        let invocation = [&["script".to_string(), name.clone()][..], &args[..]].concat();
        rows.push(row(
            "script",
            name,
            "legion",
            legion.as_deref(),
            &invocation,
            if probe.reason.is_some() { "isolated_precondition" } else { probe.mode.label() },
            None,
            &root,
            row_id,
        ));
        row_id += 1;
    }
    if legion.is_some() && actual_scripts.is_empty() {
        structural_errors.push("could not parse actual script --list response".to_string());
        for probe in SCRIPT_PROBES {
            rows.push(row(
                "script",
                probe.key,
                "legion",
                legion.as_deref(),
                &vec!["script".into(), probe.key.into()],
                probe.mode.label(),
                Some("actual --list response unavailable".to_string()),
                &root,
                row_id,
            ));
            row_id += 1;
        }
    }
    if probe_set.len() != SCRIPT_COUNT {
        structural_errors.push(format!(
            "probe map contains {} unique script keys, expected {SCRIPT_COUNT}",
            probe_set.len()
        ));
    }

    let groups: [(&str, &str, Option<&Path>, &[&str], usize, &[&str]); 3] = [
        (
            "root",
            "legion",
            legion.as_deref(),
            ROOT_COMMANDS,
            ROOT_COUNT,
            ROOT_COMMANDS,
        ),
        (
            "legion-dev",
            "legion-dev",
            dev.as_deref(),
            DEV_COMMANDS,
            DEV_COUNT,
            DEV_COMMANDS,
        ),
        (
            "xtask",
            "xtask",
            xtask.as_deref(),
            XTASK_COMMANDS,
            XTASK_COUNT,
            XTASK_COMMANDS,
        ),
    ];
    for (group, label, binary, expected, expected_count, fallback) in groups {
        let discovery_args = vec!["--help".to_string()];
        let (discovery, help_text) = discovery_row(
            &format!("{group}-help"),
            label,
            binary,
            &discovery_args,
            &root,
            row_id,
        );
        row_id += 1;
        // Clap adds a synthetic help subcommand outside the declared command enum.
        let discovered: Vec<_> = command_names_from_help(&help_text).into_iter()
            .filter(|name| name != "help").collect();
        rows.push(discovery);
        if binary.is_some() && discovered.is_empty() {
            structural_errors.push(format!("could not parse {label} --help command inventory"));
        }
        let commands = if discovered.is_empty() {
            fallback.iter().map(|s| (*s).to_string()).collect()
        } else {
            discovered
        };
        if binary.is_some() && commands.len() != expected_count {
            structural_errors.push(format!(
                "{label} --help returned {} commands, expected {expected_count}",
                commands.len()
            ));
        }
        let discovered_set: BTreeSet<_> = commands.iter().cloned().collect();
        for name in expected {
            if !discovered_set.contains(*name) && binary.is_some() {
                structural_errors.push(format!("{label} --help omitted command {name}"));
            }
        }
        let commands: BTreeSet<String> = commands.into_iter()
            .chain(expected.iter().map(|name| (*name).to_string())).collect();
        for command_name in commands {
            let args = vec![command_name.clone(), "--help".to_string()];
            rows.push(row(
                group,
                &command_name,
                label,
                binary,
                &args,
                "help",
                None,
                &root,
                row_id,
            ));
            row_id += 1;
        }
    }

    let row_count = rows.len();
    let not_exercised_count = rows
        .iter()
        .filter(|row| row["outcome"].as_str() == Some("NOT_EXERCISED"))
        .count();
    let structural_error_count = structural_errors.len();
    let has_structural_errors = structural_error_count != 0;
    let report = json!({
        "schema_version": 1,
        "generated_at_unix_ms": now_millis(),
        "network_isolation": {
            "parent_namespace": original_network,
            "probe_namespace": isolated_network,
            "ipv4_routes": routes,
        },
        "counts": {
            "script_dispatch_keys_expected": SCRIPT_COUNT,
            "script_dispatch_keys_observed": actual_scripts.len(),
            "root_commands_expected": ROOT_COUNT,
            "legion_dev_commands_expected": DEV_COUNT,
            "xtask_commands_expected": XTASK_COUNT,
            "rows": row_count,
            "not_exercised_rows": not_exercised_count,
            "structural_errors": structural_error_count,
        },
        "structural_errors": structural_errors.clone(),
        "rows": rows,
    });
    let report_path = std::env::var_os("LEGION_ENTRYPOINT_REPORT")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("entrypoint-inventory.json"));
    if let Some(parent) = report_path.parent() {
        std::fs::create_dir_all(parent).expect("create report directory");
    }
    std::fs::write(
        &report_path,
        serde_json::to_vec_pretty(&report).expect("serialize report"),
    )
    .expect("write entrypoint report");
    eprintln!("entrypoint inventory report: {}", report_path.display());
    eprintln!("entrypoint inventory rows: {row_count}");
    if has_structural_errors {
        panic!(
            "entrypoint inventory structural errors recorded in {}",
            report_path.display()
        );
    }
    let _ = std::fs::remove_dir_all(root);
}
