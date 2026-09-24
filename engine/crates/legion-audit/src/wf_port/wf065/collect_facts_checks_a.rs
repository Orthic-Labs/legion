//! Port of the FIRST HALF of `tools/audit/collect-facts.mjs`'s
//! `buildChecks(d)` — in JS source order, the checks named `repo`,
//! `decomposition`, `secrets`, `deps_cve`, `py_deps_cve`, `types`, `lint`,
//! `dead_code`, `duplication`, `ci_lint`, `docker`, `sast`, `swift_lint`,
//! `js_licenses` (the remaining half — `cargo_audit` through `build` — is a
//! separate packet's job; every one of *those* already has a parser in
//! `native_providers/legacy_checks/parsers.rs`, same as most of this half).
//!
//! Each `build_*` function below returns a [`CheckSpec`] whose `run` closure
//! reproduces one JS `add({ check, tool, ..., run: async () => {...} })`
//! call: same applicability gate, same command line, same status/skip_reason
//! rules, same `findings_count`/`meta` shape. Output parsing is NOT
//! reimplemented here where `native_providers::legacy_checks::parsers`
//! already has it (deps_cve, py_deps_cve, types/tsc, lint/biome/eslint/
//! ruff/clippy, dead_code, duplication, ci_lint, docker, sast, swift_lint,
//! js_licenses all dispatch through `parsers::dispatch_json`/
//! `dispatch_text`, the same functions `native_providers` uses for its own
//! provider surface) — this module only owns command construction,
//! applicability, and the two genuinely-JS-only checks (`repo`,
//! `decomposition`) plus `secrets`' gitleaks-report-to-candidates step
//! (`collect_facts::gitleaks_candidates`, also pre-existing).
//!
//! `pkg_mgr`/`rust_dir`/etc. all come from [`collect_facts::DetectedStack`]
//! (`detect()`, ported in full already); execution goes through
//! [`collect_facts_exec::CommandRunner`] so every `build_*` function is unit
//! tested against a fake runner, no real subprocess involved.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::native_providers::legacy_checks::parsers;
use crate::wf_port::wf065::collect_facts::{
    self, decomposition_review_loc, gitleaks_candidates, has_dep, is_generated_or_vendored_path,
    looks_missing, redact, DetectedStack, FileLoc,
};
use crate::wf_port::wf065::collect_facts_exec::{CheckSpec, CommandRunner, RunResult};

/// Split a JS shell-string command (`"npx --no-install tsc --noEmit"`) into
/// argv the way `collect-facts.mjs`'s `spawn(file, args, {shell:true})`
/// would have handed a shell — every command this half of `buildChecks`
/// issues is a plain space-separated argv with no quoting/globbing, so a
/// naive whitespace split is faithful.
fn argv(command: &str) -> Vec<String> {
    command.split_whitespace().map(str::to_string).collect()
}

// ---------------------------------------------------------------------------
// repo
// ---------------------------------------------------------------------------

/// `add({ check: 'repo', tool: 'git', required: d.git, ... })`.
pub fn build_repo<'a>(runner: &'a dyn CommandRunner, root: &'a Path, stack: &'a DetectedStack) -> CheckSpec<'a> {
    CheckSpec {
        check: "repo",
        tool: Some("git".to_string()),
        required: stack.git,
        tier: "core",
        flag_if_absent: false,
        parallel: true,
        force_skip: false,
        run: Box::new(move || {
            if !stack.git {
                return RunResult {
                    status: "unproven",
                    skip_reason: Some("not a git repo".to_string()),
                    ..Default::default()
                };
            }
            let sha_out = runner.run(&argv("git rev-parse HEAD"), root, 180_000);
            let files_out = runner.run(&argv("git ls-files"), root, 180_000);
            let sha = sha_out.stdout.trim().to_string();
            let files = files_out
                .stdout
                .split('\n')
                .filter(|f| !f.is_empty())
                .count() as u64;
            RunResult {
                status: "ran",
                command: Some("git rev-parse HEAD; git ls-files".to_string()),
                exit_code: Some(0),
                meta: Some(json!({ "commit": sha, "tracked_files": files })),
                ..Default::default()
            }
        }),
    }
}

// ---------------------------------------------------------------------------
// decomposition
// ---------------------------------------------------------------------------

const CODE_EXTENSIONS: &[&str] = &[
    "ts", "tsx", "js", "jsx", "mjs", "cjs", "py", "go", "rs", "java", "rb", "php", "c", "cc",
    "cpp", "h", "hpp", "cs", "swift", "kt", "scala", "sh", "sql",
];

fn is_code_file(path: &str) -> bool {
    let Some(ext) = path.rsplit('.').next() else {
        return false;
    };
    // JS `/\.(...)$/`: the extension must be the whole trailing segment
    // after the last `.`, and the path must actually contain a `.`.
    path.contains('.') && CODE_EXTENSIONS.iter().any(|e| e.eq_ignore_ascii_case(ext))
}

/// `add({ check: 'decomposition', tool: 'loc', ... })`. Env/config
/// threshold resolution is delegated to callers via `env_value`/
/// `config_value` (this port takes them as parameters rather than reading
/// `std::env`/`.agent/config.json` directly inside the closure, so tests
/// control the threshold deterministically — same information the JS
/// closure reads from `process.env`/the filesystem at call time).
#[allow(clippy::too_many_arguments)]
pub fn build_decomposition<'a>(
    runner: &'a dyn CommandRunner,
    root: &'a Path,
    stack: &'a DetectedStack,
    env_value: Option<&'a str>,
    config_value: Option<&'a Value>,
) -> CheckSpec<'a> {
    CheckSpec {
        check: "decomposition",
        tool: Some("loc".to_string()),
        required: false,
        tier: "core",
        flag_if_absent: false,
        parallel: true,
        force_skip: false,
        run: Box::new(move || {
            if !stack.git {
                return RunResult {
                    status: "unproven",
                    skip_reason: Some("not a git repo".to_string()),
                    ..Default::default()
                };
            }
            let threshold = decomposition_review_loc(env_value, config_value);
            let file_review_loc = threshold.value.max(0) as u64;

            let ls_files = runner.run(&argv("git ls-files"), root, 180_000);
            let files: Vec<String> = ls_files
                .stdout
                .split('\n')
                .filter(|f| !f.is_empty())
                .filter(|f| is_code_file(f) && !is_generated_or_vendored_path(f))
                .map(str::to_string)
                .collect();

            let mut file_locs = Vec::with_capacity(files.len());
            let mut include_stitch_count = 0_u64;
            for f in &files {
                let Ok(text) = std::fs::read_to_string(root.join(f)) else {
                    continue; // unreadable/binary — skip, matches JS's try/catch
                };
                let loc = text.split('\n').count() as u64;
                let bytes = text.len() as u64;
                include_stitch_count += count_include_stitches(&text);
                file_locs.push(FileLoc {
                    path: f.clone(),
                    loc,
                    bytes,
                });
            }

            let oversized = collect_facts::oversized_files(&file_locs, file_review_loc);
            let splits = collect_facts::mechanical_splits(&file_locs, file_review_loc);

            let by_class = |class: &str| -> u64 {
                oversized.iter().filter(|f| f.class == class).count() as u64
                    + splits.iter().filter(|f| f.class == class).count() as u64
            };
            let runtime = by_class("runtime");
            let test = by_class("test");
            let tooling = by_class("tooling");

            let mut ignored_meta = Value::Null;
            if !threshold.ignored.is_empty() {
                ignored_meta = json!(threshold
                    .ignored
                    .iter()
                    .map(|i| json!({ "source": i.source, "value": i.value, "reason": i.reason }))
                    .collect::<Vec<_>>());
            }

            let mut meta = json!({
                "threshold": file_review_loc,
                "thresholdKind": "review-trigger",
                "thresholdSource": threshold.source,
                "oversized": oversized,
                "mechanical_splits": splits,
                "include_stitch_count": include_stitch_count,
                "by_class": { "runtime": runtime, "test": test, "tooling": tooling },
                "runtime_review_candidates": runtime,
            });
            if !ignored_meta.is_null() {
                meta["thresholdIgnored"] = ignored_meta;
            }

            RunResult {
                status: "ran",
                command: Some(format!(
                    "measure tracked code files (review trigger > {file_review_loc} LOC; reconstruct include-split units; class: runtime|test|tooling)"
                )),
                exit_code: Some(0),
                findings_count: Some(0),
                candidate_count: Some((oversized.len() + splits.len()) as u64),
                meta: Some(meta),
                ..Default::default()
            }
        }),
    }
}

/// `(txt.match(/^\s*include!\s*\(/gm) || []).length` — count lines whose
/// leading whitespace is followed by a literal `include!(`.
fn count_include_stitches(text: &str) -> u64 {
    text.lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            trimmed.starts_with("include!") && {
                let rest = &trimmed["include!".len()..];
                rest.trim_start().starts_with('(')
            }
        })
        .count() as u64
}

// ---------------------------------------------------------------------------
// secrets (gitleaks)
// ---------------------------------------------------------------------------

/// Filesystem access the `secrets` check needs beyond command execution:
/// reading the raw gitleaks report and deleting it once redacted candidates
/// have been extracted (JS: `readFileSync(rawPath)` then `unlinkSync
/// (rawPath)`). Abstracted so tests never touch a real file.
pub trait GitleaksReport {
    fn read(&self, path: &Path) -> std::io::Result<String>;
    fn delete(&self, path: &Path);
}

/// Real filesystem-backed [`GitleaksReport`].
pub struct RealGitleaksReport;
impl GitleaksReport for RealGitleaksReport {
    fn read(&self, path: &Path) -> std::io::Result<String> {
        std::fs::read_to_string(path)
    }
    fn delete(&self, path: &Path) {
        let _ = std::fs::remove_file(path);
    }
}

/// `add({ check: 'secrets', tool: 'gitleaks', ... })`.
pub fn build_secrets<'a>(
    runner: &'a dyn CommandRunner,
    report_io: &'a dyn GitleaksReport,
    root: &'a Path,
    out_dir: &'a Path,
    stack: &'a DetectedStack,
) -> CheckSpec<'a> {
    CheckSpec {
        check: "secrets",
        tool: Some("gitleaks".to_string()),
        required: false,
        tier: "supplemental",
        flag_if_absent: true,
        parallel: true,
        force_skip: false,
        run: Box::new(move || {
            if !runner.which("gitleaks") {
                return RunResult {
                    status: "unproven",
                    skip_reason: Some("gitleaks not installed".to_string()),
                    tool_absent: true,
                    ..Default::default()
                };
            }
            let raw_path: PathBuf = out_dir.join("_gitleaks.json");
            let raw_path_str = raw_path.to_string_lossy().into_owned();
            let mode = if stack.git { "git ." } else { "dir ." };
            let cmd = format!(
                "gitleaks {mode} --report-format json --no-banner --report-path {raw_path_str}"
            );
            let out = runner.run(
                &[
                    "gitleaks".to_string(),
                    if stack.git { "git".to_string() } else { "dir".to_string() },
                    ".".to_string(),
                    "--report-format".to_string(),
                    "json".to_string(),
                    "--no-banner".to_string(),
                    "--report-path".to_string(),
                    raw_path_str.clone(),
                ],
                root,
                300_000,
            );
            // gitleaks exit: 0 = no leaks, 1 = leaks found, >1 = error.
            if out.code > 1 || looks_missing(&out.stdout, &out.stderr) {
                return RunResult {
                    status: "error",
                    command: Some(cmd),
                    exit_code: Some(out.code),
                    raw_log: redact(Some(if !out.stderr.is_empty() {
                        &out.stderr
                    } else {
                        &out.stdout
                    })),
                    ..Default::default()
                };
            }
            let findings = report_io.read(&raw_path).ok().and_then(|raw| {
                gitleaks_candidates(&raw).ok()
            });
            report_io.delete(&raw_path);
            let Some(candidates) = findings else {
                return RunResult {
                    status: "error",
                    command: Some(cmd),
                    exit_code: Some(out.code),
                    skip_reason: Some(
                        "gitleaks report unreadable — scan not proven".to_string(),
                    ),
                    raw_log: redact(Some(if !out.stderr.is_empty() {
                        &out.stderr
                    } else {
                        &out.stdout
                    })),
                    ..Default::default()
                };
            };
            let candidates_json = serde_json::to_value(&candidates).unwrap_or(Value::Array(vec![]));
            RunResult {
                status: "ran",
                command: Some(cmd),
                exit_code: Some(out.code),
                findings_count: Some(candidates.len() as u64),
                meta: Some(json!({ "secret_candidates": candidates_json })),
                raw_log: serde_json::to_string_pretty(&candidates_json).ok(),
                duration_ms: Some(out.duration_ms),
                ..Default::default()
            }
        }),
    }
}

// ---------------------------------------------------------------------------
// deps_cve (npm/pnpm/yarn audit --json)
// ---------------------------------------------------------------------------

/// `add({ check: 'deps_cve', tool: `${d.pkgMgr} audit`, required: d.node, ... })`.
pub fn build_deps_cve<'a>(runner: &'a dyn CommandRunner, root: &'a Path, stack: &'a DetectedStack) -> CheckSpec<'a> {
    CheckSpec {
        check: "deps_cve",
        tool: Some(format!("{} audit", stack.pkg_mgr)),
        required: stack.node,
        tier: "core",
        flag_if_absent: false,
        parallel: true,
        force_skip: false,
        run: Box::new(move || {
            if !stack.node {
                return RunResult {
                    status: "unproven",
                    skip_reason: Some("no package.json".to_string()),
                    ..Default::default()
                };
            }
            let cmd = format!("{} audit --json", stack.pkg_mgr);
            let out = runner.run(&argv(&cmd), root, 180_000);
            if looks_missing(&out.stdout, &out.stderr) {
                return RunResult {
                    status: "error",
                    command: Some(cmd.clone()),
                    exit_code: Some(out.code),
                    skip_reason: Some(format!("{} not available", stack.pkg_mgr)),
                    raw_log: redact(Some(if !out.stderr.is_empty() { &out.stderr } else { &out.stdout })),
                    ..Default::default()
                };
            }
            let combined = format!("{}{}", out.stderr, out.stdout);
            if regex_lite_lockfile_missing(&combined) {
                return RunResult {
                    status: "unproven",
                    command: Some(cmd.clone()),
                    exit_code: Some(out.code),
                    skip_reason: Some(format!("no lockfile for {}", stack.pkg_mgr)),
                    ..Default::default()
                };
            }
            let parsed = serde_json::from_str::<Value>(&out.stdout).ok();
            let outcome = parsed.as_ref().and_then(|v| parsers::dispatch_json("deps_cve", v));
            match outcome.filter(|o| !o.malformed) {
                Some(outcome) => RunResult {
                    status: "ran",
                    command: Some(cmd),
                    exit_code: Some(out.code),
                    findings_count: outcome.findings_count,
                    raw_log: redact(Some(if !out.stdout.is_empty() { &out.stdout } else { &out.stderr })),
                    duration_ms: Some(out.duration_ms),
                    ..Default::default()
                },
                None => RunResult {
                    status: "error",
                    command: Some(cmd),
                    exit_code: Some(out.code),
                    skip_reason: Some(format!("{} audit output unparseable — scan not proven", stack.pkg_mgr)),
                    raw_log: redact(Some(if !out.stdout.is_empty() { &out.stdout } else { &out.stderr })),
                    ..Default::default()
                },
            }
        }),
    }
}

fn regex_lite_lockfile_missing(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("requires an existing lockfile") || lower.contains("no lockfile") || lower.contains("enolock")
}

// ---------------------------------------------------------------------------
// py_deps_cve (pip-audit -f json)
// ---------------------------------------------------------------------------

/// `add({ check: 'py_deps_cve', tool: 'pip-audit', ... })`.
pub fn build_py_deps_cve<'a>(runner: &'a dyn CommandRunner, root: &'a Path, stack: &'a DetectedStack) -> CheckSpec<'a> {
    CheckSpec {
        check: "py_deps_cve",
        tool: Some("pip-audit".to_string()),
        required: false,
        tier: "core",
        flag_if_absent: true,
        parallel: true,
        force_skip: false,
        run: Box::new(move || {
            if !stack.py {
                return RunResult {
                    status: "unproven",
                    skip_reason: Some("no Python project (pyproject/setup.py/requirements)".to_string()),
                    ..Default::default()
                };
            }
            if !runner.which("pip-audit") {
                return RunResult {
                    status: "unproven",
                    skip_reason: Some("pip-audit not installed (`pipx install pip-audit`)".to_string()),
                    tool_absent: true,
                    ..Default::default()
                };
            }
            let req = ["requirements.txt", "requirements-dev.txt"]
                .into_iter()
                .find(|f| root.join(f).exists());
            let cmd = match req {
                Some(req) => format!("pip-audit -r {req} -f json"),
                None => "pip-audit -f json".to_string(),
            };
            let out = runner.run(&argv(&cmd), root, 300_000);
            if looks_missing(&out.stdout, &out.stderr) {
                return RunResult {
                    status: "unproven",
                    skip_reason: Some("pip-audit not resolvable".to_string()),
                    tool_absent: true,
                    ..Default::default()
                };
            }
            let parsed = serde_json::from_str::<Value>(&out.stdout).ok();
            let count = parsed.as_ref().and_then(|v| parsers::dispatch_json("py_deps_cve", v)).and_then(|o| o.findings_count);
            RunResult {
                status: "ran",
                command: Some(cmd),
                exit_code: Some(out.code),
                findings_count: count,
                raw_log: redact(Some(if !out.stdout.is_empty() { &out.stdout } else { &out.stderr })),
                duration_ms: Some(out.duration_ms),
                ..Default::default()
            }
        }),
    }
}

// ---------------------------------------------------------------------------
// types (tsc / basedpyright / mypy)
// ---------------------------------------------------------------------------

/// `add({ check: 'types', ... })`.
pub fn build_types<'a>(runner: &'a dyn CommandRunner, root: &'a Path, stack: &'a DetectedStack) -> CheckSpec<'a> {
    let tool = if stack.ts {
        Some("tsc".to_string())
    } else if stack.py {
        Some("basedpyright|mypy".to_string())
    } else {
        None
    };
    CheckSpec {
        check: "types",
        tool,
        required: stack.ts || stack.py,
        tier: "core",
        flag_if_absent: false,
        parallel: true,
        force_skip: false,
        run: Box::new(move || {
            if stack.ts {
                let has_ts_dep = stack.pkg.as_ref().is_some_and(|p| has_dep(p, "typescript"));
                if !has_ts_dep {
                    return RunResult {
                        status: "unproven",
                        skip_reason: Some("tsconfig present but typescript not in dependencies".to_string()),
                        tool_absent: true,
                        ..Default::default()
                    };
                }
                let cmd = "npx --no-install tsc --noEmit";
                let out = runner.run(&argv(cmd), root, 180_000);
                if looks_missing(&out.stdout, &out.stderr) {
                    return RunResult {
                        status: "unproven",
                        skip_reason: Some("tsc not resolvable via npx --no-install".to_string()),
                        tool_absent: true,
                        ..Default::default()
                    };
                }
                let combined = format!("{}{}", out.stdout, out.stderr);
                let outcome = parsers::dispatch_text("types", &combined);
                return RunResult {
                    status: "ran",
                    command: Some(cmd.to_string()),
                    exit_code: Some(out.code),
                    findings_count: outcome.and_then(|o| o.findings_count),
                    raw_log: redact(Some(&combined)),
                    duration_ms: Some(out.duration_ms),
                    ..Default::default()
                };
            }
            if stack.py {
                if runner.which("basedpyright") {
                    let cmd = "basedpyright --outputjson";
                    let out = runner.run(&argv(cmd), root, 180_000);
                    let parsed = serde_json::from_str::<Value>(&out.stdout).ok();
                    let count = parsed.as_ref().and_then(|v| parsers::dispatch_json("types", v)).and_then(|o| o.findings_count);
                    return RunResult {
                        status: "ran",
                        command: Some(cmd.to_string()),
                        exit_code: Some(out.code),
                        findings_count: count,
                        raw_log: redact(Some(&format!("{}{}", out.stdout, out.stderr))),
                        duration_ms: Some(out.duration_ms),
                        ..Default::default()
                    };
                }
                if runner.which("mypy") {
                    let cmd = "mypy .";
                    let out = runner.run(&argv(cmd), root, 180_000);
                    return RunResult {
                        status: "ran",
                        command: Some(cmd.to_string()),
                        exit_code: Some(out.code),
                        raw_log: redact(Some(&format!("{}{}", out.stdout, out.stderr))),
                        duration_ms: Some(out.duration_ms),
                        ..Default::default()
                    };
                }
                return RunResult {
                    status: "unproven",
                    skip_reason: Some("no Python type checker (basedpyright/mypy) installed".to_string()),
                    tool_absent: true,
                    ..Default::default()
                };
            }
            RunResult {
                status: "unproven",
                skip_reason: Some("no typed stack detected".to_string()),
                ..Default::default()
            }
        }),
    }
}

// ---------------------------------------------------------------------------
// lint (biome | eslint | ruff | clippy)
// ---------------------------------------------------------------------------

/// `add({ check: 'lint', ... })`.
pub fn build_lint<'a>(runner: &'a dyn CommandRunner, root: &'a Path, stack: &'a DetectedStack) -> CheckSpec<'a> {
    let tool = if stack.biome {
        Some("biome".to_string())
    } else if stack.eslint {
        Some("eslint".to_string())
    } else if stack.rust {
        Some("clippy".to_string())
    } else if stack.py {
        Some("ruff".to_string())
    } else {
        None
    };
    CheckSpec {
        check: "lint",
        tool,
        required: stack.eslint || stack.biome,
        tier: "core",
        flag_if_absent: false,
        parallel: true,
        force_skip: false,
        run: Box::new(move || {
            if stack.biome {
                let has_biome_dep = stack.pkg.as_ref().is_some_and(|p| has_dep(p, "@biomejs/biome"));
                if !has_biome_dep {
                    return RunResult {
                        status: "unproven",
                        skip_reason: Some("biome config present but @biomejs/biome not in dependencies".to_string()),
                        tool_absent: true,
                        ..Default::default()
                    };
                }
                let cmd = "npx --no-install biome lint . --reporter=json --max-diagnostics=1000";
                let out = runner.run(&argv(cmd), root, 180_000);
                if looks_missing(&out.stdout, &out.stderr) {
                    return RunResult {
                        status: "unproven",
                        skip_reason: Some("biome not resolvable via npx --no-install".to_string()),
                        tool_absent: true,
                        ..Default::default()
                    };
                }
                let parsed = serde_json::from_str::<Value>(&out.stdout).unwrap_or(json!({}));
                let count = parsers::dispatch_json("lint", &parsed).and_then(|o| o.findings_count);
                return RunResult {
                    status: "ran",
                    command: Some(cmd.to_string()),
                    exit_code: Some(out.code),
                    findings_count: count,
                    raw_log: redact(Some(if !out.stdout.is_empty() { &out.stdout } else { &out.stderr })),
                    duration_ms: Some(out.duration_ms),
                    ..Default::default()
                };
            }
            if stack.eslint {
                let has_eslint_dep = stack.pkg.as_ref().is_some_and(|p| has_dep(p, "eslint"));
                if !has_eslint_dep {
                    return RunResult {
                        status: "unproven",
                        skip_reason: Some("eslint config present but eslint not in dependencies".to_string()),
                        tool_absent: true,
                        ..Default::default()
                    };
                }
                let cmd = "npx --no-install eslint . -f json";
                let out = runner.run(&argv(cmd), root, 180_000);
                if looks_missing(&out.stdout, &out.stderr) {
                    return RunResult {
                        status: "unproven",
                        skip_reason: Some("eslint not resolvable via npx --no-install".to_string()),
                        tool_absent: true,
                        ..Default::default()
                    };
                }
                let parsed = serde_json::from_str::<Value>(&out.stdout).ok();
                let count = parsed.as_ref().and_then(|v| parsers::dispatch_json("lint", v)).and_then(|o| o.findings_count);
                return RunResult {
                    status: "ran",
                    command: Some(cmd.to_string()),
                    exit_code: Some(out.code),
                    findings_count: count,
                    raw_log: redact(Some(if !out.stdout.is_empty() { &out.stdout } else { &out.stderr })),
                    duration_ms: Some(out.duration_ms),
                    ..Default::default()
                };
            }
            if stack.py && runner.which("ruff") {
                let cmd = "ruff check . --output-format json";
                let out = runner.run(&argv(cmd), root, 180_000);
                let parsed = serde_json::from_str::<Value>(&out.stdout).ok();
                let count = parsed.as_ref().and_then(|v| parsers::dispatch_json("lint", v)).and_then(|o| o.findings_count);
                return RunResult {
                    status: "ran",
                    command: Some(cmd.to_string()),
                    exit_code: Some(out.code),
                    findings_count: count,
                    raw_log: redact(Some(if !out.stdout.is_empty() { &out.stdout } else { &out.stderr })),
                    duration_ms: Some(out.duration_ms),
                    ..Default::default()
                };
            }
            if stack.rust && runner.which("cargo") {
                let cmd = "cargo clippy --all-targets --message-format=json -- -D warnings";
                let cwd = root.join(stack.rust_dir.clone().unwrap_or_else(|| ".".to_string()));
                let out = runner.run(&argv(cmd), &cwd, 600_000);
                let outcome = parsers::dispatch_text("lint", &out.stdout);
                return RunResult {
                    status: "ran",
                    command: Some(cmd.to_string()),
                    exit_code: Some(out.code),
                    findings_count: outcome.and_then(|o| o.findings_count).or(Some(0)),
                    raw_log: redact(Some(&format!("{}{}", out.stdout, out.stderr))),
                    duration_ms: Some(out.duration_ms),
                    ..Default::default()
                };
            }
            if stack.py {
                return RunResult {
                    status: "unproven",
                    skip_reason: Some("ruff not installed".to_string()),
                    tool_absent: true,
                    ..Default::default()
                };
            }
            if stack.rust {
                return RunResult {
                    status: "unproven",
                    skip_reason: Some("cargo/clippy not installed".to_string()),
                    tool_absent: true,
                    ..Default::default()
                };
            }
            RunResult {
                status: "unproven",
                skip_reason: Some("no configured linter (biome/eslint/ruff/clippy)".to_string()),
                ..Default::default()
            }
        }),
    }
}

// ---------------------------------------------------------------------------
// dead_code (knip)
// ---------------------------------------------------------------------------

/// `add({ check: 'dead_code', tool: 'knip', ... })`.
pub fn build_dead_code<'a>(runner: &'a dyn CommandRunner, root: &'a Path, stack: &'a DetectedStack) -> CheckSpec<'a> {
    CheckSpec {
        check: "dead_code",
        tool: Some("knip".to_string()),
        required: false,
        tier: "core",
        flag_if_absent: false,
        parallel: true,
        force_skip: false,
        run: Box::new(move || {
            if !stack.node {
                return RunResult {
                    status: "unproven",
                    skip_reason: Some("no package.json".to_string()),
                    ..Default::default()
                };
            }
            let cmd = "npx --no-install knip --reporter json";
            let out = runner.run(&argv(cmd), root, 180_000);
            if looks_missing(&out.stdout, &out.stderr) {
                return RunResult {
                    status: "unproven",
                    skip_reason: Some("knip not installed (add as dep or `npm i -g knip`)".to_string()),
                    tool_absent: true,
                    ..Default::default()
                };
            }
            let parsed = serde_json::from_str::<Value>(&out.stdout).ok();
            let count = parsed.as_ref().and_then(|v| parsers::dispatch_json("dead_code", v)).and_then(|o| o.findings_count);
            RunResult {
                status: "ran",
                command: Some(cmd.to_string()),
                exit_code: Some(out.code),
                findings_count: count,
                raw_log: redact(Some(if !out.stdout.is_empty() { &out.stdout } else { &out.stderr })),
                duration_ms: Some(out.duration_ms),
                ..Default::default()
            }
        }),
    }
}

// ---------------------------------------------------------------------------
// duplication (jscpd)
// ---------------------------------------------------------------------------

/// Filesystem access the `duplication` check needs beyond command execution:
/// reading jscpd's on-disk JSON report (`<outDir>/_jscpd/jscpd-report.json`
/// — jscpd writes to disk, it does not print JSON to stdout).
pub trait JscpdReport {
    fn read(&self, path: &Path) -> std::io::Result<String>;
}

pub struct RealJscpdReport;
impl JscpdReport for RealJscpdReport {
    fn read(&self, path: &Path) -> std::io::Result<String> {
        std::fs::read_to_string(path)
    }
}

/// `add({ check: 'duplication', tool: 'jscpd', ... })`.
pub fn build_duplication<'a>(
    runner: &'a dyn CommandRunner,
    report_io: &'a dyn JscpdReport,
    root: &'a Path,
    out_dir: &'a Path,
) -> CheckSpec<'a> {
    CheckSpec {
        check: "duplication",
        tool: Some("jscpd".to_string()),
        required: false,
        tier: "core",
        flag_if_absent: false,
        parallel: true,
        force_skip: false,
        run: Box::new(move || {
            let rep = out_dir.join("_jscpd");
            let rep_str = rep.to_string_lossy().into_owned();
            let cmd = format!(
                "npx --no-install jscpd . --reporters json --output {rep_str} --min-lines 20 --ignore **/*.md,**/node_modules/**,**/dist/**,**/.git/**,**/.audit/**,**/.agent/**,**/.cache/**,**/.sampleapp/**,**/.tools/**,**/_mockups/**,**/eval/**,**/reference/**,**/docs/**,**/site/**,**/src-tauri/gen/**,**/vendor/**,**/qwik/**,**/benchmarks/article-quality/goldens/**,**/benchmarks/**/target/**,**/drizzle/meta/**,**/src/generated/**,**/pnpm-lock.yaml --silent"
            );
            let out = runner.run(&argv(&cmd), root, 180_000);
            if looks_missing(&out.stdout, &out.stderr) {
                return RunResult {
                    status: "unproven",
                    skip_reason: Some("jscpd not installed (`npm i -g jscpd`)".to_string()),
                    tool_absent: true,
                    ..Default::default()
                };
            }
            let report_text = report_io.read(&rep.join("jscpd-report.json")).ok();
            let parsed = report_text.as_deref().and_then(|t| serde_json::from_str::<Value>(t).ok());
            let outcome = parsed.as_ref().and_then(|v| parsers::dispatch_json("duplication", v));
            match outcome.filter(|o| !o.malformed) {
                Some(outcome) => {
                    let summary = parsed
                        .as_ref()
                        .and_then(|v| v.get("statistics"))
                        .and_then(|s| s.get("total"))
                        .cloned()
                        .unwrap_or(json!({}));
                    RunResult {
                        status: "ran",
                        command: Some(cmd),
                        exit_code: Some(out.code),
                        findings_count: outcome.findings_count,
                        raw_log: redact(Some(&serde_json::to_string_pretty(&summary).unwrap_or_default())),
                        duration_ms: Some(out.duration_ms),
                        ..Default::default()
                    }
                }
                None => RunResult {
                    status: "error",
                    command: Some(cmd),
                    exit_code: Some(out.code),
                    skip_reason: Some("jscpd report unreadable — scan not proven".to_string()),
                    raw_log: redact(Some(if !out.stdout.is_empty() { &out.stdout } else { &out.stderr })),
                    ..Default::default()
                },
            }
        }),
    }
}

// ---------------------------------------------------------------------------
// ci_lint (actionlint)
// ---------------------------------------------------------------------------

/// `add({ check: 'ci_lint', tool: 'actionlint', ... })`.
pub fn build_ci_lint<'a>(runner: &'a dyn CommandRunner, root: &'a Path, stack: &'a DetectedStack) -> CheckSpec<'a> {
    CheckSpec {
        check: "ci_lint",
        tool: Some("actionlint".to_string()),
        required: false,
        tier: "core",
        flag_if_absent: false,
        parallel: true,
        force_skip: false,
        run: Box::new(move || {
            if !stack.workflows {
                return RunResult {
                    status: "unproven",
                    skip_reason: Some("no .github/workflows".to_string()),
                    ..Default::default()
                };
            }
            if !runner.which("actionlint") {
                return RunResult {
                    status: "unproven",
                    skip_reason: Some("actionlint not installed".to_string()),
                    tool_absent: true,
                    ..Default::default()
                };
            }
            let cmd = vec!["actionlint".to_string(), "-format".to_string(), "{{json .}}".to_string()];
            let out = runner.run(&cmd, root, 180_000);
            let parsed = serde_json::from_str::<Value>(if out.stdout.trim().is_empty() { "[]" } else { &out.stdout }).ok();
            let count = parsed.as_ref().and_then(|v| parsers::dispatch_json("ci_lint", v)).and_then(|o| o.findings_count);
            RunResult {
                status: "ran",
                command: Some("actionlint -format \"{{json .}}\"".to_string()),
                exit_code: Some(out.code),
                findings_count: count,
                raw_log: redact(Some(if !out.stdout.is_empty() { &out.stdout } else { &out.stderr })),
                duration_ms: Some(out.duration_ms),
                ..Default::default()
            }
        }),
    }
}

// ---------------------------------------------------------------------------
// docker (hadolint)
// ---------------------------------------------------------------------------

/// `add({ check: 'docker', tool: 'hadolint', ... })`.
pub fn build_docker<'a>(runner: &'a dyn CommandRunner, root: &'a Path, stack: &'a DetectedStack) -> CheckSpec<'a> {
    CheckSpec {
        check: "docker",
        tool: Some("hadolint".to_string()),
        required: false,
        tier: "core",
        flag_if_absent: false,
        parallel: true,
        force_skip: false,
        run: Box::new(move || {
            if !stack.dockerfile {
                return RunResult {
                    status: "unproven",
                    skip_reason: Some("no Dockerfile".to_string()),
                    ..Default::default()
                };
            }
            if !runner.which("hadolint") {
                return RunResult {
                    status: "unproven",
                    skip_reason: Some("hadolint not installed".to_string()),
                    tool_absent: true,
                    ..Default::default()
                };
            }
            let cmd = "hadolint --format json Dockerfile";
            let out = runner.run(&argv(cmd), root, 180_000);
            let parsed = serde_json::from_str::<Value>(if out.stdout.trim().is_empty() { "[]" } else { &out.stdout }).ok();
            let count = parsed.as_ref().and_then(|v| parsers::dispatch_json("docker", v)).and_then(|o| o.findings_count);
            RunResult {
                status: "ran",
                command: Some(cmd.to_string()),
                exit_code: Some(out.code),
                findings_count: count,
                raw_log: redact(Some(if !out.stdout.is_empty() { &out.stdout } else { &out.stderr })),
                duration_ms: Some(out.duration_ms),
                ..Default::default()
            }
        }),
    }
}

// ---------------------------------------------------------------------------
// sast (semgrep)
// ---------------------------------------------------------------------------

/// `add({ check: 'sast', tool: 'semgrep', ... })`.
pub fn build_sast<'a>(runner: &'a dyn CommandRunner, root: &'a Path) -> CheckSpec<'a> {
    CheckSpec {
        check: "sast",
        tool: Some("semgrep".to_string()),
        required: false,
        tier: "supplemental",
        flag_if_absent: false,
        parallel: true,
        force_skip: false,
        run: Box::new(move || {
            if !runner.which("semgrep") {
                return RunResult {
                    status: "unproven",
                    skip_reason: Some("semgrep not installed".to_string()),
                    tool_absent: true,
                    ..Default::default()
                };
            }
            let cmd = "semgrep --config auto --json --quiet --exclude vendor --exclude qwik --exclude .audit --exclude .agent --exclude dist";
            let out = runner.run(&argv(cmd), root, 300_000);
            let parsed = serde_json::from_str::<Value>(&out.stdout).ok();
            let count = parsed.as_ref().and_then(|v| parsers::dispatch_json("sast", v)).and_then(|o| o.findings_count);
            RunResult {
                status: "ran",
                command: Some(cmd.to_string()),
                exit_code: Some(out.code),
                findings_count: count,
                raw_log: redact(Some(if !out.stdout.is_empty() { &out.stdout } else { &out.stderr })),
                duration_ms: Some(out.duration_ms),
                ..Default::default()
            }
        }),
    }
}

// ---------------------------------------------------------------------------
// swift_lint (swiftlint)
// ---------------------------------------------------------------------------

/// `add({ check: 'swift_lint', tool: 'swiftlint', ... })`.
pub fn build_swift_lint<'a>(runner: &'a dyn CommandRunner, root: &'a Path, stack: &'a DetectedStack) -> CheckSpec<'a> {
    CheckSpec {
        check: "swift_lint",
        tool: Some("swiftlint".to_string()),
        required: false,
        tier: "supplemental",
        flag_if_absent: false,
        parallel: true,
        force_skip: false,
        run: Box::new(move || {
            if !stack.git {
                return RunResult {
                    status: "unproven",
                    skip_reason: Some("needs git ls-files".to_string()),
                    ..Default::default()
                };
            }
            let ls_files = runner.run(&argv("git ls-files"), root, 180_000);
            let has_swift = ls_files
                .stdout
                .split('\n')
                .filter(|f| !f.is_empty())
                .any(|f| f.ends_with(".swift") && !is_generated_or_vendored_path(f));
            if !has_swift {
                return RunResult {
                    status: "unproven",
                    skip_reason: Some("no .swift sources".to_string()),
                    ..Default::default()
                };
            }
            if !runner.which("swiftlint") {
                return RunResult {
                    status: "unproven",
                    skip_reason: Some("swiftlint not installed (`brew install swiftlint`)".to_string()),
                    tool_absent: true,
                    ..Default::default()
                };
            }
            let cmd = "swiftlint lint --quiet --reporter json";
            let out = runner.run(&argv(cmd), root, 300_000);
            let parsed = serde_json::from_str::<Value>(if out.stdout.trim().is_empty() { "[]" } else { &out.stdout }).ok();
            let count = parsed.as_ref().and_then(|v| parsers::dispatch_json("swift_lint", v)).and_then(|o| o.findings_count);
            RunResult {
                status: "ran",
                command: Some(cmd.to_string()),
                exit_code: Some(out.code),
                findings_count: count,
                raw_log: redact(Some(if !out.stdout.is_empty() { &out.stdout } else { &out.stderr })),
                duration_ms: Some(out.duration_ms),
                ..Default::default()
            }
        }),
    }
}

// ---------------------------------------------------------------------------
// js_licenses (license-checker)
// ---------------------------------------------------------------------------

/// `add({ check: 'js_licenses', tool: 'license-checker', ... })`.
pub fn build_js_licenses<'a>(runner: &'a dyn CommandRunner, root: &'a Path, stack: &'a DetectedStack) -> CheckSpec<'a> {
    CheckSpec {
        check: "js_licenses",
        tool: Some("license-checker".to_string()),
        required: false,
        tier: "supplemental",
        flag_if_absent: false,
        parallel: true,
        force_skip: false,
        run: Box::new(move || {
            if !stack.node {
                return RunResult {
                    status: "unproven",
                    skip_reason: Some("no package.json".to_string()),
                    ..Default::default()
                };
            }
            let cmd = "npx --no-install license-checker --json --production";
            let out = runner.run(&argv(cmd), root, 180_000);
            if looks_missing(&out.stdout, &out.stderr) {
                return RunResult {
                    status: "unproven",
                    skip_reason: Some("license-checker not installed (`npm i -D license-checker`)".to_string()),
                    tool_absent: true,
                    ..Default::default()
                };
            }
            let parsed = serde_json::from_str::<Value>(&out.stdout).ok();
            let outcome = parsed.as_ref().and_then(|v| parsers::dispatch_json("js_licenses", v));
            RunResult {
                status: "ran",
                command: Some(cmd.to_string()),
                exit_code: Some(out.code),
                findings_count: outcome.as_ref().and_then(|o| o.findings_count),
                meta: outcome.map(|o| json!({
                    "total_deps": o.meta.iter().find(|(k, _)| *k == "totalDeps").map(|(_, v)| v.clone()),
                    "copyleft": o.meta.iter().find(|(k, _)| *k == "copyleft").map(|(_, v)| v.clone()),
                })),
                raw_log: redact(Some(if !out.stdout.is_empty() { &out.stdout } else { &out.stderr })),
                duration_ms: Some(out.duration_ms),
                ..Default::default()
            }
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wf_port::wf065::collect_facts::detect;
    use std::collections::HashMap;
    use std::io;
    use std::sync::Mutex;

    /// Deterministic fake: keyed by the joined argv, returns a preset
    /// `RunOutput`. Unregistered commands return an ENOENT-shaped spawn
    /// error so a check accidentally issuing an unexpected command fails
    /// loudly rather than silently returning empty output.
    struct FakeRunner {
        outputs: HashMap<String, crate::wf_port::wf065::collect_facts_exec::RunOutput>,
        which: HashMap<&'static str, bool>,
        calls: Mutex<Vec<String>>,
    }
    impl FakeRunner {
        fn new() -> Self {
            Self {
                outputs: HashMap::new(),
                which: HashMap::new(),
                calls: Mutex::new(Vec::new()),
            }
        }
        fn with_output(mut self, argv: &str, code: i32, stdout: &str, stderr: &str) -> Self {
            self.outputs.insert(
                argv.to_string(),
                crate::wf_port::wf065::collect_facts_exec::RunOutput {
                    code,
                    stdout: stdout.to_string(),
                    stderr: stderr.to_string(),
                    duration_ms: 1,
                    spawn_error: false,
                },
            );
            self
        }
        fn with_which(mut self, bin: &'static str, present: bool) -> Self {
            self.which.insert(bin, present);
            self
        }
    }
    impl CommandRunner for FakeRunner {
        fn run(&self, argv: &[String], _cwd: &Path, _timeout_ms: u64) -> crate::wf_port::wf065::collect_facts_exec::RunOutput {
            let key = argv.join(" ");
            self.calls.lock().unwrap().push(key.clone());
            // Unregistered commands default to a benign empty success (not an
            // ENOENT-shaped failure) so a check that legitimately spawns a
            // tool this fixture didn't bother stubbing (e.g. `duplication`'s
            // jscpd invocation, whose real signal lives in the on-disk
            // report, not stdout) doesn't get misread as "tool missing" by
            // `looks_missing`. Tests asserting tool-absence register an
            // explicit ENOENT-shaped output or use `with_which(..., false)`.
            self.outputs
                .get(&key)
                .cloned()
                .unwrap_or(crate::wf_port::wf065::collect_facts_exec::RunOutput {
                    code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                    duration_ms: 1,
                    spawn_error: false,
                })
        }
        fn which(&self, bin: &str) -> bool {
            *self.which.get(bin).unwrap_or(&false)
        }
    }

    struct FakeGitleaksReport {
        content: Option<String>,
        deleted: Mutex<bool>,
    }
    impl GitleaksReport for FakeGitleaksReport {
        fn read(&self, _path: &Path) -> io::Result<String> {
            self.content
                .clone()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no report"))
        }
        fn delete(&self, _path: &Path) {
            *self.deleted.lock().unwrap() = true;
        }
    }

    struct FakeJscpdReport {
        content: Option<String>,
    }
    impl JscpdReport for FakeJscpdReport {
        fn read(&self, _path: &Path) -> io::Result<String> {
            self.content
                .clone()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no report"))
        }
    }

    fn npm_stack() -> DetectedStack {
        DetectedStack {
            git: true,
            node: true,
            pkg: Some(json!({ "dependencies": { "typescript": "^5.0.0", "eslint": "^9.0.0" } })),
            pkg_mgr: "npm",
            ts: true,
            py: false,
            rust: false,
            rust_dir: None,
            swift: false,
            tauri: false,
            build_script: false,
            eslint: true,
            biome: false,
            workflows: false,
            dockerfile: false,
        }
    }

    #[test]
    fn repo_check_reports_commit_and_tracked_file_count() {
        let runner = FakeRunner::new()
            .with_output("git rev-parse HEAD", 0, "abc123\n", "")
            .with_output("git ls-files", 0, "a.rs\nb.rs\n", "");
        let stack = npm_stack();
        let spec = build_repo(&runner, Path::new("."), &stack);
        let result = (spec.run)();
        assert_eq!(result.status, "ran");
        assert_eq!(result.meta.unwrap()["tracked_files"], json!(2));
    }

    #[test]
    fn repo_check_unproven_outside_git() {
        let runner = FakeRunner::new();
        let mut stack = npm_stack();
        stack.git = false;
        let spec = build_repo(&runner, Path::new("."), &stack);
        let result = (spec.run)();
        assert_eq!(result.status, "unproven");
        assert_eq!(result.skip_reason.as_deref(), Some("not a git repo"));
    }

    #[test]
    fn decomposition_flags_oversized_tracked_code_file() {
        let dir = tempdir();
        std::fs::write(dir.join("big.rs"), "x\n".repeat(150)).unwrap();
        std::fs::write(dir.join("small.rs"), "x\n".repeat(5)).unwrap();
        let runner = FakeRunner::new().with_output("git ls-files", 0, "big.rs\nsmall.rs\n", "");
        let stack = detect(&dir);
        let spec = build_decomposition(&runner, &dir, &stack, Some("100"), None);
        let result = (spec.run)();
        assert_eq!(result.status, "ran");
        let oversized = &result.meta.unwrap()["oversized"];
        assert_eq!(oversized.as_array().unwrap().len(), 1);
        assert_eq!(oversized[0]["file"], json!("big.rs"));
    }

    #[test]
    fn secrets_check_converts_report_to_redacted_candidates_and_deletes_it() {
        let runner = FakeRunner::new()
            .with_which("gitleaks", true)
            .with_output(
                "gitleaks git . --report-format json --no-banner --report-path OUT/_gitleaks.json",
                0,
                "",
                "",
            );
        let report = FakeGitleaksReport {
            content: Some(r#"[{"RuleID":"aws-key","File":"a.env","StartLine":3,"Fingerprint":"fp1"}]"#.to_string()),
            deleted: Mutex::new(false),
        };
        let stack = npm_stack();
        let out_dir = Path::new("OUT");
        // Rebuild the exact argv this check issues so the fake matches:
        // report_path uses `out_dir.join("_gitleaks.json")`'s Display form.
        let spec = build_secrets(&runner, &report, Path::new("."), out_dir, &stack);
        let result = (spec.run)();
        assert_eq!(result.status, "ran");
        assert_eq!(result.findings_count, Some(1));
        assert!(*report.deleted.lock().unwrap());
    }

    #[test]
    fn secrets_check_unproven_when_gitleaks_absent() {
        let runner = FakeRunner::new().with_which("gitleaks", false);
        let report = FakeGitleaksReport { content: None, deleted: Mutex::new(false) };
        let stack = npm_stack();
        let spec = build_secrets(&runner, &report, Path::new("."), Path::new("OUT"), &stack);
        let result = (spec.run)();
        assert_eq!(result.status, "unproven");
        assert!(result.tool_absent);
    }

    #[test]
    fn deps_cve_reads_metadata_total_via_shared_parser() {
        let runner = FakeRunner::new().with_output(
            "npm audit --json",
            0,
            r#"{"metadata":{"vulnerabilities":{"total":4}}}"#,
            "",
        );
        let stack = npm_stack();
        let spec = build_deps_cve(&runner, Path::new("."), &stack);
        let result = (spec.run)();
        assert_eq!(result.status, "ran");
        assert_eq!(result.findings_count, Some(4));
    }

    #[test]
    fn deps_cve_unparseable_output_is_error_not_zero() {
        let runner = FakeRunner::new().with_output("npm audit --json", 0, "not json", "");
        let stack = npm_stack();
        let spec = build_deps_cve(&runner, Path::new("."), &stack);
        let result = (spec.run)();
        assert_eq!(result.status, "error");
        assert_eq!(result.findings_count, None);
    }

    #[test]
    fn deps_cve_no_lockfile_is_unproven() {
        let runner = FakeRunner::new().with_output("npm audit --json", 1, "", "no lockfile found");
        let stack = npm_stack();
        let spec = build_deps_cve(&runner, Path::new("."), &stack);
        let result = (spec.run)();
        assert_eq!(result.status, "unproven");
    }

    #[test]
    fn py_deps_cve_sums_vuln_arrays_when_python_project() {
        let runner = FakeRunner::new()
            .with_which("pip-audit", true)
            .with_output(
                "pip-audit -f json",
                0,
                r#"{"dependencies":[{"name":"requests","vulns":[{"id":"PYSEC-1"}]}]}"#,
                "",
            );
        let mut stack = npm_stack();
        stack.py = true;
        // A real tempdir with no requirements*.txt, so the check's own
        // `root.join(f).exists()` probe is hermetic instead of depending on
        // whatever files happen to live in the test runner's CWD.
        let dir = tempdir();
        let spec = build_py_deps_cve(&runner, &dir, &stack);
        let result = (spec.run)();
        assert_eq!(result.findings_count, Some(1));
    }

    #[test]
    fn py_deps_cve_unproven_without_python_project() {
        let runner = FakeRunner::new();
        let stack = npm_stack();
        let spec = build_py_deps_cve(&runner, Path::new("."), &stack);
        let result = (spec.run)();
        assert_eq!(result.status, "unproven");
        assert!(!result.tool_absent);
    }

    #[test]
    fn types_check_counts_tsc_error_lines() {
        let runner = FakeRunner::new().with_output(
            "npx --no-install tsc --noEmit",
            2,
            "src/a.ts(1,1): error TS1005: ';' expected.\nsrc/b.ts(2,2): error TS2322: bad.\n",
            "",
        );
        let stack = npm_stack();
        let spec = build_types(&runner, Path::new("."), &stack);
        let result = (spec.run)();
        assert_eq!(result.findings_count, Some(2));
    }

    #[test]
    fn lint_check_prefers_eslint_over_clippy_when_configured() {
        let runner = FakeRunner::new().with_output(
            "npx --no-install eslint . -f json",
            1,
            r#"[{"errorCount":1,"warningCount":2}]"#,
            "",
        );
        let stack = npm_stack();
        let spec = build_lint(&runner, Path::new("."), &stack);
        let result = (spec.run)();
        assert_eq!(result.findings_count, Some(3));
    }

    #[test]
    fn dead_code_sums_files_and_issues_via_shared_parser() {
        let runner = FakeRunner::new().with_output(
            "npx --no-install knip --reporter json",
            0,
            r#"{"files":["a.ts","b.ts"],"issues":{"a.ts":1,"b.ts":1,"c.ts":1}}"#,
            "",
        );
        let stack = npm_stack();
        let spec = build_dead_code(&runner, Path::new("."), &stack);
        let result = (spec.run)();
        assert_eq!(result.findings_count, Some(5));
    }

    #[test]
    fn duplication_reads_jscpd_report_from_disk_not_stdout() {
        let runner = FakeRunner::new();
        let report = FakeJscpdReport {
            content: Some(r#"{"statistics":{"total":{"clones":3}}}"#.to_string()),
        };
        let out_dir = Path::new("OUT");
        let spec = build_duplication(&runner, &report, Path::new("."), out_dir);
        let result = (spec.run)();
        assert_eq!(result.status, "ran");
        assert_eq!(result.findings_count, Some(3));
    }

    #[test]
    fn duplication_missing_report_is_error_scan_not_proven() {
        let runner = FakeRunner::new();
        let report = FakeJscpdReport { content: None };
        let spec = build_duplication(&runner, &report, Path::new("."), Path::new("OUT"));
        let result = (spec.run)();
        assert_eq!(result.status, "error");
        assert_eq!(
            result.skip_reason.as_deref(),
            Some("jscpd report unreadable — scan not proven")
        );
    }

    #[test]
    fn ci_lint_unproven_without_workflows_dir() {
        let runner = FakeRunner::new();
        let stack = npm_stack();
        let spec = build_ci_lint(&runner, Path::new("."), &stack);
        let result = (spec.run)();
        assert_eq!(result.status, "unproven");
    }

    #[test]
    fn ci_lint_counts_actionlint_array() {
        let runner = FakeRunner::new()
            .with_which("actionlint", true)
            .with_output(
                "actionlint -format {{json .}}",
                1,
                r#"[{"message":"unpinned action"}]"#,
                "",
            );
        let mut stack = npm_stack();
        stack.workflows = true;
        let spec = build_ci_lint(&runner, Path::new("."), &stack);
        let result = (spec.run)();
        assert_eq!(result.findings_count, Some(1));
    }

    #[test]
    fn docker_unproven_without_dockerfile() {
        let runner = FakeRunner::new();
        let stack = npm_stack();
        let spec = build_docker(&runner, Path::new("."), &stack);
        let result = (spec.run)();
        assert_eq!(result.status, "unproven");
    }

    #[test]
    fn docker_counts_hadolint_array() {
        let runner = FakeRunner::new()
            .with_which("hadolint", true)
            .with_output("hadolint --format json Dockerfile", 1, r#"[{"code":"DL3008"}]"#, "");
        let mut stack = npm_stack();
        stack.dockerfile = true;
        let spec = build_docker(&runner, Path::new("."), &stack);
        let result = (spec.run)();
        assert_eq!(result.findings_count, Some(1));
    }

    #[test]
    fn sast_unproven_when_semgrep_absent() {
        let runner = FakeRunner::new();
        let spec = build_sast(&runner, Path::new("."));
        let result = (spec.run)();
        assert_eq!(result.status, "unproven");
        assert!(result.tool_absent);
    }

    #[test]
    fn sast_counts_results_array() {
        let runner = FakeRunner::new()
            .with_which("semgrep", true)
            .with_output(
                "semgrep --config auto --json --quiet --exclude vendor --exclude qwik --exclude .audit --exclude .agent --exclude dist",
                1,
                r#"{"results":[{"check_id":"x"}]}"#,
                "",
            );
        let spec = build_sast(&runner, Path::new("."));
        let result = (spec.run)();
        assert_eq!(result.findings_count, Some(1));
    }

    #[test]
    fn swift_lint_unproven_without_swift_sources() {
        let runner = FakeRunner::new().with_output("git ls-files", 0, "a.rs\n", "");
        let stack = npm_stack();
        let spec = build_swift_lint(&runner, Path::new("."), &stack);
        let result = (spec.run)();
        assert_eq!(result.status, "unproven");
        assert_eq!(result.skip_reason.as_deref(), Some("no .swift sources"));
    }

    #[test]
    fn swift_lint_counts_findings_when_swift_sources_present() {
        let runner = FakeRunner::new()
            .with_output("git ls-files", 0, "App/Main.swift\n", "")
            .with_which("swiftlint", true)
            .with_output(
                "swiftlint lint --quiet --reporter json",
                1,
                r#"[{"rule_id":"line_length"}]"#,
                "",
            );
        let stack = npm_stack();
        let spec = build_swift_lint(&runner, Path::new("."), &stack);
        let result = (spec.run)();
        assert_eq!(result.findings_count, Some(1));
    }

    #[test]
    fn js_licenses_flags_only_copyleft_and_reports_totals() {
        let runner = FakeRunner::new().with_output(
            "npx --no-install license-checker --json --production",
            0,
            r#"{"left-pad@1.3.0":{"licenses":"MIT"},"gpl-thing@2.0.0":{"licenses":"GPL-3.0"}}"#,
            "",
        );
        let stack = npm_stack();
        let spec = build_js_licenses(&runner, Path::new("."), &stack);
        let result = (spec.run)();
        assert_eq!(result.findings_count, Some(1));
        assert_eq!(result.meta.unwrap()["copyleft"], json!(1));
    }

    fn tempdir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "wf065-checks-a-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            n
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
