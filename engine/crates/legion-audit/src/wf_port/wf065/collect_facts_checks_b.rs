//! Port of the SECOND HALF of `tools/audit/collect-facts.mjs`'s
//! `buildChecks(d)` — in JS source order, the checks named `cargo_audit`,
//! `cargo_deny`, `cargo_unused_deps`, `cargo_unsafe`, `vendored_deps`,
//! `dep_pinning`, `tool_coverage`, `contract_mirror`, `tauri_capabilities`,
//! `apple_platform`, `react_hooks`, `negative_space`, `outdated`,
//! `cargo_outdated`, `binary_pins`, `debt_markers`, `build` (the SEQUENTIAL
//! one). The first half (`repo` .. `js_licenses`) is
//! `collect_facts_checks_a.rs`'s job.
//!
//! Same shape as that sibling module: each `build_*` function returns a
//! [`CheckSpec`] (from [`collect_facts_exec`]) whose `run` closure
//! reproduces one JS `add({...})` call — same applicability gate, same
//! command line, same status/skip_reason rules, same `findings_count`/
//! `meta` shape. `checks_b()` assembles the full list, mirroring this
//! half's `add()` call sequence.
//!
//! `cargo_audit`/`cargo_deny`/`cargo_unused_deps`/`cargo_unsafe`/
//! `cargo_outdated` output parsing has counterparts in
//! `native_providers::legacy_checks::parsers` (same tools, same JSON/JSONL/
//! text shapes) — this module's parsing is written directly against each
//! tool's documented output rather than importing that `pub(super)`-scoped
//! module, but follows the identical parity rules that module's doc
//! comment states (e.g. `cargo_deny`/`cargo_unused_deps`'s `count || null`
//! turning a real zero into a null finding count is preserved, not
//! "fixed").
//!
//! Known gaps (named, not silently dropped):
//! - `apple_platform`: the XcodeGen `project.yml` keyboard-target
//!   `sources:` indentation scan (`kbSourceDirs`/`kbFiles`/`kbNetwork` —
//!   pure *inventory*, not a finding) is not ported; `keyboard_files`
//!   reports 0 and `keyboard_files_with_network_symbols` is always empty.
//!   The finding-producing logic (missing usage descriptions, ATS
//!   weakening, debug entitlement) is ported in full.
//! - `binary_pins`: the GitHub-releases/npm-registry "resolve upstream
//!   latest" network lookup is not ported. Every pin is still found and
//!   classified (`sha256_pinned`/`rolling`), with `latest: null` and
//!   `stale: null` — the JS's own "unresolved => MANUAL-CHECK, never
//!   silently clean" rule, so no finding is fabricated as fixed.

use std::path::Path;

use regex::Regex;
use serde_json::{json, Value};

use crate::wf_port::wf065::collect_facts::{classify_file, has_dep, is_generated_or_vendored_path, looks_missing, redact, DetectedStack};
use crate::wf_port::wf065::collect_facts_exec::{CheckSpec, CommandRunner, RunResult};

fn argv(command: &str) -> Vec<String> {
    command.split_whitespace().map(str::to_string).collect()
}

fn unproven(reason: &str) -> RunResult {
    RunResult {
        status: "unproven",
        skip_reason: Some(reason.to_string()),
        ..Default::default()
    }
}

fn unproven_absent(reason: &str) -> RunResult {
    RunResult {
        status: "unproven",
        skip_reason: Some(reason.to_string()),
        tool_absent: true,
        ..Default::default()
    }
}

fn read_to_string(root: &Path, rel: &str) -> String {
    std::fs::read_to_string(root.join(rel)).unwrap_or_default()
}

fn joined_stdout_stderr(stdout: &str, stderr: &str) -> String {
    format!("{stdout}{stderr}")
}

// ---------------------------------------------------------------------
// cargo_audit
// ---------------------------------------------------------------------

pub fn build_cargo_audit<'a>(runner: &'a dyn CommandRunner, root: &'a Path, stack: &'a DetectedStack) -> CheckSpec<'a> {
    CheckSpec {
        check: "cargo_audit",
        tool: Some("cargo-audit".to_string()),
        required: false,
        tier: "supplemental",
        flag_if_absent: true,
        parallel: true,
        force_skip: false,
        run: Box::new(move || {
            if !stack.rust {
                return unproven("no Cargo.toml");
            }
            let Some(rust_dir) = &stack.rust_dir else {
                return unproven("no Cargo.toml");
            };
            if !root.join(rust_dir).join("Cargo.lock").exists() {
                return unproven("no Cargo.lock");
            }
            if !runner.which("cargo-audit") {
                return unproven_absent("cargo-audit not installed (`cargo install cargo-audit`)");
            }
            let cwd = root.join(rust_dir);
            let r = runner.run(&argv("cargo audit --json"), &cwd, 300_000);
            let count = serde_json::from_str::<Value>(&r.stdout)
                .ok()
                .and_then(|j| j.get("vulnerabilities")?.get("count")?.as_u64());
            RunResult {
                status: "ran",
                command: Some(format!("cargo audit --json  (cwd: {rust_dir})")),
                exit_code: Some(r.code),
                findings_count: count,
                raw_log: redact(Some(if !r.stdout.is_empty() { &r.stdout } else { &r.stderr })),
                duration_ms: Some(r.duration_ms),
                ..Default::default()
            }
        }),
    }
}

// ---------------------------------------------------------------------
// cargo_deny
// ---------------------------------------------------------------------

pub fn build_cargo_deny<'a>(runner: &'a dyn CommandRunner, root: &'a Path, stack: &'a DetectedStack) -> CheckSpec<'a> {
    CheckSpec {
        check: "cargo_deny",
        tool: Some("cargo-deny".to_string()),
        required: false,
        tier: "supplemental",
        flag_if_absent: false,
        parallel: true,
        force_skip: false,
        run: Box::new(move || {
            if !stack.rust {
                return unproven("no Cargo.toml");
            }
            if !runner.which("cargo-deny") {
                return unproven_absent("cargo-deny not installed (`cargo install cargo-deny`)");
            }
            let rust_dir = stack.rust_dir.clone().unwrap_or_default();
            let cwd = root.join(&rust_dir);
            let r = runner.run(&argv("cargo deny --format json check"), &cwd, 300_000);
            let severity_re = Regex::new(r"(?i)error|warning").unwrap();
            let mut count = 0u64;
            for line in format!("{}\n{}", r.stderr, r.stdout).split('\n') {
                if line.trim().is_empty() {
                    continue;
                }
                let Ok(j) = serde_json::from_str::<Value>(line) else { continue };
                if j.get("type").and_then(Value::as_str) != Some("diagnostic") {
                    continue;
                }
                let sev = j
                    .get("fields")
                    .and_then(|f| f.get("severity").or_else(|| f.get("level")))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if severity_re.is_match(sev) {
                    count += 1;
                }
            }
            RunResult {
                status: "ran",
                command: Some(format!("cargo deny --format json check  (cwd: {rust_dir})")),
                exit_code: Some(r.code),
                findings_count: if count > 0 { Some(count) } else { None }, // JS `count || null`
                raw_log: redact(Some(&joined_stdout_stderr(&r.stdout, &r.stderr))),
                duration_ms: Some(r.duration_ms),
                ..Default::default()
            }
        }),
    }
}

// ---------------------------------------------------------------------
// cargo_unused_deps
// ---------------------------------------------------------------------

pub fn build_cargo_unused_deps<'a>(runner: &'a dyn CommandRunner, root: &'a Path, stack: &'a DetectedStack) -> CheckSpec<'a> {
    CheckSpec {
        check: "cargo_unused_deps",
        tool: Some("cargo-machete".to_string()),
        required: false,
        tier: "core",
        flag_if_absent: false,
        parallel: true,
        force_skip: false,
        run: Box::new(move || {
            if !stack.rust {
                return unproven("no Cargo.toml");
            }
            if !runner.which("cargo-machete") {
                return unproven_absent("cargo-machete not installed (`cargo install cargo-machete`)");
            }
            let rust_dir = stack.rust_dir.clone().unwrap_or_default();
            let cwd = root.join(&rust_dir);
            let r = runner.run(&argv("cargo machete --with-metadata"), &cwd, 180_000);
            let noise = Regex::new(r"(?i)Analyzing|If you|cargo-machete|found the following").unwrap();
            let indented = Regex::new(r"^\s+\S").unwrap();
            let count = r
                .stdout
                .split('\n')
                .filter(|l| indented.is_match(l) && !noise.is_match(l))
                .count() as u64;
            RunResult {
                status: "ran",
                command: Some(format!("cargo machete --with-metadata  (cwd: {rust_dir})")),
                exit_code: Some(r.code),
                findings_count: if count > 0 { Some(count) } else { None }, // JS `... || null`
                raw_log: redact(Some(&joined_stdout_stderr(&r.stdout, &r.stderr))),
                duration_ms: Some(r.duration_ms),
                ..Default::default()
            }
        }),
    }
}

// ---------------------------------------------------------------------
// cargo_unsafe
// ---------------------------------------------------------------------

pub fn build_cargo_unsafe<'a>(runner: &'a dyn CommandRunner, root: &'a Path, stack: &'a DetectedStack) -> CheckSpec<'a> {
    CheckSpec {
        check: "cargo_unsafe",
        tool: Some("cargo-geiger".to_string()),
        required: false,
        tier: "core",
        flag_if_absent: false,
        parallel: true,
        force_skip: false,
        run: Box::new(move || {
            if !stack.rust {
                return unproven("no Cargo.toml");
            }
            if !runner.which("cargo-geiger") {
                return unproven_absent("cargo-geiger not installed (`cargo install cargo-geiger`)");
            }
            let rust_dir = stack.rust_dir.clone().unwrap_or_default();
            let cwd = root.join(&rust_dir);
            let r = runner.run(&argv("cargo geiger --output-format Json --quiet"), &cwd, 600_000);
            let count = serde_json::from_str::<Value>(&r.stdout).ok().map(|j| {
                j.get("packages")
                    .and_then(Value::as_array)
                    .map(|pkgs| {
                        pkgs.iter()
                            .filter_map(|p| p.get("unsafety")?.get("used")?.as_object())
                            .flat_map(|used| used.values())
                            .filter_map(|cat| cat.get("unsafe_").and_then(Value::as_u64))
                            .sum::<u64>()
                    })
                    .unwrap_or(0)
            });
            RunResult {
                status: "ran",
                command: Some(format!("cargo geiger --output-format Json --quiet  (cwd: {rust_dir})")),
                exit_code: Some(r.code),
                findings_count: count,
                raw_log: redact(Some(&joined_stdout_stderr(&r.stdout, &r.stderr))),
                duration_ms: Some(r.duration_ms),
                ..Default::default()
            }
        }),
    }
}

// ---------------------------------------------------------------------
// vendored_deps
// ---------------------------------------------------------------------

pub fn build_vendored_deps<'a>(stack: &'a DetectedStack, tracked: &'a [String]) -> CheckSpec<'a> {
    CheckSpec {
        check: "vendored_deps",
        tool: Some("fs".to_string()),
        required: false,
        tier: "core",
        flag_if_absent: false,
        parallel: true,
        force_skip: false,
        run: Box::new(move || {
            if !stack.git {
                return unproven("needs git ls-files");
            }
            let manifest_re = Regex::new(r"(^|/)vendor/.*/(package\.json|Cargo\.toml)$").unwrap();
            let lockfile_re = Regex::new(r"(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|Cargo\.lock)$").unwrap();
            let strip_manifest_re = Regex::new(r"/(package\.json|Cargo\.toml)$").unwrap();
            let mut trees: Vec<Value> = Vec::new();
            let mut seen_dirs = std::collections::BTreeSet::new();
            for m in tracked.iter().filter(|f| manifest_re.is_match(f) && !f.contains("node_modules/")) {
                let dir = strip_manifest_re.replace(m, "").to_string();
                if !seen_dirs.insert(dir.clone()) {
                    continue;
                }
                let has_lockfile = tracked.iter().any(|f| f.starts_with(&format!("{dir}/")) && lockfile_re.is_match(f));
                trees.push(json!({"dir": dir, "manifest": m, "has_lockfile": has_lockfile}));
            }
            let raw_log = trees
                .iter()
                .map(|t| format!("{}  lockfile={}", t["dir"].as_str().unwrap_or(""), t["has_lockfile"]))
                .collect::<Vec<_>>()
                .join("\n");
            RunResult {
                status: "ran",
                command: Some(
                    "git ls-files → vendor/**/{package.json,Cargo.toml} (each tree is OUTSIDE root deps_cve/cargo_audit coverage)"
                        .to_string(),
                ),
                exit_code: Some(0),
                findings_count: Some(trees.len() as u64),
                meta: Some(json!({"trees": trees})),
                raw_log: Some(raw_log),
                duration_ms: Some(0),
                ..Default::default()
            }
        }),
    }
}

// ---------------------------------------------------------------------
// dep_pinning
// ---------------------------------------------------------------------

pub fn build_dep_pinning<'a>(stack: &'a DetectedStack, root: &'a Path, tracked: &'a [String]) -> CheckSpec<'a> {
    CheckSpec {
        check: "dep_pinning",
        tool: Some("grep".to_string()),
        required: false,
        tier: "core",
        flag_if_absent: false,
        parallel: true,
        force_skip: false,
        run: Box::new(move || {
            if !stack.git {
                return unproven("needs git ls-files");
            }
            let pkg_json_re = Regex::new(r"(^|/)package\.json$").unwrap();
            let cargo_toml_re = Regex::new(r"(^|/)Cargo\.toml$").unwrap();
            let git_spec_re = Regex::new(r"^(git\+|github:|git://|https?://.*\.git)").unwrap();
            let pinned_sha_re = Regex::new(r"(?i)#[0-9a-f]{7,40}$").unwrap();
            let pinned_ver_re = Regex::new(r"#(semver:)?v?\d").unwrap();
            let mut offenders: Vec<Value> = Vec::new();
            for f in tracked
                .iter()
                .filter(|f| pkg_json_re.is_match(f) && !f.contains("node_modules/") && !is_generated_or_vendored_path(f))
            {
                let Ok(p) = serde_json::from_str::<Value>(&read_to_string(root, f)) else { continue };
                for sect in ["dependencies", "devDependencies", "optionalDependencies"] {
                    let Some(obj) = p.get(sect).and_then(Value::as_object) else { continue };
                    for (name, spec) in obj {
                        let Some(spec) = spec.as_str() else { continue };
                        if git_spec_re.is_match(spec) && !pinned_sha_re.is_match(spec) && !pinned_ver_re.is_match(spec) {
                            offenders.push(json!({"file": f, "dep": name, "spec": spec, "kind": "npm-git-unpinned"}));
                        }
                    }
                }
            }
            let cargo_git_re = Regex::new(r#"(?m)^\s*([\w-]+)\s*=\s*\{[^}]*\bgit\s*=\s*"[^"]+"[^}]*\}"#).unwrap();
            let rev_tag_re = Regex::new(r"\b(rev|tag)\s*=").unwrap();
            for f in tracked.iter().filter(|f| cargo_toml_re.is_match(f) && !is_generated_or_vendored_path(f)) {
                let txt = read_to_string(root, f);
                for caps in cargo_git_re.captures_iter(&txt) {
                    let whole = &caps[0];
                    if !rev_tag_re.is_match(whole) {
                        offenders.push(json!({"file": f, "dep": &caps[1], "kind": "cargo-git-unpinned"}));
                    }
                }
            }
            let raw_log = offenders
                .iter()
                .map(|o| format!("{}: {} ({})", o["file"], o["dep"], o["kind"]))
                .collect::<Vec<_>>()
                .join("\n");
            RunResult {
                status: "ran",
                command: Some("scan tracked package.json/Cargo.toml for git deps without a commit/tag pin".to_string()),
                exit_code: Some(0),
                findings_count: Some(offenders.len() as u64),
                meta: Some(json!({"offenders": offenders})),
                raw_log: Some(raw_log),
                duration_ms: Some(0),
                ..Default::default()
            }
        }),
    }
}

// ---------------------------------------------------------------------
// tool_coverage
// ---------------------------------------------------------------------

pub fn build_tool_coverage<'a>(stack: &'a DetectedStack, root: &'a Path, tracked: &'a [String]) -> CheckSpec<'a> {
    CheckSpec {
        check: "tool_coverage",
        tool: Some("fs".to_string()),
        required: false,
        tier: "core",
        flag_if_absent: false,
        parallel: true,
        force_skip: false,
        run: Box::new(move || {
            let mut cov = serde_json::Map::new();
            cov.insert("heuristic".into(), json!(true));
            if root.join(".eslintignore").exists() {
                let lines: Vec<String> = read_to_string(root, ".eslintignore")
                    .split('\n')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty() && !s.starts_with('#'))
                    .collect();
                cov.insert("eslintignore".into(), json!(lines));
            }
            let ignores_re = Regex::new(r"ignores\s*:\s*\[([^\]]*)\]").unwrap();
            for f in ["eslint.config.js", "eslint.config.mjs", "eslint.config.cjs", "eslint.config.ts"] {
                if !root.join(f).exists() {
                    continue;
                }
                let txt = read_to_string(root, f);
                let items: Vec<String> = ignores_re
                    .captures_iter(&txt)
                    .flat_map(|c| c[1].split(',').map(|s| s.trim_matches(|ch| "'\"` ".contains(ch)).to_string()).collect::<Vec<_>>())
                    .filter(|s| !s.is_empty())
                    .collect();
                if !items.is_empty() {
                    cov.insert("eslint_flat_ignores".into(), json!(items));
                }
                break;
            }
            if stack.ts {
                let line_comment = Regex::new(r"//[^\n]*").unwrap();
                let block_comment = Regex::new(r"(?s)/\*.*?\*/").unwrap();
                let trailing_comma = Regex::new(r",\s*([}\]])").unwrap();
                let raw = read_to_string(root, "tsconfig.json");
                let no_line = line_comment.replace_all(&raw, "");
                let no_block = block_comment.replace_all(&no_line, "");
                let clean = trailing_comma.replace_all(&no_block, "$1");
                if let Ok(t) = serde_json::from_str::<Value>(&clean) {
                    cov.insert(
                        "tsconfig".into(),
                        json!({"include": t.get("include").cloned().unwrap_or(Value::Null),
                               "exclude": t.get("exclude").cloned().unwrap_or(Value::Null)}),
                    );
                }
            }
            let mut code_dirs = std::collections::BTreeSet::new();
            if stack.git {
                let code_re = Regex::new(r"\.(ts|tsx|js|jsx|mjs|cjs|py|rs)$").unwrap();
                for f in tracked.iter().filter(|f| code_re.is_match(f) && !is_generated_or_vendored_path(f)) {
                    let top = f.split('/').next().filter(|_| f.contains('/')).unwrap_or(".");
                    code_dirs.insert(top.to_string());
                }
            }
            cov.insert("top_level_code_dirs".into(), json!(code_dirs.into_iter().collect::<Vec<_>>()));
            let meta = Value::Object(cov);
            RunResult {
                status: "ran",
                command: Some(
                    "read .eslintignore / eslint flat-config ignores / tsconfig include+exclude; list top-level code dirs"
                        .to_string(),
                ),
                exit_code: Some(0),
                raw_log: serde_json::to_string_pretty(&meta).ok(),
                meta: Some(meta),
                duration_ms: Some(0),
                ..Default::default()
            }
        }),
    }
}

// ---------------------------------------------------------------------
// contract_mirror
// ---------------------------------------------------------------------

pub fn build_contract_mirror<'a>(stack: &'a DetectedStack, root: &'a Path, tracked: &'a [String]) -> CheckSpec<'a> {
    CheckSpec {
        check: "contract_mirror",
        tool: Some("grep".to_string()),
        required: false,
        tier: "core",
        flag_if_absent: false,
        parallel: true,
        force_skip: false,
        run: Box::new(move || {
            if !stack.tauri || !stack.git {
                return unproven(if stack.tauri { "needs git ls-files" } else { "no src-tauri/tauri.conf.json" });
            }
            let handler_block_re = Regex::new(r"(?s)generate_handler!\s*\[(.*?)\]").unwrap();
            let ident_re = Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_]*$").unwrap();
            let mut handlers = std::collections::BTreeSet::new();
            for f in tracked
                .iter()
                .filter(|f| f.starts_with("src-tauri/") && f.ends_with(".rs") && !is_generated_or_vendored_path(f))
            {
                let txt = read_to_string(root, f);
                for caps in handler_block_re.captures_iter(&txt) {
                    for raw in caps[1].split(',') {
                        let name = raw.trim().rsplit("::").next().unwrap_or("").trim();
                        if !name.is_empty() && ident_re.is_match(name) {
                            handlers.insert(name.to_string());
                        }
                    }
                }
            }
            let invoke_re = Regex::new(r#"\binvoke(?:<[^>]*>)?\s*\(\s*['"`]([\w-]+)['"`]"#).unwrap();
            let frontend_re = Regex::new(r"\.(ts|tsx|js|jsx|mjs|svelte|vue)$").unwrap();
            let mut invokes = std::collections::BTreeSet::new();
            for f in tracked.iter().filter(|f| {
                !f.starts_with("src-tauri/") && frontend_re.is_match(f) && !is_generated_or_vendored_path(f) && classify_file(f).as_str() != "test"
            }) {
                let txt = read_to_string(root, f);
                for caps in invoke_re.captures_iter(&txt) {
                    invokes.insert(caps[1].to_string());
                }
            }
            let uncalled: Vec<&String> = handlers.iter().filter(|h| !invokes.contains(*h)).collect();
            let unregistered: Vec<&String> = invokes.iter().filter(|i| !handlers.contains(*i)).collect();
            let raw_log = format!(
                "uncalled handlers ({}): {}\nunregistered invokes ({}): {}",
                uncalled.len(),
                uncalled.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "),
                unregistered.len(),
                unregistered.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "),
            );
            RunResult {
                status: "ran",
                command: Some(
                    "diff generate_handler![] names vs frontend invoke(\"...\") literals (wrapper-indirected calls need lens verification)"
                        .to_string(),
                ),
                exit_code: Some(0),
                findings_count: Some((uncalled.len() + unregistered.len()) as u64),
                meta: Some(json!({
                    "handlers": handlers.len(), "invokes": invokes.len(),
                    "uncalled_handlers": uncalled, "unregistered_invokes": unregistered,
                })),
                raw_log: Some(raw_log),
                duration_ms: Some(0),
                ..Default::default()
            }
        }),
    }
}

// ---------------------------------------------------------------------
// tauri_capabilities
// ---------------------------------------------------------------------

fn flag_of(id: &str, value: &Value) -> Option<String> {
    let allow_all_re = Regex::new(r"^(fs|shell|http|process|core|os):.*:(allow-all|default)$").unwrap();
    let shell_exec_re = Regex::new(r"^shell:allow-(execute|spawn|stdin-write)").unwrap();
    if allow_all_re.is_match(id) {
        return Some(format!("broad grant: {id}"));
    }
    if shell_exec_re.is_match(id) {
        return Some(format!("shell execution: {id}"));
    }
    if (id.starts_with("fs:") || id.starts_with("http:")) && value.is_object() {
        let scope = value.get("allow").cloned().unwrap_or_else(|| value.clone());
        if scope.to_string().contains("**") {
            return Some(format!("wide scope: {id}"));
        }
    }
    None
}

pub fn build_tauri_capabilities<'a>(stack: &'a DetectedStack, root: &'a Path, tracked: &'a [String]) -> CheckSpec<'a> {
    CheckSpec {
        check: "tauri_capabilities",
        tool: Some("fs".to_string()),
        required: false,
        tier: "core",
        flag_if_absent: false,
        parallel: true,
        force_skip: false,
        run: Box::new(move || {
            if !stack.tauri {
                return unproven("no src-tauri/tauri.conf.json");
            }
            let cap_dir = root.join("src-tauri").join("capabilities");
            let Ok(entries) = std::fs::read_dir(&cap_dir) else {
                return unproven("no src-tauri/capabilities/ directory");
            };
            let mut perms: Vec<Value> = Vec::new();
            let mut broad: Vec<Value> = Vec::new();
            let mut cap_files = 0u64;
            let mut unparseable = 0u64;
            let ext_re = Regex::new(r"\.(json|toml)$").unwrap();
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !ext_re.is_match(&name) {
                    continue;
                }
                cap_files += 1;
                if !name.ends_with(".json") {
                    continue;
                }
                let Ok(txt) = std::fs::read_to_string(entry.path()) else {
                    unparseable += 1;
                    continue;
                };
                let Ok(j) = serde_json::from_str::<Value>(&txt) else {
                    unparseable += 1;
                    continue;
                };
                for p in j.get("permissions").and_then(Value::as_array).into_iter().flatten() {
                    let id = match p {
                        Value::String(s) => s.clone(),
                        Value::Object(m) => m
                            .get("identifier")
                            .or_else(|| m.get("permission"))
                            .and_then(Value::as_str)
                            .map(str::to_string)
                            .unwrap_or_else(|| p.to_string()),
                        _ => p.to_string(),
                    };
                    perms.push(json!({"file": name, "permission": id}));
                    if let Some(flag) = flag_of(&id, p) {
                        broad.push(json!({"file": name, "flag": flag}));
                    }
                }
            }
            let mut exposed = 0u64;
            if stack.git {
                let cmd_re = Regex::new(r"#\[tauri::command\]").unwrap();
                for f in tracked
                    .iter()
                    .filter(|f| f.starts_with("src-tauri/") && f.ends_with(".rs") && !is_generated_or_vendored_path(f))
                {
                    exposed += cmd_re.find_iter(&read_to_string(root, f)).count() as u64;
                }
            }
            let meta = json!({
                "capability_files": cap_files, "unparseable_capability_files": unparseable,
                "total_permissions": perms.len(), "exposed_commands": exposed, "broad_grants": broad,
            });
            RunResult {
                status: "ran",
                command: Some("parse src-tauri/capabilities/*.json permissions + count #[tauri::command] handlers".to_string()),
                exit_code: Some(0),
                findings_count: Some(broad.len() as u64),
                raw_log: serde_json::to_string_pretty(&json!({"broad_grants": broad, "permissions": perms})).ok(),
                meta: Some(meta),
                duration_ms: Some(0),
                ..Default::default()
            }
        }),
    }
}

// ---------------------------------------------------------------------
// apple_platform (findings-producing logic only — see module doc-comment)
// ---------------------------------------------------------------------

struct UsageNeed {
    keys: &'static [&'static str],
    api: &'static str,
}

const NEEDS: &[UsageNeed] = &[
    UsageNeed { keys: &["NSMicrophoneUsageDescription"], api: r"AVAudioRecorder|AVAudioEngine|installTap|requestRecordPermission|AVAudioSession.*record|AVCaptureDevice\.(?:default|requestAccess)\(\s*for:\s*\.audio" },
    UsageNeed { keys: &["NSSpeechRecognitionUsageDescription"], api: r"SFSpeechRecognizer|SFSpeechAudioBuffer" },
    UsageNeed { keys: &["NSCameraUsageDescription"], api: r"UIImagePickerController|AVCaptureDevice\.(?:default|requestAccess)\(\s*for:\s*\.video|AVCaptureDevice\.default\(\s*\.builtIn" },
    UsageNeed { keys: &["NSPhotoLibraryUsageDescription"], api: r"PHPhotoLibrary|PHAsset\b" },
    UsageNeed { keys: &["NSPhotoLibraryAddUsageDescription", "NSPhotoLibraryUsageDescription"], api: r"UIImageWriteToSavedPhotosAlbum|creationRequestForAsset" },
    UsageNeed { keys: &["NSLocationWhenInUseUsageDescription"], api: r"CLLocationManager" },
    UsageNeed { keys: &["NSContactsUsageDescription"], api: r"CNContactStore" },
    UsageNeed { keys: &["NSCalendarsFullAccessUsageDescription", "NSCalendarsWriteOnlyAccessUsageDescription", "NSRemindersFullAccessUsageDescription", "NSCalendarsUsageDescription", "NSRemindersUsageDescription"], api: r"EKEventStore" },
    UsageNeed { keys: &["NSBluetoothAlwaysUsageDescription"], api: r"CBCentralManager|CBPeripheralManager" },
    UsageNeed { keys: &["NSLocalNetworkUsageDescription"], api: r"NWBrowser|NWListener|NetServiceBrowser|MCNearbyService" },
];

pub fn build_apple_platform<'a>(root: &'a Path, tracked: &'a [String]) -> CheckSpec<'a> {
    CheckSpec {
        check: "apple_platform",
        tool: Some("fs".to_string()),
        required: false,
        tier: "core",
        flag_if_absent: false,
        parallel: true,
        force_skip: false,
        run: Box::new(move || {
            let swift_files: Vec<&String> = tracked.iter().filter(|f| f.ends_with(".swift") && !is_generated_or_vendored_path(f)).collect();
            let plist_re = Regex::new(r"(^|/)Info\.plist$").unwrap();
            let plists: Vec<&String> = tracked.iter().filter(|f| plist_re.is_match(f) && !is_generated_or_vendored_path(f)).collect();
            let ents: Vec<&String> = tracked.iter().filter(|f| f.ends_with(".entitlements") && !is_generated_or_vendored_path(f)).collect();
            let proj_yml_re = Regex::new(r"(^|/)project\.yml$").unwrap();
            let proj_yml: Vec<&String> = tracked.iter().filter(|f| proj_yml_re.is_match(f)).collect();

            if swift_files.is_empty() || (plists.is_empty() && proj_yml.is_empty()) {
                return unproven("no Apple-platform target (needs .swift + Info.plist/project.yml)");
            }

            let declared_blob = plists.iter().chain(proj_yml.iter()).map(|f| read_to_string(root, f)).collect::<Vec<_>>().join("\n");
            let ent_blob = ents.iter().map(|f| read_to_string(root, f)).collect::<Vec<_>>().join("\n");
            let code_blob = swift_files.iter().map(|f| read_to_string(root, f)).collect::<Vec<_>>().join("\n");

            let mut missing_usage: Vec<Value> = Vec::new();
            for need in NEEDS {
                let api_re = Regex::new(need.api).unwrap();
                if api_re.is_match(&code_blob) && !need.keys.iter().any(|k| declared_blob.contains(k)) {
                    missing_usage.push(json!({
                        "missing_key": need.keys[0], "accepted_keys": need.keys,
                        "reason": "API is called but no usage description declared — crashes on first access",
                    }));
                }
            }
            if Regex::new("EKEventStore").unwrap().is_match(&code_blob)
                && declared_blob.contains("NSCalendarsUsageDescription")
                && !Regex::new("NSCalendarsFullAccessUsageDescription|NSCalendarsWriteOnlyAccessUsageDescription|NSRemindersFullAccessUsageDescription")
                    .unwrap()
                    .is_match(&declared_blob)
            {
                missing_usage.push(json!({
                    "missing_key": "NSCalendarsFullAccessUsageDescription",
                    "accepted_keys": ["NSCalendarsFullAccessUsageDescription", "NSCalendarsWriteOnlyAccessUsageDescription"],
                    "reason": "legacy NSCalendarsUsageDescription alone is denied on iOS 17+ — EventKit requires the full-access or write-only key",
                }));
            }

            let ats_arbitrary = Regex::new(r"(?s)<key>NSAllowsArbitraryLoads</key>\s*<true\s*/>").unwrap().is_match(&declared_blob)
                || Regex::new(r"(?i)NSAllowsArbitraryLoads\s*:\s*(true|YES)").unwrap().is_match(&declared_blob);
            let ats_insecure_http = Regex::new(r"(?s)<key>NSExceptionAllowsInsecureHTTPLoads</key>\s*<true\s*/>").unwrap().is_match(&declared_blob)
                || Regex::new(r"(?i)NSExceptionAllowsInsecureHTTPLoads\s*:\s*(true|YES)").unwrap().is_match(&declared_blob);
            let debug_ent = Regex::new(r"(?s)<key>get-task-allow</key>\s*<true\s*/>").unwrap().is_match(&ent_blob);

            let mut ats_findings: Vec<Value> = Vec::new();
            if ats_arbitrary {
                ats_findings.push(json!({"issue": "NSAllowsArbitraryLoads is true — ATS disabled app-wide"}));
            }
            if ats_insecure_http {
                ats_findings.push(json!({"issue": "NSExceptionAllowsInsecureHTTPLoads is true — cleartext HTTP permitted for an exception domain"}));
            }
            if debug_ent {
                ats_findings.push(json!({"issue": "get-task-allow entitlement is committed — debug entitlement in a tracked entitlements file"}));
            }

            let usage_key_re = Regex::new(r"NS[A-Za-z]+UsageDescription").unwrap();
            let mut declared_usage: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
            for m in usage_key_re.find_iter(&declared_blob) {
                declared_usage.insert(m.as_str().to_string());
            }
            let mut declared_usage_by_file = serde_json::Map::new();
            for f in plists.iter().chain(proj_yml.iter()) {
                let txt = read_to_string(root, f);
                let mut ks: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
                for m in usage_key_re.find_iter(&txt) {
                    ks.insert(m.as_str().to_string());
                }
                if !ks.is_empty() {
                    declared_usage_by_file.insert((*f).clone(), json!(ks.into_iter().collect::<Vec<_>>()));
                }
            }
            let ent_id_re = Regex::new(r"(?i)com\.apple\.[a-z0-9.\-]+").unwrap();
            let mut entitlements: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
            for m in ent_id_re.find_iter(&ent_blob) {
                entitlements.insert(m.as_str().to_string());
            }
            let open_access = Regex::new(r"(?i)RequestsOpenAccess\s*:\s*(true|YES)").unwrap().is_match(&declared_blob)
                || Regex::new(r"(?s)<key>RequestsOpenAccess</key>\s*<true\s*/>").unwrap().is_match(&declared_blob);

            let findings_len = missing_usage.len() + ats_findings.len();
            let meta = json!({
                "swift_files": swift_files.len(), "info_plists": plists.len(), "entitlements_files": ents.len(),
                "declared_usage_descriptions": declared_usage.into_iter().collect::<Vec<_>>(),
                "declared_usage_by_file": declared_usage_by_file,
                "entitlements": entitlements.into_iter().collect::<Vec<_>>(),
                "missing_usage_descriptions": missing_usage,
                "ats_findings": ats_findings,
                "keyboard_requests_open_access": open_access,
                "keyboard_source_dirs": Vec::<String>::new(),
                "keyboard_files": 0,
                "keyboard_files_with_network_symbols": Vec::<String>::new(),
            });
            RunResult {
                status: "ran",
                command: Some("parse Info.plist/project.yml usage descriptions + *.entitlements vs called Apple APIs".to_string()),
                exit_code: Some(if findings_len > 0 { 1 } else { 0 }),
                findings_count: Some(findings_len as u64),
                raw_log: serde_json::to_string_pretty(&meta).ok(),
                meta: Some(meta),
                duration_ms: Some(0),
                ..Default::default()
            }
        }),
    }
}

// ---------------------------------------------------------------------
// react_hooks
// ---------------------------------------------------------------------

pub fn build_react_hooks<'a>(stack: &'a DetectedStack) -> CheckSpec<'a> {
    CheckSpec {
        check: "react_hooks",
        tool: Some("fs".to_string()),
        required: false,
        tier: "core",
        flag_if_absent: false,
        parallel: true,
        force_skip: false,
        run: Box::new(move || {
            let pkg = stack.pkg.as_ref().unwrap_or(&Value::Null);
            if !stack.node || !has_dep(pkg, "react") {
                return unproven("not a React project");
            }
            let present = has_dep(pkg, "eslint-plugin-react-hooks");
            let meta = json!({
                "react": true, "eslint_plugin_react_hooks": present,
                "note": if present { "react-hooks lint configured" } else { "React app has NO eslint-plugin-react-hooks — hook-rule bugs (conditional hooks, stale deps) ship unlinted" },
            });
            RunResult {
                status: "ran",
                command: Some("check package.json: react present ⇒ eslint-plugin-react-hooks configured?".to_string()),
                exit_code: Some(0),
                findings_count: Some(if present { 0 } else { 1 }),
                meta: Some(meta),
                duration_ms: Some(0),
                ..Default::default()
            }
        }),
    }
}

// ---------------------------------------------------------------------
// negative_space
// ---------------------------------------------------------------------

pub fn build_negative_space<'a>(stack: &'a DetectedStack, root: &'a Path, tracked: &'a [String]) -> CheckSpec<'a> {
    CheckSpec {
        check: "negative_space",
        tool: Some("fs".to_string()),
        required: false,
        tier: "core",
        flag_if_absent: false,
        parallel: true,
        force_skip: false,
        run: Box::new(move || {
            let mut missing: Vec<&str> = Vec::new();
            let exists_any = |names: &[&str]| names.iter().any(|n| root.join(n).exists());
            if !exists_any(&["README.md", "README", "readme.md"]) {
                missing.push("README");
            }
            if !exists_any(&["LICENSE", "LICENSE.md", "LICENSE.txt"]) {
                missing.push("LICENSE");
            }
            if !root.join(".gitignore").exists() {
                missing.push(".gitignore");
            }
            let has_ci = stack.workflows || exists_any(&[".gitlab-ci.yml", "azure-pipelines.yml", ".circleci"]);
            if !has_ci {
                missing.push("CI");
            }
            if stack.node && !exists_any(&["package-lock.json", "pnpm-lock.yaml", "yarn.lock"]) {
                missing.push("lockfile");
            }
            let has_test_script = stack.pkg.as_ref().and_then(|p| p.get("scripts")).and_then(|s| s.get("test")).is_some();
            if !exists_any(&["test", "tests", "__tests__", "spec"]) && !has_test_script {
                missing.push("tests");
            }

            let mut meta = serde_json::Map::new();
            meta.insert("missing".into(), json!(missing));
            if stack.git {
                let code_re = Regex::new(r"\.(ts|tsx|js|jsx|mjs|cjs|py|rs|go|java|rb|swift|kt)$").unwrap();
                let mut skew = serde_json::Map::new();
                for f in tracked {
                    if !code_re.is_match(f) || is_generated_or_vendored_path(f) {
                        continue;
                    }
                    let top = f.split('/').next().filter(|_| f.contains('/')).unwrap_or(".");
                    let entry = skew.entry(top.to_string()).or_insert_with(|| json!({"code": 0, "test": 0}));
                    let key = if classify_file(f).as_str() == "test" { "test" } else { "code" };
                    let cur = entry[key].as_i64().unwrap_or(0);
                    entry[key] = json!(cur + 1);
                }
                meta.insert("test_skew".into(), Value::Object(skew));

                let mut large: Vec<(String, f64)> = Vec::new();
                for f in tracked {
                    if let Ok(m) = std::fs::metadata(root.join(f)) {
                        let mb = m.len() as f64 / 1_048_576.0;
                        if m.len() > 5 * 1024 * 1024 {
                            large.push((f.clone(), (mb * 10.0).round() / 10.0));
                        }
                    }
                }
                large.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
                large.truncate(20);
                meta.insert(
                    "large_tracked_files".into(),
                    json!(large.into_iter().map(|(f, mb)| json!({"file": f, "mb": mb})).collect::<Vec<_>>()),
                );

                let advisory_re1 = Regex::new(r"continue-on-error:\s*true").unwrap();
                let advisory_re2 = Regex::new(r"\|\|\s*true\s*$").unwrap();
                let mut advisory: Vec<String> = Vec::new();
                for f in tracked.iter().filter(|f| f.starts_with(".github/workflows/")) {
                    let txt = read_to_string(root, f);
                    for (i, l) in txt.split('\n').enumerate() {
                        if advisory_re1.is_match(l) || advisory_re2.is_match(l) {
                            advisory.push(format!("{f}:{}", i + 1));
                        }
                    }
                }
                meta.insert("ci_advisory_gates".into(), json!(advisory));

                if stack.rust {
                    let unsafe_re = Regex::new(r"\bunsafe\b").unwrap();
                    let mut unsafe_sites = serde_json::Map::new();
                    for f in tracked
                        .iter()
                        .filter(|f| f.ends_with(".rs") && !is_generated_or_vendored_path(f) && classify_file(f).as_str() != "test")
                    {
                        let n = unsafe_re.find_iter(&read_to_string(root, f)).count();
                        if n > 0 {
                            unsafe_sites.insert(f.clone(), json!(n));
                        }
                    }
                    meta.insert("unsafe_sites".into(), Value::Object(unsafe_sites));
                }
            }
            let raw_log = if missing.is_empty() { "none missing".to_string() } else { format!("Missing: {}", missing.join(", ")) };
            RunResult {
                status: "ran",
                command: Some("(fs presence checks + test-skew / large-binary / CI-advisory / unsafe inventory)".to_string()),
                exit_code: Some(0),
                findings_count: Some(missing.len() as u64),
                meta: Some(Value::Object(meta)),
                raw_log: Some(raw_log),
                duration_ms: Some(0),
                ..Default::default()
            }
        }),
    }
}

// ---------------------------------------------------------------------
// outdated
// ---------------------------------------------------------------------

pub fn build_outdated<'a>(runner: &'a dyn CommandRunner, root: &'a Path, stack: &'a DetectedStack) -> CheckSpec<'a> {
    CheckSpec {
        check: "outdated",
        tool: Some(format!("{} outdated", stack.pkg_mgr)),
        required: false,
        tier: "supplemental",
        flag_if_absent: false,
        parallel: true,
        force_skip: false,
        run: Box::new(move || {
            if !stack.node {
                return unproven("no package.json");
            }
            let cmd = format!("{} outdated --json", stack.pkg_mgr);
            let r = runner.run(&argv(&cmd), root, 180_000);
            if looks_missing(&r.stdout, &r.stderr) {
                return unproven_absent(&format!("{} not available", stack.pkg_mgr));
            }
            let mut total = None;
            let mut majors = 0u64;
            if let Ok(Value::Object(entries)) = serde_json::from_str::<Value>(if r.stdout.is_empty() { "{}" } else { &r.stdout }) {
                total = Some(entries.len() as u64);
                for v in entries.values() {
                    let c: Option<i64> = v.get("current").and_then(Value::as_str).and_then(|s| s.split('.').next()).and_then(|s| s.parse().ok());
                    let l: Option<i64> = v.get("latest").and_then(Value::as_str).and_then(|s| s.split('.').next()).and_then(|s| s.parse().ok());
                    if let (Some(c), Some(l)) = (c, l) {
                        if c != 0 && l != 0 && l > c {
                            majors += 1;
                        }
                    }
                }
            }
            RunResult {
                status: "ran",
                command: Some(cmd),
                exit_code: Some(r.code),
                findings_count: total,
                meta: Some(json!({"majors_behind": majors})),
                raw_log: redact(Some(if !r.stdout.is_empty() { &r.stdout } else { &r.stderr })),
                duration_ms: Some(r.duration_ms),
                ..Default::default()
            }
        }),
    }
}

// ---------------------------------------------------------------------
// cargo_outdated
// ---------------------------------------------------------------------

pub fn build_cargo_outdated<'a>(runner: &'a dyn CommandRunner, root: &'a Path, stack: &'a DetectedStack) -> CheckSpec<'a> {
    CheckSpec {
        check: "cargo_outdated",
        tool: Some("cargo-outdated".to_string()),
        required: false,
        tier: "supplemental",
        flag_if_absent: false,
        parallel: true,
        force_skip: false,
        run: Box::new(move || {
            if !stack.rust {
                return unproven("no Cargo.toml");
            }
            let Some(rust_dir) = &stack.rust_dir else {
                return unproven("no Cargo.toml");
            };
            if !root.join(rust_dir).join("Cargo.lock").exists() {
                return unproven("no Cargo.lock");
            }
            if !runner.which("cargo-outdated") {
                return unproven_absent("cargo-outdated not installed (`cargo install cargo-outdated`)");
            }
            let cwd = root.join(rust_dir);
            let r = runner.run(&argv("cargo outdated --format json --root-deps-only"), &cwd, 300_000);
            let mut total = None;
            let mut majors = 0u64;
            if let Ok(j) = serde_json::from_str::<Value>(if r.stdout.is_empty() { "{}" } else { &r.stdout }) {
                let deps: Vec<&Value> = j
                    .get("dependencies")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter(|x| {
                        let latest = x.get("latest").and_then(Value::as_str);
                        latest.is_some() && latest != Some("---") && latest != x.get("project").and_then(Value::as_str)
                    })
                    .collect();
                total = Some(deps.len() as u64);
                for x in deps {
                    let c: Option<i64> = x.get("project").and_then(Value::as_str).and_then(|s| s.split('.').next()).and_then(|s| s.parse().ok());
                    let l: Option<i64> = x.get("latest").and_then(Value::as_str).and_then(|s| s.split('.').next()).and_then(|s| s.parse().ok());
                    if let (Some(c), Some(l)) = (c, l) {
                        if c != 0 && l != 0 && l > c {
                            majors += 1;
                        }
                    }
                }
            }
            RunResult {
                status: "ran",
                command: Some(format!("cargo outdated --format json --root-deps-only  (cwd: {rust_dir})")),
                exit_code: Some(r.code),
                findings_count: total,
                meta: Some(json!({"majors_behind": majors})),
                raw_log: redact(Some(if !r.stdout.is_empty() { &r.stdout } else { &r.stderr })),
                duration_ms: Some(r.duration_ms),
                ..Default::default()
            }
        }),
    }
}

// ---------------------------------------------------------------------
// binary_pins (network "resolve upstream latest" not ported — see doc)
// ---------------------------------------------------------------------

pub fn build_binary_pins<'a>(stack: &'a DetectedStack, root: &'a Path, tracked: &'a [String]) -> CheckSpec<'a> {
    CheckSpec {
        check: "binary_pins",
        tool: Some("grep+github-api".to_string()),
        required: false,
        tier: "core",
        flag_if_absent: false,
        parallel: true,
        force_skip: false,
        run: Box::new(move || {
            if !stack.git {
                return unproven("needs git ls-files");
            }
            let script_re = Regex::new(r"(?i)\.(ps1|psm1|sh|bash|zsh|mjs|cjs|js|py|rb)$|(^|/)(dockerfile[^/]*|justfile|makefile)$").unwrap();
            let url_re = Regex::new(r#"(?i)https?://[^\s"'`<>\\)\]}]+\.(?:zip|tar\.gz|tar\.xz|tar\.bz2|tgz|txz|7z|exe|msi|dmg|pkg|AppImage|deb|rpm|dll|so|dylib|wasm|jar)\b[^\s"'`<>\\)\]}]*"#).unwrap();
            let sha_re = Regex::new(r"\b[0-9a-fA-F]{64}\b").unwrap();
            let ver_re = Regex::new(r"\d+\.\d+(?:\.\d+){0,2}").unwrap();
            let gh_re = Regex::new(r"(?i)github\.com/([\w.-]+)/([\w.-]+)/(?:releases/(?:latest/)?download|archive)/").unwrap();
            let rolling_re = Regex::new(r"(?i)/releases/latest/download/").unwrap();
            let npm_re = Regex::new(r"registry\.npmjs\.org/((?:@[\w.-]+/)?[\w.-]+)/-/").unwrap();
            let var_re = Regex::new(r"\$\{?([A-Za-z_]\w*)\}?").unwrap();

            let mut pins: Vec<Value> = Vec::new();
            for f in tracked
                .iter()
                .filter(|f| script_re.is_match(f) && !f.contains("node_modules/") && !is_generated_or_vendored_path(f))
            {
                let txt = read_to_string(root, f);
                let lines: Vec<&str> = txt.split('\n').collect();
                if lines.len() > 8000 {
                    continue;
                }
                for (i, line) in lines.iter().enumerate() {
                    for m in url_re.find_iter(line) {
                        let mut url = m.as_str().to_string();
                        for vc in var_re.captures_iter(&m.as_str().to_string()) {
                            let var_name = &vc[1];
                            let def_re = Regex::new(&format!(r#"\$\{{?{}\}}?\s*=\s*['"]([^'"]+)['"]"#, regex::escape(var_name))).unwrap();
                            if let Some(def) = lines.iter().find_map(|l| def_re.captures(l)) {
                                url = url.replace(&vc[0], &def[1]);
                            }
                        }
                        let start = i.saturating_sub(10);
                        let end = (i + 11).min(lines.len());
                        let near = lines[start..end].join("\n").replace(&url, "");
                        let sha256_pinned = sha_re.is_match(&near);
                        let version = ver_re.find(&url).map(|m| m.as_str().to_string());
                        let github = gh_re.captures(&url).map(|c| format!("{}/{}", &c[1], &c[2]));
                        let rolling = rolling_re.is_match(&url);
                        let npm = npm_re.captures(&url).map(|c| c[1].to_string());
                        pins.push(json!({
                            "file": f, "line": i + 1, "url": url, "version": version,
                            "sha256_pinned": sha256_pinned, "rolling": rolling,
                            "github": github, "npm": npm, "latest": Value::Null, "stale": Value::Null,
                        }));
                    }
                }
            }
            let stale = pins.iter().filter(|p| p["stale"] == json!(true)).count();
            let unpinned = pins.iter().filter(|p| p["sha256_pinned"] == json!(false)).count();
            let manual = pins.iter().filter(|p| p["sha256_pinned"] == json!(true) && p["stale"].is_null()).count();
            let raw_log = if pins.is_empty() {
                "no binary pins found".to_string()
            } else {
                pins.iter()
                    .map(|p| {
                        let status = if p["stale"] == json!(true) {
                            "STALE"
                        } else if p["stale"] == json!(false) {
                            "current"
                        } else if p["sha256_pinned"] == json!(true) {
                            "MANUAL-CHECK"
                        } else {
                            "NO-INTEGRITY-PIN"
                        };
                        format!(
                            "{}:{}  v={}  sha256={}  latest=unresolved  {}  {}",
                            p["file"].as_str().unwrap_or(""),
                            p["line"],
                            p["version"].as_str().unwrap_or("?"),
                            if p["sha256_pinned"] == json!(true) { "yes" } else { "NO" },
                            status,
                            p["url"].as_str().unwrap_or(""),
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            RunResult {
                status: "ran",
                command: Some(
                    "scan tracked build/packaging scripts for hardcoded artifact-download URLs (64-hex within ±10 lines = integrity pin); resolve github releases/latest per repo (AUDIT_OFFLINE=1 skips network)"
                        .to_string(),
                ),
                exit_code: Some(0),
                findings_count: Some((stale + unpinned + manual) as u64),
                meta: Some(json!({"pins": pins, "stale": stale, "no_integrity_pin": unpinned, "manual_check_upstream": manual})),
                raw_log: Some(raw_log),
                duration_ms: Some(0),
                ..Default::default()
            }
        }),
    }
}

// ---------------------------------------------------------------------
// debt_markers
// ---------------------------------------------------------------------

pub fn build_debt_markers<'a>(runner: &'a dyn CommandRunner, root: &'a Path, stack: &'a DetectedStack) -> CheckSpec<'a> {
    CheckSpec {
        check: "debt_markers",
        tool: Some("git grep".to_string()),
        required: false,
        tier: "core",
        flag_if_absent: false,
        parallel: true,
        force_skip: false,
        run: Box::new(move || {
            if !stack.git {
                return unproven("debt-marker scan needs a git repo");
            }
            let argv_vec: Vec<String> = vec![
                "git".into(), "grep".into(), "-nIE".into(),
                "(ponytail:|\\b(TODO|FIXME|HACK|XXX)\\b)".into(),
                "--".into(), ".".into(),
                ":(exclude)*lock.yaml".into(), ":(exclude)*lock.yml".into(), ":(exclude)*lock.json".into(),
                ":(exclude)vendor/**".into(), ":(exclude)qwik/**".into(),
            ];
            let cmd = argv_vec.join(" ");
            let r = runner.run(&argv_vec, root, 180_000);
            let lines: Vec<&str> = r.stdout.split('\n').filter(|l| !l.is_empty()).collect();
            let pony_re = Regex::new("ponytail:").unwrap();
            let pony: Vec<&&str> = lines.iter().filter(|l| pony_re.is_match(l)).collect();
            let no_trigger_re = Regex::new(r"(?i)upgrade|ceiling|\bif\b").unwrap();
            let pony_no_trigger = pony.iter().filter(|l| !no_trigger_re.is_match(l)).count();
            let todo_re = Regex::new(r"\b(TODO|FIXME|HACK|XXX)\b").unwrap();
            let todos = lines.iter().filter(|l| todo_re.is_match(l)).count();
            RunResult {
                status: "ran",
                command: Some(cmd),
                exit_code: Some(0),
                findings_count: Some(lines.len() as u64),
                meta: Some(json!({"ponytail": pony.len(), "ponytail_no_trigger": pony_no_trigger, "todo_fixme": todos})),
                raw_log: redact(Some(&r.stdout)),
                duration_ms: Some(r.duration_ms),
                ..Default::default()
            }
        }),
    }
}

// ---------------------------------------------------------------------
// build (SEQUENTIAL — runs alone, after the pool; caller filters on `parallel`)
// ---------------------------------------------------------------------

pub fn build_build<'a>(runner: &'a dyn CommandRunner, root: &'a Path, stack: &'a DetectedStack) -> CheckSpec<'a> {
    CheckSpec {
        check: "build",
        tool: Some("<project build>".to_string()),
        required: stack.build_script || stack.rust,
        tier: "core",
        flag_if_absent: false,
        parallel: false,
        force_skip: false,
        run: Box::new(move || {
            let (cmd_argv, cwd): (Vec<String>, std::path::PathBuf) = if stack.build_script {
                (vec![stack.pkg_mgr.to_string(), "run".to_string(), "build".to_string()], root.to_path_buf())
            } else if stack.rust {
                (vec!["cargo".to_string(), "build".to_string()], root.join(stack.rust_dir.as_deref().unwrap_or(".")))
            } else {
                return unproven("no build script / Cargo.toml");
            };
            let cmd = cmd_argv.join(" ");
            let r = runner.run(&cmd_argv, &cwd, 600_000);
            let warn_re = Regex::new(r"(?i)\bwarn(ing)?\b").unwrap();
            let warns = joined_stdout_stderr(&r.stdout, &r.stderr).split('\n').filter(|l| warn_re.is_match(l)).count();
            RunResult {
                status: if r.code == 0 { "ran" } else { "error" },
                command: Some(cmd),
                exit_code: Some(r.code),
                findings_count: Some(warns as u64),
                raw_log: redact(Some(&joined_stdout_stderr(&r.stdout, &r.stderr))),
                duration_ms: Some(r.duration_ms),
                ..Default::default()
            }
        }),
    }
}

/// Assembles this half's checks in the same order `buildChecks` calls
/// `add()` for them. `tracked` is a pre-fetched `git ls-files` listing
/// (`trackedFiles()`'s result) — checks that need it are unproven with
/// `!stack.git`'s reason when it is empty and git is unavailable, matching
/// every JS closure's own `if (!d.git) return {status:'unproven',...}`
/// guard (the caller decides whether to fetch `tracked` at all when
/// `!stack.git`).
#[allow(clippy::too_many_arguments)]
pub fn checks_b<'a>(runner: &'a dyn CommandRunner, root: &'a Path, stack: &'a DetectedStack, tracked: &'a [String]) -> Vec<CheckSpec<'a>> {
    vec![
        build_cargo_audit(runner, root, stack),
        build_cargo_deny(runner, root, stack),
        build_cargo_unused_deps(runner, root, stack),
        build_cargo_unsafe(runner, root, stack),
        build_vendored_deps(stack, tracked),
        build_dep_pinning(stack, root, tracked),
        build_tool_coverage(stack, root, tracked),
        build_contract_mirror(stack, root, tracked),
        build_tauri_capabilities(stack, root, tracked),
        build_apple_platform(root, tracked),
        build_react_hooks(stack),
        build_negative_space(stack, root, tracked),
        build_outdated(runner, root, stack),
        build_cargo_outdated(runner, root, stack),
        build_binary_pins(stack, root, tracked),
        build_debt_markers(runner, root, stack),
        build_build(runner, root, stack),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wf_port::wf065::collect_facts_exec::{exec_one, RunOutput};
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct FakeRunner {
        which: HashMap<&'static str, bool>,
        outputs: Mutex<HashMap<String, RunOutput>>,
    }

    impl FakeRunner {
        fn new() -> Self {
            Self { which: HashMap::new(), outputs: Mutex::new(HashMap::new()) }
        }
        fn with_which(mut self, bin: &'static str, present: bool) -> Self {
            self.which.insert(bin, present);
            self
        }
        fn with_output(self, cmd: &str, out: RunOutput) -> Self {
            self.outputs.lock().unwrap().insert(cmd.to_string(), out);
            self
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, argv: &[String], _cwd: &Path, _timeout_ms: u64) -> RunOutput {
            let key = argv.join(" ");
            self.outputs.lock().unwrap().get(&key).cloned().unwrap_or(RunOutput {
                code: 0,
                stdout: String::new(),
                stderr: String::new(),
                duration_ms: 0,
                spawn_error: false,
            })
        }
        fn which(&self, bin: &str) -> bool {
            *self.which.get(bin).unwrap_or(&false)
        }
    }

    fn stack(rust: bool) -> DetectedStack {
        DetectedStack {
            git: true, node: false, pkg: None, pkg_mgr: "npm", ts: false, py: false,
            rust, rust_dir: if rust { Some(".".to_string()) } else { None },
            swift: false, tauri: false, build_script: false, eslint: false, biome: false,
            workflows: false, dockerfile: false,
        }
    }

    fn tmp_dir(name: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("wf065b_{}_{}_{}", std::process::id(), n, name));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn cargo_audit_skips_without_cargo_toml() {
        let runner = FakeRunner::new();
        let d = stack(false);
        let spec = build_cargo_audit(&runner, Path::new("."), &d);
        let r = exec_one(&spec);
        assert_eq!(r.status, "unproven");
        assert_eq!(r.skip_reason.as_deref(), Some("no Cargo.toml"));
    }

    #[test]
    fn cargo_audit_flags_absent_tool() {
        let dir = tmp_dir("audit_absent");
        std::fs::write(dir.join("Cargo.lock"), "").unwrap();
        let runner = FakeRunner::new().with_which("cargo-audit", false);
        let d = stack(true);
        let spec = build_cargo_audit(&runner, &dir, &d);
        let r = exec_one(&spec);
        assert!(r.tool_absent);
        assert_eq!(r.status, "unproven");
    }

    #[test]
    fn cargo_audit_parses_vulnerability_count() {
        let dir = tmp_dir("audit_ran");
        std::fs::write(dir.join("Cargo.lock"), "").unwrap();
        let runner = FakeRunner::new().with_which("cargo-audit", true).with_output(
            "cargo audit --json",
            RunOutput { stdout: r#"{"vulnerabilities":{"count":3}}"#.to_string(), stderr: String::new(), code: 0, duration_ms: 12, spawn_error: false },
        );
        let d = stack(true);
        let spec = build_cargo_audit(&runner, &dir, &d);
        let r = exec_one(&spec);
        assert_eq!(r.status, "ran");
        assert_eq!(r.findings_count, Some(3));
    }

    #[test]
    fn cargo_deny_counts_error_and_warning_diagnostics() {
        let dir = tmp_dir("deny");
        let mut d = stack(true);
        d.rust_dir = Some(".".to_string());
        let stderr = "{\"type\":\"diagnostic\",\"fields\":{\"severity\":\"error\"}}\n{\"type\":\"diagnostic\",\"fields\":{\"severity\":\"warning\"}}\n{\"type\":\"diagnostic\",\"fields\":{\"severity\":\"note\"}}\nnot json\n";
        let runner = FakeRunner::new().with_which("cargo-deny", true).with_output(
            "cargo deny --format json check",
            RunOutput { stdout: String::new(), stderr: stderr.to_string(), code: 1, duration_ms: 5, spawn_error: false },
        );
        let spec = build_cargo_deny(&runner, &dir, &d);
        let r = exec_one(&spec);
        assert_eq!(r.findings_count, Some(2));
    }

    #[test]
    fn cargo_unused_deps_counts_indented_non_noise_lines() {
        let mut d = stack(true);
        d.rust_dir = Some(".".to_string());
        let stdout = "Analyzing dependencies...\ncrate foo:\n  unused_dep_one\n  unused_dep_two\nfound the following\n";
        let runner = FakeRunner::new().with_which("cargo-machete", true).with_output(
            "cargo machete --with-metadata",
            RunOutput { stdout: stdout.to_string(), stderr: String::new(), code: 0, duration_ms: 1, spawn_error: false },
        );
        let spec = build_cargo_unused_deps(&runner, Path::new("."), &d);
        let r = exec_one(&spec);
        assert_eq!(r.findings_count, Some(2));
    }

    #[test]
    fn cargo_unsafe_sums_used_unsafe_across_packages() {
        let mut d = stack(true);
        d.rust_dir = Some(".".to_string());
        let stdout = r#"{"packages":[{"unsafety":{"used":{"functions":{"unsafe_":2},"exprs":{"unsafe_":1}}}},{"unsafety":{"used":{"functions":{"unsafe_":0}}}}]}"#;
        let runner = FakeRunner::new().with_which("cargo-geiger", true).with_output(
            "cargo geiger --output-format Json --quiet",
            RunOutput { stdout: stdout.to_string(), stderr: String::new(), code: 0, duration_ms: 1, spawn_error: false },
        );
        let spec = build_cargo_unsafe(&runner, Path::new("."), &d);
        let r = exec_one(&spec);
        assert_eq!(r.findings_count, Some(3));
    }

    #[test]
    fn vendored_deps_finds_manifest_trees_with_lockfile_flag() {
        let tracked = vec![
            "vendor/foo/package.json".to_string(),
            "vendor/foo/package-lock.json".to_string(),
            "vendor/bar/Cargo.toml".to_string(),
            "node_modules/vendor/baz/package.json".to_string(),
        ];
        let d = stack(true);
        let spec = build_vendored_deps(&d, &tracked);
        let r = exec_one(&spec);
        assert_eq!(r.findings_count, Some(2));
        let meta = r.meta.unwrap();
        let trees = meta["trees"].as_array().unwrap();
        assert!(trees.iter().any(|t| t["dir"] == "vendor/foo" && t["has_lockfile"] == true));
        assert!(trees.iter().any(|t| t["dir"] == "vendor/bar" && t["has_lockfile"] == false));
    }

    #[test]
    fn dep_pinning_flags_unpinned_npm_git_dep_and_accepts_sha_pinned() {
        let dir = tmp_dir("pinning");
        std::fs::write(
            dir.join("package.json"),
            r#"{"dependencies":{"a":"git+https://example.com/a.git","b":"git+https://example.com/b.git#abcdef1234"}}"#,
        )
        .unwrap();
        let tracked = vec!["package.json".to_string()];
        let d = stack(false);
        let spec = build_dep_pinning(&d, &dir, &tracked);
        let r = exec_one(&spec);
        assert_eq!(r.findings_count, Some(1));
        let offenders = r.meta.unwrap()["offenders"].clone();
        assert_eq!(offenders[0]["dep"], "a");
    }

    #[test]
    fn negative_space_flags_missing_readme_and_license() {
        let dir = tmp_dir("negspace");
        std::fs::write(dir.join(".gitignore"), "").unwrap();
        let mut d = stack(false);
        d.workflows = true;
        let tracked: Vec<String> = Vec::new();
        let spec = build_negative_space(&d, &dir, &tracked);
        let r = exec_one(&spec);
        let missing = r.meta.unwrap()["missing"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect::<Vec<_>>();
        assert!(missing.contains(&"README".to_string()));
        assert!(missing.contains(&"LICENSE".to_string()));
        assert!(missing.contains(&"tests".to_string()));
        assert!(!missing.contains(&"CI".to_string()));
    }

    #[test]
    fn debt_markers_splits_ponytail_from_todo_and_flags_no_trigger() {
        let stdout = "a.rs:1:  // ponytail: upgrade later\nb.rs:2:  // TODO fix this\nc.rs:3:  // ponytail: just because\n";
        let cmd = "git grep -nIE (ponytail:|\\b(TODO|FIXME|HACK|XXX)\\b) -- . :(exclude)*lock.yaml :(exclude)*lock.yml :(exclude)*lock.json :(exclude)vendor/** :(exclude)qwik/**";
        let runner = FakeRunner::new().with_output(cmd, RunOutput { stdout: stdout.to_string(), stderr: String::new(), code: 0, duration_ms: 3, spawn_error: false });
        let d = stack(false);
        let spec = build_debt_markers(&runner, Path::new("."), &d);
        let r = exec_one(&spec);
        assert_eq!(r.findings_count, Some(3));
        let meta = r.meta.unwrap();
        assert_eq!(meta["ponytail"], json!(2));
        assert_eq!(meta["ponytail_no_trigger"], json!(1));
        assert_eq!(meta["todo_fixme"], json!(1));
    }

    #[test]
    fn build_uses_pkg_mgr_run_build_when_build_script_present() {
        let mut d = stack(false);
        d.build_script = true;
        d.pkg_mgr = "pnpm";
        let runner = FakeRunner::new().with_output(
            "pnpm run build",
            RunOutput { stdout: "warning: unused import\n".to_string(), stderr: String::new(), code: 0, duration_ms: 7, spawn_error: false },
        );
        let spec = build_build(&runner, Path::new("."), &d);
        let r = exec_one(&spec);
        assert_eq!(r.status, "ran");
        assert_eq!(r.findings_count, Some(1));
    }

    #[test]
    fn build_is_unproven_without_build_script_or_rust() {
        let runner = FakeRunner::new();
        let d = stack(false);
        let spec = build_build(&runner, Path::new("."), &d);
        let r = exec_one(&spec);
        assert_eq!(r.status, "unproven");
    }

    #[test]
    fn react_hooks_unproven_without_react_dependency() {
        let mut d = stack(false);
        d.node = true;
        d.pkg = Some(json!({"dependencies": {}}));
        let spec = build_react_hooks(&d);
        let r = exec_one(&spec);
        assert_eq!(r.status, "unproven");
    }

    #[test]
    fn react_hooks_flags_missing_plugin() {
        let mut d = stack(false);
        d.node = true;
        d.pkg = Some(json!({"dependencies": {"react": "^18.0.0"}}));
        let spec = build_react_hooks(&d);
        let r = exec_one(&spec);
        assert_eq!(r.status, "ran");
        assert_eq!(r.findings_count, Some(1));
    }

    #[test]
    fn checks_b_returns_all_seventeen_checks_in_source_order() {
        let runner = FakeRunner::new();
        let d = stack(true);
        let tracked: Vec<String> = Vec::new();
        let specs = checks_b(&runner, Path::new("."), &d, &tracked);
        let names: Vec<&str> = specs.iter().map(|s| s.check).collect();
        assert_eq!(
            names,
            vec![
                "cargo_audit", "cargo_deny", "cargo_unused_deps", "cargo_unsafe", "vendored_deps",
                "dep_pinning", "tool_coverage", "contract_mirror", "tauri_capabilities", "apple_platform",
                "react_hooks", "negative_space", "outdated", "cargo_outdated", "binary_pins", "debt_markers", "build",
            ]
        );
        assert!(!specs.last().unwrap().parallel); // build is the SEQUENTIAL one
    }
}
