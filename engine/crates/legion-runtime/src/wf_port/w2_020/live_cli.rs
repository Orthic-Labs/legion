//! Port of the pure logic in `skills/designer/engine/scripts/live.mjs`, plus
//! (packet r19) [`live_cli`]/[`run`] — the full `liveCli()` orchestration.
//!
//! `liveCli()` drives sibling scripts/modules that now have their own Rust
//! ports elsewhere in `engine/`:
//!   - argv `--target` parsing: `crate::p8_designer::target_args::parse_target_path`
//!     (port of `lib/target-args.mjs`).
//!   - `resolveLiveTarget`'s pure tail: `crate::wf_port::w2_019::live_target::resolve_live_target`.
//!   - `loadContext`/`resolveTargetSelection`/`resolveProjectRoot`:
//!     `crate::wf_port::w2_010::context` (port of `context.mjs`).
//!   - `.impeccable/live/config.json` / `server.json` paths and the running
//!     server's connection info: `crate::wf_port::w2_016::impeccable_paths`
//!     (port of `lib/impeccable-paths.mjs`).
//!   - config validation + glob file resolution used by both the
//!     `live-inject.mjs --check` and `--port` steps:
//!     `crate::wf_port::w2_018::inject` (port of `live-inject.mjs`).
//!   - [`scan_for_drift`] below (already ported in this module).
//!
//! `live.mjs` starts/reuses the live server and re-invokes `live-inject.mjs`
//! by shelling out to sibling Node scripts with `execSync` — that is
//! subprocess orchestration, which the port brief calls out as portable: it
//! is ported here behind the [`ProcessRunner`] trait (mirroring
//! `runScript`/`ensureServerRunning`) so tests can supply a fake runner
//! instead of actually spawning `node`.
//!
//! Not ported: the SvelteKit live-adapter branch of `live-inject.mjs`
//! (`live/sveltekit-adapter.mjs`, `detectSvelteKitProject` /
//! `applySvelteKitLiveAdapter`) — that file has no existing Rust port and is
//! outside every chunk touched here; [`inject_check`]/[`inject_port`] below
//! implement the non-SvelteKit path only, matching `w2_018`'s own documented
//! gap.
//!
//! What IS ported, faithfully:
//!   - [`missing_live_context`] — `missingLiveContext(ctx)`.
//!   - [`glob_to_regex`] — the glob-pattern-to-regex compiler shared (by
//!     comment, intentionally duplicated to avoid a circular import) with
//!     `live-inject.mjs`.
//!   - [`scan_for_drift`] — `scanForDrift(rootDir, resolvedFiles, config)`,
//!     with the recursive directory walk (`fs.readdirSync`) taken as an
//!     injectable `walk` closure so the matching/orphan logic stays testable
//!     without real disk I/O; wire a real walker (see `DirEntry`) for actual
//!     CLI use. Behavior matches the JS: same `SCAN_ROOTS`, same
//!     `IGNORE_DIRS`, same dotdir skip, same `.html`-only filter, same
//!     20-item cap and hint string, same `null` (`None`) when there are no
//!     orphans.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::p8_designer::target_args::parse_target_path;
use crate::wf_port::w2_010::context::{
    load_context, resolve_project_root, resolve_target_selection, TargetOptions,
};
use crate::wf_port::w2_016::impeccable_paths::{
    read_live_server_info, resolve_live_config_path,
};
use crate::wf_port::w2_018::inject::{
    ensure_live_gitignores, insert_tag, patch_csp_meta, remove_tag, resolve_files,
    revert_csp_meta, validate_config, ConfigError, InjectConfig,
};
use crate::wf_port::w2_019::live_target::resolve_live_target;

/// Mirrors `missingLiveContext(ctx)`. `has_product`/`has_design` correspond
/// to `ctx.hasProduct` / `ctx.hasDesign`.
pub fn missing_live_context(has_product: bool, has_design: bool) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if !has_product {
        missing.push("PRODUCT.md");
    }
    if !has_design {
        missing.push("DESIGN.md");
    }
    missing
}

/// Mirrors `globToRegex(pattern)`. Returns an anchored regex source string
/// (`^...$`) equivalent to the JS-built pattern; compile with `regex::Regex`.
pub fn glob_to_regex_source(pattern: &str) -> String {
    let mut re = String::new();
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '*' {
            if chars.get(i + 1) == Some(&'*') {
                if chars.get(i + 2) == Some(&'/') {
                    re.push_str("(?:.*/)?");
                    i += 3;
                } else {
                    re.push_str(".*");
                    i += 2;
                }
            } else {
                re.push_str("[^/]*");
                i += 1;
            }
        } else if c == '?' {
            re.push_str("[^/]");
            i += 1;
        } else if ".+^${}()|[]\\".contains(c) {
            re.push('\\');
            re.push(c);
            i += 1;
        } else {
            re.push(c);
            i += 1;
        }
    }
    format!("^{re}$")
}

/// Compiles [`glob_to_regex_source`] into a `regex::Regex`.
pub fn glob_to_regex(pattern: &str) -> regex::Regex {
    regex::Regex::new(&glob_to_regex_source(pattern)).expect("glob_to_regex_source always produces a valid pattern")
}

#[derive(Debug, Clone)]
pub struct DriftReport {
    pub orphans: Vec<String>,
    pub orphan_count: usize,
    pub hint: String,
}

const SCAN_ROOTS: &[&str] = &["public", "src", "app", "pages"];

fn ignore_dirs() -> &'static HashSet<&'static str> {
    static SET: std::sync::OnceLock<HashSet<&'static str>> = std::sync::OnceLock::new();
    SET.get_or_init(|| {
        [
            "node_modules", ".git", ".next", ".nuxt", ".svelte-kit", ".astro", ".turbo", ".vercel", ".cache",
            "coverage", "dist", "build",
        ]
        .into_iter()
        .collect()
    })
}

/// One directory entry as seen by an injected walker: `name` is the bare
/// file/dir name, `is_dir` distinguishes directories from files.
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
}

/// Mirrors `scanForDrift(rootDir, resolvedFiles, config)`.
///
/// `resolved_files` mirrors the JS's `resolvedFiles` (already forward-slash
/// or platform-separated paths — the JS normalizes with
/// `f.split(path.sep).join('/')`; callers should pass forward-slash paths
/// here to match `list_dir`'s `rel` paths, which are always built with `/`).
/// `exclude_globs` mirrors `config.exclude`. `list_dir(dir) -> Vec<DirEntry>`
/// replaces `fs.readdirSync`; return an empty vec for a directory that
/// doesn't exist or can't be read (same as the JS's `catch { return; }`).
pub fn scan_for_drift(
    resolved_files: &[String],
    exclude_globs: &[String],
    mut list_dir: impl FnMut(&str) -> Vec<DirEntry>,
) -> Option<DriftReport> {
    let resolved_set: HashSet<&str> = resolved_files.iter().map(String::as_str).collect();
    let user_exclude_regexes: Vec<regex::Regex> = exclude_globs.iter().map(|p| glob_to_regex(p)).collect();
    let is_user_excluded = |rel: &str| user_exclude_regexes.iter().any(|re| re.is_match(rel));

    let mut orphans = Vec::new();

    fn walk(
        dir: &str,
        rel_base: &str,
        list_dir: &mut impl FnMut(&str) -> Vec<DirEntry>,
        resolved_set: &HashSet<&str>,
        is_user_excluded: &dyn Fn(&str) -> bool,
        orphans: &mut Vec<String>,
    ) {
        for entry in list_dir(dir) {
            let rel = if rel_base.is_empty() {
                entry.name.clone()
            } else {
                format!("{rel_base}/{}", entry.name)
            };
            if entry.is_dir {
                if ignore_dirs().contains(entry.name.as_str()) || entry.name.starts_with('.') {
                    continue;
                }
                let child_dir = format!("{dir}/{}", entry.name);
                walk(&child_dir, &rel, list_dir, resolved_set, is_user_excluded, orphans);
            } else if entry.name.ends_with(".html") {
                if resolved_set.contains(rel.as_str()) {
                    continue;
                }
                if is_user_excluded(&rel) {
                    continue;
                }
                orphans.push(rel);
            }
        }
    }

    for root in SCAN_ROOTS {
        walk(root, root, &mut list_dir, &resolved_set, &is_user_excluded, &mut orphans);
    }

    if orphans.is_empty() {
        return None;
    }
    let orphan_count = orphans.len();
    let capped: Vec<String> = orphans.into_iter().take(20).collect();
    let hint = format!(
        "{orphan_count} HTML file(s) exist but aren't in config.files. Consider adding them, or use a glob pattern like \"public/**/*.html\"."
    );
    Some(DriftReport { orphans: capped, orphan_count, hint })
}

// ─── r19: liveCli() orchestration ───────────────────────────────────────

/// Port of `runScript(name, args, options)`'s subprocess boundary: `live.mjs`
/// shells out to sibling scripts (`live-inject.mjs`, `live-server.mjs`) with
/// `execSync`. Implementations return the child process's stdout (matching
/// the JS's `err.stdout || err.message || ''` fallback on a non-zero exit).
pub trait ProcessRunner {
    /// Mirrors `runScript('live-server.mjs', ['--background'], { cwd })`.
    fn start_live_server(&self, cwd: &Path) -> String;
}

fn safe_parse(out: &str) -> Option<Value> {
    serde_json::from_str(out.trim()).ok()
}

/// Port of `ensureServerRunning(cwd)`: reuse a running server if its PID is
/// live (`read_live_server_info` already treats a stale PID as absent and
/// deletes the file, matching the JS's `process.kill(pid, 0)` probe +
/// `readLiveServerInfo` cleanup), otherwise start one via [`ProcessRunner`].
fn ensure_server_running(runner: &dyn ProcessRunner, cwd: &Path) -> Option<Value> {
    if let Some(existing) = read_live_server_info(cwd) {
        return Some(existing.raw);
    }
    let out = runner.start_live_server(cwd);
    safe_parse(&out)
}

fn inject_config_from_json(cfg: &Value) -> Option<InjectConfig> {
    let files = cfg.get("files")?.as_array()?.iter().map(|v| v.as_str().unwrap_or("").to_string()).collect();
    let exclude = cfg
        .get("exclude")
        .and_then(Value::as_array)
        .map(|a| a.iter().map(|v| v.as_str().unwrap_or("").to_string()).collect())
        .unwrap_or_default();
    let insert_before = cfg.get("insertBefore").and_then(Value::as_str).map(str::to_string);
    let insert_after = cfg.get("insertAfter").and_then(Value::as_str).map(str::to_string);
    let comment_syntax = cfg
        .get("commentSyntax")
        .and_then(Value::as_str)
        .unwrap_or("html")
        .to_string();
    Some(InjectConfig { files, exclude, insert_before, insert_after, comment_syntax })
}

fn config_error_message(err: &ConfigError) -> &'static str {
    match err {
        ConfigError::FilesRequired => "config.files must be a non-empty array of strings",
        ConfigError::InsertAnchorRequired => "config must set insertBefore or insertAfter",
        ConfigError::InvalidCommentSyntax => "config.commentSyntax must be 'html' or 'jsx'",
    }
}

/// Port of `live-inject.mjs --check` (the non-SvelteKit path; SvelteKit
/// detection is out of scope, see module docs). Always returns a value to
/// print, matching the JS's `console.log(JSON.stringify(...))` on every
/// branch of `--check`.
pub fn inject_check(cwd: &Path) -> Value {
    let config_path = resolve_live_config_path(cwd, cwd, None, None);
    if !config_path.exists() {
        return json!({ "ok": false, "error": "config_missing", "path": config_path.to_string_lossy() });
    }
    let raw = match std::fs::read_to_string(&config_path) {
        Ok(r) => r,
        Err(err) => {
            return json!({
                "ok": false, "error": "config_invalid", "message": err.to_string(),
                "path": config_path.to_string_lossy(),
            })
        }
    };
    let cfg: Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(err) => {
            return json!({
                "ok": false, "error": "config_invalid", "message": err.to_string(),
                "path": config_path.to_string_lossy(),
            })
        }
    };
    let Some(parsed) = inject_config_from_json(&cfg) else {
        return json!({
            "ok": false, "error": "config_invalid", "message": "malformed config",
            "path": config_path.to_string_lossy(),
        });
    };
    if let Err(err) = validate_config(&parsed) {
        return json!({
            "ok": false, "error": "config_invalid", "message": config_error_message(&err),
            "path": config_path.to_string_lossy(),
        });
    }
    json!({ "ok": true, "config": cfg, "path": config_path.to_string_lossy() })
}

/// Port of `live-inject.mjs --port PORT` (the non-SvelteKit insert path).
/// Returns `None` when the config is missing or invalid — the JS crashes
/// with an uncaught throw / `process.exit(1)` and no parseable stdout in
/// that case, which is exactly what `runScript`'s caller sees as `null`
/// after `safeParse`.
pub fn inject_port(cwd: &Path, port: u32) -> Option<Value> {
    let config_path = resolve_live_config_path(cwd, cwd, None, None);
    if !config_path.exists() {
        return None;
    }
    let raw = std::fs::read_to_string(&config_path).ok()?;
    let cfg: Value = serde_json::from_str(&raw).ok()?;
    let parsed = inject_config_from_json(&cfg)?;
    validate_config(&parsed).ok()?;

    let resolved_files = resolve_files(cwd, &parsed);
    let git_ignore = ensure_live_gitignores(cwd).ok();
    let git_ignore_json = git_ignore
        .map(|g| json!({ "file": g.file, "mode": g.mode, "changed": g.changed }))
        .unwrap_or(Value::Null);

    let mut results = Vec::new();
    let mut any_inserted = false;
    for rel_file in &resolved_files {
        let abs_file = cwd.join(rel_file);
        if !abs_file.exists() {
            results.push(json!({ "file": rel_file, "error": "file_not_found" }));
            continue;
        }
        let content = match std::fs::read_to_string(&abs_file) {
            Ok(c) => c,
            Err(_) => {
                results.push(json!({ "file": rel_file, "error": "file_not_found" }));
                continue;
            }
        };
        let without_old = revert_csp_meta(&remove_tag(&content));
        let with_tag = insert_tag(&without_old, &parsed, port, rel_file);
        if with_tag == without_old {
            let anchor = parsed.insert_before.as_deref().or(parsed.insert_after.as_deref());
            results.push(json!({ "file": rel_file, "error": "insertion_point_not_found", "anchor": anchor }));
            continue;
        }
        let updated = patch_csp_meta(&with_tag, port);
        if std::fs::write(&abs_file, &updated).is_err() {
            results.push(json!({ "file": rel_file, "error": "file_not_found" }));
            continue;
        }
        any_inserted = true;
        results.push(json!({ "file": rel_file, "inserted": true, "cspPatched": updated != with_tag }));
    }

    Some(json!({ "ok": any_inserted, "port": port, "gitIgnore": git_ignore_json, "results": results }))
}

/// A real filesystem [`DirEntry`] walker for [`scan_for_drift`], used by the
/// live CLI orchestration (as opposed to `scan_for_drift`'s own tests, which
/// use a fake).
fn list_dir_real(dir: &str) -> Vec<DirEntry> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_str()?.to_string();
            let is_dir = e.file_type().ok()?.is_dir();
            Some(DirEntry { name, is_dir })
        })
        .collect()
}

/// Faithful port of `liveCli()`. `original_cwd` mirrors `process.cwd()`;
/// `argv` mirrors `process.argv.slice(2)`. Returns `(exit_code, stdout)`,
/// matching the JS's `console.log(JSON.stringify(...))` + `process.exit`
/// pairs (the JS's `--help` branch prints plain text instead of JSON, kept
/// verbatim here too).
pub fn live_cli(runner: &dyn ProcessRunner, original_cwd: &Path, argv: &[String]) -> (i32, String) {
    if argv.iter().any(|a| a == "--help" || a == "-h") {
        let usage = "Usage: node live.mjs\n\nPrepare everything for live variant mode in a single command:\n  - Checks .impeccable/live/config.json (required, created once per project)\n  - Starts (or reuses) the live server in the background\n  - Injects the browser script tag\n  - Reads PRODUCT.md / DESIGN.md for project context\n  - In monorepos, choose a child app first; --target <path> is the fallback/manual path\n\nOn success, prints a JSON blob with:\n  { ok, serverPort, serverToken, pageFiles, projectRoot, repoRoot, targetPath, productPath, designPath }\n\nOn target_selection_required, prints:\n  { ok: false, error: \"target_selection_required\", targetCandidates }\n\nOn config_missing, prints:\n  { ok: false, error: \"config_missing\", configPath, hint }\n\nThe agent should then:\n  1. If target_selection_required, ask which app to use and rerun from that child cwd\n  2. If config_missing, create the config and re-run this script\n  3. Optionally open the project's dev/preview URL in the browser (see reference/live.md—not serverPort)\n  4. Enter the poll loop: node live-poll.mjs";
        return (0, usage.to_string());
    }

    let original_cwd = original_cwd.to_path_buf();
    let target_path = match parse_target_path(argv, true) {
        Ok(t) => t,
        Err(err) => return (1, err.message),
    };

    let (project_root, target_options) = match &target_path {
        Some(t) => {
            let abs = if Path::new(t).is_absolute() { PathBuf::from(t) } else { original_cwd.join(t) };
            let opts = TargetOptions::with(abs.to_string_lossy().replace('\\', "/"));
            let root = resolve_project_root(&original_cwd, &opts);
            (root, opts)
        }
        None => (original_cwd.clone(), TargetOptions::none()),
    };
    let live_target = resolve_live_target(&original_cwd, target_path.as_deref(), &project_root);
    let output_target_path = live_target.target_path.clone();

    if let Some(selection) = resolve_target_selection(&original_cwd, &target_options) {
        let candidates: Vec<Value> = selection
            .target_candidates
            .iter()
            .map(|c| {
                json!({
                    "name": c.name, "path": c.path, "targetExample": c.target_example,
                    "productStatus": c.product_status, "productPath": c.product_path,
                    "designStatus": c.design_status, "designPath": c.design_path,
                })
            })
            .collect();
        return (
            0,
            serde_json::to_string_pretty(&json!({
                "ok": false,
                "error": "target_selection_required",
                "targetPath": selection.target_path,
                "projectRoot": selection.project_root.to_string_lossy(),
                "repoRoot": selection.repo_root.to_string_lossy(),
                "targetCandidates": candidates,
                "hint": "Ask the user which app Impeccable should use, then rerun live from that child app cwd. Use --target <path> only as a fallback or explicit path diagnostic.",
            }))
            .unwrap(),
        );
    }

    let ctx = load_context(&original_cwd, &target_options);
    let active_cwd = ctx.project_root.clone();

    let missing_context = missing_live_context(ctx.has_product, ctx.has_design);
    if !missing_context.is_empty() {
        let next_command = if missing_context.contains(&"PRODUCT.md") { "init" } else { "document" };
        return (
            0,
            serde_json::to_string_pretty(&json!({
                "ok": false,
                "error": "context_missing",
                "missing": missing_context,
                "nextCommand": next_command,
                "targetPath": output_target_path,
                "projectRoot": ctx.project_root.to_string_lossy(),
                "repoRoot": ctx.repo_root.to_string_lossy(),
                "productPath": ctx.product_path,
                "designPath": ctx.design_path,
            }))
            .unwrap(),
        );
    }

    // 1. Check config.
    let check_result = inject_check(&active_cwd);
    let check_ok = check_result.get("ok").and_then(Value::as_bool).unwrap_or(false);
    if !check_ok {
        let mut merged = check_result;
        if let Some(obj) = merged.as_object_mut() {
            obj.insert("targetPath".into(), json!(output_target_path));
            obj.insert("projectRoot".into(), json!(ctx.project_root.to_string_lossy()));
            obj.insert("repoRoot".into(), json!(ctx.repo_root.to_string_lossy()));
        }
        return (0, serde_json::to_string_pretty(&merged).unwrap());
    }

    // 2. Start (or reuse) the server.
    let Some(server_info) = ensure_server_running(runner, &active_cwd) else {
        return (1, serde_json::to_string(&json!({ "ok": false, "error": "server_start_failed" })).unwrap());
    };
    let Some(server_port) = server_info.get("port").and_then(Value::as_u64) else {
        return (1, serde_json::to_string(&json!({ "ok": false, "error": "server_start_failed" })).unwrap());
    };

    // 3. Inject the script tag at the current port.
    let Some(inject_result) = inject_port(&active_cwd, server_port as u32) else {
        return (
            1,
            serde_json::to_string(&json!({
                "ok": false, "error": "inject_failed", "detail": Value::Null, "serverPort": server_port,
            }))
            .unwrap(),
        );
    };
    let inject_ok = inject_result.get("ok").and_then(Value::as_bool).unwrap_or(false);
    if !inject_ok {
        return (
            1,
            serde_json::to_string(&json!({
                "ok": false, "error": "inject_failed", "detail": inject_result, "serverPort": server_port,
            }))
            .unwrap(),
        );
    }

    // 4. Drift-heal scan.
    let config = check_result.get("config").cloned().unwrap_or(json!({}));
    let resolved_files: Vec<String> = match inject_config_from_json(&config) {
        Some(cfg) => resolve_files(&active_cwd, &cfg).into_iter().collect(),
        None => Vec::new(),
    };
    let exclude_globs: Vec<String> = config
        .get("exclude")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let drift = scan_for_drift(&resolved_files, &exclude_globs, |dir| list_dir_real(&format!("{}/{dir}", active_cwd.display())));
    let drift_json = drift
        .map(|d| json!({ "orphans": d.orphans, "orphanCount": d.orphan_count, "hint": d.hint }))
        .unwrap_or(Value::Null);

    let server_token = server_info.get("token").cloned().unwrap_or(Value::Null);

    // 5. Emit everything the agent needs.
    (
        0,
        serde_json::to_string_pretty(&json!({
            "ok": true,
            "serverPort": server_port,
            "serverToken": server_token,
            "pageFiles": resolved_files,
            "liveConfigPath": check_result.get("path").cloned().unwrap_or(Value::Null),
            "configDrift": drift_json,
            "targetPath": output_target_path,
            "projectRoot": ctx.project_root.to_string_lossy(),
            "repoRoot": ctx.repo_root.to_string_lossy(),
            "hasProduct": ctx.has_product,
            "product": ctx.product,
            "productPath": ctx.product_path,
            "hasDesign": ctx.has_design,
            "design": ctx.design,
            "designPath": ctx.design_path,
        }))
        .unwrap(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_live_context_reports_absent_files() {
        assert_eq!(missing_live_context(false, false), vec!["PRODUCT.md", "DESIGN.md"]);
        assert_eq!(missing_live_context(true, false), vec!["DESIGN.md"]);
        assert_eq!(missing_live_context(true, true), Vec::<&str>::new());
    }

    #[test]
    fn glob_to_regex_handles_star_doublestar_and_escapes() {
        assert!(glob_to_regex("public/**/*.html").is_match("public/a/b/c.html"));
        assert!(glob_to_regex("public/**/*.html").is_match("public/c.html"));
        assert!(glob_to_regex("*.html").is_match("index.html"));
        assert!(!glob_to_regex("*.html").is_match("sub/index.html"));
        assert!(glob_to_regex("a.b").is_match("a.b"));
        assert!(!glob_to_regex("a.b").is_match("aXb"));
        assert!(glob_to_regex("file?.html").is_match("file1.html"));
        assert!(!glob_to_regex("file?.html").is_match("file12.html"));
    }

    fn fake_fs<'f>(files: &'f [(&'f str, &'f [&'f str])]) -> impl for<'a> FnMut(&'a str) -> Vec<DirEntry> + 'f {
        move |dir: &str| {
            let mut entries = Vec::new();
            let mut seen_dirs = HashSet::new();
            for (path, _) in files {
                if let Some(rest) = path.strip_prefix(&format!("{dir}/")) {
                    let first = rest.split('/').next().unwrap();
                    let is_dir = rest.contains('/');
                    if is_dir {
                        if seen_dirs.insert(first) {
                            entries.push(DirEntry { name: first.to_string(), is_dir: true });
                        }
                    } else {
                        entries.push(DirEntry { name: first.to_string(), is_dir: false });
                    }
                }
            }
            entries
        }
    }

    #[test]
    fn scan_for_drift_returns_none_when_all_covered() {
        let files = [("public/index.html", &[][..])];
        let resolved = vec!["public/index.html".to_string()];
        let report = scan_for_drift(&resolved, &[], fake_fs(&files));
        assert!(report.is_none());
    }

    #[test]
    fn scan_for_drift_reports_orphans_and_skips_excluded_and_ignored_dirs() {
        let files = [
            ("public/index.html", &[][..]),
            ("public/orphan.html", &[][..]),
            ("public/skip-me.html", &[][..]),
            ("public/node_modules/junk.html", &[][..]),
        ];
        let resolved = vec!["public/index.html".to_string()];
        let exclude = vec!["public/skip-me.html".to_string()];
        let report = scan_for_drift(&resolved, &exclude, fake_fs(&files)).unwrap();
        assert_eq!(report.orphans, vec!["public/orphan.html".to_string()]);
        assert_eq!(report.orphan_count, 1);
        assert!(report.hint.contains("1 HTML file"));
    }

    #[test]
    fn scan_for_drift_caps_orphans_at_20_but_reports_true_count() {
        let mut file_list: Vec<(String, &[&str])> = Vec::new();
        for i in 0..25 {
            file_list.push((format!("public/o{i}.html"), &[][..]));
        }
        let files_ref: Vec<(&str, &[&str])> = file_list.iter().map(|(p, _)| (p.as_str(), &[][..])).collect();
        let report = scan_for_drift(&[], &[], fake_fs(&files_ref)).unwrap();
        assert_eq!(report.orphans.len(), 20);
        assert_eq!(report.orphan_count, 25);
    }
}
