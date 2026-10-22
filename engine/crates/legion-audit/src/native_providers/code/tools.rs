//! Policy-bound tool runs for the `code.*` providers.
//!
//! The self-sourced evidence in [`super::evidence`] only *discovers* the
//! compilers, linters and type checkers a provider names. This module runs the
//! ones that are safe to run, through the same sandboxed external-tool route
//! the legacy checks and the security producer use (`ExternalProjectTool`,
//! typically `AuditExternalProjectTool` over `EffectExecutor`):
//!
//! * argv only, never a shell; the executable is resolved by this module and
//!   its digest sealed in the request;
//! * environment is the legacy allowlist from `audit_environment(&scratch)`:
//!   every temp, cache and target directory lives in the run's `AuditScratch`,
//!   never in the audited tree;
//! * macOS runs inside the authenticated deny-network sandbox; a host without
//!   an authenticator yields the typed gap `sandbox-missing:<tool>` instead of
//!   an unsandboxed run (unless the host explicitly disables the policy);
//! * every tool is invoked with its offline flag where one exists.
//!
//! What runs (only when the matching manifest/config is in the frozen
//! denominator, and the tool is installed):
//!
//! | provider | analyzer tool | command |
//! |----------|---------------|---------|
//! | `code.rust` | `metadata` | `cargo metadata --locked --offline --format-version 1` |
//! | | `check` | `cargo check --locked --offline --workspace --all-targets --message-format=json` |
//! | | `lint` | `cargo clippy --locked --offline --workspace --all-targets --message-format=json` (only if `cargo-clippy` is installed) |
//! | | `test` | `cargo test --locked --offline --workspace --all-targets` (exact SDK authorization required) |
//! | `code.javascript` | `type` | `<local>/node_modules/.bin/tsc --noEmit -p tsconfig.json --pretty false` |
//! | | `lint` | `<local>/node_modules/.bin/eslint --no-cache --format json --no-error-on-unmatched-pattern .` |
//! | `code.python` | `compile` | `python3 -I -B -c <py_compile to scratch> <list> <scratch>` |
//! | | `lint` | `ruff check --no-cache --output-format json .` |
//! | | `type` | `mypy --no-incremental --cache-dir <scratch> --no-color-output --show-error-codes --no-pretty .` |
//! | | `test` | `pytest --assert=plain -o cache_dir=<scratch> --basetemp <scratch>` |
//! | | `package` | `python3 -I -B -m build --wheel --no-isolation --outdir <scratch> <frozen packageRoot>` plus actual wheel validation |
//! | `code.dotnet` | `restore` / `build` / `analyzer` / `test` | Enrolled SDK8, sealed expanded NuGet cache, Roslyn/FSharpLint & retained TRX (requires exact injected SDK authorization) |
//! | `code.long-tail` | shell / PowerShell syntax | parse-only invocations, isolated source snapshots |
//!
//! Rust builds & tests and Python configured tools/backends execute project code only through
//! supplied ExternalProjectTool; Python uses frozen staged inputs & denies writes
//! to the original audited tree. Explicit package/v1 never installs dependencies. The
//! installed CLI's OwnerAdmissionRequired policy remains denied. An SDK
//! caller must supply its own exact policy admission & authenticated sandbox.
//! Other historical build/test contracts remain deferred plans; package installs
//! & network-dependent audits never become tool passes.

use super::evidence::NativeFinding;
use crate::{
    inventory::InventoryEntry,
    native_providers::{
        legacy_checks::{audit_environment, AuditScratch},
        security::producer::SandboxPolicy,
    },
};
use legion_provider_sdk::{
    ExecutionReceipt, ExecutionState, ExternalProjectTool, ExternalToolRequest,
};
use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, HashMap},
    path::{Component, Path, PathBuf},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

#[path = "dotnet_sdk.rs"]
mod dotnet_sdk;
#[cfg(test)]
#[path = "dotnet_sdk_accuracy.rs"]
mod dotnet_sdk_accuracy;
#[path = "javascript_sdk.rs"]
mod javascript_sdk;
#[path = "mobile_sdk.rs"]
mod mobile_sdk;
#[path = "native_commands.rs"]
mod native_commands;
#[path = "python_commands.rs"]
mod python_commands;
#[path = "rust_dependency.rs"]
mod rust_dependency;

/// Findings kept per provider from tool diagnostics; the rest is a counted gap.
pub const MAX_TOOL_FINDINGS: usize = 200;
/// Reason attached to project command contracts without an SDK execution route.
pub const POLICY_NO_PROJECT_CODE: &str = "policy-no-project-code-execution";
const MAX_ROOTS: usize = 6;
const MAX_MANIFEST_BYTES: u64 = 512 * 1024;
const MAX_MESSAGE_CHARS: usize = 300;
const POLICY_ID: &str = "audit";

const CONFIG_FILES_ESLINT: &[&str] = &[
    "eslint.config.js",
    "eslint.config.mjs",
    "eslint.config.cjs",
    "eslint.config.ts",
    "eslint.config.mts",
    "eslint.config.cts",
    ".eslintrc",
    ".eslintrc.js",
    ".eslintrc.cjs",
    ".eslintrc.json",
    ".eslintrc.yml",
    ".eslintrc.yaml",
];
const PYTHON_PROJECT_FILES: &[&str] = &[
    "pyproject.toml",
    "ruff.toml",
    ".ruff.toml",
    "setup.py",
    "setup.cfg",
    "requirements.txt",
    "Pipfile",
];

/// Run-scoped inputs for the tool runner.
pub struct ToolContext<'a> {
    pub root: &'a Path,
    pub tool: &'a dyn ExternalProjectTool,
    pub scratch: &'a AuditScratch,
    pub sandbox: SandboxPolicy,
    #[cfg(all(test, target_os = "macos"))]
    pub dotnet_qualification_loopback: bool,
    pub search_path: Option<&'a [PathBuf]>,
    pub plan_digest: &'a str,
    pub inventory_digest: &'a str,
    pub provider_id: &'a str,
    pub per_tool_timeout_ms: u64,
    pub total_budget_ms: u64,
    pub output_limit: usize,
}

/// What happened to one analyzer tool id.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// Every planned run completed and its output parsed.
    Ran,
    Missing,
    AdmissionUnavailable,
    Timeout,
    Budget,
    SandboxMissing,
    /// Full typed reason, e.g. `tool-failed:check:exit-101`.
    Failed(String),
    /// Not run, with the suffix naming why (`policy-...`, `no-manifest`).
    NotRun(String),
}

impl Outcome {
    /// The `unavailable:<reason>` payload for a tool that did not run.
    pub fn reason(&self, tool: &str) -> String {
        match self {
            Outcome::Ran => format!("tool-ran:{tool}"),
            Outcome::Missing => format!("tool-missing:{tool}"),
            Outcome::AdmissionUnavailable => crate::execution_policy::ADMISSION_UNAVAILABLE.into(),
            Outcome::Timeout => format!("tool-timeout:{tool}"),
            Outcome::Budget => format!("tool-budget-exhausted:{tool}"),
            Outcome::SandboxMissing => format!("sandbox-missing:{tool}"),
            Outcome::Failed(detail) => detail.clone(),
            Outcome::NotRun(why) => format!("tool-not-run:{tool}:{why}"),
        }
    }

    fn rank(&self) -> u8 {
        match self {
            Outcome::Ran => 0,
            Outcome::Missing | Outcome::NotRun(_) => 1,
            Outcome::AdmissionUnavailable => 3,
            Outcome::Failed(_) => 2,
            Outcome::SandboxMissing => 3,
            Outcome::Budget => 4,
            Outcome::Timeout => 5,
        }
    }
}

/// Everything the tool runs produced for one provider.
#[derive(Debug, Default)]
pub struct ToolEvidence {
    /// Analyzer input `tools` object (`status`, `identity`, `artifactDigest`, `scope`).
    pub tools: Map<String, Value>,
    /// Context proven by native tool output, not manifest membership.
    pub validated_context: Map<String, Value>,
    pub outcomes: BTreeMap<&'static str, Outcome>,
    /// Deduplicated, capped diagnostics inside the denominator.
    pub findings: Vec<NativeFinding>,
    /// Provider-prefixed gap strings (outside-denominator, truncation, ...).
    pub gaps: Vec<String>,
    /// One receipt summary per tool run.
    pub receipts: Vec<Value>,
    /// Applicable command contracts blocked by project execution policy.
    /// These are plans, never execution receipts or completed tool evidence.
    pub deferred_commands: Vec<Value>,
}

// ---------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Parser {
    CargoMetadata,
    /// `true` for clippy (lint) runs.
    CargoJson(bool),
    Tsc,
    Eslint,
    Ruff,
    PyCompile,
    Mypy,
    PythonWheel,
    Dotnet,
    RustDependency,
    /// Exit-only project command contract: failure is a gap, never a fabricated finding.
    Process,
    Syntax,
    MobileCompiler,
    MobileLint,
    MobileProcess,
}

struct Planned {
    /// Analyzer tool id this run is evidence for.
    tool: &'static str,
    /// Candidate executable names, first found wins.
    programs: &'static [&'static str],
    /// Look only in `node_modules/.bin` (walking up to the root).
    local_bin: bool,
    /// Also resolve next to this already-resolved program (a cargo subcommand beside `cargo`).
    sibling_of: Option<&'static str>,
    /// Extra executable that must exist (`cargo-clippy`).
    requires: Option<&'static str>,
    cwd_rel: String,
    args: Vec<String>,
    parser: Parser,
    accepted: &'static [i32],
    env: Vec<(&'static str, String)>,
    /// Diagnostics are printed on stderr rather than stdout.
    diagnostics_on_stderr: bool,
    /// Original denominator path for an isolated syntax input.
    source_path: Option<String>,
    source_digest: Option<String>,
}

#[derive(Default)]
struct Plan {
    commands: Vec<Planned>,
    /// Tool id -> why nothing was planned for it.
    not_planned: BTreeMap<&'static str, &'static str>,
    /// Provider-agnostic notes (`tool-roots-truncated:cargo:2`).
    notes: Vec<String>,
    /// Scratch files to remove after the runs.
    cleanup: Vec<PathBuf>,
    /// Frozen original input maps for dependency runs, keyed by cwd.
    rust_dependency_bindings: BTreeMap<String, Value>,
    deferred: Vec<Planned>,
}

fn name_of(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn dir_of(path: &str) -> String {
    match path.rfind('/') {
        Some(index) => path[..index].to_string(),
        None => String::new(),
    }
}

fn is_within(child: &str, parent: &str) -> bool {
    if child == parent {
        return false;
    }
    parent.is_empty() || child.starts_with(&format!("{parent}/"))
}

fn dirs_named(entries: &[InventoryEntry], names: &[&str]) -> BTreeSet<String> {
    entries
        .iter()
        .filter(|entry| names.contains(&name_of(&entry.path)))
        .map(|entry| dir_of(&entry.path))
        .collect()
}

fn read_small(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_MANIFEST_BYTES {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

fn cap_roots(mut dirs: Vec<String>, tool: &str, notes: &mut Vec<String>) -> Vec<String> {
    if dirs.len() > MAX_ROOTS {
        notes.push(format!(
            "tool-roots-truncated:{tool}:{}",
            dirs.len() - MAX_ROOTS
        ));
        dirs.truncate(MAX_ROOTS);
    }
    dirs
}

fn plan_rust(root: &Path, entries: &[InventoryEntry], plan: &mut Plan) {
    let manifests = dirs_named(entries, &["Cargo.toml"]);
    if manifests.is_empty() {
        for tool in ["metadata", "check", "lint", "test"] {
            plan.not_planned.insert(tool, "no-manifest");
        }
        return;
    }
    let workspaces: Vec<String> = manifests
        .iter()
        .filter(|dir| {
            read_small(&root.join(dir.as_str()).join("Cargo.toml")).is_some_and(|text| {
                text.lines().any(|line| {
                    let line = line.trim();
                    line == "[workspace]" || line.starts_with("[workspace.")
                })
            })
        })
        .cloned()
        .collect();
    let run_roots: Vec<String> = manifests
        .iter()
        .filter(|dir| {
            !workspaces
                .iter()
                .any(|workspace| is_within(dir.as_str(), workspace.as_str()))
        })
        .cloned()
        .collect();
    let run_roots = cap_roots(run_roots, "cargo", &mut plan.notes);
    for dir in run_roots {
        let command =
            |tool: &'static str, args: &[&str], parser: Parser, accepted: &'static [i32]| Planned {
                tool,
                programs: &["cargo"],
                local_bin: false,
                sibling_of: None,
                requires: None,
                cwd_rel: dir.clone(),
                args: args.iter().map(|arg| (*arg).to_owned()).collect(),
                parser,
                accepted,
                env: Vec::new(),
                diagnostics_on_stderr: false,
                source_path: None,
                source_digest: None,
            };
        plan.commands.push(command(
            "metadata",
            &["metadata", "--locked", "--offline", "--format-version", "1"],
            Parser::CargoMetadata,
            &[0],
        ));
        plan.commands.push(command(
            "check",
            &[
                "check",
                "--locked",
                "--offline",
                "--workspace",
                "--all-targets",
                "--message-format=json",
            ],
            Parser::CargoJson(false),
            &[0, 101],
        ));
        let mut lint = command(
            "lint",
            &[
                "clippy",
                "--locked",
                "--offline",
                "--workspace",
                "--all-targets",
                "--message-format=json",
            ],
            Parser::CargoJson(true),
            &[0, 101],
        );
        lint.requires = Some("cargo-clippy");
        lint.sibling_of = Some("cargo");
        plan.commands.push(lint);
        let test = command(
            "test",
            &[
                "test",
                "--locked",
                "--offline",
                "--workspace",
                "--all-targets",
            ],
            Parser::Process,
            &[0],
        );
        plan.commands.push(test);
    }
}

fn plan_javascript(
    root: &Path,
    entries: &[InventoryEntry],
    scratch: &AuditScratch,
    plan: &mut Plan,
) {
    let tsconfigs = cap_roots(
        dirs_named(entries, &["tsconfig.json"])
            .into_iter()
            .collect(),
        "tsc",
        &mut plan.notes,
    );
    if tsconfigs.is_empty() {
        plan.not_planned.insert("type", "no-config");
    }
    for (index, dir) in tsconfigs.into_iter().enumerate() {
        let mut args: Vec<String> = ["--noEmit", "-p", "tsconfig.json", "--pretty", "false"]
            .iter()
            .map(|arg| (*arg).to_owned())
            .collect();
        // An incremental/composite project would otherwise drop a
        // .tsbuildinfo beside the sources even with --noEmit.
        let tsconfig = root.join(&dir).join("tsconfig.json");
        if read_small(&tsconfig)
            .is_some_and(|text| text.contains("\"incremental\"") || text.contains("\"composite\""))
        {
            args.push("--tsBuildInfoFile".into());
            args.push(
                scratch
                    .cache_dir()
                    .join(format!("tsc-{index}.tsbuildinfo"))
                    .to_string_lossy()
                    .into_owned(),
            );
        }
        plan.commands.push(Planned {
            tool: "type",
            programs: &["tsc"],
            local_bin: true,
            sibling_of: None,
            requires: None,
            cwd_rel: dir,
            args,
            parser: Parser::Tsc,
            accepted: &[0, 1, 2],
            env: Vec::new(),
            diagnostics_on_stderr: false,
            source_path: None,
            source_digest: None,
        });
    }
    let eslint_dirs = cap_roots(
        dirs_named(entries, CONFIG_FILES_ESLINT)
            .into_iter()
            .collect(),
        "eslint",
        &mut plan.notes,
    );
    if eslint_dirs.is_empty() {
        plan.not_planned.insert("lint", "no-config");
    }
    for dir in eslint_dirs {
        plan.commands.push(Planned {
            tool: "lint",
            programs: &["eslint"],
            local_bin: true,
            sibling_of: None,
            requires: None,
            cwd_rel: dir,
            args: [
                "--no-cache",
                "--format",
                "json",
                "--no-error-on-unmatched-pattern",
                ".",
            ]
            .iter()
            .map(|arg| (*arg).to_owned())
            .collect(),
            parser: Parser::Eslint,
            accepted: &[0, 1],
            env: Vec::new(),
            diagnostics_on_stderr: false,
            source_path: None,
            source_digest: None,
        });
    }
}

const PY_COMPILE_SCRIPT: &str = r#"
import sys, os, json, py_compile
lst, out = sys.argv[1], sys.argv[2]
with open(lst, encoding='utf-8') as source:
    files = json.load(source)
if not files or files != json.loads(sys.argv[3]) or len(set(files)) != len(files):
    raise ValueError('invalid frozen compile scope')
for i, rel in enumerate(files):
    if not isinstance(rel, str) or not os.path.isfile(rel):
        raise ValueError('frozen compile source unavailable')
    try:
        py_compile.compile(rel, cfile=os.path.join(out, '%d.pyc' % i), doraise=True)
    except py_compile.PyCompileError as e:
        v = e.exc_value
        msg = getattr(v, 'msg', None) or str(e.msg).strip().splitlines()[-1]
        print(json.dumps({'path': rel, 'line': getattr(v, 'lineno', None) or 1, 'message': str(msg)[:300]}))
print(json.dumps({'done': len(files), 'files': files}))
"#;

fn plan_python(
    root: &Path,
    entries: &[InventoryEntry],
    selected: &BTreeSet<String>,
    scratch: &AuditScratch,
    plan: &mut Plan,
) {
    let (stage, input_digest) = match python_commands::stage(root, entries, scratch) {
        Ok(stage) => stage,
        Err(reason) => {
            plan.notes.push(reason);
            for tool in ["compile", "lint", "type", "test", "package"] {
                plan.not_planned
                    .insert(tool, "python-frozen-input-incomplete");
            }
            return;
        }
    };
    if !selected.is_empty() {
        let list = scratch.tmp_dir().join("py-compile-files.txt");
        let body = serde_json::to_vec(selected).expect("frozen path set serializes");
        let out_dir = scratch.cache_dir().join("py-compile");
        if std::fs::write(&list, &body).is_ok() && std::fs::create_dir_all(&out_dir).is_ok() {
            plan.cleanup.push(list.clone());
            plan.commands.push(Planned {
                tool: "compile",
                programs: &["python3", "python"],
                local_bin: false,
                sibling_of: None,
                requires: None,
                cwd_rel: stage.to_string_lossy().into_owned(),
                args: vec![
                    "-I".into(),
                    "-B".into(),
                    "-c".into(),
                    PY_COMPILE_SCRIPT.into(),
                    list.to_string_lossy().into_owned(),
                    out_dir.to_string_lossy().into_owned(),
                    String::from_utf8(body).expect("frozen path JSON is UTF-8"),
                ],
                parser: Parser::PyCompile,
                accepted: &[0, 1],
                env: vec![("PYTHONSAFEPATH", "1".into())],
                diagnostics_on_stderr: false,
                source_path: None,
                source_digest: Some(input_digest.clone()),
            });
        } else {
            plan.not_planned.insert("compile", "scratch-unwritable");
        }
    }
    if dirs_named(entries, PYTHON_PROJECT_FILES).is_empty() {
        plan.not_planned.insert("lint", "no-manifest");
    } else {
        plan.commands.push(Planned {
            tool: "lint",
            programs: &["ruff"],
            local_bin: false,
            sibling_of: None,
            requires: None,
            cwd_rel: stage.to_string_lossy().into_owned(),
            args: ["check", "--no-cache", "--output-format", "json", "."]
                .iter()
                .map(|arg| (*arg).to_owned())
                .collect(),
            parser: Parser::Ruff,
            accepted: &[0, 1],
            env: vec![("PYTHONSAFEPATH", "1".into())],
            diagnostics_on_stderr: false,
            source_path: None,
            source_digest: Some(input_digest.clone()),
        });
    }
    // Ruff config may exclude frozen sources; JSON findings do not prove checked-file scope.
    // Preserve this runtime gap even when every sealed known-answer control matches.
    if plan.commands.iter().any(|command| command.tool == "lint") {
        plan.notes.push("lint-scope-unproven".into());
    }
    python_commands::extend(entries, scratch, &stage, &input_digest, plan);
}

/// Analyzer tool ids that are never run, with the typed reason.
fn policy_tools(provider_id: &str) -> &'static [&'static str] {
    match provider_id {
        "code.javascript" => &["build", "test"],
        "code.rust" | "code.python" | "code.dotnet" => &[],
        _ => &["test"],
    }
}

fn plan_commands(
    provider_id: &str,
    root: &Path,
    entries: &[InventoryEntry],
    selected: &BTreeSet<String>,
    scratch: &AuditScratch,
) -> Plan {
    let mut plan = Plan::default();
    match provider_id {
        "code.rust" => plan_rust(root, entries, &mut plan),
        "code.javascript" => plan_javascript(root, entries, scratch, &mut plan),
        "code.python" => plan_python(root, entries, selected, scratch, &mut plan),
        "code.mobile" => mobile_sdk::plan(root, entries, selected, scratch, &mut plan),
        _ => {}
    }
    native_commands::plan(provider_id, root, entries, selected, scratch, &mut plan);
    if provider_id == "code.rust" {
        rust_dependency::plan(root, entries, scratch, &mut plan);
    }
    if provider_id == "code.javascript" {
        javascript_sdk::plan(root, entries, selected, scratch, &mut plan);
    }
    plan
}

// ---------------------------------------------------------------------------
// Path handling
// ---------------------------------------------------------------------------

/// `raw` as printed by a tool run in `cwd_rel`, normalized to a repo-relative
/// forward-slash path. `None` when it lies outside the repository.
fn repo_relative(root: &Path, canonical_root: &Path, cwd_rel: &str, raw: &str) -> Option<String> {
    let raw = raw.replace('\\', "/");
    let path = Path::new(&raw);
    let joined: PathBuf = if path.is_absolute() {
        match path
            .strip_prefix(root)
            .or_else(|_| path.strip_prefix(canonical_root))
        {
            Ok(rest) => rest.to_path_buf(),
            Err(_) => return None,
        }
    } else if cwd_rel.is_empty() {
        path.to_path_buf()
    } else {
        Path::new(cwd_rel).join(path)
    };
    let mut parts: Vec<String> = Vec::new();
    for component in joined.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            Component::CurDir => {}
            Component::ParentDir => {
                parts.pop()?;
            }
            _ => return None,
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("/"))
    }
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

fn in_dir(dir: &Path, name: &str) -> Option<PathBuf> {
    let mut candidates = vec![dir.join(name)];
    if cfg!(windows) {
        for extension in ["exe", "cmd", "bat", "com"] {
            candidates.push(dir.join(format!("{name}.{extension}")));
        }
    }
    candidates.into_iter().find(|path| is_executable(path))
}

fn sha256_text(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

struct Resolver<'a> {
    ctx: &'a ToolContext<'a>,
    cache: HashMap<String, Option<PathBuf>>,
    digests: HashMap<PathBuf, Option<String>>,
}

impl<'a> Resolver<'a> {
    fn new(ctx: &'a ToolContext<'a>) -> Self {
        Self {
            ctx,
            cache: HashMap::new(),
            digests: HashMap::new(),
        }
    }

    fn search_dirs(&self) -> Vec<PathBuf> {
        match self.ctx.search_path {
            Some(dirs) => dirs.to_vec(),
            None => std::env::var_os("PATH")
                .map(|path| std::env::split_paths(&path).collect())
                .unwrap_or_default(),
        }
    }

    fn on_path(&self, name: &str) -> Option<PathBuf> {
        self.search_dirs().iter().find_map(|dir| in_dir(dir, name))
    }

    fn local_bin(&self, cwd: &Path, name: &str) -> Option<PathBuf> {
        let mut dir = cwd.to_path_buf();
        loop {
            if let Some(found) = in_dir(&dir.join("node_modules/.bin"), name) {
                return Some(found);
            }
            if dir == self.ctx.root || !dir.starts_with(self.ctx.root) {
                return None;
            }
            dir = dir.parent()?.to_path_buf();
        }
    }

    fn resolve(&mut self, command: &Planned, cwd: &Path) -> Option<PathBuf> {
        let key = format!(
            "{}|{}|{}|{}",
            command.programs.join(","),
            command.local_bin,
            command.sibling_of.unwrap_or(""),
            if command.local_bin {
                cwd.to_string_lossy().into_owned()
            } else {
                String::new()
            }
        );
        if let Some(cached) = self.cache.get(&key) {
            return cached.clone();
        }
        let found = command.programs.iter().find_map(|name| {
            if mobile_sdk::is_mobile(command.parser) {
                mobile_sdk::resolve(self.ctx, command, name)
            } else if command.local_bin {
                self.local_bin(cwd, name)
            } else {
                self.on_path(name)
                    .or_else(|| self.beside(command.sibling_of, name))
            }
        });
        self.cache.insert(key, found.clone());
        found
    }

    /// `name` in the directory of the resolved `sibling` program (symlink and
    /// canonical directory both tried).
    fn beside(&self, sibling: Option<&str>, name: &str) -> Option<PathBuf> {
        let sibling = self.on_path(sibling?)?;
        let mut dirs = Vec::new();
        if let Some(parent) = sibling.parent() {
            dirs.push(parent.to_path_buf());
        }
        if let Some(parent) = std::fs::canonicalize(&sibling)
            .ok()
            .and_then(|path| path.parent().map(Path::to_path_buf))
        {
            dirs.push(parent);
        }
        dirs.iter().find_map(|dir| in_dir(dir, name))
    }

    fn has_required(&self, command: &Planned) -> bool {
        match command.requires {
            None => true,
            Some(name) => self
                .on_path(name)
                .or_else(|| self.beside(command.sibling_of, name))
                .is_some(),
        }
    }

    fn digest(&mut self, path: &Path) -> Option<String> {
        if let Some(cached) = self.digests.get(path) {
            return cached.clone();
        }
        let digest = std::fs::canonicalize(path)
            .ok()
            .and_then(|canonical| std::fs::read(canonical).ok())
            .map(|bytes| sha256_text(&bytes));
        self.digests.insert(path.to_path_buf(), digest.clone());
        digest
    }
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

struct RunOutput {
    outcome: Outcome,
    receipt: Option<Value>,
    version: String,
    program: String,
    executable_digest: String,
    stdout_digest: Option<String>,
    diagnostics: Vec<Diag>,
    covered: BTreeSet<String>,
}

impl RunOutput {
    fn failed(outcome: Outcome) -> Self {
        Self {
            outcome,
            receipt: None,
            version: String::new(),
            program: String::new(),
            executable_digest: String::new(),
            stdout_digest: None,
            diagnostics: Vec::new(),
            covered: BTreeSet::new(),
        }
    }
}

struct Diag {
    rule: String,
    severity: &'static str,
    path: String,
    line: usize,
    message: String,
}

pub(super) fn read_artifact(
    scratch: &AuditScratch,
    record: &legion_effects::ArtifactRecord,
) -> Option<Vec<u8>> {
    if !record.immutable {
        return None;
    }
    let path = Path::new(&record.path);
    let bytes = if path.is_absolute() {
        std::fs::read(path).ok()?
    } else {
        std::fs::read(scratch.artifacts_dir().join(path)).ok()?
    };
    (bytes.len() == record.bytes && sha256_text(&bytes) == record.digest).then_some(bytes)
}

pub(super) fn classify(tool: &str, receipt: &ExecutionReceipt) -> Option<Outcome> {
    if receipt.state == ExecutionState::UnauthorizedEffect
        && !receipt.process_tree.started
        && receipt.policy.as_ref().is_some_and(|policy| {
            policy.id == crate::execution_policy::POLICY_ID
                && !policy.allowed
                && policy.reason.as_deref() == Some(crate::execution_policy::ADMISSION_UNAVAILABLE)
        })
    {
        return Some(Outcome::AdmissionUnavailable);
    }
    match receipt.state {
        ExecutionState::Completed if receipt.complete => None,
        ExecutionState::Completed => {
            Some(Outcome::Failed(format!("tool-failed:{tool}:incomplete")))
        }
        ExecutionState::MissingExecutable => Some(Outcome::Missing),
        ExecutionState::Timeout => Some(Outcome::Timeout),
        ExecutionState::SandboxMissing => Some(Outcome::SandboxMissing),
        ExecutionState::OutputLimited => Some(Outcome::Failed(format!("output-limited:{tool}"))),
        ExecutionState::Cancelled => Some(Outcome::Failed(format!("tool-cancelled:{tool}"))),
        ExecutionState::Failed => Some(Outcome::Failed(match receipt.exit_code {
            Some(code) => format!("tool-failed:{tool}:exit-{code}"),
            None => format!("tool-failed:{tool}:failed"),
        })),
        other => Some(Outcome::Failed(format!(
            "tool-failed:{tool}:{}",
            other.as_str()
        ))),
    }
}

fn shorten(text: &str) -> String {
    let single = text.split_whitespace().collect::<Vec<_>>().join(" ");
    single.chars().take(MAX_MESSAGE_CHARS).collect()
}

async fn run_one(
    ctx: &ToolContext<'_>,
    resolver: &mut Resolver<'_>,
    command: &Planned,
    rust_binding: Option<&Value>,
    sequence: usize,
    timeout_ms: u64,
    cancellation: CancellationToken,
) -> RunOutput {
    if mobile_sdk::is_mobile(command.parser) {
        if let Err(reason) = mobile_sdk::snapshot(command) {
            return RunOutput::failed(Outcome::Failed(format!(
                "tool-failed:{}:input-before:{reason}",
                command.tool
            )));
        }
    }
    let cwd = if command.cwd_rel.is_empty() {
        ctx.root.to_path_buf()
    } else {
        ctx.root.join(&command.cwd_rel)
    };
    if !resolver.has_required(command) {
        return RunOutput::failed(Outcome::Missing);
    }
    let Some(executable) = resolver.resolve(command, &cwd) else {
        return RunOutput::failed(Outcome::Missing);
    };
    let Some(executable_digest) = resolver.digest(&executable) else {
        return RunOutput::failed(Outcome::Missing);
    };
    if command.parser == Parser::Dotnet {
        if ctx.sandbox != SandboxPolicy::Required {
            return RunOutput::failed(Outcome::NotRun(
                "dotnet-requires-authenticated-sandbox".into(),
            ));
        }
        if let Err(reason) = dotnet_sdk::executable_valid(command, &executable) {
            return RunOutput::failed(Outcome::Failed(format!(
                "tool-failed:{}:{reason}",
                command.tool
            )));
        }
    }
    let program = command
        .programs
        .iter()
        .find(|name| {
            executable
                .file_name()
                .and_then(|file| file.to_str())
                .is_some_and(|file| file == **name || file.starts_with(&format!("{name}.")))
        })
        .copied()
        .unwrap_or(command.programs[0])
        .to_owned();

    let (mut environment, mut allowlist) = audit_environment(ctx.scratch);
    if let Some(dirs) = ctx.search_path {
        if let Ok(joined) = std::env::join_paths(dirs) {
            environment.insert("PATH".into(), joined.to_string_lossy().into_owned());
        }
    }
    for name in ["CARGO_HOME", "RUSTUP_HOME"] {
        if let Ok(value) = std::env::var(name) {
            environment.insert(name.into(), value);
            allowlist.insert(name.into());
        }
    }
    // Apple rustc needs SDK selection for native linking; this is input, not authority.
    // Qualification binds exact selection/config/SDK bytes independently.
    if ctx.provider_id == "code.rust" {
        if let Ok(value) = std::env::var("SDKROOT") {
            environment.insert("SDKROOT".into(), value);
            allowlist.insert("SDKROOT".into());
        }
    }
    let fixed: [(&str, &str); 3] = [
        ("NO_COLOR", "1"),
        ("CARGO_NET_OFFLINE", "true"),
        ("CARGO_TERM_COLOR", "never"),
    ];
    for (name, value) in fixed {
        environment.insert(name.into(), value.into());
        allowlist.insert(name.into());
    }
    for (name, value) in &command.env {
        environment.insert((*name).into(), value.clone());
        allowlist.insert((*name).into());
    }
    let executable_text = executable.to_string_lossy().into_owned();
    let cwd_text = cwd.to_string_lossy().into_owned();
    // PowerShell uses its profile-free probe.
    let version_probe_executable = executable_text.clone();
    let tool_version_args = if command.parser == Parser::Dotnet {
        dotnet_sdk::version_args(command)
    } else if command.tool == "powershell-syntax" {
        vec![
            "-NoLogo".into(),
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-Command".into(),
            "$PSVersionTable.PSVersion.ToString()".into(),
        ]
    } else {
        vec!["--version".into()]
    };
    let (launch_executable, launch_args, sandbox, version_args, needs_sandbox) = match ctx.sandbox {
        SandboxPolicy::Disabled => (
            executable_text.clone(),
            command.args.clone(),
            None,
            None,
            false,
        ),
        SandboxPolicy::Required => {
            let authenticate = || {
                legion_effects::authenticate_sandbox(
                    &executable_text,
                    &command.args,
                    if ctx.provider_id == "code.python" {
                        ctx.root.to_str().unwrap_or("")
                    } else {
                        &cwd_text
                    },
                    if ctx.provider_id == "code.python" {
                        legion_effects::SandboxMode::DenyNetworkDenyProjectWrite
                    } else {
                        legion_effects::SandboxMode::DenyNetwork
                    },
                    &ctx.scratch.sandbox_dir(),
                )
            };
            #[cfg(all(test, target_os = "macos"))]
            let authentication = {
                dotnet_sdk_accuracy::apply_qualification_environment(
                    ctx.dotnet_qualification_loopback,
                    ctx.provider_id,
                    command.tool,
                    &mut environment,
                    &mut allowlist,
                );
                dotnet_sdk_accuracy::authenticate_qualification_sandbox(
                    ctx,
                    command.tool,
                    &executable_text,
                    &command.args,
                    &cwd_text,
                )
                .unwrap_or_else(authenticate)
            };
            #[cfg(not(all(test, target_os = "macos")))]
            let authentication = authenticate();
            match authentication {
                Ok(auth) => {
                    // Probe the real tool's version through the same wrapper
                    // prefix (`-f profile -- tool`).
                    let mut probe: Vec<String> =
                        auth.wrapped_args.iter().take(3).cloned().collect();
                    probe.push(version_probe_executable.clone());
                    probe.extend(tool_version_args.iter().cloned());
                    (
                        auth.wrapped_executable,
                        auth.wrapped_args,
                        Some(legion_effects::SandboxReceipt {
                            id: auth.id,
                            network: auth.network,
                            filesystem_scope: auth.filesystem_scope,
                        }),
                        Some(probe),
                        true,
                    )
                }
                // No authenticator: the executor refuses the absent receipt.
                Err(_) => (
                    executable_text.clone(),
                    command.args.clone(),
                    None,
                    None,
                    true,
                ),
            }
        }
    };
    let native_tool_identity = mobile_sdk::is_mobile(command.parser).then(|| json!({
        "path": executable, "digest": executable_digest,
        "identityScope": "native executable; installed SDK/runtime enrollment recorded in nativeInputSnapshots",
    }));
    let launch_digest = resolver.digest(Path::new(&launch_executable));

    let request = ExternalToolRequest {
        request_id: format!(
            "audit:code:{}:{}:{sequence}:{}",
            ctx.provider_id, command.tool, ctx.inventory_digest
        ),
        provider_id: ctx.provider_id.to_owned(),
        plan_id: ctx.plan_digest.to_owned(),
        policy_id: POLICY_ID.into(),
        task_id: Some(command.tool.to_owned()),
        executable: launch_executable,
        args: launch_args,
        cwd: cwd_text,
        shell: false,
        expected_digest: launch_digest,
        accepted_exit_codes: command.accepted.iter().copied().collect(),
        environment,
        environment_allowlist: allowlist,
        requires_network_sandbox: needs_sandbox,
        sandbox,
        timeout_ms,
        stdout_limit: ctx.output_limit,
        stderr_limit: ctx.output_limit,
        version_args: version_args.unwrap_or(tool_version_args),
        ..ExternalToolRequest::default()
    };
    let javascript_command = ctx.provider_id == "code.javascript";
    let snapshot = || {
        if javascript_command {
            javascript_sdk::snapshot(ctx, command, &executable)
        } else if ctx.provider_id == "code.python" {
            python_commands::snapshot(command)
        } else if mobile_sdk::is_mobile(command.parser) {
            mobile_sdk::snapshot(command)
        } else if command.parser == Parser::Dotnet {
            dotnet_sdk::snapshot(command)
        } else {
            rust_dependency::snapshot(command, rust_binding, &executable)
        }
    };
    let native_input_before = if matches!(command.parser, Parser::RustDependency | Parser::Dotnet)
        || javascript_command
        || mobile_sdk::is_mobile(command.parser)
        || ctx.provider_id == "code.python"
    {
        match snapshot() {
            Ok(snapshot) => Some(snapshot),
            Err(reason) => {
                return RunOutput::failed(Outcome::Failed(format!(
                    "tool-failed:{}:input-before:{reason}",
                    command.tool
                )))
            }
        }
    } else {
        None
    };
    let receipt = ctx.tool.execute(request, cancellation).await;
    // Recheck even failed/refused executions. Retain actual receipt unchanged;
    // input snapshots describe closure stability, never authorize execution.
    let native_input_after = native_input_before.as_ref().map(|_| snapshot());
    let native_input_error = match (&native_input_before, &native_input_after) {
        (Some(before), Some(Ok(after))) if before != after => {
            Some("input-closure-changed".to_owned())
        }
        (Some(_), Some(Err(reason))) => Some(format!("input-after:{reason}")),
        _ => None,
    };

    let mut output = RunOutput::failed(Outcome::Ran);
    output.program = program.clone();
    output.executable_digest = executable_digest.clone();
    output.version = receipt
        .executable
        .as_ref()
        .and_then(|identity| identity.version.output.as_deref())
        .and_then(|text| text.lines().find(|line| !line.trim().is_empty()))
        .unwrap_or_default()
        .trim()
        .to_owned();
    let stdout = receipt
        .stdout
        .as_ref()
        .and_then(|record| read_artifact(ctx.scratch, record));
    let stderr = receipt
        .stderr
        .as_ref()
        .and_then(|record| read_artifact(ctx.scratch, record));
    output.stdout_digest = stdout.as_deref().map(sha256_text);
    let mut argv = vec![program];
    argv.extend(command.args.iter().map(|arg| {
        // The python script and scratch paths are noise in a receipt.
        if arg.len() > 200 {
            format!("<{} bytes>", arg.len())
        } else {
            arg.clone()
        }
    }));
    let cwd_label = if command.cwd_rel.is_empty() {
        ".".to_owned()
    } else {
        command.cwd_rel.clone()
    };
    let sandbox_mode = match ctx.sandbox {
        SandboxPolicy::Required if ctx.provider_id == "code.python" => {
            "deny-network-deny-project-write"
        }
        SandboxPolicy::Required => "deny-network",
        SandboxPolicy::Disabled => "disabled",
    };
    let stderr_digest = stderr.as_deref().map(sha256_text);
    let program_label = argv[0].clone();
    let mut retained_receipt = crate::execution_policy::receipt_json(&receipt);
    let mut summary = json!({
        "sdkReceipt": retained_receipt.clone(),
        "tool": command.tool,
        "program": program_label,
        "sourcePath": command.source_path,
        "sourceDigest": command.source_digest,
        "nativeToolIdentity": native_tool_identity,
        "version": output.version,
        "argv": argv,
        "cwd": cwd_label,
        "exitCode": receipt.exit_code,
        "state": receipt.state.as_str(),
        "complete": receipt.complete,
        "offline": true,
        "executableDigest": executable_digest,
        "artifactDigest": output.stdout_digest,
        "stderrDigest": stderr_digest,
        "receiptId": receipt.receipt_id,
        "policyId": receipt.policy_id,
        "durationMs": receipt.timing.duration_ms,
        "sandbox": {
            "mode": sandbox_mode,
            "required": receipt.sandbox.required,
            "receiptId": receipt.sandbox.receipt_id,
            "networkEnabled": receipt.sandbox.network_enabled,
        },
    });
    if let Some(before) = &native_input_before {
        summary["nativeInputSnapshots"] = json!({
            "before": before,
            "after": native_input_after.as_ref().and_then(|result| result.as_ref().ok()),
            "afterError": native_input_after.as_ref().and_then(|result| result.as_ref().err()),
            "unchanged": native_input_error.is_none(),
        });
    }
    if command.parser == Parser::Dotnet {
        let result = dotnet_sdk::results(command);
        summary["dotnetStandardResults"] =
            json!({"retained":result.as_ref().ok(),"error":result.as_ref().err()});
        summary["dotnetAnalyzerScope"] = dotnet_sdk::analyzer_scope(command);
    }
    for (key, value) in summary.as_object().expect("summary object") {
        if classify(command.tool, &receipt) == Some(Outcome::AdmissionUnavailable) {
            retained_receipt
                .as_object_mut()
                .expect("receipt object")
                .entry(key.clone())
                .or_insert_with(|| value.clone());
        } else {
            retained_receipt[key] = value.clone();
        }
    }
    output.receipt = Some(retained_receipt);
    if let Some(outcome) = classify(command.tool, &receipt) {
        output.outcome = outcome;
        return output;
    }
    if let Some(identity) = &native_tool_identity {
        if identity["path"]
            .as_str()
            .and_then(|path| std::fs::read(path).ok())
            .map(|bytes| sha256_text(&bytes))
            .as_deref()
            != identity["digest"].as_str()
        {
            output.outcome = Outcome::Failed(format!(
                "tool-failed:{}:native-executable-changed",
                command.tool
            ));
            return output;
        }
    }
    if let Some(reason) = native_input_error {
        output.outcome = Outcome::Failed(format!("tool-failed:{}:{reason}", command.tool));
        return output;
    }
    if javascript_command
        && command.programs.contains(&"pnpm")
        && native_input_before
            .as_ref()
            .and_then(|v| v["packageManagerVersion"].as_str())
            != Some(output.version.as_str())
    {
        output.outcome = Outcome::Failed(format!(
            "tool-failed:{}:declared-pnpm-version-mismatch",
            command.tool
        ));
        return output;
    }
    if matches!(
        command.parser,
        Parser::Syntax
            | Parser::Dotnet
            | Parser::Process
            | Parser::MobileCompiler
            | Parser::MobileLint
            | Parser::MobileProcess
    ) && (stdout.is_none() || stderr.is_none())
    {
        output.outcome = Outcome::Failed(format!("tool-output-unreadable:{}", command.tool));
        return output;
    }
    let syntax_output = (command.parser == Parser::Syntax).then(|| {
        let mut bytes = stdout.clone().unwrap_or_default();
        bytes.push(b'\n');
        bytes.extend_from_slice(stderr.as_deref().unwrap_or_default());
        bytes
    });
    let stream = if let Some(bytes) = &syntax_output {
        Some(bytes.as_slice())
    } else if command.diagnostics_on_stderr {
        stderr.as_deref()
    } else {
        stdout.as_deref()
    };
    let Some(bytes) = stream else {
        output.outcome = Outcome::Failed(format!("tool-output-unreadable:{}", command.tool));
        return output;
    };
    if javascript_command && matches!(command.parser, Parser::Tsc | Parser::Eslint) {
        match javascript_sdk::covered(ctx, command, bytes, receipt.exit_code) {
            Ok(covered) => output.covered = covered,
            Err(reason) => {
                output.outcome = Outcome::Failed(format!("tool-failed:{}:{reason}", command.tool));
                return output;
            }
        }
    }
    if javascript_command && ["build", "test"].contains(&command.tool) {
        match javascript_sdk::operation(
            ctx,
            command,
            bytes,
            stderr.as_deref().unwrap_or_default(),
            receipt.exit_code,
        ) {
            Ok((proof, covered)) => {
                output.covered = covered;
                if let Some(retained) = output.receipt.as_mut() {
                    retained["nativeOperationObservation"] = proof;
                }
            }
            Err(reason) => {
                output.outcome = Outcome::Failed(format!("tool-failed:{}:{reason}", command.tool));
                return output;
            }
        }
    }
    let parsed = if command.parser == Parser::Dotnet {
        dotnet_sdk::parse(
            command,
            bytes,
            stderr.as_deref().unwrap_or_default(),
            receipt.exit_code,
        )
    } else if javascript_command && command.parser == Parser::Tsc {
        javascript_sdk::typescript(ctx, command, bytes, receipt.exit_code).map(|v| v.0)
    } else if javascript_command && command.parser == Parser::Eslint {
        javascript_sdk::eslint(bytes, receipt.exit_code).map(|v| v.0)
    } else if mobile_sdk::is_mobile(command.parser) {
        mobile_sdk::parse(bytes, stderr.as_deref(), receipt.exit_code, command)
    } else if command.parser == Parser::RustDependency {
        rust_dependency::parse(bytes, receipt.exit_code, command, rust_binding)
    } else if command.parser == Parser::Mypy {
        if stderr.as_deref().is_none_or(|b| !b.is_empty()) {
            Err("mypy-stderr-unaccounted".into())
        } else {
            python_commands::parse_mypy(bytes, receipt.exit_code)
        }
    } else if command.parser == Parser::PythonWheel {
        python_commands::parse_wheel(bytes, command)
    } else if command.parser == Parser::PyCompile {
        let paths = command
            .args
            .get(6)
            .and_then(|data| serde_json::from_str::<BTreeSet<String>>(data).ok());
        match paths {
            Some(paths) => parse_py_compile(bytes, &paths),
            None => Err("compile-scope-unreadable".into()),
        }
    } else {
        parse(command.parser, bytes, receipt.exit_code)
    };
    match parsed {
        Ok(mut diagnostics) => {
            if let Some(path) = &command.source_path {
                for diagnostic in &mut diagnostics {
                    diagnostic.path = path.clone();
                }
            }
            output.diagnostics = diagnostics;
        }
        Err(reason) => {
            output.outcome = Outcome::Failed(format!("tool-failed:{}:{reason}", command.tool));
        }
    }
    if output.outcome == Outcome::Ran
        && matches!(command.parser, Parser::CargoJson(_))
        && (receipt.exit_code != Some(0) || !cargo_build_succeeded(bytes))
    {
        output.outcome = Outcome::Failed(format!(
            "tool-failed:{}:cargo-build-incomplete",
            command.tool
        ));
    }
    if output.outcome == Outcome::Ran && output.version.is_empty() {
        output.outcome =
            Outcome::Failed(format!("tool-failed:{}:version-unreadable", command.tool));
    }
    output
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

fn parse(parser: Parser, bytes: &[u8], exit: Option<i32>) -> Result<Vec<Diag>, String> {
    match parser {
        Parser::CargoMetadata => {
            let value: Value =
                serde_json::from_slice(bytes).map_err(|_| "unparseable-metadata".to_owned())?;
            if value.get("packages").and_then(Value::as_array).is_some() {
                Ok(Vec::new())
            } else {
                Err("unparseable-metadata".into())
            }
        }
        Parser::CargoJson(clippy) => parse_cargo(bytes, clippy),
        Parser::Tsc => parse_tsc(bytes, exit),
        Parser::Eslint => parse_eslint(bytes),
        Parser::Ruff => parse_ruff(bytes, exit),
        Parser::PyCompile => Err("compile-scope-required".into()),
        Parser::Mypy | Parser::PythonWheel => Err("python-frozen-context-required".into()),
        Parser::Dotnet => Err("dotnet-context-required".into()),
        Parser::RustDependency => Err("rust-dependency-source-binding-required".into()),
        Parser::Process => match exit {
            Some(0) => Ok(Vec::new()),
            Some(code) => Err(format!("exit-{code}")),
            None => Err("process-missing-exit-code".into()),
        },
        Parser::Syntax => parse_syntax(bytes, exit),
        Parser::MobileCompiler | Parser::MobileLint | Parser::MobileProcess => {
            Err("mobile-source-platform-binding-required".into())
        }
    }
}

fn line_of(value: Option<u64>) -> usize {
    value.unwrap_or(1).max(1) as usize
}

fn parse_syntax(bytes: &[u8], exit: Option<i32>) -> Result<Vec<Diag>, String> {
    if exit.is_none() {
        return Err("syntax-check-missing-exit-code".into());
    }
    if exit == Some(0) {
        return Ok(Vec::new());
    }
    let text = String::from_utf8_lossy(bytes);
    if text.trim().is_empty() {
        return Err("syntax-check-no-diagnostic".into());
    }
    let line = Regex::new(r"(?:line |:)(\d+)")
        .ok()
        .and_then(|re| re.captures(&text).and_then(|c| c[1].parse().ok()))
        .unwrap_or(1);
    Ok(vec![Diag {
        rule: "native-syntax".into(),
        severity: "error",
        path: String::new(),
        line,
        message: shorten(&text),
    }])
}

fn cargo_build_succeeded(bytes: &[u8]) -> bool {
    let mut completion = None;
    for line in String::from_utf8_lossy(bytes).lines() {
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if value.get("reason").and_then(Value::as_str) == Some("build-finished") {
            if completion.is_some() {
                return false;
            }
            completion = value.get("success").and_then(Value::as_bool);
            if completion.is_none() {
                return false;
            }
        }
    }
    completion == Some(true)
}

fn parse_cargo(bytes: &[u8], clippy: bool) -> Result<Vec<Diag>, String> {
    let _ = clippy;
    let text = String::from_utf8_lossy(bytes);
    let mut finished = false;
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        match value.get("reason").and_then(Value::as_str) {
            Some("build-finished") => finished = true,
            Some("compiler-message") => {
                let Some(message) = value.get("message") else {
                    continue;
                };
                let level = message.get("level").and_then(Value::as_str).unwrap_or("");
                if level != "error" && level != "warning" {
                    continue;
                }
                let spans = message.get("spans").and_then(Value::as_array);
                let primary = spans.and_then(|spans| {
                    spans
                        .iter()
                        .find(|span| span.get("is_primary").and_then(Value::as_bool) == Some(true))
                        .or_else(|| spans.first())
                });
                let Some(span) = primary else {
                    continue;
                };
                let Some(file) = span.get("file_name").and_then(Value::as_str) else {
                    continue;
                };
                let code = message
                    .get("code")
                    .and_then(|code| code.get("code"))
                    .and_then(Value::as_str);
                let rule = match code {
                    Some(code) if code.starts_with("clippy::") => {
                        format!("clippy:{}", &code["clippy::".len()..])
                    }
                    Some(code) => format!("rustc:{code}"),
                    None => "rustc".to_owned(),
                };
                let is_clippy_lint = code.is_some_and(|code| code.starts_with("clippy::"));
                out.push(Diag {
                    rule,
                    severity: if level == "error" && !is_clippy_lint {
                        "error"
                    } else {
                        "warning"
                    },
                    path: file.to_owned(),
                    line: line_of(span.get("line_start").and_then(Value::as_u64)),
                    message: shorten(
                        message
                            .get("message")
                            .and_then(Value::as_str)
                            .unwrap_or("compiler diagnostic"),
                    ),
                });
            }
            _ => {}
        }
    }
    if finished {
        Ok(out)
    } else {
        Err("no-build-finished".into())
    }
}

fn parse_tsc(bytes: &[u8], exit: Option<i32>) -> Result<Vec<Diag>, String> {
    let located = Regex::new(r"^(.+?)\((\d+),\d+\): (error|warning) (TS\d+): (.*)$")
        .map_err(|error| error.to_string())?;
    let global = Regex::new(r"^error TS\d+").map_err(|error| error.to_string())?;
    let text = String::from_utf8_lossy(bytes);
    let mut out = Vec::new();
    let mut global_error = false;
    for line in text.lines() {
        let line = line.trim_end();
        if let Some(captures) = located.captures(line) {
            out.push(Diag {
                rule: format!("tsc:{}", &captures[4]),
                severity: if &captures[3] == "error" {
                    "error"
                } else {
                    "warning"
                },
                path: captures[1].to_owned(),
                line: captures[2].parse::<usize>().unwrap_or(1).max(1),
                message: shorten(&captures[5]),
            });
        } else if global.is_match(line) {
            global_error = true;
        }
    }
    if global_error || (out.is_empty() && exit.is_some_and(|code| code != 0)) {
        return Err(format!("exit-{}", exit.unwrap_or(-1)));
    }
    Ok(out)
}

fn parse_eslint(bytes: &[u8]) -> Result<Vec<Diag>, String> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| "unparseable-output".to_owned())?;
    let results = value
        .as_array()
        .ok_or_else(|| "unparseable-output".to_owned())?;
    let mut out = Vec::new();
    for result in results {
        let Some(file) = result.get("filePath").and_then(Value::as_str) else {
            continue;
        };
        for message in result
            .get("messages")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let rule = message
                .get("ruleId")
                .and_then(Value::as_str)
                .unwrap_or("parse-error");
            let fatal = message.get("fatal").and_then(Value::as_bool) == Some(true);
            out.push(Diag {
                rule: format!("eslint:{rule}"),
                severity: if fatal { "error" } else { "warning" },
                path: file.to_owned(),
                line: line_of(message.get("line").and_then(Value::as_u64)),
                message: shorten(message.get("message").and_then(Value::as_str).unwrap_or("")),
            });
        }
    }
    Ok(out)
}

fn parse_ruff(bytes: &[u8], exit: Option<i32>) -> Result<Vec<Diag>, String> {
    let results: Vec<Value> =
        serde_json::from_slice(bytes).map_err(|_| "unparseable-output".to_owned())?;
    if !matches!(exit, Some(0 | 1)) || (exit == Some(0)) != results.is_empty() {
        return Err("ruff-exit-diagnostic-mismatch".into());
    }
    let mut out = Vec::new();
    for result in results {
        let file = result
            .get("filename")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or("ruff-filename-missing")?;
        let code = match result.get("code") {
            Some(Value::Null) => None,
            Some(Value::String(code)) if !code.is_empty() => Some(code.as_str()),
            _ => return Err("ruff-code-malformed".into()),
        };
        let location = result.get("location").ok_or("ruff-location-missing")?;
        let line = location
            .get("row")
            .and_then(Value::as_u64)
            .and_then(|n| usize::try_from(n).ok())
            .filter(|n| *n > 0)
            .ok_or("ruff-location-malformed")?;
        location
            .get("column")
            .and_then(Value::as_u64)
            .filter(|n| *n > 0)
            .ok_or("ruff-location-malformed")?;
        let message = result
            .get("message")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or("ruff-message-missing")?;
        out.push(Diag {
            rule: code
                .map(|code| format!("ruff:{code}"))
                .unwrap_or_else(|| "ruff:syntax-error".into()),
            severity: if code.is_some() { "warning" } else { "error" },
            path: file.to_owned(),
            line,
            message: shorten(message),
        });
    }
    Ok(out)
}

fn parse_py_compile(bytes: &[u8], expected: &BTreeSet<String>) -> Result<Vec<Diag>, String> {
    if expected.is_empty() {
        return Err("compile-scope-empty".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "compile-output-encoding")?;
    let mut done = false;
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for line in text.lines() {
        if done {
            return Err("compile-output-after-completion".into());
        }
        let value: Value = serde_json::from_str(line).map_err(|_| "compile-output-malformed")?;
        let object = value.as_object().ok_or("compile-output-malformed")?;
        if object.contains_key("done") {
            if object.len() != 2 || value["done"].as_u64() != Some(expected.len() as u64) {
                return Err("compile-completion-count".into());
            }
            let files: Vec<String> = serde_json::from_value(value["files"].clone())
                .map_err(|_| "compile-completion-scope")?;
            if files.len() != expected.len()
                || files.iter().cloned().collect::<BTreeSet<_>>() != *expected
            {
                return Err("compile-completion-scope".into());
            }
            done = true;
            continue;
        }
        if object.len() != 3 {
            return Err("compile-diagnostic-malformed".into());
        }
        let path = value["path"]
            .as_str()
            .filter(|p| expected.contains(*p))
            .ok_or("compile-diagnostic-path")?;
        if !seen.insert(path.to_owned()) {
            return Err("compile-diagnostic-duplicate".into());
        }
        let line = value["line"]
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .filter(|n| *n > 0)
            .ok_or("compile-diagnostic-line")?;
        let message = value["message"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or("compile-diagnostic-message")?;
        out.push(Diag {
            rule: "py-compile:syntax-error".into(),
            severity: "error",
            path: path.into(),
            line,
            message: shorten(message),
        });
    }
    if done {
        Ok(out)
    } else {
        Err("no-completion-marker".into())
    }
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Accumulator {
    outcome: Option<Outcome>,
    program: String,
    version: String,
    executable_digest: String,
    stdout_digests: Vec<String>,
    runs: Vec<Value>,
    covered: BTreeSet<String>,
}

impl Accumulator {
    fn merge(&mut self, outcome: Outcome) {
        if self
            .outcome
            .as_ref()
            .is_none_or(|current| outcome.rank() > current.rank())
        {
            self.outcome = Some(outcome);
        }
    }
}

/// Submit every planned verification command this provider's analyzer wants
/// receipts for and project the results. `entries` is the frozen denominator;
/// `selected` the in-language paths whose findings are admissible.
pub async fn run(
    ctx: &ToolContext<'_>,
    config_tools: &[&'static str],
    entries: &[InventoryEntry],
    selected: &BTreeSet<String>,
    cancellation: CancellationToken,
) -> ToolEvidence {
    if ctx.provider_id == "code.jvm" {
        return super::jvm_sdk::run(ctx, entries, selected, cancellation).await;
    }
    let provider_id = ctx.provider_id;
    let plan = plan_commands(provider_id, ctx.root, entries, selected, ctx.scratch);
    let mut evidence = ToolEvidence::default();
    for command in &plan.deferred {
        evidence.deferred_commands.push(json!({
            "tool": command.tool, "programCandidates": command.programs,
            "argv": command.args, "cwd": command.cwd_rel,
            "executed": false, "reason": POLICY_NO_PROJECT_CODE,
        }));
        evidence
            .outcomes
            .insert(command.tool, Outcome::NotRun(POLICY_NO_PROJECT_CODE.into()));
        evidence.gaps.push(format!(
            "{provider_id}:tool-not-run:{}:{POLICY_NO_PROJECT_CODE}",
            command.tool
        ));
    }
    for note in &plan.notes {
        evidence.gaps.push(format!("{provider_id}:{note}"));
    }
    for (tool, why) in &plan.not_planned {
        evidence
            .outcomes
            .insert(tool, Outcome::NotRun((*why).into()));
    }

    // Tools that are never run, by policy or because nothing applies.
    for tool in config_tools {
        if policy_tools(provider_id).contains(tool)
            && !plan.commands.iter().any(|command| command.tool == *tool)
        {
            evidence
                .outcomes
                .insert(*tool, Outcome::NotRun(POLICY_NO_PROJECT_CODE.into()));
        } else if let Some(why) = plan.not_planned.get(*tool) {
            evidence
                .outcomes
                .insert(*tool, Outcome::NotRun((*why).to_owned()));
        }
    }

    let mobile_closure_before =
        (provider_id == "code.mobile").then(|| mobile_sdk::closure_snapshot(ctx.root));
    let started = Instant::now();
    let canonical_root = std::fs::canonicalize(ctx.root).unwrap_or_else(|_| ctx.root.to_path_buf());
    let mut resolver = Resolver::new(ctx);
    let mut accumulators: BTreeMap<&'static str, Accumulator> = BTreeMap::new();
    let mut diagnostics: Vec<(String, Diag)> = Vec::new();

    for (sequence, command) in plan.commands.iter().enumerate() {
        let accumulator = accumulators.entry(command.tool).or_default();
        if let Some(Err(reason)) = &mobile_closure_before {
            accumulator.merge(Outcome::Failed(reason.clone()));
            continue;
        }
        let elapsed = started.elapsed().as_millis() as u64;
        let remaining = ctx.total_budget_ms.saturating_sub(elapsed);
        if remaining == 0 {
            accumulator.merge(Outcome::Budget);
            continue;
        }
        if cancellation.is_cancelled() {
            accumulator.merge(Outcome::Failed(format!("tool-cancelled:{}", command.tool)));
            continue;
        }
        let timeout = ctx.per_tool_timeout_ms.min(remaining).max(1);
        let output = run_one(
            ctx,
            &mut resolver,
            command,
            plan.rust_dependency_bindings.get(&command.cwd_rel),
            sequence,
            timeout,
            cancellation.clone(),
        )
        .await;
        if let Some(receipt) = output.receipt.clone() {
            evidence.receipts.push(receipt.clone());
            accumulator.runs.push(receipt);
        }
        if accumulator.program.is_empty() && !output.program.is_empty() {
            accumulator.program = output.program.clone();
            accumulator.version = output.version.clone();
            accumulator.executable_digest = output.executable_digest.clone();
        }
        if let Some(digest) = &output.stdout_digest {
            accumulator.stdout_digests.push(digest.clone());
        }
        accumulator.covered.extend(output.covered.clone());
        accumulator.merge(output.outcome.clone());
        if let Some(why) = plan.not_planned.get(command.tool) {
            accumulator.merge(Outcome::NotRun((*why).into()));
        }
        for mut diag in output.diagnostics {
            if ctx.provider_id == "code.python" && Path::new(&diag.path).is_absolute() {
                let Some(relative) = Path::new(&diag.path).strip_prefix(&command.cwd_rel).ok()
                else {
                    evidence.gaps.push(format!(
                        "{provider_id}:python-diagnostic-outside-frozen-stage"
                    ));
                    continue;
                };
                diag.path = relative.to_string_lossy().into_owned();
            }
            // Isolated adapters already rebind diagnostics to the original
            // repository-relative source. Their physical scratch cwd is only
            // execution evidence, never the diagnostic path's base.
            let diagnostic_cwd = if command.source_path.is_some()
                || ctx.provider_id == "code.python"
                || command.parser == Parser::Dotnet
            {
                String::new()
            } else {
                command.cwd_rel.clone()
            };
            diagnostics.push((diagnostic_cwd, diag));
        }
    }
    if let Some(before) = mobile_closure_before {
        let after = mobile_sdk::closure_snapshot(ctx.root);
        evidence
            .receipts
            .push(json!({"kind":"mobile-native-enrollment-boundary",
            "before":before.as_ref().ok(),"after":after.as_ref().ok(),
            "beforeError":before.as_ref().err(),"afterError":after.as_ref().err()}));
        if before.is_err() || after.is_err() || before.as_ref().ok() != after.as_ref().ok() {
            for tool in config_tools {
                accumulators
                    .entry(*tool)
                    .or_default()
                    .merge(Outcome::Failed(
                        "mobile-native-enrollment-boundary-failed".into(),
                    ));
            }
        }
    }
    for path in &plan.cleanup {
        let _ = std::fs::remove_file(path);
    }

    for (tool, mut accumulator) in accumulators {
        if provider_id == "code.javascript" && ["type", "lint"].contains(&tool) {
            let missing: Vec<_> = selected.difference(&accumulator.covered).cloned().collect();
            if !missing.is_empty() {
                accumulator.merge(Outcome::Failed(format!(
                    "tool-failed:{tool}:source-scope-incomplete:{}",
                    missing.len()
                )));
                evidence.gaps.push(format!(
                    "{provider_id}:{tool}:source-scope-incomplete:{}",
                    missing.join(",")
                ));
            }
        }
        let outcome = accumulator.outcome.clone().unwrap_or(Outcome::Missing);
        let ran = outcome == Outcome::Ran;
        let status = match outcome {
            Outcome::Ran => "pass",
            Outcome::Missing | Outcome::AdmissionUnavailable => "unavailable",
            Outcome::Timeout => "timeout",
            _ => "fail",
        };
        let identity = if accumulator.program.is_empty() {
            Value::Null
        } else {
            json!({
                "name": accumulator.program,
                "version": accumulator.version,
                "executableDigest": accumulator.executable_digest,
            })
        };
        let artifact_digest = if ran && !accumulator.stdout_digests.is_empty() {
            json!(sha256_text(
                accumulator.stdout_digests.join("\n").as_bytes()
            ))
        } else {
            Value::Null
        };
        evidence.tools.insert(
            tool.to_owned(),
            json!({
                "status": status,
                "identity": identity,
                "artifactDigest": artifact_digest,
                "scope": if provider_id == "code.javascript" {json!({"runs": accumulator.runs, "offline": true, "observedSourcePaths": accumulator.covered})} else {json!({"runs": accumulator.runs, "offline": true})},
            }),
        );
        evidence.outcomes.insert(tool, outcome);
    }

    // Diagnostics -> findings inside the frozen denominator.
    let mut outside = 0usize;
    let mut seen: BTreeSet<(String, String, usize)> = BTreeSet::new();
    let mut findings: Vec<NativeFinding> = Vec::new();
    for (cwd_rel, diag) in diagnostics {
        let Some(path) =
            repo_relative(ctx.root, &canonical_root, &cwd_rel, &diag.path).filter(|path| {
                selected.contains(path)
                    || (provider_id == "code.rust"
                        && diag.rule.starts_with("cargo-audit:")
                        && entries.iter().any(|entry| {
                            entry.path == *path
                                && name_of(path) == "Cargo.lock"
                                && entry.digest.is_some()
                        }))
            })
        else {
            outside += 1;
            continue;
        };
        if !seen.insert((diag.rule.clone(), path.clone(), diag.line)) {
            continue;
        }
        findings.push(NativeFinding {
            rule: Cow::Owned(diag.rule),
            severity: diag.severity,
            path,
            line: diag.line,
            message: diag.message,
        });
    }
    findings.sort_by(|left, right| {
        let rank = |severity: &str| u8::from(severity != "error");
        rank(left.severity)
            .cmp(&rank(right.severity))
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.line.cmp(&right.line))
            .then_with(|| left.rule.cmp(&right.rule))
    });
    if findings.len() > MAX_TOOL_FINDINGS {
        evidence.gaps.push(format!(
            "{provider_id}:tool-findings-truncated:{}",
            findings.len() - MAX_TOOL_FINDINGS
        ));
        findings.truncate(MAX_TOOL_FINDINGS);
    }
    if outside > 0 {
        evidence.gaps.push(format!(
            "{provider_id}:tool-diagnostics-outside-denominator:{outside}"
        ));
    }
    evidence.findings = findings;
    for (tool, outcome) in &evidence.outcomes {
        if *outcome != Outcome::Ran {
            evidence
                .gaps
                .push(format!("{provider_id}:{}", outcome.reason(tool)));
        }
    }
    evidence
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn owner_admission_denial_retains_effect_evidence_and_unavailable_reason() {
        let request = ExternalToolRequest {
            request_id: "code-denied".into(),
            provider_id: "code.rust".into(),
            plan_id: "sha256:frozen-plan".into(),
            policy_id: POLICY_ID.into(),
            executable: "definitely-missing-code-scanner".into(),
            cwd: std::env::temp_dir()
                .join("missing-code-root")
                .to_string_lossy()
                .into_owned(),
            ..ExternalToolRequest::default()
        };
        let receipt = crate::execution_policy::deny(&request).await;
        assert_eq!(
            classify("check", &receipt),
            Some(Outcome::AdmissionUnavailable)
        );
        assert_eq!(
            Outcome::AdmissionUnavailable.reason("check"),
            crate::execution_policy::ADMISSION_UNAVAILABLE
        );
        let retained = crate::execution_policy::receipt_json(&receipt);
        assert_eq!(retained["planId"], request.plan_id);
        assert_eq!(retained["processTree"]["started"], false);
        assert_eq!(retained["policy"]["allowed"], false);
        assert_eq!(retained["parser"]["attempted"], false);
        assert_eq!(
            retained["executionPolicy"],
            crate::execution_policy::resolved_policy()
        );
        assert_eq!(
            retained["executionPolicyIdentity"],
            crate::execution_policy::binding()["executionPolicyIdentity"]
        );
    }

    #[test]
    fn python_completion_rejects_truncation_wrong_scope_and_malformed_diagnostics() {
        let expected = BTreeSet::from(["answer.py".to_owned()]);
        assert!(
            parse_py_compile(br#"{"done":1,"files":["answer.py"]}"#, &expected)
                .unwrap()
                .is_empty()
        );
        for bytes in [
            br#"{"done":0,"files":[]}"#.as_slice(),
            br#"{"done":1,"files":["other.py"]}"#,
            b"garbage\n{\"done\":1,\"files\":[\"answer.py\"]}",
            br#"{"path":"answer.py"}"#,
            b"{\"done\":1,\"files\":[\"answer.py\"]}\n{}",
        ] {
            assert!(parse_py_compile(bytes, &expected).is_err());
        }
        assert!(parse_ruff(b"[]", Some(0)).unwrap().is_empty());
        assert!(parse_ruff(b"[]", Some(1)).is_err());
        assert!(parse_ruff(b"[{}]", Some(1)).is_err());
        assert!(parse_ruff(b"{}", Some(0)).is_err());
    }

    #[test]
    fn process_completion_never_converts_test_failure_to_a_clean_pass() {
        assert!(parse(Parser::Process, b"ok example 0.001s", Some(0))
            .unwrap()
            .is_empty());
        assert!(parse(Parser::Process, b"FAIL example", Some(1)).is_err());
        assert!(parse(Parser::Process, b"", None).is_err());
    }

    #[test]
    fn native_syntax_failure_is_diagnostic_not_a_clean_pass() {
        assert!(parse_syntax(b"Syntax OK", Some(0)).unwrap().is_empty());
        let diagnostics = parse_syntax(
            b"PHP Parse error: bad token in snapshot.php on line 12",
            Some(255),
        )
        .unwrap();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].line, 12);
        assert_eq!(diagnostics[0].severity, "error");
        assert!(parse_syntax(b"", Some(1)).is_err());
    }

    #[test]
    fn repo_relative_normalizes_and_rejects_escapes() {
        let root = Path::new("/repo");
        assert_eq!(
            repo_relative(root, root, "crates/a", "src/lib.rs").as_deref(),
            Some("crates/a/src/lib.rs")
        );
        assert_eq!(
            repo_relative(root, root, "crates/a", "./../b/x.rs").as_deref(),
            Some("crates/b/x.rs")
        );
        // `/repo/...` is only an absolute path on Unix.
        #[cfg(unix)]
        {
            assert_eq!(
                repo_relative(root, root, "", "/repo/src/main.rs").as_deref(),
                Some("src/main.rs")
            );
            assert_eq!(repo_relative(root, root, "", "/elsewhere/x.rs"), None);
        }
        assert_eq!(repo_relative(root, root, "", "../x.rs"), None);
    }

    #[test]
    fn cargo_diagnostics_use_the_primary_span_and_skip_notes() {
        let stdout = br#"{"reason":"compiler-message","message":{"level":"error","message":"mismatched types","code":{"code":"E0308"},"spans":[{"file_name":"src/lib.rs","line_start":7,"is_primary":true}]}}
{"reason":"compiler-message","message":{"level":"warning","message":"needless return","code":{"code":"clippy::needless_return"},"spans":[{"file_name":"src/lib.rs","line_start":9,"is_primary":true}]}}
{"reason":"compiler-message","message":{"level":"note","message":"x","code":null,"spans":[]}}
{"reason":"build-finished","success":false}
"#;
        let diags = parse_cargo(stdout, false).unwrap();
        assert_eq!(diags.len(), 2);
        assert_eq!(
            (diags[0].rule.as_str(), diags[0].severity, diags[0].line),
            ("rustc:E0308", "error", 7)
        );
        assert_eq!(
            (diags[1].rule.as_str(), diags[1].severity),
            ("clippy:needless_return", "warning")
        );
        assert!(parse_cargo(b"", false).is_err());
    }

    #[test]
    fn tsc_lines_parse() {
        let tsc = parse_tsc(
            b"src/a.ts(3,5): error TS2322: Type 'x' is not assignable.\n",
            Some(2),
        )
        .unwrap();
        assert_eq!((tsc[0].path.as_str(), tsc[0].line), ("src/a.ts", 3));
        assert!(parse_tsc(b"error TS5058: bad path\n", Some(1)).is_err());
    }
}

#[cfg(test)]
mod rust_execution_tests {
    use super::*;
    #[test]
    fn failed_or_missing_cargo_completion_never_passes_build_coverage() {
        assert!(!cargo_build_succeeded(
            br#"{"reason":"build-finished","success":false}"#
        ));
        assert!(!cargo_build_succeeded(br#"{"reason":"build-finished"}"#));
        assert!(!cargo_build_succeeded(b""));
        assert!(!cargo_build_succeeded(b"{\"reason\":\"build-finished\",\"success\":true}\n{\"reason\":\"build-finished\",\"success\":true}"));
        assert!(cargo_build_succeeded(
            br#"{"reason":"build-finished","success":true}"#
        ));
        assert_eq!(policy_tools("code.rust"), &[] as &[&str]);
    }
}
