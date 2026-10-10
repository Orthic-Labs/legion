//! Real, read-only tool runs for the `code.*` providers.
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
//! | `code.javascript` | `type` | `<local>/node_modules/.bin/tsc --noEmit -p tsconfig.json --pretty false` |
//! | | `lint` | `<local>/node_modules/.bin/eslint --no-cache --format json --no-error-on-unmatched-pattern .` |
//! | `code.python` | `compile` | `python3 -I -B -c <py_compile to scratch> <list> <scratch>` |
//! | | `lint` | `ruff check --no-cache --output-format json .` |
//! | `code.go` | `module` | `go list -m` (`GOPROXY=off`, `GOTOOLCHAIN=local`) |
//! | | `vet` | `go vet ./...` |
//! | | `format` | `gofmt -l .` |
//!
//! Never run: test suites (`test` is always the typed gap
//! `tool-not-run:test:policy-no-project-code-execution`), package-manager
//! scripts and builds, installs, network-dependent audits.

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

/// Findings kept per provider from tool diagnostics; the rest is a counted gap.
pub const MAX_TOOL_FINDINGS: usize = 200;
/// Reason attached to every analyzer tool that would execute project tests.
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
    pub outcomes: BTreeMap<&'static str, Outcome>,
    /// Deduplicated, capped diagnostics inside the denominator.
    pub findings: Vec<NativeFinding>,
    /// Provider-prefixed gap strings (outside-denominator, truncation, ...).
    pub gaps: Vec<String>,
    /// One receipt summary per tool run.
    pub receipts: Vec<Value>,
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
    GoVet,
    Gofmt,
    GoList,
}

struct Planned {
    /// Analyzer tool id this run is evidence for.
    tool: &'static str,
    /// Candidate executable names, first found wins.
    programs: &'static [&'static str],
    /// Look only in `node_modules/.bin` (walking up to the root).
    local_bin: bool,
    /// Also resolve next to this already-resolved program (`gofmt` beside `go`).
    sibling_of: Option<&'static str>,
    /// Extra executable that must exist (`cargo-clippy`).
    requires: Option<&'static str>,
    cwd_rel: String,
    args: Vec<String>,
    parser: Parser,
    accepted: &'static [i32],
    env: Vec<(&'static str, String)>,
    /// Diagnostics are printed on stderr (`go vet`).
    diagnostics_on_stderr: bool,
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
        for tool in ["metadata", "check", "lint"] {
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
        });
    }
}

const PY_COMPILE_SCRIPT: &str = "\
import sys, os, json, py_compile
lst, out = sys.argv[1], sys.argv[2]
n = 0
for i, rel in enumerate(open(lst, encoding='utf-8').read().split('\\n')):
    if not rel or not os.path.isfile(rel):
        continue
    n += 1
    try:
        py_compile.compile(rel, cfile=os.path.join(out, '%d.pyc' % i), doraise=True)
    except py_compile.PyCompileError as e:
        v = e.exc_value
        msg = getattr(v, 'msg', None) or str(e.msg).strip().splitlines()[-1]
        print(json.dumps({'path': rel, 'line': getattr(v, 'lineno', None) or 1, 'message': str(msg)[:300]}))
    except Exception as e:
        print(json.dumps({'path': rel, 'line': 1, 'message': 'compile failed: ' + type(e).__name__}))
print(json.dumps({'done': n}))
";

fn plan_python(
    entries: &[InventoryEntry],
    selected: &BTreeSet<String>,
    scratch: &AuditScratch,
    plan: &mut Plan,
) {
    if !selected.is_empty() {
        let list = scratch.tmp_dir().join("py-compile-files.txt");
        let body = selected
            .iter()
            .filter(|path| !path.contains('\n'))
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        let out_dir = scratch.cache_dir().join("py-compile");
        if std::fs::write(&list, body).is_ok() && std::fs::create_dir_all(&out_dir).is_ok() {
            plan.cleanup.push(list.clone());
            plan.commands.push(Planned {
                tool: "compile",
                programs: &["python3", "python"],
                local_bin: false,
                sibling_of: None,
                requires: None,
                cwd_rel: String::new(),
                args: vec![
                    "-I".into(),
                    "-B".into(),
                    "-c".into(),
                    PY_COMPILE_SCRIPT.into(),
                    list.to_string_lossy().into_owned(),
                    out_dir.to_string_lossy().into_owned(),
                ],
                parser: Parser::PyCompile,
                accepted: &[0, 1],
                env: Vec::new(),
                diagnostics_on_stderr: false,
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
            cwd_rel: String::new(),
            args: ["check", "--no-cache", "--output-format", "json", "."]
                .iter()
                .map(|arg| (*arg).to_owned())
                .collect(),
            parser: Parser::Ruff,
            accepted: &[0, 1],
            env: Vec::new(),
            diagnostics_on_stderr: false,
        });
    }
}

fn plan_go(entries: &[InventoryEntry], plan: &mut Plan) {
    let modules = cap_roots(
        dirs_named(entries, &["go.mod"]).into_iter().collect(),
        "go",
        &mut plan.notes,
    );
    if modules.is_empty() {
        for tool in ["module", "vet", "format"] {
            plan.not_planned.insert(tool, "no-manifest");
        }
        return;
    }
    for dir in modules {
        let command = |tool: &'static str,
                       programs: &'static [&'static str],
                       args: &[&str],
                       parser: Parser,
                       accepted: &'static [i32],
                       stderr: bool| Planned {
            tool,
            programs,
            local_bin: false,
            sibling_of: Some("go"),
            requires: None,
            cwd_rel: dir.clone(),
            args: args.iter().map(|arg| (*arg).to_owned()).collect(),
            parser,
            accepted,
            // No network, no toolchain download; module mode stays the
            // project default (vendor directories keep working).
            env: vec![
                ("GOPROXY", "off".to_owned()),
                ("GOTOOLCHAIN", "local".to_owned()),
            ],
            diagnostics_on_stderr: stderr,
        };
        plan.commands.push(command(
            "module",
            &["go"],
            &["list", "-m"],
            Parser::GoList,
            &[0],
            false,
        ));
        plan.commands.push(command(
            "vet",
            &["go"],
            &["vet", "./..."],
            Parser::GoVet,
            &[0, 1, 2],
            true,
        ));
        plan.commands.push(command(
            "format",
            &["gofmt"],
            &["-l", "."],
            Parser::Gofmt,
            &[0],
            false,
        ));
    }
}

/// Analyzer tool ids that are never run, with the typed reason.
fn policy_tools(provider_id: &str) -> &'static [&'static str] {
    match provider_id {
        "code.javascript" => &["build", "test"],
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
        "code.python" => plan_python(entries, selected, scratch, &mut plan),
        "code.go" => plan_go(entries, &mut plan),
        _ => {}
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
            if command.local_bin {
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

fn read_artifact(
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

fn classify(tool: &str, receipt: &ExecutionReceipt) -> Option<Outcome> {
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
    sequence: usize,
    timeout_ms: u64,
    cancellation: CancellationToken,
) -> RunOutput {
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
    for name in [
        "CARGO_HOME",
        "RUSTUP_HOME",
        "GOPATH",
        "GOROOT",
        "GOMODCACHE",
    ] {
        if let Ok(value) = std::env::var(name) {
            environment.insert(name.into(), value);
            allowlist.insert(name.into());
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
    let (launch_executable, launch_args, sandbox, version_args, needs_sandbox) = match ctx.sandbox {
        SandboxPolicy::Disabled => (
            executable_text.clone(),
            command.args.clone(),
            None,
            None,
            false,
        ),
        SandboxPolicy::Required => match legion_effects::authenticate_sandbox(
            &executable_text,
            &command.args,
            &cwd_text,
            legion_effects::SandboxMode::DenyNetwork,
            &ctx.scratch.sandbox_dir(),
        ) {
            Ok(auth) => {
                // Probe the real tool's version through the same wrapper
                // prefix (`-f profile -- tool`).
                let mut probe: Vec<String> = auth.wrapped_args.iter().take(4).cloned().collect();
                probe.push("--version".into());
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
            // No authenticator: leave the receipt absent so the executor
            // refuses (typed `sandbox-missing`, never an unsandboxed run).
            Err(_) => (
                executable_text.clone(),
                command.args.clone(),
                None,
                None,
                true,
            ),
        },
    };
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
        version_args: version_args.unwrap_or_else(|| vec!["--version".into()]),
        ..ExternalToolRequest::default()
    };
    let receipt = ctx.tool.execute(request, cancellation).await;

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
        SandboxPolicy::Required => "deny-network",
        SandboxPolicy::Disabled => "disabled",
    };
    let stderr_digest = stderr.as_deref().map(sha256_text);
    let program_label = argv[0].clone();
    output.receipt = Some(json!({
        "tool": command.tool,
        "program": program_label,
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
    }));
    if let Some(outcome) = classify(command.tool, &receipt) {
        output.outcome = outcome;
        return output;
    }
    let stream = if command.diagnostics_on_stderr {
        stderr.as_deref()
    } else {
        stdout.as_deref()
    };
    let Some(bytes) = stream else {
        output.outcome = Outcome::Failed(format!("tool-output-unreadable:{}", command.tool));
        return output;
    };
    match parse(command.parser, bytes, receipt.exit_code) {
        Ok(diagnostics) => output.diagnostics = diagnostics,
        Err(reason) => {
            output.outcome = Outcome::Failed(format!("tool-failed:{}:{reason}", command.tool));
        }
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
        Parser::Ruff => parse_ruff(bytes),
        Parser::PyCompile => parse_py_compile(bytes),
        Parser::GoVet => parse_go_vet(bytes, exit),
        Parser::Gofmt => parse_gofmt(bytes),
        Parser::GoList => Ok(Vec::new()),
    }
}

fn line_of(value: Option<u64>) -> usize {
    value.unwrap_or(1).max(1) as usize
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

fn parse_ruff(bytes: &[u8]) -> Result<Vec<Diag>, String> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| "unparseable-output".to_owned())?;
    let results = value
        .as_array()
        .ok_or_else(|| "unparseable-output".to_owned())?;
    let mut out = Vec::new();
    for result in results {
        let Some(file) = result.get("filename").and_then(Value::as_str) else {
            continue;
        };
        let code = result.get("code").and_then(Value::as_str);
        out.push(Diag {
            rule: match code {
                Some(code) => format!("ruff:{code}"),
                None => "ruff:syntax-error".to_owned(),
            },
            severity: if code.is_some() { "warning" } else { "error" },
            path: file.to_owned(),
            line: line_of(
                result
                    .get("location")
                    .and_then(|location| location.get("row"))
                    .and_then(Value::as_u64),
            ),
            message: shorten(result.get("message").and_then(Value::as_str).unwrap_or("")),
        });
    }
    Ok(out)
}

fn parse_py_compile(bytes: &[u8]) -> Result<Vec<Diag>, String> {
    let text = String::from_utf8_lossy(bytes);
    let mut done = false;
    let mut out = Vec::new();
    for line in text.lines() {
        let Ok(value) = serde_json::from_str::<Value>(line.trim()) else {
            continue;
        };
        if value.get("done").is_some() {
            done = true;
            continue;
        }
        let Some(path) = value.get("path").and_then(Value::as_str) else {
            continue;
        };
        out.push(Diag {
            rule: "py-compile:syntax-error".to_owned(),
            severity: "error",
            path: path.to_owned(),
            line: line_of(value.get("line").and_then(Value::as_u64)),
            message: shorten(value.get("message").and_then(Value::as_str).unwrap_or("")),
        });
    }
    if done {
        Ok(out)
    } else {
        Err("no-completion-marker".into())
    }
}

fn parse_go_vet(bytes: &[u8], exit: Option<i32>) -> Result<Vec<Diag>, String> {
    let located = Regex::new(r"^(?:vet: )?(.+?\.go):(\d+):(?:\d+:)?\s*(.*)$")
        .map_err(|error| error.to_string())?;
    let text = String::from_utf8_lossy(bytes);
    let mut out = Vec::new();
    for line in text.lines() {
        if line.starts_with('#') {
            continue;
        }
        if let Some(captures) = located.captures(line.trim_end()) {
            out.push(Diag {
                rule: "go-vet".to_owned(),
                severity: "warning",
                path: captures[1].to_owned(),
                line: captures[2].parse::<usize>().unwrap_or(1).max(1),
                message: shorten(&captures[3]),
            });
        }
    }
    if out.is_empty() && exit.is_some_and(|code| code != 0) {
        return Err(format!("exit-{}", exit.unwrap_or(-1)));
    }
    Ok(out)
}

fn parse_gofmt(bytes: &[u8]) -> Result<Vec<Diag>, String> {
    let text = String::from_utf8_lossy(bytes);
    let mut out = Vec::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if !line.ends_with(".go") {
            return Err("unexpected-output".into());
        }
        out.push(Diag {
            rule: "gofmt".to_owned(),
            severity: "warning",
            path: line.to_owned(),
            line: 1,
            message: "file is not gofmt-formatted".to_owned(),
        });
    }
    Ok(out)
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

/// Run every read-only verification command this provider's analyzer wants
/// receipts for and project the results. `entries` is the frozen denominator;
/// `selected` the in-language paths whose findings are admissible.
pub async fn run(
    ctx: &ToolContext<'_>,
    config_tools: &[&'static str],
    entries: &[InventoryEntry],
    selected: &BTreeSet<String>,
    cancellation: CancellationToken,
) -> ToolEvidence {
    let provider_id = ctx.provider_id;
    let plan = plan_commands(provider_id, ctx.root, entries, selected, ctx.scratch);
    let mut evidence = ToolEvidence::default();
    for note in &plan.notes {
        evidence.gaps.push(format!("{provider_id}:{note}"));
    }

    // Tools that are never run, by policy or because nothing applies.
    for tool in config_tools {
        if policy_tools(provider_id).contains(tool) {
            evidence
                .outcomes
                .insert(*tool, Outcome::NotRun(POLICY_NO_PROJECT_CODE.into()));
        } else if let Some(why) = plan.not_planned.get(*tool) {
            evidence
                .outcomes
                .insert(*tool, Outcome::NotRun((*why).to_owned()));
        }
    }

    let started = Instant::now();
    let canonical_root = std::fs::canonicalize(ctx.root).unwrap_or_else(|_| ctx.root.to_path_buf());
    let mut resolver = Resolver::new(ctx);
    let mut accumulators: BTreeMap<&'static str, Accumulator> = BTreeMap::new();
    let mut diagnostics: Vec<(String, Diag)> = Vec::new();

    for (sequence, command) in plan.commands.iter().enumerate() {
        let accumulator = accumulators.entry(command.tool).or_default();
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
        accumulator.merge(output.outcome.clone());
        for diag in output.diagnostics {
            diagnostics.push((command.cwd_rel.clone(), diag));
        }
    }
    for path in &plan.cleanup {
        let _ = std::fs::remove_file(path);
    }

    for (tool, accumulator) in accumulators {
        let outcome = accumulator.outcome.clone().unwrap_or(Outcome::Missing);
        let ran = outcome == Outcome::Ran;
        let status = match outcome {
            Outcome::Ran => "pass",
            Outcome::Missing => "unavailable",
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
                "scope": {"runs": accumulator.runs, "offline": true},
            }),
        );
        evidence.outcomes.insert(tool, outcome);
    }

    // Diagnostics -> findings inside the frozen denominator.
    let mut outside = 0usize;
    let mut seen: BTreeSet<(String, String, usize)> = BTreeSet::new();
    let mut findings: Vec<NativeFinding> = Vec::new();
    for (cwd_rel, diag) in diagnostics {
        let Some(path) = repo_relative(ctx.root, &canonical_root, &cwd_rel, &diag.path)
            .filter(|path| selected.contains(path))
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
    evidence
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn tsc_and_vet_lines_parse() {
        let tsc = parse_tsc(
            b"src/a.ts(3,5): error TS2322: Type 'x' is not assignable.\n",
            Some(2),
        )
        .unwrap();
        assert_eq!((tsc[0].path.as_str(), tsc[0].line), ("src/a.ts", 3));
        assert!(parse_tsc(b"error TS5058: bad path\n", Some(1)).is_err());
        let vet = parse_go_vet(b"# pkg\n./main.go:12:3: printf format %d\n", Some(1)).unwrap();
        assert_eq!((vet[0].path.as_str(), vet[0].line), ("./main.go", 12));
        assert!(parse_go_vet(b"go: cannot find module\n", Some(1)).is_err());
    }
}
