//! Port of the native "language pack" providers (chunk wf038, area
//! `src/providers/native`, target crate `legion-audit`).
//!
//! Source (JS) modules, one per language, each exporting a frozen provider
//! object `{ id, version, detect, commands, normalize, coverage, fixtures }`:
//!   - `src/providers/native/javascript/index.mjs` -> `language.javascript`
//!   - `src/providers/native/jvm/index.mjs`         -> `language.jvm`
//!   - `src/providers/native/php/index.mjs`         -> `language.php`
//!   - `src/providers/native/python/index.mjs`      -> `language.python`
//!   - `src/providers/native/ruby/index.mjs`         -> `language.ruby`
//!
//! Each JS provider is a thin, near-identical shape: `detect` decides
//! applicability from a `projection` (parsed extensions / files), `commands`
//! builds the ordered command list for a given root/files/manifests/profile,
//! `normalize` maps one command's execution result to a pass/error record,
//! and `coverage` reports which parsed extensions were examined. This module
//! ports that shape faithfully per language rather than collapsing it into
//! one generic engine, so each language's exact command ids, executables,
//! args, and conditions stay independently readable and auditable, matching
//! the JS source file-by-file.
//!
//! DROP: none. No code in these five JS source files calls into Membrane or
//! Blueprint (the `javascript` module's header comment mentions "Blueprint
//! AST/SCIP" only as descriptive prose; no Blueprint/Membrane API is
//! referenced by any `detect`/`commands`/`normalize`/`coverage` body), so
//! there is nothing to drop from this chunk.

pub mod javascript;
pub mod jvm;
pub mod php;
pub mod python;
pub mod ruby;

use std::path::{Path, PathBuf};

/// Mirrors the JS `projection` shape read by `detect`/`coverage`:
/// `{ parsedExtensions, files }`. Extensions are compared exactly as given
/// by the caller (the JS source does not normalize case except where a
/// specific `detect` explicitly lowercases before comparing).
#[derive(Debug, Clone, Default)]
pub struct Projection {
    pub parsed_extensions: Vec<String>,
    pub files: Vec<String>,
}

/// Mirrors the JS `{ root, files, manifests, profile }` argument passed to
/// each provider's `commands()`.
#[derive(Debug, Clone, Default)]
pub struct CommandsInput {
    pub root: PathBuf,
    pub files: Vec<String>,
    pub manifests: Vec<String>,
    /// `None` / any value other than `Some("fast")` behaves like JS
    /// `profile !== 'fast'`.
    pub profile: Option<String>,
}

impl CommandsInput {
    fn is_fast(&self) -> bool {
        self.profile.as_deref() == Some("fast")
    }
}

/// Mirrors one entry pushed into the JS `commands` array:
/// `{ id, executable, args, cwd, kind }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub id: &'static str,
    pub executable: &'static str,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub kind: &'static str,
}

/// Mirrors the JS `{ execution }` argument passed to `normalize`: only
/// `exitCode` and `toolVersion` are ever read by these five providers.
#[derive(Debug, Clone, Default)]
pub struct ExecutionResult {
    pub exit_code: Option<i32>,
    pub tool_version: Option<String>,
}

/// One entry of the JS `coverageGaps` array: `{ kind: 'command-failed',
/// command }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageGap {
    pub kind: &'static str,
    pub command: String,
}

/// Mirrors the JS `normalize()` return shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizeResult {
    pub provider: &'static str,
    pub status: &'static str,
    pub complete: bool,
    pub command: String,
    pub tool_version: Option<String>,
    pub coverage_gaps: Vec<CoverageGap>,
}

fn normalize_for(
    provider: &'static str,
    command_id: &str,
    execution: Option<&ExecutionResult>,
) -> NormalizeResult {
    let exit_code_zero = matches!(execution.and_then(|e| e.exit_code), Some(0));
    NormalizeResult {
        provider,
        status: if exit_code_zero { "pass" } else { "error" },
        complete: exit_code_zero,
        command: command_id.to_string(),
        tool_version: execution.and_then(|e| e.tool_version.clone()),
        coverage_gaps: if exit_code_zero {
            Vec::new()
        } else {
            vec![CoverageGap {
                kind: "command-failed",
                command: command_id.to_string(),
            }]
        },
    }
}

/// Mirrors the JS `coverage()` return shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageResult {
    pub provider: &'static str,
    pub examined: Vec<String>,
    pub complete: bool,
}

fn coverage_for(provider: &'static str, projection: &Projection, allowed: &[&str]) -> CoverageResult {
    CoverageResult {
        provider,
        examined: projection
            .parsed_extensions
            .iter()
            .filter(|ext| allowed.contains(&ext.as_str()))
            .cloned()
            .collect(),
        complete: true,
    }
}

/// Fixtures every one of these five JS providers declares identically:
/// `{ positive: [], negative: [], unsupported: [] }`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fixtures {
    pub positive: Vec<String>,
    pub negative: Vec<String>,
    pub unsupported: Vec<String>,
}

fn manifests_contains(manifests: &[String], exact: &str) -> bool {
    manifests.iter().any(|m| m == exact)
}

fn files_contains(files: &[String], exact: &str) -> bool {
    files.iter().any(|f| f == exact)
}

/// Case-sensitive suffix match, mirroring a JS `/\.(a|b|c)$/.test(file)`
/// regex (none of these five source files pass a case-insensitive flag).
fn ext_matches(file: &str, extensions: &[&str]) -> bool {
    extensions.iter().any(|ext| file.ends_with(&format!(".{ext}")))
}

/// Case-sensitive suffix match against a fixed set of literal filename
/// suffixes, mirroring a JS `/(a|b|c)$/.test(file)` regex.
fn suffix_matches(file: &str, suffixes: &[&str]) -> bool {
    suffixes.iter().any(|s| file.ends_with(s))
}

fn parsed_extensions_has(projection: &Projection, wanted: &str) -> bool {
    projection
        .parsed_extensions
        .iter()
        .any(|ext| ext.to_ascii_lowercase() == wanted)
}

fn cwd(input: &CommandsInput) -> PathBuf {
    input.root.clone()
}

fn root_as_arg(root: &Path) -> String {
    root.to_string_lossy().into_owned()
}
