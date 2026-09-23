//! Port of `src/providers/native/rust/index.mjs` and
//! `src/providers/native/swift-objc/index.mjs`
//! (chunk wf039, area `src/providers/native`, target crate `legion-audit`).
//!
//! Both JS modules are language packs with the same `detect`/`commands`/
//! `normalize`/`coverage`/`fixtures` shape used across the `native/*`
//! family (see also chunk wf037's port of the c-family/dart/dotnet/go
//! packs). `rust/index.mjs` additionally exports a free function,
//! `unsafeBoundaries(files, readFile)`, that sweeps source text for
//! `unsafe` blocks/fns/impls and `extern "C"` boundaries.
//!
//! This port is self-contained: it defines its own small `PackCommand` /
//! `Execution` / `NormalizeResult` / `PackCoverage` shapes rather than
//! reusing another chunk's private types, since sibling `wf_port` chunks
//! are ported independently and in parallel.
//!
//! No Membrane/Blueprint references exist in either source file, so there
//! is nothing to drop here.

use regex::Regex;
use std::sync::OnceLock;

/// Mirrors the `profile` parameter passed to a pack's `commands()`. Both JS
/// sources compare with `!== 'fast'`, so any profile other than exactly
/// `"fast"` (including `None`, i.e. `undefined`) takes the non-fast branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Fast,
    Other,
}

impl Profile {
    pub fn from_str_opt(value: Option<&str>) -> Self {
        match value {
            Some("fast") => Profile::Fast,
            _ => Profile::Other,
        }
    }

    fn is_fast(self) -> bool {
        matches!(self, Profile::Fast)
    }
}

/// Mirrors one entry pushed onto a pack's `commands` array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackCommand {
    pub id: &'static str,
    pub executable: Option<&'static str>,
    pub args: Vec<String>,
    pub cwd: String,
    pub kind: &'static str,
    /// Only set by the swift-objc pack's degraded entry.
    pub reason: Option<&'static str>,
}

/// Mirrors the `execution` argument passed into a pack's `normalize()`:
/// `execution?.exitCode`, `execution?.toolVersion`, and (swift-objc only)
/// `execution?.degraded` / `execution?.reason`.
#[derive(Debug, Clone, Default)]
pub struct Execution {
    pub exit_code: Option<i64>,
    pub tool_version: Option<String>,
    pub degraded: bool,
    pub reason: Option<String>,
}

/// Mirrors one entry of `normalize()`'s `coverageGaps` array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageGap {
    pub kind: &'static str,
    pub command: Option<String>,
    pub reason: Option<String>,
}

/// Mirrors the object returned by every pack's `normalize()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizeResult {
    pub provider: &'static str,
    pub status: &'static str,
    pub complete: bool,
    pub command: Option<String>,
    pub tool_version: Option<String>,
    pub coverage_gaps: Vec<CoverageGap>,
}

/// Mirrors the object returned by every pack's `coverage()`. Both packs
/// hard-code `complete: true`, matching the JS source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackCoverage {
    pub provider: &'static str,
    pub examined: Vec<String>,
    pub complete: bool,
}

/// Mirrors every pack's `fixtures: { positive: [], negative: [], unsupported: [] }`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackFixtures {
    pub positive: Vec<String>,
    pub negative: Vec<String>,
    pub unsupported: Vec<String>,
}

pub fn empty_fixtures() -> PackFixtures {
    PackFixtures::default()
}

// ---------------------------------------------------------------------
// src/providers/native/rust/index.mjs
// ---------------------------------------------------------------------

pub mod rust {
    use super::*;

    pub const PROVIDER: &str = "language.rust";

    /// Mirrors `detect({ projection })`:
    /// ```js
    /// (projection?.parsedExtensions ?? []).some((ext) => ext.toLowerCase() === 'rs')
    ///   || (projection?.files ?? []).some((file) => file === 'Cargo.toml')
    /// ```
    pub fn detect(parsed_extensions: &[String], files: &[String]) -> bool {
        parsed_extensions
            .iter()
            .any(|ext| ext.to_lowercase() == "rs")
            || files.iter().any(|file| file == "Cargo.toml")
    }

    /// Mirrors `commands({ root, files, manifests, profile })`. `files` is
    /// accepted for parity with the JS signature but, matching the source,
    /// is not read.
    pub fn commands(
        root: &str,
        _files: &[String],
        manifests: &[String],
        profile: Profile,
    ) -> Vec<PackCommand> {
        let mut commands = Vec::new();
        if manifests.iter().any(|m| m == "Cargo.toml") {
            commands.push(PackCommand {
                id: "rust.check",
                executable: Some("cargo"),
                args: vec!["check".into(), "--offline".into()],
                cwd: root.to_string(),
                kind: "type-check",
                reason: None,
            });
            if !profile.is_fast() {
                commands.push(PackCommand {
                    id: "rust.clippy",
                    executable: Some("cargo"),
                    args: vec![
                        "clippy".into(),
                        "--offline".into(),
                        "--".into(),
                        "-D".into(),
                        "warnings".into(),
                    ],
                    cwd: root.to_string(),
                    kind: "lint",
                    reason: None,
                });
                commands.push(PackCommand {
                    id: "rust.test",
                    executable: Some("cargo"),
                    args: vec!["test".into(), "--offline".into()],
                    cwd: root.to_string(),
                    kind: "test",
                    reason: None,
                });
            }
        }
        commands
    }

    /// Mirrors `normalize({ commandId, execution, artifacts })`; `artifacts`
    /// is unused in the JS source.
    pub fn normalize(command_id: &str, execution: Option<&Execution>) -> NormalizeResult {
        let exit_code = execution.and_then(|e| e.exit_code);
        let pass = exit_code == Some(0);
        NormalizeResult {
            provider: PROVIDER,
            status: if pass { "pass" } else { "error" },
            complete: pass,
            command: Some(command_id.to_string()),
            tool_version: execution.and_then(|e| e.tool_version.clone()),
            coverage_gaps: if pass {
                Vec::new()
            } else {
                vec![CoverageGap {
                    kind: "command-failed",
                    command: Some(command_id.to_string()),
                    reason: None,
                }]
            },
        }
    }

    /// Mirrors `coverage({ projection, plan, results })`; `plan`/`results`
    /// are unused in the JS source: `examined` is every `rs` entry found in
    /// `parsedExtensions` (which, per the JS `.filter((ext) => ext === 'rs')`,
    /// is case-sensitive here, unlike `detect`'s lowercased comparison).
    pub fn coverage(parsed_extensions: &[String]) -> PackCoverage {
        PackCoverage {
            provider: PROVIDER,
            examined: parsed_extensions
                .iter()
                .filter(|ext| ext.as_str() == "rs")
                .cloned()
                .collect(),
            complete: true,
        }
    }

    pub fn fixtures() -> PackFixtures {
        empty_fixtures()
    }

    /// Mirrors one entry pushed by `unsafeBoundaries`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct UnsafeBoundary {
        pub file: String,
        pub line: u32,
        pub kind: &'static str,
    }

    fn unsafe_block_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"\bunsafe\s*(?:fn|\{|impl)").expect("valid regex"))
    }

    fn extern_c_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r#"extern\s+"C""#).expect("valid regex"))
    }

    /// Mirrors:
    /// ```js
    /// export function unsafeBoundaries(files, readFile) {
    ///   const boundaries = [];
    ///   for (const file of files) {
    ///     const text = readFile(file) ?? '';
    ///     const matches = [...text.matchAll(/\bunsafe\s*(?:fn|\{|impl)/g)];
    ///     for (const match of matches) {
    ///       const line = text.slice(0, match.index).split('\n').length;
    ///       boundaries.push({ file, line, kind: 'unsafe-block' });
    ///     }
    ///     if (/extern\s+"C"/.test(text)) {
    ///       boundaries.push({ file, line: 1, kind: 'ffi-boundary' });
    ///     }
    ///   }
    ///   return boundaries;
    /// }
    /// ```
    /// `read_file` mirrors the JS callback: it may return `None` for a file
    /// (JS `?? ''`). Line numbers are 1-based, matching
    /// `text.slice(0, match.index).split('\n').length`.
    pub fn unsafe_boundaries(
        files: &[String],
        read_file: impl Fn(&str) -> Option<String>,
    ) -> Vec<UnsafeBoundary> {
        let mut boundaries = Vec::new();
        for file in files {
            let text = read_file(file).unwrap_or_default();
            for m in unsafe_block_re().find_iter(&text) {
                let line = text[..m.start()].matches('\n').count() as u32 + 1;
                boundaries.push(UnsafeBoundary {
                    file: file.clone(),
                    line,
                    kind: "unsafe-block",
                });
            }
            if extern_c_re().is_match(&text) {
                boundaries.push(UnsafeBoundary {
                    file: file.clone(),
                    line: 1,
                    kind: "ffi-boundary",
                });
            }
        }
        boundaries
    }
}

// ---------------------------------------------------------------------
// src/providers/native/swift-objc/index.mjs
// ---------------------------------------------------------------------

pub mod swift_objc {
    use super::*;

    pub const PROVIDER: &str = "language.swift-objc";

    fn source_ext_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"\.(swift|m|mm)$").expect("valid regex"))
    }

    fn manifest_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(r"(Package\.swift|\.xcodeproj|\.xcworkspace)").expect("valid regex")
        })
    }

    /// Mirrors `detect({ projection })`.
    pub fn detect(files: &[String]) -> bool {
        files.iter().any(|file| source_ext_re().is_match(file))
            || files.iter().any(|file| manifest_re().is_match(file))
    }

    /// Mirrors `commands({ root, files, manifests, profile, platform })`.
    /// `files` is accepted for parity with the JS signature but, matching
    /// the source, is not read. When `platform !== 'darwin'` the JS source
    /// short-circuits to a single degraded entry (`executable: null,
    /// args: []`) and never inspects `manifests`.
    pub fn commands(
        root: &str,
        _files: &[String],
        manifests: &[String],
        profile: Profile,
        platform: &str,
    ) -> Vec<PackCommand> {
        if platform != "darwin" {
            return vec![PackCommand {
                id: "swift.degraded",
                executable: None,
                args: Vec::new(),
                cwd: root.to_string(),
                kind: "degraded",
                reason: Some("Swift toolchain requires macOS"),
            }];
        }
        let mut commands = Vec::new();
        if manifests.iter().any(|m| m == "Package.swift") {
            commands.push(PackCommand {
                id: "swift.build",
                executable: Some("swift"),
                args: vec!["build".into()],
                cwd: root.to_string(),
                kind: "build",
                reason: None,
            });
            if !profile.is_fast() {
                commands.push(PackCommand {
                    id: "swift.test",
                    executable: Some("swift"),
                    args: vec!["test".into()],
                    cwd: root.to_string(),
                    kind: "test",
                    reason: None,
                });
                commands.push(PackCommand {
                    id: "swift.lint",
                    executable: Some("swiftlint"),
                    args: vec!["lint".into()],
                    cwd: root.to_string(),
                    kind: "lint",
                    reason: None,
                });
            }
        }
        commands
    }

    /// Mirrors `normalize({ commandId, execution, artifacts })`. When
    /// `execution?.degraded` is truthy, the JS source returns a distinct
    /// shape (`status: 'unproven', complete: false`, a single
    /// `host-limited` coverage gap) and never looks at `commandId` or
    /// `execution.exitCode`.
    pub fn normalize(command_id: &str, execution: Option<&Execution>) -> NormalizeResult {
        if let Some(exec) = execution {
            if exec.degraded {
                return NormalizeResult {
                    provider: PROVIDER,
                    status: "unproven",
                    complete: false,
                    command: None,
                    tool_version: None,
                    coverage_gaps: vec![CoverageGap {
                        kind: "host-limited",
                        command: None,
                        reason: exec.reason.clone(),
                    }],
                };
            }
        }
        let exit_code = execution.and_then(|e| e.exit_code);
        let pass = exit_code == Some(0);
        NormalizeResult {
            provider: PROVIDER,
            status: if pass { "pass" } else { "error" },
            complete: pass,
            command: Some(command_id.to_string()),
            tool_version: execution.and_then(|e| e.tool_version.clone()),
            coverage_gaps: if pass {
                Vec::new()
            } else {
                vec![CoverageGap {
                    kind: "command-failed",
                    command: Some(command_id.to_string()),
                    reason: None,
                }]
            },
        }
    }

    const EXAMINABLE_EXTENSIONS: &[&str] = &["swift", "m", "mm"];

    /// Mirrors `coverage({ projection, plan, results })`; `plan`/`results`
    /// are unused in the JS source.
    pub fn coverage(parsed_extensions: &[String]) -> PackCoverage {
        PackCoverage {
            provider: PROVIDER,
            examined: parsed_extensions
                .iter()
                .filter(|ext| EXAMINABLE_EXTENSIONS.contains(&ext.as_str()))
                .cloned()
                .collect(),
            complete: true,
        }
    }

    pub fn fixtures() -> PackFixtures {
        empty_fixtures()
    }
}
