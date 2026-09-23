//! Port of `src/providers/native/index.mjs`, `src/providers/native/c-family/index.mjs`,
//! `src/providers/native/dart/index.mjs`, `src/providers/native/dotnet/index.mjs`, and
//! `src/providers/native/go/index.mjs`.
//!
//! The JS module `src/providers/native/index.mjs` defines a frozen command
//! matrix (`NATIVE_PROVIDERS`) describing lint/type/test/build entrypoints
//! per language family, plus `nativeProviderFor(extension)` which resolves a
//! file extension to its family record. The four family submodules
//! (`c-family`, `dart`, `dotnet`, `go`) are language packs with a
//! `detect`/`commands`/`normalize`/`coverage`/`fixtures` shape: `detect`
//! decides whether the pack applies to a projection, `commands` builds the
//! process-invocation plan from discovered manifests and a profile, and
//! `normalize` turns one command's execution result into the provider's
//! stable result shape. `c-family` additionally exports
//! `unsafeMemoryPatterns`, a lightweight regex sweep for unsafe libc calls
//! and allocations without a visible `free` in the leading slice of source.

use regex::Regex;
use std::collections::BTreeMap;
use std::sync::OnceLock;

// ---------------------------------------------------------------------
// src/providers/native/index.mjs — the top-level command matrix.
// ---------------------------------------------------------------------

/// Mirrors the JS `commands: { lint, type, test, build }` object. `type` is
/// a reserved word in Rust, so the field is named `type_check`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeCommands {
    pub lint: Option<&'static str>,
    pub type_check: Option<&'static str>,
    pub test: Option<&'static str>,
    pub build: Option<&'static str>,
}

/// Mirrors one entry of the JS `NATIVE_PROVIDERS` frozen object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeProvider {
    pub id: &'static str,
    pub provider_version: &'static str,
    pub role: &'static str,
    pub phase: &'static str,
    pub languages: &'static [&'static str],
    pub commands: NativeCommands,
    pub host_capabilities: &'static [&'static str],
}

const NATIVE_JAVASCRIPT: NativeProvider = NativeProvider {
    id: "native.javascript",
    provider_version: "1.0.0",
    role: "deterministic",
    phase: "facts",
    languages: &["javascript", "typescript"],
    commands: NativeCommands {
        lint: Some("eslint"),
        type_check: Some("tsc"),
        test: Some("node --test"),
        build: Some("npm run build"),
    },
    host_capabilities: &["process"],
};

const NATIVE_PYTHON: NativeProvider = NativeProvider {
    id: "native.python",
    provider_version: "1.0.0",
    role: "deterministic",
    phase: "facts",
    languages: &["python"],
    commands: NativeCommands {
        lint: Some("ruff"),
        type_check: Some("basedpyright"),
        test: Some("pytest"),
        build: Some("python -m compileall"),
    },
    host_capabilities: &["process"],
};

const NATIVE_RUST: NativeProvider = NativeProvider {
    id: "native.rust",
    provider_version: "1.0.0",
    role: "deterministic",
    phase: "facts",
    languages: &["rust"],
    commands: NativeCommands {
        lint: Some("cargo clippy"),
        type_check: Some("cargo check"),
        test: Some("cargo test"),
        build: Some("cargo build"),
    },
    host_capabilities: &["process"],
};

const NATIVE_GO: NativeProvider = NativeProvider {
    id: "native.go",
    provider_version: "1.0.0",
    role: "deterministic",
    phase: "facts",
    languages: &["go"],
    commands: NativeCommands {
        lint: Some("go vet"),
        type_check: Some("go build"),
        test: Some("go test"),
        build: None,
    },
    host_capabilities: &["process"],
};

const NATIVE_JVM: NativeProvider = NativeProvider {
    id: "native.jvm",
    provider_version: "1.0.0",
    role: "deterministic",
    phase: "facts",
    languages: &["java", "kotlin", "scala"],
    commands: NativeCommands {
        lint: Some("gradle lint"),
        type_check: Some("gradle compileJava"),
        test: Some("gradle test"),
        build: None,
    },
    host_capabilities: &["process"],
};

const NATIVE_DOTNET: NativeProvider = NativeProvider {
    id: "native.dotnet",
    provider_version: "1.0.0",
    role: "deterministic",
    phase: "facts",
    languages: &["csharp", "fsharp", "vb"],
    commands: NativeCommands {
        lint: Some("dotnet format"),
        type_check: Some("dotnet build"),
        test: Some("dotnet test"),
        build: None,
    },
    host_capabilities: &["process"],
};

/// Mirrors `NATIVE_PROVIDERS`, keyed by provider id.
pub fn native_providers() -> &'static BTreeMap<&'static str, NativeProvider> {
    static MAP: OnceLock<BTreeMap<&'static str, NativeProvider>> = OnceLock::new();
    MAP.get_or_init(|| {
        BTreeMap::from([
            ("native.javascript", NATIVE_JAVASCRIPT),
            ("native.python", NATIVE_PYTHON),
            ("native.rust", NATIVE_RUST),
            ("native.go", NATIVE_GO),
            ("native.jvm", NATIVE_JVM),
            ("native.dotnet", NATIVE_DOTNET),
        ])
    })
}

/// Mirrors `nativeProviderFor(extension)`. The JS version looks the
/// extension up in an internal `map` object and returns
/// `NATIVE_PROVIDERS[map[extension]] ?? null`; an extension absent from
/// `map`, or present but pointing at a family id absent from
/// `NATIVE_PROVIDERS`, both resolve to `None`.
pub fn native_provider_for(extension: &str) -> Option<&'static NativeProvider> {
    let family_id = match extension {
        "js" | "ts" | "mjs" | "cjs" => "native.javascript",
        "py" => "native.python",
        "rs" => "native.rust",
        "go" => "native.go",
        "java" | "kt" | "scala" => "native.jvm",
        "cs" | "fs" | "vb" => "native.dotnet",
        _ => return None,
    };
    native_providers().get(family_id)
}

// ---------------------------------------------------------------------
// Shared language-pack shapes used by c-family/dart/dotnet/go.
// ---------------------------------------------------------------------

/// Mirrors one entry pushed onto a pack's `commands` array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackCommand {
    pub id: &'static str,
    pub executable: &'static str,
    pub args: Vec<String>,
    pub cwd: String,
    pub kind: &'static str,
}

/// Mirrors the `profile` parameter passed to a pack's `commands()`. JS
/// compares with `!== 'fast'`, so any profile other than exactly `"fast"`
/// (including `None`, i.e. `undefined`) takes the non-fast branch.
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

/// Mirrors the `execution` argument passed into a pack's `normalize()`:
/// `execution?.exitCode` and `execution?.toolVersion`.
#[derive(Debug, Clone, Default)]
pub struct Execution {
    pub exit_code: Option<i64>,
    pub tool_version: Option<String>,
}

/// Mirrors one entry of `normalize()`'s `coverageGaps` array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageGap {
    pub kind: &'static str,
    pub command: String,
}

/// Mirrors the object returned by every pack's `normalize()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizeResult {
    pub provider: &'static str,
    pub status: &'static str,
    pub complete: bool,
    pub command: String,
    pub tool_version: Option<String>,
    pub coverage_gaps: Vec<CoverageGap>,
}

fn normalize_common(
    provider: &'static str,
    command_id: &str,
    execution: Option<&Execution>,
) -> NormalizeResult {
    let exit_code = execution.and_then(|execution| execution.exit_code);
    let pass = exit_code == Some(0);
    NormalizeResult {
        provider,
        status: if pass { "pass" } else { "error" },
        complete: pass,
        command: command_id.to_string(),
        tool_version: execution.and_then(|execution| execution.tool_version.clone()),
        coverage_gaps: if pass {
            Vec::new()
        } else {
            vec![CoverageGap {
                kind: "command-failed",
                command: command_id.to_string(),
            }]
        },
    }
}

/// Mirrors the object returned by every pack's `coverage()`. Every pack
/// hard-codes `complete: true`, matching the JS source.
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
// src/providers/native/c-family/index.mjs
// ---------------------------------------------------------------------

pub mod c_family {
    use super::*;

    pub const PROVIDER: &str = "language.c-family";

    fn source_ext_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"\.(c|cc|cpp|cxx|h|hpp)$").expect("valid regex"))
    }

    fn manifest_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(r"(CMakeLists\.txt|compile_commands\.json)$").expect("valid regex")
        })
    }

    /// Mirrors `detect({ projection })`.
    pub fn detect(files: &[String]) -> bool {
        files.iter().any(|file| source_ext_re().is_match(file))
            || files.iter().any(|file| manifest_re().is_match(file))
    }

    /// Mirrors `commands({ root, files, manifests, profile })`. `files` is
    /// accepted for parity with the JS signature but, matching the source,
    /// is not read.
    pub fn commands(root: &str, _files: &[String], manifests: &[String], profile: Profile) -> Vec<PackCommand> {
        let mut commands = Vec::new();
        let has_compile_commands = manifests.iter().any(|m| m == "compile_commands.json");
        if has_compile_commands {
            commands.push(PackCommand {
                id: "c-family.syntax",
                executable: "clang",
                args: vec![
                    "--analyze".into(),
                    "-Xanalyzer".into(),
                    "-analyzer-output=text".into(),
                ],
                cwd: root.to_string(),
                kind: "syntax",
            });
        } else if manifests.iter().any(|m| m == "CMakeLists.txt") {
            commands.push(PackCommand {
                id: "c-family.cmake",
                executable: "cmake",
                args: vec!["--build".into(), "build".into()],
                cwd: root.to_string(),
                kind: "build",
            });
        }
        if !profile.is_fast() {
            commands.push(PackCommand {
                id: "c-family.tidy",
                executable: "clang-tidy",
                args: vec!["-p".into(), "build".into()],
                cwd: root.to_string(),
                kind: "lint",
            });
            commands.push(PackCommand {
                id: "c-family.cppcheck",
                executable: "cppcheck",
                args: vec!["--enable=warning".into(), ".".into()],
                cwd: root.to_string(),
                kind: "lint",
            });
        }
        commands
    }

    /// Mirrors `normalize({ commandId, execution, artifacts })`; `artifacts`
    /// is unused in the JS source.
    pub fn normalize(command_id: &str, execution: Option<&Execution>) -> NormalizeResult {
        normalize_common(PROVIDER, command_id, execution)
    }

    const EXAMINABLE_EXTENSIONS: &[&str] = &["c", "cc", "cpp", "cxx", "h", "hpp"];

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

    /// Mirrors one entry pushed by `unsafeMemoryPatterns`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct UnsafeMemoryObservation {
        pub file: String,
        pub rule_id: &'static str,
        pub severity_hint: &'static str,
        pub claim: &'static str,
        pub line: u32,
    }

    fn unsafe_libc_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(r"\b(?:strcpy|sprintf|gets|scanf)\s*\(").expect("valid regex")
        })
    }

    fn unchecked_allocation_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(r"\b(?:malloc|realloc)\s*\([^)]*\)\s*\)\s*;").expect("valid regex")
        })
    }

    fn free_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"free\s*\(").expect("valid regex"))
    }

    /// Mirrors `unsafeMemoryPatterns(files, readFile)`. `readFile` mirrors
    /// the JS callback: it may return `None` for a file (JS `?? ''`), and
    /// the "leading 4000 characters" slice is taken on the UTF-16-adjacent
    /// JS `String.prototype.slice(0, 4000)`; this port takes the first 4000
    /// Unicode scalar values, which matches for all-ASCII/Latin-1 source
    /// text (the overwhelmingly common case for the byte-length check this
    /// heuristic performs).
    pub fn unsafe_memory_patterns(
        files: &[String],
        read_file: impl Fn(&str) -> Option<String>,
    ) -> Vec<UnsafeMemoryObservation> {
        let mut observations = Vec::new();
        for file in files {
            let text = read_file(file).unwrap_or_default();
            if unsafe_libc_re().is_match(&text) {
                observations.push(UnsafeMemoryObservation {
                    file: file.clone(),
                    rule_id: "c-family.unsafe-libc",
                    severity_hint: "high",
                    claim: "Unsafe libc function without bounds.",
                    line: 1,
                });
            }
            let leading: String = text.chars().take(4000).collect();
            if unchecked_allocation_re().is_match(&text) && !free_re().is_match(&leading) {
                observations.push(UnsafeMemoryObservation {
                    file: file.clone(),
                    rule_id: "c-family.unchecked-allocation",
                    severity_hint: "medium",
                    claim: "Allocation without visible free path.",
                    line: 1,
                });
            }
        }
        observations
    }
}

// ---------------------------------------------------------------------
// src/providers/native/dart/index.mjs
// ---------------------------------------------------------------------

pub mod dart {
    use super::*;

    pub const PROVIDER: &str = "language.dart";

    fn dart_ext_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"\.dart$").expect("valid regex"))
    }

    fn manifest_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(r"(pubspec\.yaml|analysis_options\.yaml)$").expect("valid regex")
        })
    }

    fn pubspec_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"pubspec\.yaml").expect("valid regex"))
    }

    /// Mirrors `detect({ projection })`.
    pub fn detect(files: &[String]) -> bool {
        files.iter().any(|file| dart_ext_re().is_match(file))
            || files.iter().any(|file| manifest_re().is_match(file))
    }

    /// Mirrors `commands({ root, files, manifests, profile })`.
    pub fn commands(root: &str, _files: &[String], manifests: &[String], profile: Profile) -> Vec<PackCommand> {
        let mut commands = Vec::new();
        if manifests.iter().any(|m| pubspec_re().is_match(m)) {
            commands.push(PackCommand {
                id: "dart.analyze",
                executable: "dart",
                args: vec!["analyze".into()],
                cwd: root.to_string(),
                kind: "static",
            });
            if !profile.is_fast() {
                commands.push(PackCommand {
                    id: "dart.test",
                    executable: "dart",
                    args: vec!["test".into()],
                    cwd: root.to_string(),
                    kind: "test",
                });
            }
        }
        commands
    }

    /// Mirrors `normalize({ commandId, execution, artifacts })`.
    pub fn normalize(command_id: &str, execution: Option<&Execution>) -> NormalizeResult {
        normalize_common(PROVIDER, command_id, execution)
    }

    /// Mirrors `coverage({ projection, plan, results })`.
    pub fn coverage(parsed_extensions: &[String]) -> PackCoverage {
        PackCoverage {
            provider: PROVIDER,
            examined: parsed_extensions
                .iter()
                .filter(|ext| ext.as_str() == "dart")
                .cloned()
                .collect(),
            complete: true,
        }
    }

    pub fn fixtures() -> PackFixtures {
        empty_fixtures()
    }
}

// ---------------------------------------------------------------------
// src/providers/native/dotnet/index.mjs
// ---------------------------------------------------------------------

pub mod dotnet {
    use super::*;

    pub const PROVIDER: &str = "language.dotnet";

    fn source_ext_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"\.(cs|fs|vb)$").expect("valid regex"))
    }

    fn manifest_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"\.(csproj|fsproj|vbproj|sln)$").expect("valid regex"))
    }

    fn build_manifest_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"\.(csproj|sln)$").expect("valid regex"))
    }

    /// Mirrors `detect({ projection })`.
    pub fn detect(files: &[String]) -> bool {
        files.iter().any(|file| source_ext_re().is_match(file))
            || files.iter().any(|file| manifest_re().is_match(file))
    }

    /// Mirrors `commands({ root, files, manifests, profile })`.
    pub fn commands(root: &str, _files: &[String], manifests: &[String], profile: Profile) -> Vec<PackCommand> {
        let mut commands = Vec::new();
        if manifests.iter().any(|m| build_manifest_re().is_match(m)) {
            commands.push(PackCommand {
                id: "dotnet.build",
                executable: "dotnet",
                args: vec!["build".into(), "--no-restore".into()],
                cwd: root.to_string(),
                kind: "build",
            });
            if !profile.is_fast() {
                commands.push(PackCommand {
                    id: "dotnet.test",
                    executable: "dotnet",
                    args: vec!["test".into(), "--no-restore".into()],
                    cwd: root.to_string(),
                    kind: "test",
                });
            }
        }
        commands
    }

    /// Mirrors `normalize({ commandId, execution, artifacts })`.
    pub fn normalize(command_id: &str, execution: Option<&Execution>) -> NormalizeResult {
        normalize_common(PROVIDER, command_id, execution)
    }

    const EXAMINABLE_EXTENSIONS: &[&str] = &["cs", "fs", "vb"];

    /// Mirrors `coverage({ projection, plan, results })`.
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

// ---------------------------------------------------------------------
// src/providers/native/go/index.mjs
// ---------------------------------------------------------------------

pub mod go {
    use super::*;

    pub const PROVIDER: &str = "language.go";

    /// Mirrors `detect({ projection })`: `(projection?.parsedExtensions ??
    /// []).some((ext) => ext.toLowerCase() === 'go') ||
    /// (projection?.files ?? []).some((file) => file === 'go.mod')`.
    pub fn detect(parsed_extensions: &[String], files: &[String]) -> bool {
        parsed_extensions
            .iter()
            .any(|ext| ext.to_lowercase() == "go")
            || files.iter().any(|file| file == "go.mod")
    }

    /// Mirrors `commands({ root, files, manifests, profile })`.
    pub fn commands(root: &str, _files: &[String], manifests: &[String], profile: Profile) -> Vec<PackCommand> {
        let mut commands = Vec::new();
        if manifests.iter().any(|m| m == "go.mod") {
            commands.push(PackCommand {
                id: "go.vet",
                executable: "go",
                args: vec!["vet".into(), "./...".into()],
                cwd: root.to_string(),
                kind: "lint",
            });
            if !profile.is_fast() {
                commands.push(PackCommand {
                    id: "go.test",
                    executable: "go",
                    args: vec!["test".into(), "./...".into()],
                    cwd: root.to_string(),
                    kind: "test",
                });
                commands.push(PackCommand {
                    id: "go.vuln",
                    executable: "govulncheck",
                    args: vec!["./...".into()],
                    cwd: root.to_string(),
                    kind: "vulnerability",
                });
            }
        }
        commands
    }

    /// Mirrors `normalize({ commandId, execution, artifacts })`.
    pub fn normalize(command_id: &str, execution: Option<&Execution>) -> NormalizeResult {
        normalize_common(PROVIDER, command_id, execution)
    }

    /// Mirrors `coverage({ projection, plan, results })`.
    pub fn coverage(parsed_extensions: &[String]) -> PackCoverage {
        PackCoverage {
            provider: PROVIDER,
            examined: parsed_extensions
                .iter()
                .filter(|ext| ext.as_str() == "go")
                .cloned()
                .collect(),
            complete: true,
        }
    }

    pub fn fixtures() -> PackFixtures {
        empty_fixtures()
    }
}
