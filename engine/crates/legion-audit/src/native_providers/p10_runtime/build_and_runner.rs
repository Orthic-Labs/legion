//! Faithful Rust port of four legacy JS providers:
//!
//!   - `src/providers/build/cmake/index.mjs`
//!   - `src/providers/build/gradle/index.mjs`
//!   - `src/providers/build/maven/index.mjs`
//!   - `src/providers/native-family-runner.mjs`
//!
//! `native-family-runner.mjs` does not itself call out to
//! `src/providers/native/*` — it defines its own inline `FAMILY_SPECS`
//! (per-language command derivation) and `FRAMEWORK_SPECS` (per-framework
//! static-finding inspection) tables and dispatches over them directly. This
//! port keeps that same self-contained shape so the module compiles and is
//! testable independent of the sibling `native_lang` packet landing first.
//! If the integrator wants per-language command derivation to route through
//! the sibling module instead of the table in this file, the expected shape
//! is:
//!
//! ```ignore
//! pub fn dispatch_family(
//!     family_id: &str,
//!     root: &std::path::Path,
//!     files: &[String],
//! ) -> Vec<FamilyCommand>;
//! ```
//!
//! where `FamilyCommand` is the struct defined below (or an equivalent
//! `{id, command, args, timeout_ms}` shape) — `family_commands()` in this
//! file would then delegate to it for the `language.*` family ids.
//!
//! Membrane/Blueprint: none of the four ported JS files call out to Membrane
//! or Blueprint services. One finding message in the Tailwind framework
//! check contains the literal prose fragment "Blueprint denominator" (it
//! refers to the audit plan's coverage denominator, not the Blueprint
//! product); it is ported verbatim as inert text, not as an integration.

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------
// Shared hashing helpers (native-family-runner.mjs: sha256, pathDigest)
// ---------------------------------------------------------------------

pub fn sha256_of(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

pub fn path_digest(paths: &[String]) -> String {
    let mut sorted: Vec<&str> = paths.iter().map(|s| s.as_str()).collect();
    sorted.sort_unstable();
    sha256_of(&sorted.join("\0"))
}

// ---------------------------------------------------------------------
// CMake build provider (src/providers/build/cmake/index.mjs)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CmakePresetReceipt {
    pub schema_version: u32,
    pub kind: String,
    pub root: String,
    pub preset_present: bool,
    pub preset_name: Option<String>,
    pub build_dir: Option<String>,
}

pub fn cmake_preset_receipt(
    root: &str,
    preset_present: bool,
    preset_name: Option<&str>,
    build_dir: Option<&str>,
) -> CmakePresetReceipt {
    CmakePresetReceipt {
        schema_version: 1,
        kind: "legion-cmake-preset".to_string(),
        root: root.to_string(),
        preset_present,
        preset_name: preset_name.map(|s| s.to_string()),
        build_dir: build_dir.map(|s| s.to_string()),
    }
}

/// Shape shared by cmake/gradle/maven's `*Command` builders:
/// `{ executable, args, cwd, timeoutMs, environmentKeys }`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeCommandSpec {
    pub executable: String,
    pub args: Vec<String>,
    pub cwd: String,
    pub timeout_ms: u64,
    pub environment_keys: Vec<String>,
}

pub fn cmake_command(
    root: &str,
    preset: Option<&str>,
    build_dir: Option<&str>,
    targets: &[String],
) -> NativeCommandSpec {
    let build_dir = build_dir.unwrap_or("build");
    let mut args: Vec<String> = match preset {
        Some(p) => vec!["--preset".to_string(), p.to_string()],
        None => vec![
            "-S".to_string(),
            root.to_string(),
            "-B".to_string(),
            build_dir.to_string(),
        ],
    };
    if !targets.is_empty() {
        args.push("--target".to_string());
        args.extend(targets.iter().cloned());
    }
    NativeCommandSpec {
        executable: "cmake".to_string(),
        args,
        cwd: root.to_string(),
        timeout_ms: 300_000,
        environment_keys: vec!["PATH".into(), "HOME".into(), "CC".into(), "CXX".into()],
    }
}

// ---------------------------------------------------------------------
// Gradle build provider (src/providers/build/gradle/index.mjs)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GradleWrapperReceipt {
    pub schema_version: u32,
    pub kind: String,
    pub root: String,
    pub wrapper_present: bool,
    pub wrapper_sha256: Option<String>,
    pub distribution_sha256: Option<String>,
    pub integrity_verified: bool,
}

pub fn gradle_wrapper_receipt(
    root: &str,
    wrapper_present: bool,
    wrapper_sha256: Option<&str>,
    distribution_sha256: Option<&str>,
) -> GradleWrapperReceipt {
    GradleWrapperReceipt {
        schema_version: 1,
        kind: "legion-gradle-wrapper".to_string(),
        root: root.to_string(),
        wrapper_present,
        wrapper_sha256: wrapper_sha256.map(|s| s.to_string()),
        distribution_sha256: distribution_sha256.map(|s| s.to_string()),
        integrity_verified: wrapper_sha256.is_some() && distribution_sha256.is_some(),
    }
}

pub fn gradle_command(root: &str, offline: Option<bool>, tasks: Option<&[String]>) -> NativeCommandSpec {
    let offline = offline.unwrap_or(true);
    let mut args: Vec<String> = tasks
        .map(|t| t.to_vec())
        .unwrap_or_else(|| vec!["compileJava".to_string()]);
    if offline {
        args.push("--offline".to_string());
    }
    NativeCommandSpec {
        executable: "./gradlew".to_string(),
        args,
        cwd: root.to_string(),
        timeout_ms: 300_000,
        environment_keys: vec!["PATH".into(), "HOME".into(), "GRADLE_OPTS".into()],
    }
}

// ---------------------------------------------------------------------
// Maven build provider (src/providers/build/maven/index.mjs)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MavenWrapperReceipt {
    pub schema_version: u32,
    pub kind: String,
    pub root: String,
    pub wrapper_present: bool,
    pub wrapper_sha256: Option<String>,
    pub integrity_verified: bool,
}

pub fn maven_wrapper_receipt(
    root: &str,
    wrapper_present: bool,
    wrapper_sha256: Option<&str>,
) -> MavenWrapperReceipt {
    MavenWrapperReceipt {
        schema_version: 1,
        kind: "legion-maven-wrapper".to_string(),
        root: root.to_string(),
        wrapper_present,
        wrapper_sha256: wrapper_sha256.map(|s| s.to_string()),
        integrity_verified: wrapper_sha256.is_some(),
    }
}

pub fn maven_command(root: &str, offline: Option<bool>, goals: Option<&[String]>) -> NativeCommandSpec {
    let offline = offline.unwrap_or(true);
    let mut args: Vec<String> = goals
        .map(|g| g.to_vec())
        .unwrap_or_else(|| vec!["compile".to_string()]);
    if offline {
        args.push("-o".to_string());
    }
    NativeCommandSpec {
        executable: "./mvnw".to_string(),
        args,
        cwd: root.to_string(),
        timeout_ms: 300_000,
        environment_keys: vec!["PATH".into(), "HOME".into(), "MAVEN_ARGS".into()],
    }
}

// ---------------------------------------------------------------------
// native-family-runner.mjs: shared path/text matching helpers
// ---------------------------------------------------------------------

/// Port of JS's `(^|\/)name$` basename regex idiom.
fn matches_basename(file: &str, name: &str) -> bool {
    file == name || file.ends_with(&format!("/{name}"))
}

/// Port of JS's `(^|\/)name\/` directory-segment idiom.
fn contains_segment_dir(file: &str, name: &str) -> bool {
    let prefixed = format!("{name}/");
    file.starts_with(&prefixed) || file.contains(&format!("/{prefixed}"))
}

fn dir_segments(file: &str) -> Vec<&str> {
    let parts: Vec<&str> = file.split('/').collect();
    if parts.len() <= 1 {
        Vec::new()
    } else {
        parts[..parts.len() - 1].to_vec()
    }
}

fn safe_read(root: &Path, file: &str) -> String {
    std::fs::read_to_string(root.join(file)).unwrap_or_default()
}

fn safe_json(path: &Path) -> Value {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(Value::Null)
}

// ---------------------------------------------------------------------
// native-family-runner.mjs: FAMILY_SPECS (language.*)
// ---------------------------------------------------------------------

/// Shape of the per-family plan command entries: `{id, command, args,
/// timeoutMs}`.
#[derive(Debug, Clone)]
pub struct FamilyCommand {
    pub id: String,
    pub command: String,
    pub args: Vec<String>,
    pub timeout_ms: Option<u64>,
}

impl FamilyCommand {
    fn new(id: &str, command: &str, args: Vec<String>) -> Self {
        Self { id: id.to_string(), command: command.to_string(), args, timeout_ms: None }
    }
}

const FAMILY_IDS: &[&str] = &[
    "language.javascript-typescript",
    "language.python",
    "language.rust",
    "language.swift-objective-c",
    "language.shell-powershell",
    "language.java-kotlin-scala",
    "language.dotnet",
    "language.php",
    "language.go",
    "language.c-cpp",
    "language.ruby",
    "language.dart",
    "language.elixir-erlang",
];

fn family_commands(family_id: &str, root: &Path, files: &[String]) -> Vec<FamilyCommand> {
    match family_id {
        "language.javascript-typescript" => family_js_ts(root, files),
        "language.python" => family_python(root, files),
        "language.rust" => family_rust(root, files),
        "language.swift-objective-c" => family_swift(root, files),
        "language.shell-powershell" => family_shell(root, files),
        "language.java-kotlin-scala" => family_java(root, files),
        "language.dotnet" => family_dotnet(root, files),
        "language.php" => family_php(root, files),
        "language.go" => family_go(root, files),
        "language.c-cpp" => family_c_cpp(root, files),
        "language.ruby" => family_ruby(root, files),
        "language.dart" => family_dart(root, files),
        "language.elixir-erlang" => family_elixir(root, files),
        _ => Vec::new(),
    }
}

fn family_js_ts(root: &Path, _files: &[String]) -> Vec<FamilyCommand> {
    let manager = if root.join("pnpm-lock.yaml").exists() {
        "pnpm"
    } else if root.join("yarn.lock").exists() {
        "yarn"
    } else {
        "npm"
    };
    let pkg = safe_json(&root.join("package.json"));
    let scripts = pkg
        .get("scripts")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let mut commands = Vec::new();
    {
        let mut run_script = |id: &str, names: &[&str]| {
            if let Some(name) = names.iter().find(|n| scripts.contains_key(**n)) {
                if manager == "npm" {
                    commands.push(FamilyCommand::new(
                        id,
                        "npm",
                        vec!["run".into(), (*name).to_string(), "--if-present".into()],
                    ));
                } else {
                    commands.push(FamilyCommand::new(id, manager, vec!["run".into(), (*name).to_string()]));
                }
            }
        };
        run_script("types", &["typecheck", "types", "check"]);
        run_script("lint", &["lint"]);
        run_script("test", &["test", "test:unit"]);
        run_script("build", &["build"]);
    }
    commands
}

fn family_python(_root: &Path, files: &[String]) -> Vec<FamilyCommand> {
    let mut commands = vec![FamilyCommand::new(
        "compile",
        "python",
        vec!["-m".into(), "compileall".into(), "-q".into(), ".".into()],
    )];
    let has_tests = files.iter().any(|f| {
        dir_segments(f)
            .iter()
            .any(|seg| *seg == "test" || *seg == "tests" || seg.starts_with("test_"))
            || {
                let base = f.rsplit('/').next().unwrap_or(f.as_str());
                base.starts_with("test_") && base.ends_with(".py")
            }
            || f.ends_with("_test.py")
    });
    if has_tests {
        commands.push(FamilyCommand::new(
            "test",
            "python",
            vec!["-m".into(), "pytest".into(), "-q".into()],
        ));
    }
    commands
}

fn family_rust(_root: &Path, files: &[String]) -> Vec<FamilyCommand> {
    let manifest = match files.iter().find(|f| matches_basename(f, "Cargo.toml")) {
        Some(m) => m.clone(),
        None => return Vec::new(),
    };
    let manifest_args = vec!["--manifest-path".to_string(), manifest];
    vec![
        FamilyCommand::new(
            "metadata",
            "cargo",
            [vec!["metadata".into(), "--format-version".into(), "1".into()], manifest_args.clone()].concat(),
        ),
        FamilyCommand::new(
            "check",
            "cargo",
            [vec!["check".into(), "--workspace".into(), "--all-targets".into()], manifest_args.clone()].concat(),
        ),
        FamilyCommand::new(
            "clippy",
            "cargo",
            [
                vec!["clippy".into(), "--workspace".into(), "--all-targets".into()],
                manifest_args.clone(),
                vec!["--".into(), "-D".into(), "warnings".into()],
            ]
            .concat(),
        ),
        FamilyCommand::new("test", "cargo", [vec!["test".into(), "--workspace".into()], manifest_args].concat()),
    ]
}

fn family_swift(_root: &Path, files: &[String]) -> Vec<FamilyCommand> {
    if files.iter().any(|f| matches_basename(f, "Package.swift")) {
        return vec![
            FamilyCommand::new("build", "swift", vec!["build".into()]),
            FamilyCommand::new("test", "swift", vec!["test".into()]),
        ];
    }
    files
        .iter()
        .filter(|f| f.ends_with(".swift"))
        .map(|f| FamilyCommand {
            id: format!("typecheck:{f}"),
            command: "swiftc".to_string(),
            args: vec!["-typecheck".into(), f.clone()],
            timeout_ms: Some(60_000),
        })
        .collect()
}

fn family_shell(_root: &Path, files: &[String]) -> Vec<FamilyCommand> {
    let mut commands = Vec::new();
    for file in files {
        if file.ends_with(".sh") || file.ends_with(".bash") || file.ends_with(".zsh") {
            commands.push(FamilyCommand {
                id: format!("syntax:{file}"),
                command: "bash".to_string(),
                args: vec!["-n".into(), file.clone()],
                timeout_ms: Some(30_000),
            });
        }
        if file.ends_with(".ps1") || file.ends_with(".psm1") {
            let escaped = file.replace('\'', "''");
            let ps_cmd = format!(
                "$errors=$null; [void][System.Management.Automation.Language.Parser]::ParseFile('{escaped}', [ref]$null, [ref]$errors); if($errors.Count){{$errors | Out-String; exit 1}}"
            );
            let (exe, mut args) = if cfg!(target_os = "windows") {
                ("powershell".to_string(), vec!["-NoProfile".to_string(), "-NonInteractive".to_string(), "-Command".to_string()])
            } else {
                ("pwsh".to_string(), vec!["-NoProfile".to_string(), "-NonInteractive".to_string(), "-Command".to_string()])
            };
            args.push(ps_cmd);
            commands.push(FamilyCommand { id: format!("syntax:{file}"), command: exe, args, timeout_ms: Some(30_000) });
        }
    }
    commands
}

fn family_java(root: &Path, files: &[String]) -> Vec<FamilyCommand> {
    let mut commands = Vec::new();
    let gradlew_name = if cfg!(target_os = "windows") { "gradlew.bat" } else { "gradlew" };
    if root.join(gradlew_name).exists() {
        let wrapper = if cfg!(target_os = "windows") { "gradlew.bat".to_string() } else { "./gradlew".to_string() };
        commands.push(FamilyCommand::new("build", &wrapper, vec!["build".into(), "--no-daemon".into()]));
        commands.push(FamilyCommand::new("test", &wrapper, vec!["test".into(), "--no-daemon".into()]));
        return commands;
    }
    let mvnw_name = if cfg!(target_os = "windows") { "mvnw.cmd" } else { "mvnw" };
    if root.join(mvnw_name).exists() {
        let wrapper = if cfg!(target_os = "windows") { "mvnw.cmd".to_string() } else { "./mvnw".to_string() };
        commands.push(FamilyCommand::new("verify", &wrapper, vec!["-B".into(), "verify".into()]));
        return commands;
    }
    if files.iter().any(|f| matches_basename(f, "pom.xml")) {
        commands.push(FamilyCommand::new("verify", "mvn", vec!["-B".into(), "verify".into()]));
        return commands;
    }
    if files
        .iter()
        .any(|f| matches_basename(f, "build.gradle") || matches_basename(f, "build.gradle.kts"))
    {
        commands.push(FamilyCommand::new("build", "gradle", vec!["build".into(), "--no-daemon".into()]));
    }
    commands
}

fn family_dotnet(_root: &Path, files: &[String]) -> Vec<FamilyCommand> {
    let target = files
        .iter()
        .find(|f| f.ends_with(".sln") || f.ends_with(".slnx"))
        .or_else(|| files.iter().find(|f| f.ends_with(".csproj") || f.ends_with(".fsproj") || f.ends_with(".vbproj")));
    let target = match target {
        Some(t) => t.clone(),
        None => return Vec::new(),
    };
    vec![
        FamilyCommand::new("restore", "dotnet", vec!["restore".into(), target.clone()]),
        FamilyCommand::new("build", "dotnet", vec!["build".into(), target.clone(), "--no-restore".into()]),
        FamilyCommand::new("test", "dotnet", vec!["test".into(), target, "--no-build".into()]),
    ]
}

fn family_php(_root: &Path, files: &[String]) -> Vec<FamilyCommand> {
    let mut commands: Vec<FamilyCommand> = files
        .iter()
        .filter(|f| f.ends_with(".php"))
        .map(|f| FamilyCommand {
            id: format!("syntax:{f}"),
            command: "php".to_string(),
            args: vec!["-l".into(), f.clone()],
            timeout_ms: Some(30_000),
        })
        .collect();
    if files.iter().any(|f| matches_basename(f, "composer.json")) {
        commands.insert(
            0,
            FamilyCommand::new("composer-validate", "composer", vec!["validate".into(), "--no-interaction".into(), "--strict".into()]),
        );
    }
    commands
}

fn family_go(_root: &Path, _files: &[String]) -> Vec<FamilyCommand> {
    vec![
        FamilyCommand::new("test", "go", vec!["test".into(), "./...".into()]),
        FamilyCommand::new("vet", "go", vec!["vet".into(), "./...".into()]),
    ]
}

fn family_c_cpp(root: &Path, files: &[String]) -> Vec<FamilyCommand> {
    if root.join("build").exists() && files.iter().any(|f| matches_basename(f, "CMakeLists.txt")) {
        return vec![FamilyCommand::new("build", "cmake", vec!["--build".into(), "build".into()])];
    }
    if files.iter().any(|f| matches_basename(f, "Makefile") || matches_basename(f, "makefile")) {
        return vec![FamilyCommand::new("build-plan", "make", vec!["-n".into()])];
    }
    Vec::new()
}

fn family_ruby(_root: &Path, files: &[String]) -> Vec<FamilyCommand> {
    let mut commands: Vec<FamilyCommand> = files
        .iter()
        .filter(|f| f.ends_with(".rb"))
        .map(|f| FamilyCommand {
            id: format!("syntax:{f}"),
            command: "ruby".to_string(),
            args: vec!["-c".into(), f.clone()],
            timeout_ms: Some(30_000),
        })
        .collect();
    if files.iter().any(|f| matches_basename(f, "Gemfile")) && files.iter().any(|f| matches_basename(f, "Rakefile")) {
        commands.push(FamilyCommand::new("test", "bundle", vec!["exec".into(), "rake".into(), "test".into()]));
    }
    commands
}

fn family_dart(_root: &Path, files: &[String]) -> Vec<FamilyCommand> {
    let flutter = files.iter().any(|f| {
        contains_segment_dir(f, "android") || contains_segment_dir(f, "ios") || f == "lib/main.dart" || f.ends_with("/lib/main.dart")
    });
    if flutter {
        vec![
            FamilyCommand::new("analyze", "flutter", vec!["analyze".into()]),
            FamilyCommand::new("test", "flutter", vec!["test".into()]),
        ]
    } else {
        vec![
            FamilyCommand::new("analyze", "dart", vec!["analyze".into()]),
            FamilyCommand::new("test", "dart", vec!["test".into()]),
        ]
    }
}

fn family_elixir(_root: &Path, files: &[String]) -> Vec<FamilyCommand> {
    if files.iter().any(|f| matches_basename(f, "mix.exs")) {
        return vec![
            FamilyCommand::new("compile", "mix", vec!["compile".into(), "--warnings-as-errors".into()]),
            FamilyCommand::new("test", "mix", vec!["test".into()]),
        ];
    }
    if files.iter().any(|f| matches_basename(f, "rebar.config")) {
        return vec![FamilyCommand::new("test", "rebar3", vec!["eunit".into()])];
    }
    Vec::new()
}

// ---------------------------------------------------------------------
// native-family-runner.mjs: FRAMEWORK_SPECS (framework.*)
//
// These are heuristic string-matching approximations of the original JS
// regexes (some of which used multi-line / lookahead-like patterns not
// directly expressible without a regex crate, which this file does not
// depend on). They are verified against the six ported unit tests from
// tests/native-family-runner.test.mjs, which pass with this approximation,
// but exact byte-for-byte regex-edge-case parity with the JS is not
// guaranteed for inputs outside those cases.
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub rule_id: String,
    pub level: String,
    pub message: String,
    pub file: Option<String>,
    pub line: u32,
}

fn finding(rule_id: &str, level: &str, message: &str, file: Option<&str>) -> Finding {
    Finding {
        rule_id: rule_id.to_string(),
        level: level.to_string(),
        message: message.to_string(),
        file: file.map(|s| s.to_string()),
        line: 1,
    }
}

const FRAMEWORK_IDS: &[&str] = &[
    "framework.react",
    "framework.tauri",
    "framework.tailwind",
    "framework.laravel",
    "framework.aspnet",
    "framework.spring",
];

fn framework_findings(framework_id: &str, root: &Path, files: &[String]) -> Vec<Finding> {
    match framework_id {
        "framework.react" => framework_react(root, files),
        "framework.tauri" => framework_tauri(root, files),
        "framework.tailwind" => framework_tailwind(root, files),
        "framework.laravel" => framework_laravel(root, files),
        "framework.aspnet" => framework_aspnet(root, files),
        "framework.spring" => framework_spring(root, files),
        _ => Vec::new(),
    }
}

fn framework_react(root: &Path, files: &[String]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for file in files.iter().filter(|f| f.ends_with(".js") || f.ends_with(".jsx") || f.ends_with(".ts") || f.ends_with(".tsx")) {
        let text = safe_read(root, file);
        if text.contains("dangerouslySetInnerHTML") && text.contains('=') {
            findings.push(finding(
                "react-dangerous-html",
                "warning",
                "dangerouslySetInnerHTML requires a proven sanitization boundary.",
                Some(file),
            ));
        }
        let lower = text.to_lowercase();
        let has_storage_call = lower.contains("localstorage.setitem(") || lower.contains("localstorage.getitem(");
        let has_auth_key = ["token", "auth", "jwt", "session"].iter().any(|k| {
            lower.contains(&format!("'{k}")) || lower.contains(&format!("\"{k}"))
        });
        if has_storage_call && has_auth_key {
            findings.push(finding(
                "react-auth-localstorage",
                "warning",
                "Authentication material appears to be stored in localStorage.",
                Some(file),
            ));
        }
        let has_effect_listener =
            text.contains("useEffect(") && (text.contains("addEventListener(") || text.contains("setInterval(") || text.contains("setTimeout("));
        let has_cleanup = text.contains("removeEventListener") || text.contains("clearInterval") || text.contains("clearTimeout");
        if has_effect_listener && !has_cleanup {
            findings.push(finding(
                "react-effect-cleanup",
                "warning",
                "Effect creates a listener or timer without visible cleanup.",
                Some(file),
            ));
        }
        if text.contains(".map(") && text.contains('<') && !text.contains("key=") {
            findings.push(finding("react-list-key", "warning", "Rendered collection has no visible stable key.", Some(file)));
        }
    }
    findings
}

fn extract_invoke_calls(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let needle = "invoke";
    let mut idx = 0usize;
    while idx < text.len() {
        let Some(pos) = text[idx..].find(needle) else { break };
        let start = idx + pos + needle.len();
        let rest = text[start..].trim_start();
        if let Some(rest2) = rest.strip_prefix('(') {
            let rest2 = rest2.trim_start();
            if let Some(q) = rest2.chars().next() {
                if q == '\'' || q == '"' {
                    if let Some(end) = rest2[q.len_utf8()..].find(q) {
                        out.push(rest2[q.len_utf8()..q.len_utf8() + end].to_string());
                    }
                }
            }
        }
        idx = start;
    }
    out
}

fn extract_tauri_commands(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let marker = "#[tauri::command]";
    let mut idx = 0usize;
    while idx < text.len() {
        let Some(pos) = text[idx..].find(marker) else { break };
        let start = idx + pos + marker.len();
        let window_end = (start + 200).min(text.len());
        let window = &text[start..window_end];
        if let Some(fn_pos) = window.find("fn ") {
            let after = &window[fn_pos + 3..];
            let name: String = after.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
            if !name.is_empty() {
                out.push(name);
            }
        }
        idx = start;
    }
    out
}

fn framework_tauri(root: &Path, files: &[String]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let configs: Vec<&String> = files
        .iter()
        .filter(|f| f.ends_with("tauri.conf.json") || f.ends_with("tauri.conf.json5") || f.ends_with("Tauri.toml"))
        .collect();
    if configs.is_empty() {
        findings.push(finding(
            "tauri-config-missing",
            "error",
            "Tauri source is present but no supported configuration file is in the denominator.",
            None,
        ));
    }
    for file in files.iter().filter(|f| f.contains("capabilities/") && (f.ends_with(".json") || f.ends_with(".toml"))) {
        let text = safe_read(root, file);
        let has_broad = text.contains("shell:allow-execute")
            || text.contains("shell:allow-spawn")
            || text.contains("fs:allow-write")
            || text.contains("fs:allow-remove");
        let has_scope = text.contains("windows") || text.contains("webviews") || text.contains("platforms");
        if has_broad && !has_scope {
            findings.push(finding(
                "tauri-broad-capability",
                "warning",
                "Powerful Tauri permission has no visible window, webview, or platform restriction.",
                Some(file),
            ));
        }
    }
    let mut frontend: BTreeSet<String> = BTreeSet::new();
    let mut backend: BTreeSet<String> = BTreeSet::new();
    for file in files
        .iter()
        .filter(|f| f.ends_with(".js") || f.ends_with(".jsx") || f.ends_with(".ts") || f.ends_with(".tsx") || f.ends_with(".rs"))
    {
        let text = safe_read(root, file);
        for cmd in extract_invoke_calls(&text) {
            frontend.insert(cmd);
        }
        if file.ends_with(".rs") {
            for cmd in extract_tauri_commands(&text) {
                backend.insert(cmd);
            }
        }
    }
    for command in &frontend {
        if !backend.contains(command) {
            findings.push(finding(
                "tauri-unregistered-command",
                "error",
                &format!("Frontend invokes {command} but no matching Tauri command was found."),
                None,
            ));
        }
    }
    findings
}

fn framework_tailwind(root: &Path, files: &[String]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let configs: Vec<&String> = files
        .iter()
        .filter(|f| {
            let base = f.rsplit('/').next().unwrap_or(f.as_str());
            base == "tailwind.config.js" || base == "tailwind.config.cjs" || base == "tailwind.config.mjs" || base == "tailwind.config.ts"
        })
        .collect();
    if configs.is_empty() {
        findings.push(finding(
            "tailwind-config-missing",
            "warning",
            "Tailwind dependency exists but no Tailwind config is in the Blueprint denominator.",
            None,
        ));
    }
    for file in files
        .iter()
        .filter(|f| f.ends_with(".js") || f.ends_with(".jsx") || f.ends_with(".ts") || f.ends_with(".tsx") || f.ends_with(".vue") || f.ends_with(".svelte") || f.ends_with(".html"))
    {
        let text = safe_read(root, file);
        if (text.contains("class={") || text.contains("className={")) && text.contains("${") {
            findings.push(finding(
                "tailwind-dynamic-class",
                "warning",
                "Runtime-built Tailwind class may be absent from generated CSS.",
                Some(file),
            ));
        }
        if text.contains("transition-all") {
            findings.push(finding(
                "tailwind-transition-all",
                "note",
                "transition-all broadens animation work and can hide unintended transitions.",
                Some(file),
            ));
        }
    }
    findings
}

fn framework_laravel(root: &Path, files: &[String]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for file in files.iter().filter(|f| f.ends_with(".php")) {
        let text = safe_read(root, file);
        if text.contains("Model::unguard(") {
            findings.push(finding("laravel-unguard", "error", "Global mass-assignment protection is disabled.", Some(file)));
        }
        if text.contains("DB::select($") || text.contains("DB::statement($") || text.contains("DB::unprepared($") {
            findings.push(finding("laravel-raw-sql", "error", "Variable input is passed directly to a raw SQL API.", Some(file)));
        }
        if text.contains("{!!") && text.contains("!!}") {
            findings.push(finding("blade-raw-output", "warning", "Blade raw-output syntax requires explicit trust justification.", Some(file)));
        }
        let normalized: String = text.to_lowercase().chars().filter(|c| !c.is_whitespace()).collect();
        if normalized.contains("app_debug=true") {
            findings.push(finding("laravel-debug-enabled", "error", "Laravel debug mode is enabled in a tracked configuration.", Some(file)));
        }
    }
    findings
}

fn framework_aspnet(root: &Path, files: &[String]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for file in files.iter().filter(|f| f.ends_with(".cs")) {
        let text = safe_read(root, file);
        if text.contains("AllowAnyOrigin()") && text.contains("AllowCredentials()") {
            findings.push(finding("aspnet-cors-credentials", "error", "CORS combines any origin with credentials.", Some(file)));
        }
        if text.contains("[AllowAnonymous]") {
            let lower = text.to_lowercase();
            if lower.contains("delete") || lower.contains("admin") || lower.contains("billing") || lower.contains("payment") || lower.contains("token") {
                findings.push(finding(
                    "aspnet-sensitive-anonymous",
                    "warning",
                    "A sensitive-looking endpoint is explicitly anonymous.",
                    Some(file),
                ));
            }
        }
        if text.contains("UseDeveloperExceptionPage()") && !text.contains("IsDevelopment()") {
            findings.push(finding(
                "aspnet-dev-errors",
                "warning",
                "Developer exception page is not visibly guarded by development environment.",
                Some(file),
            ));
        }
    }
    findings
}

fn framework_spring(root: &Path, files: &[String]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for file in files.iter().filter(|f| f.ends_with(".java") || f.ends_with(".kt")) {
        let text = safe_read(root, file);
        let csrf_disabled = (text.contains("csrf(") && text.contains(".disable(")) || (text.contains("csrf {") && text.contains("disable("));
        if csrf_disabled {
            findings.push(finding(
                "spring-csrf-disabled",
                "warning",
                "Spring Security CSRF protection is disabled; verify the application is strictly stateless.",
                Some(file),
            ));
        }
        let lower = text.to_lowercase();
        if text.contains("requestMatchers(") && text.contains(".permitAll(") && (lower.contains("admin") || lower.contains("internal") || lower.contains("actuator")) {
            findings.push(finding("spring-sensitive-permit-all", "error", "Sensitive-looking Spring route is configured permitAll.", Some(file)));
        }
        if text.contains("SpelExpressionParser") && text.contains("parseExpression(") {
            findings.push(finding("spring-spel-input", "error", "Potentially variable input reaches a SpEL parser.", Some(file)));
        }
    }
    findings
}

// ---------------------------------------------------------------------
// native-family-runner.mjs: process execution (commandExists, runCommand)
// ---------------------------------------------------------------------

struct SpawnResult {
    spawn_error: bool,
    timed_out: bool,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run_with_timeout(cwd: Option<&Path>, command: &str, args: &[String], timeout: Duration) -> SpawnResult {
    let mut cmd = Command::new(command);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped()).stdin(Stdio::null());
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(_) => {
            return SpawnResult { spawn_error: true, timed_out: false, exit_code: None, stdout: String::new(), stderr: String::new() };
        }
    };
    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let stdout_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut p) = stdout_pipe {
            let _ = p.read_to_end(&mut buf);
        }
        buf
    });
    let stderr_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut p) = stderr_pipe {
            let _ = p.read_to_end(&mut buf);
        }
        buf
    });
    let start = Instant::now();
    let status_opt = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => break None,
        }
    };
    let stdout_bytes = stdout_handle.join().unwrap_or_default();
    let stderr_bytes = stderr_handle.join().unwrap_or_default();
    let stdout = String::from_utf8_lossy(&stdout_bytes).to_string();
    let stderr = String::from_utf8_lossy(&stderr_bytes).to_string();
    match status_opt {
        Some(status) => SpawnResult { spawn_error: false, timed_out: false, exit_code: status.code(), stdout, stderr },
        None => SpawnResult { spawn_error: false, timed_out: true, exit_code: None, stdout, stderr },
    }
}

fn command_exists(command: &str) -> bool {
    let result = run_with_timeout(None, command, &["--version".to_string()], Duration::from_secs(10));
    !result.spawn_error && !result.timed_out && result.exit_code == Some(0)
}

fn truncate_chars(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandReceipt {
    pub id: String,
    pub command: String,
    pub status: String,
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr: Option<String>,
}

fn run_command(root: &Path, spec: &FamilyCommand) -> CommandReceipt {
    let command_str = std::iter::once(spec.command.clone())
        .chain(spec.args.iter().cloned())
        .collect::<Vec<_>>()
        .join(" ");
    if !command_exists(&spec.command) {
        return CommandReceipt {
            id: spec.id.clone(),
            command: command_str,
            status: "unproven".to_string(),
            exit_code: None,
            reason: Some("toolchain-missing".to_string()),
            stdout: None,
            stderr: None,
        };
    }
    let timeout = Duration::from_millis(spec.timeout_ms.unwrap_or(180_000));
    let result = run_with_timeout(Some(root), &spec.command, &spec.args, timeout);
    let status = if result.spawn_error || result.timed_out {
        "error"
    } else if result.exit_code == Some(0) {
        "pass"
    } else {
        "fail"
    };
    CommandReceipt {
        id: spec.id.clone(),
        command: command_str,
        status: status.to_string(),
        exit_code: result.exit_code,
        reason: None,
        stdout: Some(truncate_chars(&result.stdout, 200_000)),
        stderr: Some(truncate_chars(&result.stderr, 200_000)),
    }
}

// ---------------------------------------------------------------------
// native-family-runner.mjs: runNativeFamilies / applicableFiles / main
// ---------------------------------------------------------------------

fn applicable_files(plan: &Value, family_id: &str) -> Vec<String> {
    plan.get("coverageFamilies")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.iter().find(|item| item.get("id").and_then(|v| v.as_str()) == Some(family_id)))
        .and_then(|item| item.get("denominator"))
        .and_then(|d| d.get("paths"))
        .and_then(|p| p.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default()
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoverageGap {
    pub kind: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FamilyCoverage {
    pub paths: Vec<String>,
    pub path_count: usize,
    pub examined_paths: Vec<String>,
    pub examined_paths_digest: String,
    pub unexamined_paths: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commands_planned: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commands_completed: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inspected: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FamilyResult {
    pub provider: String,
    pub family: String,
    pub applicable: bool,
    pub required: bool,
    pub status: String,
    pub complete: bool,
    pub coverage: FamilyCoverage,
    pub receipts: Vec<CommandReceipt>,
    pub findings: Vec<Finding>,
    pub coverage_gaps: Vec<CoverageGap>,
    pub degradation: Vec<Value>,
}

pub fn run_native_families(root: &Path, plan: &Value) -> Vec<FamilyResult> {
    let all_plan_paths: BTreeSet<String> = plan
        .get("denominator")
        .and_then(|d| d.get("paths"))
        .and_then(|p| p.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.replace('\\', "/"))).collect())
        .unwrap_or_default();

    let mut results = Vec::new();

    for family_id in FAMILY_IDS {
        let files = applicable_files(plan, family_id);
        if files.is_empty() {
            continue;
        }
        let commands = family_commands(family_id, root, &files);
        let receipts: Vec<CommandReceipt> = commands.iter().map(|c| run_command(root, c)).collect();
        let unavailable = receipts.iter().any(|r| r.status == "unproven");
        let failed = receipts.iter().any(|r| r.status == "fail" || r.status == "error");
        let examined: BTreeSet<String> = files.iter().cloned().collect();
        let mut unexamined: Vec<String> = all_plan_paths.iter().filter(|p| !examined.contains(*p)).cloned().collect();
        unexamined.sort();
        let commands_completed = receipts.iter().filter(|r| r.status != "unproven").count();
        results.push(FamilyResult {
            provider: format!("native.{family_id}"),
            family: family_id.to_string(),
            applicable: true,
            required: true,
            status: if failed {
                "fail".to_string()
            } else if unavailable || commands.is_empty() {
                "unproven".to_string()
            } else {
                "pass".to_string()
            },
            complete: !commands.is_empty() && !unavailable,
            coverage: FamilyCoverage {
                paths: files.clone(),
                path_count: files.len(),
                examined_paths: files.clone(),
                examined_paths_digest: path_digest(&files),
                unexamined_paths: unexamined,
                commands_planned: Some(commands.len()),
                commands_completed: Some(commands_completed),
                inspected: None,
            },
            receipts,
            findings: Vec::new(),
            coverage_gaps: if commands.is_empty() {
                vec![CoverageGap {
                    kind: "native-command".to_string(),
                    detail: "No safe project-native build/test command could be derived.".to_string(),
                }]
            } else if unavailable {
                vec![CoverageGap {
                    kind: "toolchain".to_string(),
                    detail: "A required project-native toolchain is unavailable.".to_string(),
                }]
            } else {
                Vec::new()
            },
            degradation: Vec::new(),
        });
    }

    for framework_id in FRAMEWORK_IDS {
        let files = applicable_files(plan, framework_id);
        if files.is_empty() {
            continue;
        }
        let findings = framework_findings(framework_id, root, &files);
        let examined: BTreeSet<String> = files.iter().cloned().collect();
        let mut unexamined: Vec<String> = all_plan_paths.iter().filter(|p| !examined.contains(*p)).cloned().collect();
        unexamined.sort();
        results.push(FamilyResult {
            provider: format!("native.{framework_id}"),
            family: framework_id.to_string(),
            applicable: true,
            required: true,
            status: if findings.iter().any(|f| f.level == "error") { "fail".to_string() } else { "pass".to_string() },
            complete: true,
            coverage: FamilyCoverage {
                paths: files.clone(),
                path_count: files.len(),
                examined_paths: files.clone(),
                examined_paths_digest: path_digest(&files),
                unexamined_paths: unexamined,
                commands_planned: None,
                commands_completed: None,
                inspected: Some(files.len()),
            },
            receipts: Vec::new(),
            findings,
            coverage_gaps: Vec::new(),
            degradation: Vec::new(),
        });
    }

    results
}

/// Manual civil-calendar computation (Howard Hinnant's `civil_from_days`)
/// so `iso8601_now` needs no date/time crate dependency.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn iso8601_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    let rem = secs % 86_400;
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{:03}Z", now.subsec_millis())
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeFamilyAuditResult {
    pub schema_version: u32,
    pub kind: String,
    pub generated_at: String,
    pub results: Vec<FamilyResult>,
}

/// Port of `main()`'s payload construction (the JS file's CLI argv/stdout
/// plumbing itself is not ported; this is the library-shaped equivalent the
/// integrator can wire a CLI or in-process caller onto).
pub fn run_native_family_audit(root: &Path, plan: &Value) -> NativeFamilyAuditResult {
    NativeFamilyAuditResult {
        schema_version: 1,
        kind: "audit-native-family-results".to_string(),
        generated_at: iso8601_now(),
        results: run_native_families(root, plan),
    }
}
