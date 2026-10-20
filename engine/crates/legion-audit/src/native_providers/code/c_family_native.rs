//! Source-bound native C-family commands. Compilation databases are data, never
//! shell commands. Only replayable Clang arguments enter this bounded adapter.
//! JSON compilation database: https://clang.llvm.org/docs/JSONCompilationDatabase.html
//! Explicit SDK: https://cmake.org/cmake/help/latest/variable/CMAKE_OSX_SYSROOT.html
//! CTest: https://cmake.org/cmake/help/latest/manual/ctest.1.html
//! Clang-Tidy CLI: https://clang.llvm.org/extra/clang-tidy/
use super::*;
use std::{fs, io::Read};

const MAX_FILES: usize = 2000;
const MAX_BYTES: usize = 32 * 1024 * 1024;
const MAX_COMMANDS: usize = 200;
const MAX_DEPTH: usize = 32;
const MAX_NODES: usize = MAX_FILES * 4;
const BINDING: &str = "c-family-binding.json";

pub(super) fn is_native(parser: Parser) -> bool {
    matches!(
        parser,
        Parser::ClangCompiler | Parser::ClangTidy | Parser::CFamilyProcess
    )
}

fn relative(path: &str) -> bool {
    !path.is_empty()
        && !path.chars().any(|c| matches!(c, '\\' | '\n' | '\r' | '\0'))
        && Path::new(path).components().count() <= MAX_DEPTH
        && Path::new(path)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
}

fn read(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let before = fs::symlink_metadata(path).map_err(|_| "input-unreadable")?;
    if !before.is_file() || before.file_type().is_symlink() || before.len() > limit as u64 {
        return Err("input-type-or-budget".into());
    }
    let mut file = fs::File::open(path).map_err(|_| "input-unreadable")?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "input-unreadable")?;
    let after = fs::symlink_metadata(path).map_err(|_| "input-unreadable")?;
    if bytes.len() > limit
        || !after.is_file()
        || after.file_type().is_symlink()
        || bytes.len() as u64 != before.len()
        || before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
    {
        return Err("input-changed-or-budget".into());
    }
    Ok(bytes)
}

fn within(root: &Path, cwd: &Path, text: &str) -> Result<String, String> {
    // Native Windows separators still pass every canonical containment check below.
    if text
        .chars()
        .any(|c| matches!(c, '\n' | '\r' | '\0') || (c == '\\' && !cfg!(windows)))
    {
        return Err("unsupported-path".into());
    }
    let joined = cwd.join(text);
    let canonical = joined.canonicalize().map_err(|_| "path-unreadable")?;
    let rel = canonical
        .strip_prefix(root)
        .map_err(|_| "external-context")?;
    // Canonical equality refuses symlink aliases, including parent components.
    if Path::new(text)
        .components()
        .any(|c| matches!(c, Component::ParentDir))
        || joined
            .components()
            .any(|c| matches!(c, Component::ParentDir))
        || joined != canonical
    {
        return Err("noncanonical-context".into());
    }
    let rel = rel.to_str().ok_or("unsupported-path")?.replace('\\', "/");
    if rel.is_empty() || relative(&rel) {
        Ok(rel)
    } else {
        Err("unsupported-path".into())
    }
}

fn source(path: &str) -> bool {
    matches!(
        Path::new(path).extension().and_then(|s| s.to_str()),
        Some("c" | "cc" | "cpp" | "cxx")
    )
}

#[derive(Clone)]
struct SdkContext {
    root: PathBuf,
    enrollment: PathBuf,
    enrollment_digest: String,
    tree_digest: String,
    files: BTreeMap<String, String>,
    runtime: BTreeMap<String, String>,
}
impl SdkContext {
    fn load(path: &Path, expected: Option<&str>) -> Result<Self, String> {
        let bytes = read(path, MAX_BYTES)?;
        let enrollment_digest = sha256_text(&bytes);
        if expected.is_some_and(|d| d != enrollment_digest) {
            return Err("sdk-enrollment-drift".into());
        }
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| "sdk-enrollment-json")?;
        if value["schema"] != "legion-c-family-toolchain/1"
            || value["productionQualification"] != false
        {
            return Err("sdk-enrollment-schema".into());
        }
        let sdk = &value["sdk"];
        let root = PathBuf::from(sdk["root"].as_str().ok_or("sdk-root")?);
        if root.canonicalize().ok().as_ref() != Some(&root) || value["sdkRoot"] != sdk["root"] {
            return Err("noncanonical-sdk-root".into());
        }
        let files: BTreeMap<String, String> =
            serde_json::from_value(sdk["files"].clone()).map_err(|_| "sdk-files")?;
        let aliases: BTreeMap<String, String> =
            serde_json::from_value(sdk["aliases"].clone()).map_err(|_| "sdk-aliases")?;
        if files.is_empty() || files.len() > 200000 {
            return Err("sdk-file-budget".into());
        }
        fn walk(
            root: &Path,
            dir: &Path,
            files: &mut BTreeMap<String, String>,
            aliases: &mut BTreeMap<String, String>,
            nodes: &mut usize,
            total: &mut u64,
            depth: usize,
        ) -> Result<(), String> {
            if depth > MAX_DEPTH {
                return Err("sdk-tree-depth".into());
            }
            for entry in fs::read_dir(dir).map_err(|_| "sdk-tree-unreadable")? {
                *nodes += 1;
                if *nodes > 400000 {
                    return Err("sdk-node-budget".into());
                }
                let path = entry.map_err(|_| "sdk-tree-unreadable")?.path();
                let meta = fs::symlink_metadata(&path).map_err(|_| "sdk-tree-unreadable")?;
                if meta.file_type().is_symlink() {
                    let target = path.canonicalize().map_err(|_| "sdk-alias-unreadable")?;
                    if !target.starts_with(root) {
                        return Err("external-sdk-alias".into());
                    }
                    aliases.insert(
                        path.to_string_lossy().into_owned(),
                        target.to_string_lossy().into_owned(),
                    );
                } else if meta.is_dir() {
                    walk(root, &path, files, aliases, nodes, total, depth + 1)?;
                } else if meta.is_file() {
                    *total = total.checked_add(meta.len()).ok_or("sdk-byte-budget")?;
                    if *total > 8 * 1024 * 1024 * 1024 {
                        return Err("sdk-byte-budget".into());
                    }
                    files.insert(
                        path.to_string_lossy().into_owned(),
                        sha256_text(&read(&path, MAX_BYTES)?),
                    );
                } else {
                    return Err("sdk-special-file".into());
                }
            }
            Ok(())
        }
        let (mut observed_files, mut observed_aliases) = (BTreeMap::new(), BTreeMap::new());
        walk(
            &root,
            &root,
            &mut observed_files,
            &mut observed_aliases,
            &mut 0,
            &mut 0,
            0,
        )?;
        if observed_files != files || observed_aliases != aliases {
            return Err("sdk-tree-drift".into());
        }
        let tree_digest = sha256_text(
            &serde_json::to_vec(&BTreeMap::from([
                ("files", json!(files)),
                ("aliases", json!(aliases)),
            ]))
            .map_err(|_| "sdk-tree-encoding")?,
        );
        if sdk["digest"].as_str() != Some(tree_digest.as_str()) {
            return Err("sdk-tree-identity".into());
        }
        let runtime: BTreeMap<String, String> =
            serde_json::from_value(value["runtimeFiles"].clone())
                .map_err(|_| "sdk-runtime-files")?;
        if runtime.is_empty() || runtime.len() > 200000 {
            return Err("native-runtime-file-budget".into());
        }
        let mut total = 0u64;
        for (name, expected) in &runtime {
            let path = Path::new(name);
            if path.canonicalize().ok().as_deref() != Some(path) {
                return Err("noncanonical-native-runtime".into());
            }
            let data = read(path, 512 * 1024 * 1024)?;
            total = total
                .checked_add(data.len() as u64)
                .ok_or("native-runtime-byte-budget")?;
            if total > 8 * 1024 * 1024 * 1024 || sha256_text(&data) != *expected {
                return Err("native-runtime-closure-drift".into());
            }
        }
        Ok(Self {
            root,
            enrollment: path.into(),
            enrollment_digest,
            tree_digest,
            files,
            runtime,
        })
    }
}

fn flags(
    root: &Path,
    cwd: &Path,
    row: &Value,
    file: &str,
    stage: &Path,
    sdk: Option<&Path>,
) -> Result<(bool, Vec<String>), String> {
    let args = row
        .get("arguments")
        .and_then(Value::as_array)
        .ok_or("arguments-array-required")?;
    if args.is_empty() || args.len() > 256 || row.get("command").is_some() {
        return Err("ambiguous-or-excessive-arguments".into());
    }
    let args = args
        .iter()
        .map(|v| v.as_str().ok_or("non-string-argument"))
        .collect::<Result<Vec<_>, _>>()?;
    let compiler = Path::new(args[0])
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("unsupported-compiler")?;
    if !matches!(compiler, "clang" | "clang++") {
        return Err("unsupported-compiler".into());
    }
    let cpp = compiler == "clang++";
    let mut out = Vec::new();
    let mut i = 1;
    let mut saw_source = false;
    let mut saw_compile = false;
    while i < args.len() {
        let arg = args[i];
        if arg.len() > 4096 || arg.chars().any(|c| matches!(c, '\n' | '\r' | '\0')) {
            return Err("unsupported-argument".into());
        }
        if arg == "-c" {
            saw_compile = true;
            i += 1;
            continue;
        }
        if arg
            .strip_prefix("-D")
            .is_some_and(|v| v == "NDEBUG" || v.starts_with("NDEBUG="))
        {
            return Err("assertions-disabled".into());
        }
        if arg == "-isysroot" {
            let path = PathBuf::from(*args.get(i + 1).ok_or("missing-sysroot")?);
            if sdk != Some(path.as_path()) || path.canonicalize().ok().as_ref() != Some(&path) {
                return Err("unenrolled-sysroot".into());
            }
            out.push(arg.into());
            out.push(path.to_string_lossy().into_owned());
            i += 2;
            continue;
        }
        if arg == "-o" {
            i += 2;
            if i > args.len() {
                return Err("missing-output".into());
            }
            continue;
        }
        if matches!(arg, "-I" | "-iquote") {
            let value = args.get(i + 1).ok_or("missing-include-path")?;
            let path = within(root, cwd, value)?;
            out.push(arg.into());
            out.push(stage.join(path).to_string_lossy().into_owned());
            i += 2;
            continue;
        }
        if arg.starts_with("-I") && arg.len() > 2 {
            let path = within(root, cwd, &arg[2..])?;
            out.push(format!("-I{}", stage.join(path).display()));
            i += 1;
            continue;
        }
        if matches!(arg, "-D" | "-U" | "-x") {
            let value = args.get(i + 1).ok_or("missing-option-value")?;
            if arg == "-D" && (*value == "NDEBUG" || value.starts_with("NDEBUG=")) {
                return Err("assertions-disabled".into());
            }
            if arg == "-x" && !matches!(*value, "c" | "c++") {
                return Err("unsupported-language".into());
            }
            if value.len() > 4096 || value.chars().any(|c| matches!(c, '\n' | '\r' | '\0')) {
                return Err("unsupported-argument".into());
            }
            out.push(arg.into());
            out.push((*value).into());
            i += 2;
            continue;
        }
        if (arg.starts_with("-D") || arg.starts_with("-U")) && arg.len() > 2
            || matches!(
                arg,
                "-pthread" | "-fno-exceptions" | "-fexceptions" | "-fno-rtti" | "-frtti"
            )
            || matches!(
                arg,
                "-fsanitize=address,undefined"
                    | "-fno-omit-frame-pointer"
                    | "-fno-sanitize-recover=all"
            )
            || matches!(
                arg,
                "-O0" | "-O1" | "-O2" | "-O3" | "-Os" | "-Oz" | "-g" | "-g0"
            )
            || arg.strip_prefix("-std=").is_some_and(|s| {
                matches!(
                    s,
                    "c89"
                        | "c90"
                        | "c99"
                        | "c11"
                        | "c17"
                        | "c18"
                        | "c2x"
                        | "c23"
                        | "gnu89"
                        | "gnu99"
                        | "gnu11"
                        | "gnu17"
                        | "gnu2x"
                        | "c++98"
                        | "c++03"
                        | "c++11"
                        | "c++14"
                        | "c++17"
                        | "c++20"
                        | "c++23"
                        | "gnu++11"
                        | "gnu++14"
                        | "gnu++17"
                        | "gnu++20"
                        | "gnu++23"
                )
            })
        {
            out.push(arg.into());
            i += 1;
            continue;
        }
        // Warning switches may not alter loading, outputs, search paths or plugins.
        if arg.starts_with("-W")
            && arg[2..]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '='))
        {
            out.push(arg.into());
            i += 1;
            continue;
        }
        if !arg.starts_with('-') && within(root, cwd, arg)? == file && !saw_source {
            saw_source = true;
            i += 1;
            continue;
        }
        return Err("unsupported-compile-argument".into());
    }
    if !saw_source || !saw_compile {
        return Err("single-translation-unit-required".into());
    }
    Ok((cpp, out))
}

fn prepare(
    root: &Path,
    entries: &[InventoryEntry],
    scratch: &AuditScratch,
) -> Result<(PathBuf, String), String> {
    let root = root.canonicalize().map_err(|_| "root-unreadable")?;
    if entries.len() > MAX_FILES {
        return Err("input-file-budget".into());
    }
    if entries.iter().any(|e| {
        Path::new(&e.path).file_name().and_then(|v| v.to_str()) == Some("CMakeLists.txt")
            && e.path != "CMakeLists.txt"
    }) {
        return Err("unsupported-nested-cmake-project".into());
    }
    if !entries.iter().any(|e| e.path == "CMakeLists.txt") {
        return Err("root-cmake-project-required".into());
    }
    let stage = scratch.tmp_dir().join("c-family").join("source");
    fs::create_dir_all(&stage).map_err(|_| "scratch-unwritable")?;
    fs::create_dir_all(stage.parent().ok_or("stage-parent")?.join("home/.config"))
        .map_err(|_| "scratch-unwritable")?;
    let mut files = BTreeMap::new();
    let mut total = 0usize;
    for entry in entries {
        if !relative(&entry.path) || within(&root, &root, &entry.path)? != entry.path {
            return Err("noncanonical-inventory-path".into());
        }
        let bytes = read(&root.join(&entry.path), MAX_BYTES.saturating_sub(total))?;
        total += bytes.len();
        let digest = sha256_text(&bytes);
        if entry.digest.as_deref() != Some(digest.as_str()) {
            return Err("inventory-digest-mismatch".into());
        }
        let target = stage.join(&entry.path);
        fs::create_dir_all(target.parent().ok_or("stage-parent")?)
            .map_err(|_| "scratch-unwritable")?;
        fs::write(&target, bytes).map_err(|_| "scratch-unwritable")?;
        files.insert(entry.path.clone(), digest);
    }
    let bytes = serde_json::to_vec(
        &json!({"schema":"legion-c-family-input/1", "root":root,"stage":stage,"files":files}),
    )
    .map_err(|_| "binding-encoding")?;
    fs::write(stage.parent().ok_or("stage-parent")?.join(BINDING), &bytes)
        .map_err(|_| "scratch-unwritable")?;
    Ok((stage, sha256_text(&bytes)))
}

// Admission precedes CMake evaluation. This intentionally small executable-only
// surface has no include(), custom command, package lookup, arbitrary set(),
// generator expression, user toolchain, or test command expansion. Unsupported
// projects retain explicit gaps; trace replay additionally binds real inputs.
fn preflight_cmake(stage: &Path) -> Result<(), String> {
    let bytes = read(&stage.join("CMakeLists.txt"), MAX_MANIFEST_BYTES as usize)?;
    let patterns=[
        r"^cmake_minimum_required\(VERSION [0-9]+\.[0-9]+(?:\.[0-9]+)?\)$",
        r"^project\([A-Za-z_][A-Za-z0-9_]* LANGUAGES C CXX\)$",
        r"^set\(CMAKE_C_STANDARD (?:11|17|23)\)$",
        r"^set\(CMAKE_CXX_STANDARD (?:11|14|17|20|23)\)$",
        r"^add_executable\([A-Za-z_][A-Za-z0-9_]*(?: [A-Za-z_][A-Za-z0-9_-]*\.(?:c|cc|cpp|cxx))+\)$",
        r#"^target_include_directories\([A-Za-z_][A-Za-z0-9_]* PRIVATE "\$\{CMAKE_CURRENT_SOURCE_DIR\}"\)$"#,
        r"^target_compile_options\([A-Za-z_][A-Za-z0-9_]* PRIVATE(?: -W(?:all|extra))+\)$",
        r"^enable_testing\(\)$",
        r"^add_test\(NAME [A-Za-z_][A-Za-z0-9_]* COMMAND [A-Za-z_][A-Za-z0-9_]*\)$",
        r#"^set_tests_properties\([A-Za-z_][A-Za-z0-9_]* PROPERTIES LABELS "legion-assertions=[1-9][0-9]{0,5}"\)$"#,
    ].into_iter().map(|p|Regex::new(p).expect("fixed CMake admission pattern")).collect::<Vec<_>>();
    for line in std::str::from_utf8(&bytes)
        .map_err(|_| "cmake-source-encoding")?
        .lines()
        .map(str::trim)
    {
        // An incomplete project invocation has no effects & remains an actual
        // native malformed-input control, rejected by CMake's own parser.
        if line.is_empty() || line.starts_with('#') || line == "project(" {
            continue;
        }
        if !patterns.iter().any(|p| p.is_match(line)) {
            return Err("unsupported-project-cmake-syntax".into());
        }
    }
    Ok(())
}

fn planned(
    tool: &'static str,
    programs: &'static [&'static str],
    cwd: &Path,
    args: Vec<String>,
    parser: Parser,
    binding: &str,
    stage: &Path,
) -> Planned {
    Planned {
        tool,
        programs,
        local_bin: false,
        sibling_of: None,
        requires: None,
        cwd_rel: cwd.to_string_lossy().into_owned(),
        args,
        parser,
        accepted: if parser == Parser::CFamilyProcess {
            &[0]
        } else {
            &[0, 1]
        },
        env: vec![
            ("CPATH", String::new()),
            ("C_INCLUDE_PATH", String::new()),
            ("CPLUS_INCLUDE_PATH", String::new()),
            ("OBJC_INCLUDE_PATH", String::new()),
            (
                "HOME",
                stage
                    .parent()
                    .unwrap()
                    .join("home")
                    .to_string_lossy()
                    .into_owned(),
            ),
            (
                "USERPROFILE",
                stage
                    .parent()
                    .unwrap()
                    .join("home")
                    .to_string_lossy()
                    .into_owned(),
            ),
            (
                "XDG_CONFIG_HOME",
                stage
                    .parent()
                    .unwrap()
                    .join("home/.config")
                    .to_string_lossy()
                    .into_owned(),
            ),
            (
                "LEGION_C_FAMILY_STAGE",
                stage.to_string_lossy().into_owned(),
            ),
        ],
        diagnostics_on_stderr: parser == Parser::ClangCompiler,
        source_path: None,
        source_digest: Some(binding.into()),
    }
}

struct Session<'a> {
    ctx: &'a ToolContext<'a>,
    resolver: Resolver<'a>,
    evidence: ToolEvidence,
    accumulators: BTreeMap<&'static str, Accumulator>,
    started: Instant,
    sequence: usize,
    stage: PathBuf,
    binding: String,
    selected: BTreeSet<String>,
    generated: BTreeMap<String, String>,
    cmake_share: PathBuf,
    sdk: Option<SdkContext>,
    cancellation: CancellationToken,
}
impl Session<'_> {
    fn gap(&mut self, tool: &'static str, reason: &str) {
        self.accumulators
            .entry(tool)
            .or_default()
            .merge(Outcome::Failed(format!("tool-failed:{tool}:{reason}")));
    }
    async fn execute(&mut self, mut command: Planned) -> bool {
        if let Some(sdk) = &self.sdk {
            command.env.push((
                "LEGION_C_FAMILY_SDK_ENROLLMENT",
                sdk.enrollment.to_string_lossy().into_owned(),
            ));
            command.env.push((
                "LEGION_C_FAMILY_SDK_ENROLLMENT_DIGEST",
                sdk.enrollment_digest.clone(),
            ));
        }
        command.env.push((
            "LEGION_C_FAMILY_CMAKE_SHARE",
            self.cmake_share.to_string_lossy().into_owned(),
        ));
        command.env.push((
            "LEGION_C_FAMILY_GENERATED",
            serde_json::to_string(&self.generated).expect("string map"),
        ));
        let remaining = self
            .ctx
            .total_budget_ms
            .saturating_sub(self.started.elapsed().as_millis() as u64);
        if remaining == 0 {
            self.accumulators
                .entry(command.tool)
                .or_default()
                .merge(Outcome::Budget);
            return false;
        }
        let output = run_one(
            self.ctx,
            &mut self.resolver,
            &command,
            None,
            self.sequence,
            self.ctx.per_tool_timeout_ms.min(remaining).max(1),
            self.cancellation.clone(),
        )
        .await;
        self.sequence += 1;
        let ok = output.outcome == Outcome::Ran;
        let acc = self.accumulators.entry(command.tool).or_default();
        if let Some(receipt) = output.receipt {
            self.evidence.receipts.push(receipt.clone());
            acc.runs.push(receipt);
        }
        if acc.program.is_empty() && !output.program.is_empty() {
            acc.program = output.program;
            acc.version = output.version;
            acc.executable_digest = output.executable_digest;
        }
        if let Some(digest) = output.stdout_digest {
            acc.stdout_digests.push(digest);
        }
        acc.merge(output.outcome);
        if command.tool == "sanitizer" && command.programs.contains(&"ctest") {
            if let Some(receipt) = self.evidence.receipts.last() {
                for stream in ["stdout", "stderr"] {
                    if let Some(bytes) = receipt_artifact(self.ctx.scratch, receipt, stream) {
                        let pattern = Regex::new(r"(?m)^(.+?):(\d+):(\d+): runtime error: (.+)$")
                            .expect("fixed UBSan pattern");
                        for capture in pattern.captures_iter(&String::from_utf8_lossy(&bytes)) {
                            if let Ok(path) =
                                within(&self.stage, Path::new(&command.cwd_rel), &capture[1])
                            {
                                self.evidence.findings.push(NativeFinding {
                                    rule: Cow::Borrowed("ubsan:runtime-error"),
                                    severity: "error",
                                    path,
                                    line: capture[2].parse().unwrap_or(1),
                                    message: shorten(&capture[4]),
                                });
                            }
                        }
                    }
                }
            }
        }
        for diag in output.diagnostics {
            self.evidence.findings.push(NativeFinding {
                rule: Cow::Owned(diag.rule),
                severity: diag.severity,
                path: diag.path,
                line: diag.line,
                message: diag.message,
            });
        }
        ok
    }
    async fn process(
        &mut self,
        tool: &'static str,
        programs: &'static [&'static str],
        cwd: &Path,
        args: Vec<String>,
    ) -> bool {
        self.execute(planned(
            tool,
            programs,
            cwd,
            args,
            Parser::CFamilyProcess,
            &self.binding,
            &self.stage,
        ))
        .await
    }
    fn finish(mut self, context: Option<Value>) -> ToolEvidence {
        for tool in ["compiler", "lint", "analyzer", "sanitizer", "test"] {
            let acc = self.accumulators.entry(tool).or_default();
            let outcome = acc
                .outcome
                .clone()
                .unwrap_or_else(|| Outcome::NotRun("prerequisite-unavailable".into()));
            let ran = outcome == Outcome::Ran;
            let identity = if acc.program.is_empty() {
                Value::Null
            } else {
                json!({"name":acc.program,"version":acc.version,"executableDigest":acc.executable_digest})
            };
            let artifact = if ran && !acc.stdout_digests.is_empty() {
                json!(sha256_text(acc.stdout_digests.join("\n").as_bytes()))
            } else {
                Value::Null
            };
            self.evidence.tools.insert(tool.into(),json!({"status":if ran {"pass"}else{"fail"},"identity":identity,"artifactDigest":artifact,"scope":{"runs":acc.runs,"offline":true,"operationsVersion":"c-family-operations/v1","configuration":"Debug; host default target; executable assertions; source-owned checker set","checkerSet":if tool=="lint" {json!(["bugprone-branch-clone"])} else {Value::Null},"compileDatabase":context}}));
            if !ran {
                self.evidence.gaps.push(format!(
                    "{}:{}",
                    self.ctx.provider_id,
                    outcome.reason(tool)
                ));
            }
            self.evidence.outcomes.insert(tool, outcome);
        }
        let outside = self
            .evidence
            .findings
            .iter()
            .filter(|f| !self.selected.contains(&f.path))
            .count();
        self.evidence
            .findings
            .retain(|f| self.selected.contains(&f.path));
        if outside > 0 {
            self.evidence.gaps.push(format!(
                "{}:tool-diagnostics-outside-denominator:{outside}",
                self.ctx.provider_id
            ));
        }
        self.evidence.findings.sort_by(|a, b| {
            a.path
                .cmp(&b.path)
                .then(a.line.cmp(&b.line))
                .then(a.rule.cmp(&b.rule))
        });
        self.evidence
            .findings
            .dedup_by(|a, b| a.path == b.path && a.line == b.line && a.rule == b.rule);
        if self.evidence.findings.len() > MAX_TOOL_FINDINGS {
            self.evidence.gaps.push(format!(
                "{}:tool-findings-truncated:{}",
                self.ctx.provider_id,
                self.evidence.findings.len() - MAX_TOOL_FINDINGS
            ));
            self.evidence.findings.truncate(MAX_TOOL_FINDINGS);
        }
        self.evidence
    }
}

fn database(
    stage: &Path,
    build: &Path,
    selected: &BTreeSet<String>,
    sdk: Option<&Path>,
) -> Result<Vec<(String, bool, Vec<String>)>, String> {
    let bytes = read(
        &build.join("compile_commands.json"),
        MAX_MANIFEST_BYTES as usize,
    )?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| "malformed-generated-compile-database")?;
    let rows = value
        .as_array()
        .filter(|r| !r.is_empty() && r.len() <= MAX_COMMANDS)
        .ok_or("empty-or-excessive-compile-database")?;
    let mut result = Vec::new();
    let mut covered = BTreeSet::new();
    for row in rows {
        let directory = PathBuf::from(row["directory"].as_str().ok_or("compile-directory")?);
        if !directory
            .canonicalize()
            .ok()
            .is_some_and(|p| p.starts_with(build))
        {
            return Err("external-compile-directory".into());
        }
        let file = within(
            stage,
            &directory,
            row["file"].as_str().ok_or("compile-file")?,
        )?;
        if !selected.contains(&file) || !source(&file) {
            return Err("unsupported-or-unselected-translation-unit".into());
        }
        // CMake's generated database uses `command`, per its documented format.
        // No shell runs: parse only a deliberately narrow POSIX argv grammar.
        let mut normalized = row.clone();
        if normalized.get("arguments").is_none() {
            let command = normalized["command"].as_str().ok_or("compile-arguments")?;
            let args = split_command(command)?;
            normalized
                .as_object_mut()
                .ok_or("compile-row")?
                .remove("command");
            normalized["arguments"] = json!(args);
        }
        let (cpp, args) = flags(stage, &directory, &normalized, &file, stage, sdk)?;
        covered.insert(file.clone());
        result.push((file, cpp, args));
    }
    if selected
        .iter()
        .filter(|p| source(p))
        .any(|p| !covered.contains(p))
    {
        return Err("orphan-source-not-built".into());
    }
    Ok(result)
}

fn split_command(text: &str) -> Result<Vec<String>, String> {
    let mut args = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut escape = false;
    let mut started = false;
    for c in text.chars() {
        if matches!(
            c,
            '\n' | '\r' | '\0' | '`' | '$' | ';' | '|' | '&' | '<' | '>'
        ) {
            return Err("unsupported-command-grammar".into());
        }
        if escape {
            word.push(c);
            escape = false;
            started = true;
            continue;
        }
        if c == '\\' && quote != Some('\'') {
            escape = true;
            started = true;
            continue;
        }
        if let Some(q) = quote {
            if c == q {
                quote = None;
            } else {
                word.push(c);
            }
            started = true;
            continue;
        }
        if matches!(c, '\'' | '"') {
            quote = Some(c);
            started = true;
        } else if c.is_whitespace() {
            if started {
                args.push(std::mem::take(&mut word));
                started = false;
            }
        } else {
            word.push(c);
            started = true;
        }
    }
    if quote.is_some() || escape {
        return Err("unterminated-command-grammar".into());
    }
    if started {
        args.push(word);
    }
    Ok(args)
}

fn configuration_inputs(
    stage: &Path,
    build: &Path,
    share: &Path,
) -> Result<BTreeMap<String, String>, String> {
    let trace = build.join("configure-trace.jsonl");
    let bytes = read(&trace, MAX_BYTES)?;
    let mut total = bytes.len();
    let mut files = BTreeMap::new();
    files.insert(trace.to_string_lossy().into_owned(), sha256_text(&bytes));
    for line in std::str::from_utf8(&bytes)
        .map_err(|_| "configure-trace-encoding")?
        .lines()
    {
        let value: Value = serde_json::from_str(line).map_err(|_| "configure-trace-json")?;
        if value.get("version").is_some() {
            continue;
        }
        let file = PathBuf::from(value["file"].as_str().ok_or("configure-trace-file")?);
        let canonical = file
            .canonicalize()
            .map_err(|_| "configure-input-unreadable")?;
        if !(canonical.starts_with(stage)
            || canonical.starts_with(build)
            || canonical.starts_with(share))
        {
            return Err("external-cmake-context".into());
        }
        if canonical.starts_with(stage)
            && ![
                "cmake_minimum_required",
                "project",
                "set",
                "add_executable",
                "target_include_directories",
                "target_compile_options",
                "enable_testing",
                "add_test",
                "set_tests_properties",
            ]
            .contains(&value["cmd"].as_str().ok_or("configure-trace-command")?)
        {
            return Err("unsupported-project-cmake-command".into());
        }
        let key = canonical.to_string_lossy().into_owned();
        if !files.contains_key(&key) {
            if files.len() >= MAX_FILES {
                return Err("configure-input-budget".into());
            }
            let data = read(&canonical, MAX_BYTES.saturating_sub(total))?;
            total += data.len();
            files.insert(key, sha256_text(&data));
        }
    }
    fn walk(
        path: &Path,
        files: &mut BTreeMap<String, String>,
        nodes: &mut usize,
        total: &mut usize,
        depth: usize,
    ) -> Result<(), String> {
        if depth > MAX_DEPTH {
            return Err("build-context-depth".into());
        }
        for entry in fs::read_dir(path).map_err(|_| "build-context-unreadable")? {
            *nodes += 1;
            if *nodes > MAX_NODES {
                return Err("build-context-budget".into());
            }
            let path = entry.map_err(|_| "build-context-unreadable")?.path();
            let meta = fs::symlink_metadata(&path).map_err(|_| "build-context-unreadable")?;
            if meta.file_type().is_symlink() {
                return Err("build-context-symlink".into());
            }
            if meta.is_dir() {
                walk(&path, files, nodes, total, depth + 1)?;
            } else if [
                "Makefile",
                "build.make",
                "flags.make",
                "link.txt",
                "CMakeCache.txt",
                "CTestTestfile.cmake",
            ]
            .contains(&name_of(path.to_str().ok_or("build-context-path")?))
            {
                if files.len() >= MAX_FILES {
                    return Err("build-context-budget".into());
                }
                let data = read(&path, MAX_BYTES.saturating_sub(*total))?;
                *total += data.len();
                files.insert(path.to_string_lossy().into_owned(), sha256_text(&data));
            }
        }
        Ok(())
    }
    walk(build, &mut files, &mut 0, &mut total, 0)?;
    if !files.keys().any(|p| p.ends_with("/link.txt")) {
        return Err("link-contract-missing".into());
    }
    Ok(files)
}

fn dependency_coverage(
    stage: &Path,
    build: &Path,
    selected: &BTreeSet<String>,
    sdk: Option<&SdkContext>,
) -> Result<Value, String> {
    fn walk(
        path: &Path,
        out: &mut Vec<PathBuf>,
        nodes: &mut usize,
        depth: usize,
    ) -> Result<(), String> {
        if depth > MAX_DEPTH {
            return Err("dependency-depth".into());
        }
        for entry in fs::read_dir(path).map_err(|_| "dependency-unreadable")? {
            *nodes += 1;
            if *nodes > MAX_NODES || out.len() >= MAX_FILES {
                return Err("dependency-budget".into());
            }
            let p = entry.map_err(|_| "dependency-unreadable")?.path();
            let m = fs::symlink_metadata(&p).map_err(|_| "dependency-unreadable")?;
            if m.file_type().is_symlink() {
                return Err("dependency-symlink".into());
            }
            if m.is_dir() {
                walk(&p, out, nodes, depth + 1)?;
            } else if p.to_string_lossy().ends_with(".o.d") {
                out.push(p);
            }
        }
        Ok(())
    }
    let mut paths = Vec::new();
    walk(build, &mut paths, &mut 0, 0)?;
    if paths.is_empty() {
        return Err("dependency-evidence-missing".into());
    }
    let mut covered = BTreeSet::new();
    let mut sdk_headers = BTreeMap::new();
    let mut artifacts = BTreeMap::new();
    let mut total = 0;
    for path in paths {
        let bytes = read(
            &path,
            (MAX_MANIFEST_BYTES as usize).min(MAX_BYTES.saturating_sub(total)),
        )?;
        total += bytes.len();
        artifacts.insert(
            path.to_string_lossy().into_owned(),
            json!({"digest":sha256_text(&bytes),"bytes":bytes}),
        );
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| "dependency-encoding")?
            .replace("\\\n", " ");
        let (_, rhs) = text.split_once(':').ok_or("dependency-format")?;
        // Escaped/space-containing names require a real Make parser.
        if rhs.contains('\\') {
            return Err("unsupported-dependency-escaping".into());
        }
        for token in rhs.split_whitespace() {
            if let Ok(rel) = within(stage, build, token) {
                covered.insert(rel);
            } else if let Some(sdk) = sdk {
                let p = build
                    .join(token)
                    .canonicalize()
                    .map_err(|_| "sdk-dependency-unreadable")?;
                let key = p.to_string_lossy().into_owned();
                if !matches!(p.extension().and_then(|s| s.to_str()), Some("h" | "hpp"))
                    || sdk
                        .runtime
                        .get(&key)
                        .is_none_or(|d| read(&p, MAX_BYTES).map_or(true, |b| sha256_text(&b) != *d))
                {
                    return Err("unenrolled-sdk-dependency".into());
                }
                sdk_headers.insert(key.clone(), sdk.runtime[&key].clone());
            } else {
                return Err("external-dependency-context".into());
            }
        }
    }
    if selected.iter().any(|p| !covered.contains(p)) {
        return Err("orphan-source-or-header".into());
    }
    Ok(json!({"covered":covered,"dependencyArtifacts":artifacts,"sdkHeaders":sdk_headers}))
}

fn receipt_artifact(scratch: &AuditScratch, receipt: &Value, stream: &str) -> Option<Vec<u8>> {
    let v = receipt.pointer(&format!("/sdkReceipt/{stream}"))?;
    let artifact = legion_effects::ArtifactRecord {
        path: v["path"].as_str()?.into(),
        digest: v["digest"].as_str()?.into(),
        bytes: usize::try_from(v["bytes"].as_u64()?).ok()?,
        immutable: v["immutable"].as_bool()?,
    };
    read_artifact(scratch, &artifact)
}

fn junit(bytes: &[u8], registered: &Value) -> Result<Value, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "junit-encoding")?;
    if !text.trim_end().ends_with("</testsuite>")
        || text.contains("<!DOCTYPE")
        || text.contains("<!ENTITY")
    {
        return Err("junit-envelope".into());
    }
    let suite =
        Regex::new(r#"<testsuite\s[^>]*tests="(\d+)"[^>]*>"#).map_err(|_| "junit-pattern")?;
    let names =
        Regex::new(r#"<testcase\s[^>]*name="([^"<>]+)"[^>]*>"#).map_err(|_| "junit-pattern")?;
    let count = suite
        .captures(text)
        .and_then(|c| c[1].parse::<usize>().ok())
        .ok_or("junit-count")?;
    let expected: BTreeSet<_> = registered["tests"]
        .as_array()
        .ok_or("registered-tests")?
        .iter()
        .filter_map(|v| v["name"].as_str())
        .collect();
    let actual: BTreeSet<_> = names.captures_iter(text).map(|c| c[1].to_owned()).collect();
    if names.captures_iter(text).count() != actual.len() {
        return Err("junit-duplicate-test".into());
    }
    if count == 0
        || count != actual.len()
        || actual.len() != expected.len()
        || actual.iter().any(|n| !expected.contains(n.as_str()))
    {
        return Err("junit-test-denominator".into());
    }
    if text.contains("<skipped") {
        return Err("junit-skipped-test".into());
    }
    Ok(
        json!({"testCount":count,"testNames":actual,"failures":text.matches("<failure").count(),"rawBytes":bytes,"digest":sha256_text(bytes)}),
    )
}

fn object_products(build: &Path) -> Result<Value, String> {
    let database: Value = serde_json::from_slice(&read(
        &build.join("compile_commands.json"),
        MAX_MANIFEST_BYTES as usize,
    )?)
    .map_err(|_| "object-database")?;
    let mut products = BTreeMap::new();
    for row in database.as_array().ok_or("object-database")? {
        let args = if let Some(values) = row["arguments"].as_array() {
            values
                .iter()
                .map(|v| v.as_str().map(str::to_owned).ok_or("object-arguments"))
                .collect::<Result<Vec<_>, _>>()?
        } else {
            split_command(row["command"].as_str().ok_or("object-arguments")?)?
        };
        let index = args
            .iter()
            .position(|v| v == "-o")
            .ok_or("object-output-missing")?;
        let path = Path::new(row["directory"].as_str().ok_or("object-directory")?)
            .join(args.get(index + 1).ok_or("object-output-missing")?);
        let path = path.canonicalize().map_err(|_| "object-output-missing")?;
        if !path.starts_with(build) || !path.to_string_lossy().ends_with(".o") {
            return Err("object-output-outside-build".into());
        }
        let bytes = read(&path, MAX_BYTES)?;
        if bytes.is_empty() {
            return Err("empty-object".into());
        }
        products.insert(path.to_string_lossy().into_owned(), sha256_text(&bytes));
    }
    if products.is_empty() {
        return Err("no-built-objects".into());
    }
    Ok(json!(products))
}

fn test_results(path: &Path, stage: &Path, build: &Path) -> Result<Value, String> {
    let bytes = read(path, MAX_MANIFEST_BYTES as usize)?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| "ctest-json")?;
    let tests = value["tests"]
        .as_array()
        .filter(|v| !v.is_empty())
        .ok_or("no-registered-tests")?;
    let mut names = BTreeSet::new();
    let mut executables = BTreeMap::new();
    let mut assertion_count = 0usize;
    for test in tests {
        let name = test["name"]
            .as_str()
            .filter(|n| !n.is_empty())
            .ok_or("ctest-test-name")?;
        if !names.insert(name) {
            return Err("duplicate-test-name".into());
        }
        let command = test["command"]
            .as_array()
            .filter(|v| !v.is_empty())
            .ok_or("ctest-command")?;
        let executable = Path::new(command[0].as_str().ok_or("ctest-executable")?);
        if !executable
            .canonicalize()
            .ok()
            .is_some_and(|p| p.starts_with(build))
        {
            return Err("external-test-executable".into());
        }
        let bytes = read(executable, MAX_BYTES)?;
        if bytes.is_empty() || !is_executable(executable) {
            return Err("test-product-not-executable".into());
        }
        executables.insert(
            executable.to_string_lossy().into_owned(),
            sha256_text(&bytes),
        );
        // Native fixtures declare assertions; a passing process by itself does
        // not prove a nonzero assertion denominator.
        let properties = test["properties"].as_array().ok_or("ctest-properties")?;
        let label = properties
            .iter()
            .find(|p| p["name"] == "LABELS")
            .and_then(|p| p["value"].as_array())
            .ok_or("assertion-contract-missing")?;
        let assertions = label
            .iter()
            .filter_map(Value::as_str)
            .find_map(|v| {
                v.strip_prefix("legion-assertions=")
                    .and_then(|s| s.parse::<usize>().ok())
            })
            .filter(|n| *n > 0)
            .ok_or("assertion-contract-missing")?;
        assertion_count = assertion_count
            .checked_add(assertions)
            .ok_or("assertion-count-overflow")?;
    }
    let _ = stage;
    Ok(
        json!({"digest":sha256_text(&bytes),"tests":tests,"executables":executables,"declaredAssertions":assertion_count}),
    )
}

pub(super) async fn run(
    ctx: &ToolContext<'_>,
    entries: &[InventoryEntry],
    selected: &BTreeSet<String>,
    cancellation: CancellationToken,
) -> ToolEvidence {
    if ctx.sandbox != SandboxPolicy::Required {
        let mut evidence = ToolEvidence::default();
        for tool in ["compiler", "lint", "analyzer", "sanitizer", "test"] {
            evidence.outcomes.insert(
                tool,
                Outcome::NotRun("authenticated-sandbox-required".into()),
            );
            evidence.gaps.push(format!(
                "{}:tool-not-run:{tool}:authenticated-sandbox-required",
                ctx.provider_id
            ));
        }
        return evidence;
    }
    let (stage, binding) = match prepare(ctx.root, entries, ctx.scratch) {
        Ok(v) => v,
        Err(e) => {
            let mut out = ToolEvidence::default();
            out.gaps
                .push(format!("{}:c-family-input:{e}", ctx.provider_id));
            for tool in ["compiler", "lint", "analyzer", "sanitizer", "test"] {
                out.outcomes
                    .insert(tool, Outcome::NotRun("c-family-input-unavailable".into()));
            }
            return out;
        }
    };
    if let Err(reason) = preflight_cmake(&stage) {
        let mut out = ToolEvidence::default();
        out.gaps
            .push(format!("{}:c-family-input:{reason}", ctx.provider_id));
        for tool in ["compiler", "lint", "analyzer", "sanitizer", "test"] {
            out.outcomes.insert(
                tool,
                Outcome::NotRun("unsupported-project-cmake-syntax".into()),
            );
        }
        return out;
    }
    let sdk = match std::env::var_os("LEGION_C_FAMILY_ENROLLMENT_JSON") {
        Some(path) => match SdkContext::load(Path::new(&path), None) {
            Ok(sdk) => Some(sdk),
            Err(e) => {
                let mut out = ToolEvidence::default();
                out.gaps
                    .push(format!("{}:c-family-sdk:{e}", ctx.provider_id));
                for tool in ["compiler", "lint", "analyzer", "sanitizer", "test"] {
                    out.outcomes
                        .insert(tool, Outcome::NotRun("sdk-context-unavailable".into()));
                }
                return out;
            }
        },
        None => None,
    };
    let mut s = Session {
        ctx,
        resolver: Resolver::new(ctx),
        evidence: ToolEvidence::default(),
        accumulators: BTreeMap::new(),
        started: Instant::now(),
        sequence: 0,
        stage: stage.clone(),
        binding,
        selected: selected.clone(),
        generated: BTreeMap::new(),
        cmake_share: PathBuf::new(),
        sdk,
        cancellation,
    };
    let Some(clang) = s
        .resolver
        .on_path("clang")
        .filter(|p| rubocop::trusted_path(ctx.root, p))
    else {
        s.gap("compiler", "clang-missing");
        return s.finish(None);
    };
    let Some(clangxx) = s
        .resolver
        .on_path("clang++")
        .filter(|p| rubocop::trusted_path(ctx.root, p))
    else {
        s.gap("compiler", "clangxx-missing");
        return s.finish(None);
    };
    let Some(cmake) = s
        .resolver
        .on_path("cmake")
        .filter(|p| rubocop::trusted_path(ctx.root, p))
        .and_then(|p| p.canonicalize().ok())
    else {
        s.gap("compiler", "cmake-missing");
        return s.finish(None);
    };
    s.cmake_share = cmake
        .parent()
        .and_then(Path::parent)
        .unwrap_or(Path::new("/missing-cmake-prefix"))
        .join("share");
    let Some(make) = s
        .resolver
        .on_path("make")
        .filter(|p| rubocop::trusted_path(ctx.root, p))
    else {
        s.gap("compiler", "make-missing");
        return s.finish(None);
    };
    let build = stage.parent().unwrap().join("build");
    let instrumented = stage.parent().unwrap().join("instrumented");
    if fs::create_dir_all(&build).is_err() || fs::create_dir_all(&instrumented).is_err() {
        s.gap("compiler", "build-scratch-unwritable");
        return s.finish(None);
    }
    let sdk_root = s.sdk.as_ref().map(|sdk| sdk.root.clone());
    let configure = |dest: &Path, sanitized: bool| -> Vec<String> {
        let flags = if sanitized {
            "-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all"
        } else {
            "-O0 -g"
        };
        let mut args = vec![
            "--trace-expand".into(),
            "--trace-format=json-v1".into(),
            format!(
                "--trace-redirect={}",
                dest.join("configure-trace.jsonl").display()
            ),
            "-S".into(),
            stage.to_string_lossy().into_owned(),
            "-B".into(),
            dest.to_string_lossy().into_owned(),
            "-G".into(),
            "Unix Makefiles".into(),
            "-DCMAKE_BUILD_TYPE=Debug".into(),
            "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON".into(),
            format!("-DCMAKE_MAKE_PROGRAM={}", make.display()),
            format!("-DCMAKE_C_COMPILER={}", clang.display()),
            format!("-DCMAKE_CXX_COMPILER={}", clangxx.display()),
            format!("-DCMAKE_C_FLAGS={flags}"),
            format!("-DCMAKE_CXX_FLAGS={flags}"),
            "-DBUILD_TESTING=ON".into(),
            "-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF".into(),
            "-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF".into(),
        ];
        if let Some(root) = &sdk_root {
            args.push(format!("-DCMAKE_OSX_SYSROOT={}", root.display()));
        }
        args
    };
    if !s
        .process("compiler", &["cmake"], &stage, configure(&build, false))
        .await
    {
        return s.finish(None);
    }
    match configuration_inputs(&stage, &build, &s.cmake_share) {
        Ok(map) => s.generated.extend(map),
        Err(e) => {
            s.gap("compiler", &e);
            return s.finish(None);
        }
    }
    let rows = match database(&stage, &build, selected, sdk_root.as_deref()) {
        Ok(r) => r,
        Err(e) => {
            s.gap("compiler", &e);
            return s.finish(None);
        }
    };
    let db_bytes = match read(
        &build.join("compile_commands.json"),
        MAX_MANIFEST_BYTES as usize,
    ) {
        Ok(b) => b,
        Err(e) => {
            s.gap("compiler", &e);
            return s.finish(None);
        }
    };
    s.generated.insert(
        build
            .join("compile_commands.json")
            .to_string_lossy()
            .into_owned(),
        sha256_text(&db_bytes),
    );
    let mut context = json!({"path":build.join("compile_commands.json"),"digest":sha256_text(&db_bytes),"bytes":db_bytes,"sourceBinding":s.binding,"sdk":s.sdk.as_ref().map(|sdk|json!({"root":sdk.root,"treeDigest":sdk.tree_digest,"fileCount":sdk.files.len(),"enrollmentDigest":sdk.enrollment_digest})),"operationsVersion":"c-family-operations/v1"});
    // Every database row/configuration is replayed; duplicate file rows are not
    // silently reduced to one configuration.
    for (file, cpp, flags) in &rows {
        for tool in ["compiler", "lint", "analyzer"] {
            let mut args = if tool == "lint" {
                vec![
                    "--config={}".into(),
                    "--checks=-*,bugprone-branch-clone".into(),
                    "--use-color=false".into(),
                    stage.join(file).to_string_lossy().into_owned(),
                    "--".into(),
                ]
            } else {
                Vec::new()
            };
            args.extend(flags.clone());
            args.extend([
                "-fno-color-diagnostics".into(),
                "-fno-caret-diagnostics".into(),
            ]);
            if tool != "lint" {
                args.push(
                    if tool == "analyzer" {
                        "--analyze"
                    } else {
                        "-fsyntax-only"
                    }
                    .into(),
                );
                if tool == "analyzer" {
                    args.extend(["-Xanalyzer".into(), "-analyzer-output=text".into()]);
                }
                args.push(stage.join(file).to_string_lossy().into_owned());
            }
            let parser = if tool == "lint" {
                Parser::ClangTidy
            } else {
                Parser::ClangCompiler
            };
            let command = planned(
                tool,
                if tool == "lint" {
                    &["clang-tidy"]
                } else if *cpp {
                    &["clang++"]
                } else {
                    &["clang"]
                },
                &stage,
                args,
                parser,
                &s.binding,
                &stage,
            );
            s.execute(command).await;
        }
    }
    if !s
        .process(
            "compiler",
            &["cmake"],
            &stage,
            vec![
                "--build".into(),
                build.to_string_lossy().into_owned(),
                "--parallel".into(),
                "1".into(),
            ],
        )
        .await
    {
        return s.finish(Some(context));
    }
    match object_products(&build) {
        Ok(v) => {
            if let Ok(map) = serde_json::from_value::<BTreeMap<String, String>>(v.clone()) {
                s.generated.extend(map);
            }
            context["objectProducts"] = v;
        }
        Err(e) => s.gap("compiler", &e),
    }
    match dependency_coverage(&stage, &build, selected, s.sdk.as_ref()) {
        Ok(v) => context["dependencyCoverage"] = v,
        Err(e) => {
            for tool in ["compiler", "lint", "analyzer"] {
                s.gap(tool, &e);
            }
        }
    }
    if s.process(
        "test",
        &["ctest"],
        &build,
        vec![
            "--show-only=json-v1".into(),
            "--output-log".into(),
            build.join("tests.json.log").to_string_lossy().into_owned(),
        ],
    )
    .await
    {
        // CTest --show-only emits JSON to stdout. Read actual retained SDK bytes,
        // never fabricate test metadata from CMake source.
        let bytes = s
            .evidence
            .receipts
            .last()
            .and_then(|r| receipt_artifact(ctx.scratch, r, "stdout"));
        let listing = build.join("test-list.json");
        if let Some(bytes) = bytes {
            if fs::write(&listing, bytes).is_ok() {
                match test_results(&listing, &stage, &build) {
                    Ok(v) => {
                        if let Ok(map) = serde_json::from_value::<BTreeMap<String, String>>(
                            v["executables"].clone(),
                        ) {
                            s.generated.extend(map);
                        }
                        context["registeredTests"] = v;
                    }
                    Err(e) => s.gap("test", &e),
                }
            } else {
                s.gap("test", "test-list-unwritable");
            }
        } else {
            s.gap("test", "test-list-unreadable");
        }
        if context.get("registeredTests").is_some() {
            s.process(
                "test",
                &["ctest"],
                &build,
                vec![
                    "--output-on-failure".into(),
                    "--no-tests=error".into(),
                    "--output-junit".into(),
                    build.join("junit.xml").to_string_lossy().into_owned(),
                ],
            )
            .await;
        }
    }
    if s.process(
        "sanitizer",
        &["cmake"],
        &stage,
        configure(&instrumented, true),
    )
    .await
    {
        match configuration_inputs(&stage, &instrumented, &s.cmake_share) {
            Ok(map) => s.generated.extend(map),
            Err(e) => s.gap("sanitizer", &e),
        }
        match database(&stage, &instrumented, selected, sdk_root.as_deref()) {
            Ok(sanitized) => {
                if let Ok(bytes) = read(
                    &instrumented.join("compile_commands.json"),
                    MAX_MANIFEST_BYTES as usize,
                ) {
                    s.generated.insert(
                        instrumented
                            .join("compile_commands.json")
                            .to_string_lossy()
                            .into_owned(),
                        sha256_text(&bytes),
                    );
                } else {
                    s.gap("sanitizer", "instrumented-database-unreadable");
                }
                if sanitized
                    .iter()
                    .any(|(_, _, flags)| !flags.iter().any(|f| f == "-fsanitize=address,undefined"))
                {
                    s.gap("sanitizer", "instrumentation-not-in-generated-database");
                } else if s
                    .process(
                        "sanitizer",
                        &["cmake"],
                        &stage,
                        vec![
                            "--build".into(),
                            instrumented.to_string_lossy().into_owned(),
                            "--parallel".into(),
                            "1".into(),
                        ],
                    )
                    .await
                {
                    if s.process(
                        "sanitizer",
                        &["ctest"],
                        &instrumented,
                        vec![
                            "--show-only=json-v1".into(),
                            "--output-log".into(),
                            instrumented
                                .join("tests.json.log")
                                .to_string_lossy()
                                .into_owned(),
                        ],
                    )
                    .await
                    {
                        let listing = instrumented.join("test-list.json");
                        if let Some(bytes) = s
                            .evidence
                            .receipts
                            .last()
                            .and_then(|r| receipt_artifact(ctx.scratch, r, "stdout"))
                        {
                            if fs::write(&listing, bytes).is_ok() {
                                match test_results(&listing, &stage, &instrumented) {
                                    Ok(v) => {
                                        if let Ok(map) =
                                            serde_json::from_value::<BTreeMap<String, String>>(
                                                v["executables"].clone(),
                                            )
                                        {
                                            s.generated.extend(map);
                                        }
                                        context["sanitizerRegisteredTests"] = v;
                                    }
                                    Err(e) => s.gap("sanitizer", &e),
                                }
                            } else {
                                s.gap("sanitizer", "instrumented-test-list-unwritable");
                            }
                        } else {
                            s.gap("sanitizer", "instrumented-test-list-unreadable");
                        }
                    }
                    let link_ok = s
                        .generated
                        .keys()
                        .filter(|p| {
                            Path::new(p).starts_with(&instrumented) && p.ends_with("/link.txt")
                        })
                        .all(|p| {
                            fs::read_to_string(p).is_ok_and(|text| {
                                text.contains("-fsanitize=address,undefined")
                                    && !text.contains("-fno-sanitize")
                            })
                        });
                    if !link_ok {
                        s.gap("sanitizer", "instrumented-link-flags-unproven");
                    }
                    let mut command = planned(
                        "sanitizer",
                        &["ctest"],
                        &instrumented,
                        vec![
                            "--output-on-failure".into(),
                            "--no-tests=error".into(),
                            "--output-junit".into(),
                            instrumented
                                .join("junit.xml")
                                .to_string_lossy()
                                .into_owned(),
                        ],
                        Parser::CFamilyProcess,
                        &s.binding,
                        &stage,
                    );
                    command.env.extend([
                        (
                            "ASAN_OPTIONS",
                            "detect_leaks=0:halt_on_error=1:abort_on_error=0:exitcode=86".into(),
                        ),
                        ("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1".into()),
                    ]);
                    if link_ok
                        && context.get("sanitizerRegisteredTests").is_some()
                        && context["sanitizerRegisteredTests"]["declaredAssertions"]
                            == context["registeredTests"]["declaredAssertions"]
                    {
                        s.execute(command).await;
                    } else {
                        s.gap("sanitizer", "registered-assertions-unavailable");
                    }
                    match object_products(&instrumented) {
                        Ok(v) => {
                            if let Ok(map) =
                                serde_json::from_value::<BTreeMap<String, String>>(v.clone())
                            {
                                s.generated.extend(map);
                            }
                            context["sanitizerObjectProducts"] = v;
                        }
                        Err(e) => s.gap("sanitizer", &e),
                    }
                    match dependency_coverage(&stage, &instrumented, selected, s.sdk.as_ref()) {
                        Ok(v) => context["sanitizerDependencyCoverage"] = v,
                        Err(e) => s.gap("sanitizer", &e),
                    }
                }
            }
            Err(e) => s.gap("sanitizer", &e),
        }
    }
    for (tool, path) in [
        ("test", build.join("junit.xml")),
        ("sanitizer", instrumented.join("junit.xml")),
    ] {
        match read(&path, MAX_MANIFEST_BYTES as usize) {
            Ok(bytes) => {
                match junit(
                    &bytes,
                    &context[if tool == "sanitizer" {
                        "sanitizerRegisteredTests"
                    } else {
                        "registeredTests"
                    }],
                ) {
                    Ok(v) => {
                        if v["failures"].as_u64().is_some_and(|n| n > 0)
                            && s.accumulators.get(tool).and_then(|a| a.outcome.as_ref())
                                == Some(&Outcome::Ran)
                        {
                            s.gap(tool, "junit-inconsistent-exit");
                        }
                        context[format!("{tool}Results")] = v;
                    }
                    Err(e) => s.gap(tool, &e),
                }
            }
            Err(e) => s.gap(tool, &format!("per-test-results:{e}")),
        }
    }
    s.finish(Some(context))
}

fn source_stage(command: &Planned) -> Result<PathBuf, String> {
    command
        .env
        .iter()
        .find(|(n, _)| *n == "LEGION_C_FAMILY_STAGE")
        .map(|(_, p)| PathBuf::from(p))
        .ok_or_else(|| "source-binding-missing".into())
}

pub(super) fn snapshot(command: &Planned) -> Result<Value, String> {
    let stage = source_stage(command)?;
    let binding_bytes = read(
        &stage
            .parent()
            .ok_or("source-binding-missing")?
            .join(BINDING),
        MAX_BYTES,
    )?;
    if command.source_digest.as_deref() != Some(sha256_text(&binding_bytes).as_str()) {
        return Err("binding-changed".into());
    }
    let binding: Value = serde_json::from_slice(&binding_bytes).map_err(|_| "binding-malformed")?;
    let root = Path::new(binding["root"].as_str().ok_or("binding-root")?);
    let files = binding["files"].as_object().ok_or("binding-files")?;
    fn listed_tree(
        root: &Path,
        dir: &Path,
        files: &serde_json::Map<String, Value>,
        nodes: &mut usize,
        depth: usize,
    ) -> Result<(), String> {
        if depth > MAX_DEPTH {
            return Err("staged-tree-depth".into());
        }
        for entry in fs::read_dir(dir).map_err(|_| "staged-tree-unreadable")? {
            *nodes += 1;
            if *nodes > MAX_FILES * 4 {
                return Err("staged-tree-budget".into());
            }
            let p = entry.map_err(|_| "staged-tree-unreadable")?.path();
            let m = fs::symlink_metadata(&p).map_err(|_| "staged-tree-unreadable")?;
            if m.file_type().is_symlink() {
                return Err("staged-tree-symlink".into());
            }
            if m.is_dir() {
                listed_tree(root, &p, files, nodes, depth + 1)?;
            } else if m.is_file() {
                let rel = p
                    .strip_prefix(root)
                    .map_err(|_| "staged-path")?
                    .to_str()
                    .ok_or("staged-path")?;
                if !files.contains_key(rel) {
                    return Err("unfrozen-staged-input".into());
                }
            } else {
                return Err("staged-input-type".into());
            }
        }
        Ok(())
    }
    listed_tree(&stage, &stage, files, &mut 0, 0)?;
    let mut verified = BTreeMap::new();
    for (path, digest) in files {
        if !relative(path) {
            return Err("binding-path".into());
        }
        for base in [stage.as_path(), root] {
            if within(base, base, path)? != *path {
                return Err("input-path-changed".into());
            }
            if Some(sha256_text(&read(&base.join(path), MAX_BYTES)?).as_str()) != digest.as_str() {
                return Err("source-closure-changed".into());
            }
        }
        verified.insert(path, digest);
    }
    let generated: BTreeMap<String, String> = serde_json::from_str(
        command
            .env
            .iter()
            .find(|(n, _)| *n == "LEGION_C_FAMILY_GENERATED")
            .map(|(_, v)| v.as_str())
            .unwrap_or("{}"),
    )
    .map_err(|_| "generated-binding")?;
    for (path, digest) in &generated {
        let cmake_share = PathBuf::from(
            command
                .env
                .iter()
                .find(|(n, _)| *n == "LEGION_C_FAMILY_CMAKE_SHARE")
                .map(|(_, p)| p.as_str())
                .ok_or("cmake-share-binding")?,
        );
        if !(Path::new(path).starts_with(stage.parent().ok_or("stage-parent")?)
            || Path::new(path).starts_with(&cmake_share))
            || sha256_text(&read(Path::new(path), MAX_BYTES)?) != *digest
        {
            return Err("generated-context-changed".into());
        }
    }
    let sdk = if let Some((_, path)) = command
        .env
        .iter()
        .find(|(n, _)| *n == "LEGION_C_FAMILY_SDK_ENROLLMENT")
    {
        let expected = command
            .env
            .iter()
            .find(|(n, _)| *n == "LEGION_C_FAMILY_SDK_ENROLLMENT_DIGEST")
            .map(|(_, v)| v.as_str())
            .ok_or("sdk-enrollment-binding")?;
        let sdk = SdkContext::load(Path::new(path), Some(expected))?;
        Some(
            json!({"root":sdk.root,"treeDigest":sdk.tree_digest,"fileCount":sdk.files.len(),"enrollmentDigest":sdk.enrollment_digest}),
        )
    } else {
        None
    };
    Ok(
        json!({"schema":"legion-c-family-input-snapshot/1","sdk":sdk,"bindingDigest":command.source_digest,"sourceRoot":root,"stagedRoot":stage,"files":verified,"generatedContext":generated}),
    )
}

pub(super) fn parse(
    bytes: &[u8],
    stderr: Option<&[u8]>,
    exit: Option<i32>,
    command: &Planned,
) -> Result<Vec<Diag>, String> {
    if !matches!(exit, Some(0 | 1)) {
        return Err("clang-inconsistent-exit".into());
    }
    let stage = source_stage(command)?;
    let stage = stage.canonicalize().map_err(|_| "stage-unreadable")?;
    let located = Regex::new(
        r"^(.+?):(\d+):(\d+): (warning|error|fatal error|note): (.*?)(?: \[([^\]]+)\])?$",
    )
    .map_err(|_| "diagnostic-pattern")?;
    let text = std::str::from_utf8(bytes).map_err(|_| "clang-output-encoding")?;
    let mut diagnostics = Vec::new();
    let mut saw_error = false;
    let mut summary_count = None;
    let generated = Regex::new(r"(\d+) (?:warnings?|errors?)").map_err(|_| "summary-pattern")?;
    for line in text
        .lines()
        .map(str::trim_end)
        .filter(|s| !s.trim().is_empty())
    {
        if let Some(c) = located.captures(line) {
            if &c[4] == "note" {
                continue;
            }
            let path = within(&stage, Path::new(&command.cwd_rel), &c[1])?;
            saw_error |= matches!(&c[4], "error" | "fatal error");
            diagnostics.push(Diag {
                rule: format!(
                    "{}:{}",
                    if command.parser == Parser::ClangCompiler {
                        "clang"
                    } else {
                        "clang-tidy"
                    },
                    c.get(6).map(|m| m.as_str()).unwrap_or("diagnostic")
                ),
                severity: if &c[4] == "warning" {
                    "warning"
                } else {
                    "error"
                },
                path,
                line: c[2]
                    .parse::<usize>()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or("diagnostic-line")?,
                message: shorten(&c[5]),
            });
        } else if line.chars().next().is_some_and(|c| c.is_ascii_digit())
            && (line.ends_with(" generated.") || line.ends_with(" treated as errors"))
        {
            if line.ends_with(" generated.") {
                let count = generated
                    .captures_iter(line)
                    .filter_map(|c| c[1].parse::<usize>().ok())
                    .sum::<usize>();
                if count == 0 || summary_count.is_some_and(|n| n != count) {
                    return Err("clang-diagnostic-summary".into());
                }
                summary_count = Some(count);
            }
            continue;
        } else {
            // Missing includes, invalid options & partial/malformed tool streams
            // must never turn into a nonempty-clean control.
            return Err("clang-unmapped-output".into());
        }
    }
    if command.parser == Parser::ClangTidy {
        let stderr = std::str::from_utf8(stderr.ok_or("clang-stderr-unreadable")?)
            .map_err(|_| "clang-output-encoding")?;
        for line in stderr.lines().map(str::trim).filter(|s| !s.is_empty()) {
            if !(line.chars().next().is_some_and(|c| c.is_ascii_digit())
                && line.ends_with(" generated."))
            {
                return Err("clang-tidy-operational-stderr".into());
            }
            let count = generated
                .captures_iter(line)
                .filter_map(|c| c[1].parse::<usize>().ok())
                .sum::<usize>();
            if count == 0 || summary_count.is_some_and(|n| n != count) {
                return Err("clang-diagnostic-summary".into());
            }
            summary_count = Some(count);
        }
    }
    if summary_count.is_some_and(|n| n != diagnostics.len()) {
        return Err("clang-incomplete-diagnostics".into());
    }
    if exit == Some(1) && !saw_error {
        return Err("clang-nondiagnostic-failure".into());
    }
    Ok(diagnostics)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_shell_grammar_rejects_effects_and_keeps_quoted_paths() {
        assert_eq!(
            split_command("clang '-DVALUE=two words' -c source.c").unwrap(),
            ["clang", "-DVALUE=two words", "-c", "source.c"]
        );
        for command in [
            "clang $(id) -c x.c",
            "clang `id` -c x.c",
            "clang -c x.c; id",
            "clang -c x.c | id",
            "clang \"unterminated",
        ] {
            assert!(split_command(command).is_err());
        }
    }

    #[test]
    fn junit_needs_actual_nonempty_exact_test_denominator() {
        let registered = json!({"tests":[{"name":"four_assertions"}]});
        let valid=b"<?xml version=\"1.0\"?><testsuite tests=\"1\"><testcase name=\"four_assertions\"><system-out>native</system-out></testcase></testsuite>";
        assert_eq!(junit(valid, &registered).unwrap()["testCount"], 1);
        for invalid in [b"<testsuite tests=\"0\"></testsuite>".as_slice(),b"<testsuite tests=\"1\"><testcase name=\"other\"></testcase></testsuite>".as_slice(),b"<testsuite tests=\"1\"><testcase name=\"four_assertions\"><skipped/></testcase></testsuite>".as_slice(),b"<testsuite tests=\"1\">".as_slice()]{assert!(junit(invalid,&registered).is_err());}
    }

    #[test]
    fn response_plugins_frameworks_and_external_sysroots_are_not_replayed() {
        let root = std::env::var_os("LEGION_C_FAMILY_SCRATCH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/Volumes/D/scratch"))
            .join(format!("c-family-argv-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        fs::write(root.join("source.c"), "int value(void){return 1;}\n").unwrap();
        for extra in [
            "@flags.rsp",
            "-fplugin=plugin.so",
            "-Xclang",
            "-F/Library/Frameworks",
            "-isysroot",
            "-include",
            "-fmodules",
        ] {
            let row = json!({"arguments":["clang",extra,"-c",root.join("source.c")]});
            assert!(flags(&root, &root, &row, "source.c", &root, None).is_err());
        }
        let sdk = root.join("enrolled-sdk");
        fs::create_dir_all(&sdk).unwrap();
        let row = json!({"arguments":["clang","-isysroot",sdk,"-c",root.join("source.c")]});
        assert!(flags(&root, &root, &row, "source.c", &root, Some(&sdk)).is_ok());
        assert!(flags(&root, &root, &row, "source.c", &root, Some(&root)).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_diagnostic_output_and_unmapped_paths_cannot_be_clean() {
        let root = std::env::var_os("LEGION_C_FAMILY_SCRATCH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/Volumes/D/scratch"))
            .join(format!("c-family-diag-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        fs::write(root.join("source.c"), "int value(void){return 1;}\n").unwrap();
        let child = root.join("child");
        fs::create_dir_all(&child).unwrap();
        let child = child.canonicalize().unwrap();
        let native_source = root.join("source.c");
        assert!(within(&child, &root, native_source.to_str().unwrap()).is_err());
        let separator = std::path::MAIN_SEPARATOR;
        let parent_alias = format!(
            "{}{separator}child{separator}..{separator}source.c",
            root.display()
        );
        assert!(within(&root, &root, &parent_alias).is_err());
        let mut command = planned(
            "compiler",
            &["clang"],
            &root,
            Vec::new(),
            Parser::ClangCompiler,
            "sha256:fixture",
            &root,
        );
        assert!(parse(b"unrecognized banner", Some(b""), Some(0), &command).is_err());
        assert!(parse(b"", Some(b""), Some(1), &command).is_err());
        assert!(parse(
            b"/unmapped/source.c:2:1: warning: planted [-Wunused-variable]\n1 warning generated.\n",
            Some(b""),
            Some(0),
            &command
        )
        .is_err());
        let located = format!(
            "{}:2:1: warning: planted [-Wunused-variable]\n1 warning generated.\n",
            root.join("source.c").display()
        );
        let diagnostics = parse(located.as_bytes(), Some(b""), Some(0), &command).unwrap();
        assert_eq!(diagnostics[0].path, "source.c");
        assert_eq!(diagnostics[0].line, 2);
        command.parser = Parser::ClangTidy;
        assert!(parse(b"", Some(b"1 warning generated.\n"), Some(0), &command).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
