//! Bounded offline .NET SDK execution. No owner admission is supplied here.
//! SDK/package enrollment is an external provisioning step, never project execution.
use super::{sha256_text, Diag, Parser, Plan, Planned};
use crate::{inventory::InventoryEntry, native_providers::legacy_checks::AuditScratch};
use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha512};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
};

const TASKS: &[&str] = &["restore", "build", "analyzer", "test"];
const MAX_FILES: usize = 100_000;
const MAX_BYTES: u64 = 3 * 1024 * 1024 * 1024;
const MAX_SOURCE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TEXT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_ENROLLMENT_BYTES: u64 = 32 * 1024 * 1024;

fn safe_rel(value: &str) -> bool {
    !value.is_empty()
        && !value.contains(['\\', '\0', '\n', '\r'])
        && Path::new(value)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}
fn digest_map(files: &BTreeMap<String, String>) -> Result<String, String> {
    serde_json::to_vec(files)
        .map(|bytes| sha256_text(&bytes))
        .map_err(|_| "map-serialization".into())
}
fn read(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let before = fs::symlink_metadata(path).map_err(|_| "input-unreadable")?;
    if !before.is_file() || before.len() > limit {
        return Err("input-type-or-budget".into());
    }
    let mut file = fs::File::open(path).map_err(|_| "input-unreadable")?;
    let opened = file.metadata().map_err(|_| "input-unreadable")?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "input-unreadable")?;
    let after = fs::symlink_metadata(path).map_err(|_| "input-unreadable")?;
    if !after.is_file()
        || bytes.len() as u64 > limit
        || bytes.len() as u64 != before.len()
        || opened.len() != before.len()
        || after.len() != before.len()
        || opened.modified().ok() != before.modified().ok()
        || after.modified().ok() != before.modified().ok()
    {
        return Err("input-changed".into());
    }
    Ok(bytes)
}
fn text(path: &Path) -> Result<String, String> {
    String::from_utf8(read(path, MAX_TEXT_BYTES)?).map_err(|_| "input-not-utf8".into())
}
fn canonical(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() || fs::canonicalize(path).map_err(|_| "input-root")? != path {
        return Err("input-root-not-canonical".into());
    }
    Ok(path.to_owned())
}
fn tree(root: &Path) -> Result<BTreeMap<String, String>, String> {
    fn walk(
        root: &Path,
        dir: &Path,
        files: &mut BTreeMap<String, String>,
        bytes: &mut u64,
        nodes: &mut usize,
        depth: usize,
    ) -> Result<(), String> {
        if depth > 64 {
            return Err("input-tree-budget".into());
        }
        for entry in fs::read_dir(dir).map_err(|_| "input-tree-unreadable")? {
            *nodes += 1;
            if *nodes > MAX_FILES * 2 {
                return Err("input-tree-budget".into());
            }
            let path = entry.map_err(|_| "input-tree-unreadable")?.path();
            let meta = fs::symlink_metadata(&path).map_err(|_| "input-tree-unreadable")?;
            if meta.is_dir() {
                walk(root, &path, files, bytes, nodes, depth + 1)?;
            } else if meta.is_file() {
                if files.len() >= MAX_FILES {
                    return Err("input-tree-budget".into());
                }
                let data = read(
                    &path,
                    MAX_BYTES.checked_sub(*bytes).ok_or("input-tree-budget")?,
                )?;
                *bytes += data.len() as u64;
                let relative = path
                    .strip_prefix(root)
                    .map_err(|_| "input-path")?
                    .to_str()
                    .ok_or("input-path")?
                    .replace('\\', "/");
                if !safe_rel(&relative) {
                    return Err("input-path".into());
                }
                files.insert(relative, sha256_text(&data));
            } else {
                return Err("input-symlink-or-special".into());
            }
        }
        Ok(())
    }
    canonical(root)?;
    let mut files = BTreeMap::new();
    walk(root, root, &mut files, &mut 0, &mut 1, 0)?;
    Ok(files)
}
fn field<'a>(value: &'a Value, name: &str) -> Result<&'a str, String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("enrollment-field:{name}"))
}
fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in bytes.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for index in 0..4 {
            result.push(if index > chunk.len() {
                '='
            } else {
                TABLE[((value >> (18 - index * 6)) & 63) as usize] as char
            });
        }
    }
    result
}
fn locked_cache(bytes: &[u8], packages: &Path) -> Result<(), String> {
    let lock: Value = serde_json::from_slice(bytes).map_err(|_| "package-lock-malformed")?;
    if lock["version"] != 1 {
        return Err("package-lock-version".into());
    }
    let dependencies = lock["dependencies"]
        .as_object()
        .ok_or("package-lock-dependencies")?;
    if dependencies.is_empty() {
        return Err("package-lock-no-framework".into());
    }
    for (_, rows) in dependencies {
        for (name, row) in rows.as_object().ok_or("package-lock-framework")? {
            if !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            {
                return Err("package-lock-id".into());
            }
            if ![Some("Direct"), Some("Transitive")].contains(&row["type"].as_str()) {
                return Err("package-lock-type-unsupported".into());
            }
            let version = field(row, "resolved")?;
            if !version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-+".contains(&b))
            {
                return Err("package-lock-version".into());
            }
            let expected = field(row, "contentHash")?;
            let name = name.to_ascii_lowercase();
            let version = version.to_ascii_lowercase();
            let root = packages.join(&name).join(&version);
            canonical(&root)?;
            let hash = text(&root.join(format!("{name}.{version}.nupkg.sha512")))?;
            let archive = read(
                &root.join(format!("{name}.{version}.nupkg")),
                MAX_SOURCE_BYTES,
            )?;
            let metadata: Value =
                serde_json::from_slice(&read(&root.join(".nupkg.metadata"), MAX_TEXT_BYTES)?)
                    .map_err(|_| "package-cache-metadata-malformed")?;
            // NuGet.Client c754078 PackageExtractor.cs:434-445 records archive
            // SHA512 in .sha512 & unsigned contentHash in metadata/lock files.
            if hash.trim() != base64(&Sha512::digest(&archive))
                || expected.is_empty()
                || metadata.get("contentHash").and_then(Value::as_str) != Some(expected)
            {
                return Err("package-cache-missing-or-hash-mismatch".into());
            }
        }
    }
    Ok(())
}
fn enrollment() -> Result<(PathBuf, Value), String> {
    let path = PathBuf::from(
        std::env::var_os("LEGION_DOTNET_ENROLLMENT").ok_or("sdk-enrollment-missing")?,
    );
    canonical(&path)?;
    let value: Value = serde_json::from_slice(&read(&path, MAX_ENROLLMENT_BYTES)?)
        .map_err(|_| "sdk-enrollment-malformed")?;
    if value["schema"] != "legion-dotnet-sdk-enrollment/1"
        || value["sdkVersion"] != "8.0.426"
        || value["runtimeVersion"] != "8.0.32"
    {
        return Err("sdk-enrollment-version".into());
    }
    for name in ["sdkRoot", "packagesRoot"] {
        canonical(Path::new(field(&value, name)?))?;
    }
    if value["sdkProvenance"]["metadataUrl"] != "https://dotnetcli.blob.core.windows.net/dotnet/release-metadata/8.0/releases.json"
        || value["sdkProvenance"]["version"] != "8.0.426"
        || value["sdkProvenance"]["archiveUrl"] != "https://builds.dotnet.microsoft.com/dotnet/Sdk/8.0.426/dotnet-sdk-8.0.426-osx-arm64.tar.gz"
        || value["sdkProvenance"]["archiveSha512"] != "17cd408c92eb6ceedc06d41fa726c783b9be020c6ae5f3624ad3a0b2c26a78aa7d09f38338003163a72bb14d437731debf533c0451a5c6a05de3b1e37a3aa50a"
        || value["packageProvenance"].as_array().is_none_or(Vec::is_empty)
    { return Err("official-provenance-incomplete".into()); }
    Ok((path, value))
}

/// v1 refuses dynamic/out-of-tree MSBuild behavior rather than rewriting project semantics.
/// All unsupported original inputs remain counted gaps.
fn project(value: &str, extension: &str) -> Result<(Vec<String>, bool), String> {
    if value.contains(['&', '$', '@']) || value.contains("<!--") || value.contains("<!") {
        return Err("dynamic-or-entity-project-unsupported".into());
    }
    let tag = Regex::new(r"<([^<>]*)>").map_err(|_| "project-parser")?;
    let property = Regex::new(r"<TargetFrameworks?>([^<>]+)</TargetFrameworks?>")
        .map_err(|_| "project-parser")?;
    let allowed = [
        "Project",
        "PropertyGroup",
        "ItemGroup",
        "PackageReference",
        "TargetFramework",
        "TargetFrameworks",
        "OutputType",
        "IsPackable",
        "IsTestProject",
        "EnableNETAnalyzers",
        "AnalysisLevel",
        "AnalysisMode",
        "EnforceCodeStyleInBuild",
        "TreatWarningsAsErrors",
        "Nullable",
        "ImplicitUsings",
        "GenerateProgramFile",
        "GenerateAssemblyInfo",
        "LangVersion",
        "NoWarn",
        "RootNamespace",
        "OptionStrict",
        "OptionExplicit",
        "OptionInfer",
        "Compile",
    ];
    for captures in tag.captures_iter(value) {
        let raw = captures[1]
            .trim()
            .trim_start_matches('/')
            .trim_end_matches('/')
            .trim();
        if raw.starts_with("?xml ") && raw.ends_with('?') {
            continue;
        }
        let name = raw.split_whitespace().next().ok_or("project-tag")?;
        if !allowed.contains(&name) {
            return Err(format!("msbuild-element-unsupported:{name}"));
        }
        let attributes = raw.strip_prefix(name).unwrap_or_default().trim();
        match name {
            "Project" if attributes == "Sdk=\"Microsoft.NET.Sdk\"" || attributes.is_empty() => {}
            "PackageReference" => {
                let shape = Regex::new(r#"^Include="[A-Za-z0-9_.-]+" Version="[0-9]+\.[0-9]+\.[0-9]+(?:[.-][A-Za-z0-9.-]+)?"$"#).map_err(|_| "project-parser")?;
                if !shape.is_match(attributes) {
                    return Err("package-reference-unsupported".into());
                }
            }
            "Compile" if extension == "fsproj" => {
                let shape = Regex::new(r#"^Include="[A-Za-z0-9_./-]+\.fs"$"#)
                    .map_err(|_| "project-parser")?;
                if !shape.is_match(attributes)
                    || attributes.contains("..")
                    || attributes.contains(":")
                {
                    return Err("compile-input-unsupported".into());
                }
            }
            _ if attributes.is_empty() => {}
            _ => return Err(format!("msbuild-attributes-unsupported:{name}")),
        }
    }
    if !value
        .trim_start()
        .starts_with("<Project Sdk=\"Microsoft.NET.Sdk\">")
        || !value.trim_end().ends_with("</Project>")
    {
        return Err("sdk-project-required".into());
    }
    let declarations = property.captures_iter(value).collect::<Vec<_>>();
    if declarations.len() != 1 {
        return Err("target-framework-declaration".into());
    }
    let frameworks = declarations[0][1]
        .split(';')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if frameworks.len() != 1 || frameworks.iter().any(|v| v != "net8.0") {
        return Err("target-framework-unsupported".into());
    }
    let is_test = value.contains("<IsTestProject>true</IsTestProject>")
        && value.contains("Include=\"Microsoft.NET.Test.Sdk\"");
    Ok((frameworks, is_test))
}

pub(super) fn plan(
    root: &Path,
    entries: &[InventoryEntry],
    scratch: &AuditScratch,
    plan: &mut Plan,
) {
    if let Err(reason) = plan_inner(root, entries, scratch, plan) {
        for task in TASKS {
            plan.not_planned.insert(task, "dotnet-input-incomplete");
        }
        plan.notes.push(format!("dotnet:{reason}"));
    }
}
fn plan_inner(
    root: &Path,
    entries: &[InventoryEntry],
    scratch: &AuditScratch,
    plan: &mut Plan,
) -> Result<(), String> {
    let root = fs::canonicalize(root).map_err(|_| "source-root")?;
    let (enrollment_path, enrolled) = enrollment()?;
    let sdk = Path::new(field(&enrolled, "sdkRoot")?);
    let packages = Path::new(field(&enrolled, "packagesRoot")?);
    if sdk.starts_with(&root) || packages.starts_with(&root) {
        return Err("toolchain-inside-project".into());
    }
    let sdk_files = tree(sdk)?;
    if !sdk_files.contains_key("shared/Microsoft.NETCore.App/8.0.32/libcoreclr.dylib") {
        return Err("enrolled-runtime-missing".into());
    }
    let package_files = tree(packages)?;
    if digest_map(&sdk_files)? != field(&enrolled, "sdkDigest")?
        || digest_map(&package_files)? != field(&enrolled, "packagesDigest")?
    {
        return Err("enrolled-closure-changed".into());
    }
    let fsharp = enrolled.get("fsharpAnalyzer").filter(|v| v["id"] == "dotnet-fsharplint" && v["version"] == "0.27.0"
        && v["sourceCommit"] == "43c8586c82eb2309b5cb9fee1b32d59e899f07e5"
        && v["archiveSha512"] == "9TDJCUYrime4mR6ypEN6N95JnBqq3ieFawUQawxkev/+7UaXSk1namitl/cxfFWtYsiiUoSDNf9hO0WKBpnCCw==");
    if let Some(analyzer) = fsharp {
        let path = Path::new(field(analyzer, "root")?);
        if path.starts_with(&root) || digest_map(&tree(path)?)? != field(analyzer, "digest")? {
            return Err("fsharp-analyzer-closure".into());
        }
    }
    let mut source_files = BTreeMap::new();
    let mut source_contents = BTreeMap::new();
    let mut total = 0;
    let mut projects = Vec::new();
    for entry in entries {
        if !safe_rel(&entry.path) || entries.len() > 20_000 {
            return Err("source-path-or-budget".into());
        }
        let path = root.join(&entry.path);
        canonical(&path)?;
        let bytes = read(&path, MAX_SOURCE_BYTES - total)?;
        total += bytes.len() as u64;
        let digest = sha256_text(&bytes);
        if entry.digest.as_deref() != Some(digest.as_str()) {
            return Err("source-frozen-digest".into());
        }
        source_files.insert(entry.path.clone(), digest);
        source_contents.insert(entry.path.clone(), bytes);
        let file = entry
            .path
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if [
            "directory.build.props",
            "directory.build.targets",
            "directory.packages.props",
            "nuget.config",
        ]
        .contains(&file.as_str())
            || [".props", ".targets", ".sln", ".slnx", ".runsettings"]
                .iter()
                .any(|suffix| file.ends_with(suffix))
        {
            return Err(format!("project-configuration-unsupported:{}", entry.path));
        }
        if ["csproj", "fsproj", "vbproj"]
            .iter()
            .any(|ext| entry.path.ends_with(&format!(".{ext}")))
        {
            let ext = entry.path.rsplit('.').next().unwrap_or_default();
            let (frameworks, is_test) = project(
                &String::from_utf8(source_contents[&entry.path].clone())
                    .map_err(|_| "project-utf8")?,
                ext,
            )?;
            projects.push((entry.path.clone(), ext.to_owned(), frameworks, is_test));
        }
    }
    if projects.is_empty() || projects.len() > 6 {
        return Err("project-count".into());
    }
    let editor = source_contents
        .get(".editorconfig")
        .ok_or("root-editorconfig-required")?;
    if !String::from_utf8_lossy(editor)
        .lines()
        .any(|line| line.trim() == "root = true")
    {
        return Err("root-editorconfig-required".into());
    }
    let global: Value = serde_json::from_slice(
        source_contents
            .get("global.json")
            .ok_or("global-json-missing")?,
    )
    .map_err(|_| "global-json-malformed")?;
    if global["sdk"]["version"] != enrolled["sdkVersion"]
        || global["sdk"]["rollForward"] != "disable"
        || global["sdk"]["allowPrerelease"] != false
        || global.as_object().is_none_or(|v| v.len() != 1)
        || global["sdk"].as_object().is_none_or(|v| v.len() != 3)
    {
        return Err("sdk-not-exactly-pinned".into());
    }
    let stage = scratch.cache_dir().join("dotnet-source");
    fs::create_dir(&stage).map_err(|_| "source-stage-not-fresh")?;
    let stage = fs::canonicalize(stage).map_err(|_| "source-stage")?;
    for (path, bytes) in &source_contents {
        let destination = stage.join(path);
        fs::create_dir_all(destination.parent().ok_or("source-parent")?)
            .map_err(|_| "source-stage-write")?;
        fs::write(destination, bytes).map_err(|_| "source-stage-write")?;
    }
    let control = scratch.cache_dir().join("dotnet-control");
    fs::create_dir(&control).map_err(|_| "control-not-fresh")?;
    let control = fs::canonicalize(control).map_err(|_| "control-root")?;
    let config = control.join("NuGet.Config");
    let config_text = "<configuration><packageSources><clear /></packageSources><fallbackPackageFolders><clear /></fallbackPackageFolders><disabledPackageSources><clear /></disabledPackageSources></configuration>\n";
    fs::write(&config, config_text).map_err(|_| "offline-config-write")?;
    let manifest = control.join("inputs.json");
    let binding = json!({"schema":"legion-dotnet-input-binding/1", "sourceRoot":root, "stageRoot":stage,
        "sourceFiles":source_files, "sourceContents":source_contents, "enrollmentPath":enrollment_path,
        "enrollmentDigest":sha256_text(&read(&enrollment_path, MAX_ENROLLMENT_BYTES)?), "sdkRoot":sdk,
        "sdkDigest":enrolled["sdkDigest"], "packagesRoot":packages, "packagesDigest":enrolled["packagesDigest"],
        "offlineConfig":config, "offlineConfigDigest":sha256_text(config_text.as_bytes()), "enrollment":enrolled});
    let binding_bytes = serde_json::to_vec(&binding).map_err(|_| "input-binding")?;
    fs::write(&manifest, &binding_bytes).map_err(|_| "input-binding-write")?;
    let mut commands = Vec::new();
    for (index, (path, ext, frameworks, is_test)) in projects.iter().enumerate() {
        let project_dir = Path::new(path).parent().ok_or("project-parent")?;
        let lock_path = project_dir
            .join("packages.lock.json")
            .to_string_lossy()
            .replace('\\', "/");
        locked_cache(
            source_contents
                .get(&lock_path)
                .ok_or_else(|| format!("package-lock-missing:{path}"))?,
            packages,
        )?;
        let outputs = control.join(format!("artifacts-{index}"));
        let results = control.join(format!("test-results-{index}"));
        fs::create_dir(&results).map_err(|_| "test-results-not-fresh")?;
        for task in TASKS {
            if *task == "analyzer" && ext == "fsproj" && fsharp.is_none() {
                plan.not_planned
                    .insert("analyzer", "fsharp-analyzer-not-enrolled");
                plan.notes
                    .push(format!("dotnet:fsharp-analyzer-not-enrolled:{path}"));
                continue;
            }
            if *task == "test" && !is_test {
                plan.not_planned
                    .insert("test", "non-test-project-in-denominator");
                plan.notes.push(format!("dotnet:non-test-project:{path}"));
                continue;
            }
            let mut args = vec![
                if *task == "analyzer" { "build" } else { task }.to_string(),
                stage.join(path).to_string_lossy().into_owned(),
            ];
            args.extend([
                "--nologo".into(),
                "--verbosity".into(),
                "normal".into(),
                "--artifacts-path".into(),
                outputs.to_string_lossy().into_owned(),
                "-p:NuGetAudit=false".into(),
                "-p:RestoreIgnoreFailedSources=false".into(),
                "-p:UseSharedCompilation=false".into(),
                "-p:BuildInParallel=false".into(),
                "-nodeReuse:false".into(),
            ]);
            args.extend([
                "-p:ImportDirectoryBuildProps=false".into(),
                "-p:ImportDirectoryBuildTargets=false".into(),
                "-p:ImportDirectoryPackagesProps=false".into(),
            ]);
            match *task {
                "restore" => args.extend([
                    "--locked-mode".into(),
                    "--no-cache".into(),
                    "--disable-parallel".into(),
                    "--configfile".into(),
                    config.to_string_lossy().into_owned(),
                    "--packages".into(),
                    packages.to_string_lossy().into_owned(),
                ]),
                "build" => args.extend(["--no-restore".into(), "-p:RunAnalyzers=false".into()]),
                "analyzer" => args.extend([
                    "--no-restore".into(),
                    "-t:Rebuild".into(),
                    "-p:RunAnalyzers=true".into(),
                    "-p:RunAnalyzersDuringBuild=true".into(),
                    "-p:EnableNETAnalyzers=true".into(),
                    "-p:ReportAnalyzer=true".into(),
                ]),
                "test" => args.extend([
                    "--no-restore".into(),
                    "--no-build".into(),
                    "--logger".into(),
                    "trx;LogFilePrefix=dotnet-sdk".into(),
                    "--results-directory".into(),
                    results.to_string_lossy().into_owned(),
                ]),
                _ => return Err("task".into()),
            }
            let env = vec![
                ("DOTNET_ROOT", sdk.to_string_lossy().into_owned()),
                ("DOTNET_MULTILEVEL_LOOKUP", "0".into()),
                ("DOTNET_ROLL_FORWARD", "LatestPatch".into()),
                ("DOTNET_CLI_TELEMETRY_OPTOUT", "1".into()),
                ("DOTNET_SKIP_FIRST_TIME_EXPERIENCE", "1".into()),
                ("DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE", "true".into()),
                ("DOTNET_NOLOGO", "1".into()),
                ("MSBUILDDISABLENODEREUSE", "1".into()),
                ("MSBuildEnableWorkloadResolver", "false".into()),
                ("NUGET_PACKAGES", packages.to_string_lossy().into_owned()),
                (
                    "NUGET_HTTP_CACHE_PATH",
                    control.join("http-cache").to_string_lossy().into_owned(),
                ),
                (
                    "DOTNET_CLI_HOME",
                    control.join("home").to_string_lossy().into_owned(),
                ),
                (
                    "LEGION_DOTNET_INPUT_MANIFEST",
                    manifest.to_string_lossy().into_owned(),
                ),
                ("LEGION_DOTNET_FRAMEWORKS", frameworks.join(";")),
                (
                    "LEGION_DOTNET_TEST_RESULTS",
                    results.to_string_lossy().into_owned(),
                ),
            ];
            let mut env = env;
            env.extend([
                ("HOME", control.join("home").to_string_lossy().into_owned()),
                (
                    "USERPROFILE",
                    control.join("home").to_string_lossy().into_owned(),
                ),
                (
                    "XDG_CONFIG_HOME",
                    control.join("home/.config").to_string_lossy().into_owned(),
                ),
                (
                    "MSBuildUserExtensionsPath",
                    control.join("home/msbuild").to_string_lossy().into_owned(),
                ),
            ]);
            let is_fsharp_analyzer = *task == "analyzer" && ext == "fsproj";
            if is_fsharp_analyzer {
                let analyzer = fsharp.ok_or("fsharp-analyzer-not-enrolled")?;
                let entrypoint = Path::new(field(analyzer, "root")?)
                    .join("tools/net8.0/any/dotnet-fsharplint.dll");
                if !source_files.contains_key("fsharplint.json") {
                    return Err("fsharp-rule-config-missing".into());
                }
                let prefix = project_dir.to_string_lossy().replace('\\', "/");
                let files: Vec<_> = source_files
                    .keys()
                    .filter(|name| {
                        name.ends_with(".fs")
                            && (prefix.is_empty() || name.starts_with(&format!("{prefix}/")))
                    })
                    .cloned()
                    .collect();
                if files.is_empty() {
                    return Err("fsharp-source-empty".into());
                }
                args = vec![
                    entrypoint.to_string_lossy().into_owned(),
                    "--format".into(),
                    "MSBuild".into(),
                    "lint".into(),
                    stage
                        .join(project_dir)
                        .join("**/*.fs")
                        .to_string_lossy()
                        .into_owned(),
                    "--lint-config".into(),
                    stage.join("fsharplint.json").to_string_lossy().into_owned(),
                ];
                env.push((
                    "LEGION_DOTNET_FSHARP_FILES",
                    serde_json::to_string(&files).map_err(|_| "fsharp-file-binding")?,
                ));
            }
            commands.push(Planned {
                tool: task,
                programs: &["dotnet"],
                local_bin: false,
                sibling_of: None,
                requires: None,
                cwd_rel: stage.to_string_lossy().into_owned(),
                args,
                parser: Parser::Dotnet,
                accepted: if is_fsharp_analyzer {
                    &[0, 255, -1]
                } else if *task == "test" || *task == "restore" {
                    &[0]
                } else {
                    &[0, 1]
                },
                env,
                diagnostics_on_stderr: false,
                source_path: None,
                source_digest: Some(sha256_text(&binding_bytes)),
            });
        }
    }
    // Planning is atomic; an incomplete input never leaves executable partial work.
    plan.commands.extend(commands);
    Ok(())
}
fn env<'a>(command: &'a Planned, name: &str) -> Result<&'a str, String> {
    command
        .env
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.as_str())
        .ok_or_else(|| format!("binding-env:{name}"))
}
fn binding(command: &Planned) -> Result<Value, String> {
    let bytes = read(
        Path::new(env(command, "LEGION_DOTNET_INPUT_MANIFEST")?),
        MAX_SOURCE_BYTES * 5,
    )?;
    if command.source_digest.as_deref() != Some(sha256_text(&bytes).as_str()) {
        return Err("input-binding-changed".into());
    }
    serde_json::from_slice(&bytes).map_err(|_| "input-binding-malformed".into())
}
pub(super) fn executable_valid(command: &Planned, executable: &Path) -> Result<(), String> {
    let binding = binding(command)?;
    let expected = Path::new(field(&binding, "sdkRoot")?).join(if cfg!(windows) {
        "dotnet.exe"
    } else {
        "dotnet"
    });
    if executable != expected {
        return Err("sdk-host-not-enrolled".into());
    }
    Ok(())
}
pub(super) fn version_args(command: &Planned) -> Vec<String> {
    if command
        .env
        .iter()
        .any(|(key, _)| *key == "LEGION_DOTNET_FSHARP_FILES")
    {
        vec![command.args[0].clone(), "--version".into()]
    } else {
        vec!["--version".into()]
    }
}
pub(super) fn analyzer_scope(command: &Planned) -> Value {
    if command.tool != "analyzer" {
        return Value::Null;
    }
    if let Ok(files) = env(command, "LEGION_DOTNET_FSHARP_FILES") {
        json!({"kind":"fsharp-file-rule-analysis", "files":serde_json::from_str::<Value>(files).ok(),
            "configuration":Path::new(&command.cwd_rel).join("fsharplint.json"),
            "unsupportedCoverage":[{"kind":"fsharp-project-type-analysis-unmeasured"},{"kind":"fsharp-cross-file-rule-coverage-unmeasured"}],
            "roslynParity":false})
    } else {
        json!({"kind":"sdk-roslyn-analyzers", "configuration":Path::new(&command.cwd_rel).join(".editorconfig"), "arbitraryRuleCoverageQualified":false})
    }
}
pub(super) fn snapshot(command: &Planned) -> Result<Value, String> {
    let binding = binding(command)?;
    let stage = Path::new(field(&binding, "stageRoot")?);
    let source = Path::new(field(&binding, "sourceRoot")?);
    let user_imports = Path::new(env(command, "MSBuildUserExtensionsPath")?);
    if user_imports.exists() && !tree(user_imports)?.is_empty() {
        return Err("unexpected-user-msbuild-import".into());
    }
    let expected: BTreeMap<String, String> =
        serde_json::from_value(binding["sourceFiles"].clone()).map_err(|_| "source-binding")?;
    if tree(stage)? != expected {
        return Err("staged-source-changed".into());
    }
    for (path, digest) in &expected {
        let path = source.join(path);
        canonical(&path)?;
        if sha256_text(&read(&path, MAX_SOURCE_BYTES)?) != *digest {
            return Err("original-source-changed".into());
        }
    }
    for (root, digest) in [("sdkRoot", "sdkDigest"), ("packagesRoot", "packagesDigest")] {
        if digest_map(&tree(Path::new(field(&binding, root)?))?)? != field(&binding, digest)? {
            return Err(format!("{root}-closure-changed"));
        }
    }
    if let Some(analyzer) = binding["enrollment"]
        .get("fsharpAnalyzer")
        .filter(|v| v["id"] == "dotnet-fsharplint")
    {
        if digest_map(&tree(Path::new(field(analyzer, "root")?))?)? != field(analyzer, "digest")? {
            return Err("fsharp-analyzer-closure-changed".into());
        }
    }
    for (path, digest) in [
        ("enrollmentPath", "enrollmentDigest"),
        ("offlineConfig", "offlineConfigDigest"),
    ] {
        if sha256_text(&read(
            Path::new(field(&binding, path)?),
            if path == "enrollmentPath" {
                MAX_ENROLLMENT_BYTES
            } else {
                MAX_TEXT_BYTES
            },
        )?) != field(&binding, digest)?
        {
            return Err(format!("{path}-changed"));
        }
    }
    Ok(binding)
}

/// Retain actual standard result bytes even when dotnet test exits nonzero.
pub(super) fn results(command: &Planned) -> Result<Value, String> {
    if command.tool != "test" {
        return Ok(Value::Null);
    }
    let root = Path::new(env(command, "LEGION_DOTNET_TEST_RESULTS")?);
    let mut retained = Vec::new();
    for (relative, digest) in tree(root)? {
        if !relative.ends_with(".trx") {
            continue;
        }
        let content = text(&root.join(&relative))?;
        if sha256_text(content.as_bytes()) != digest {
            return Err("test-results-changed".into());
        }
        retained.push(json!({"path":relative,"digest":digest,"content":content}));
    }
    Ok(json!(retained))
}
fn test_counts(value: &Value) -> Result<(), String> {
    let counter = Regex::new(r#"<Counters\b([^>]*)/?>"#).map_err(|_| "trx-parser")?;
    let attr = Regex::new(r#"([A-Za-z]+)="([0-9]+)""#).map_err(|_| "trx-parser")?;
    let rows = value.as_array().ok_or("trx-results")?;
    if rows.is_empty() {
        return Err("test-no-standard-results".into());
    }
    for row in rows {
        let content = field(row, "content")?;
        let counters = counter.captures_iter(content).collect::<Vec<_>>();
        if counters.len() != 1 {
            return Err("test-counter-shape".into());
        }
        let attrs: BTreeMap<_, _> = attr
            .captures_iter(&counters[0][1])
            .map(|c| (c[1].to_owned(), c[2].parse::<u64>().unwrap_or(0)))
            .collect();
        let count = |key| attrs.get(key).copied().unwrap_or(0);
        if count("total") == 0
            || count("executed") == 0
            || count("passed") != count("executed")
            || count("failed") != 0
            || count("error") != 0
            || count("timeout") != 0
            || count("aborted") != 0
            || count("notExecuted") != 0
            || count("executed") != count("total")
        {
            return Err("test-not-nonempty-success".into());
        }
        let units =
            Regex::new(r#"<UnitTestResult\b[^>]*\boutcome="Passed""#).map_err(|_| "trx-parser")?;
        if units.find_iter(content).count() as u64 != count("executed") {
            return Err("test-results-counter-mismatch".into());
        }
    }
    Ok(())
}
pub(super) fn parse(
    command: &Planned,
    stdout: &[u8],
    stderr: &[u8],
    exit: Option<i32>,
) -> Result<Vec<Diag>, String> {
    let mut combined = String::from_utf8_lossy(stdout).into_owned();
    combined.push('\n');
    combined.push_str(&String::from_utf8_lossy(stderr));
    if command.tool == "test" {
        let results = results(command)?;
        test_counts(&results)?;
        if results.as_array().map(Vec::len)
            != Some(env(command, "LEGION_DOTNET_FRAMEWORKS")?.split(';').count())
        {
            return Err("test-framework-results-incomplete".into());
        }
        if exit != Some(0) {
            return Err("test-process-failed".into());
        }
        return Ok(Vec::new());
    }
    if command
        .env
        .iter()
        .any(|(key, _)| *key == "LEGION_DOTNET_FSHARP_FILES")
    {
        let files: Vec<String> = serde_json::from_str(env(command, "LEGION_DOTNET_FSHARP_FILES")?)
            .map_err(|_| "fsharp-file-binding")?;
        for path in &files {
            let marker = format!(
                "========== Linting {} ==========",
                Path::new(&command.cwd_rel).join(path).to_string_lossy()
            );
            if combined.matches(&marker).count() != 1 {
                return Err("fsharp-file-completion-incomplete".into());
            }
        }
        let advisory = "FSharpLint error: WARNING: Wildcard detected, but not recommended. Using a project (slnx/sln/fsproj) can detect more issues.";
        let errors: Vec<_> = combined
            .lines()
            .filter(|line| line.starts_with("FSharpLint error:"))
            .collect();
        let finished = Regex::new(r"========== Finished: \d+ warnings ==========")
            .map_err(|_| "fsharp-summary-parser")?;
        if !combined.contains("Running FSharpLint with ")
            || !combined.contains("========== Summary: ")
            || errors != [advisory]
            || finished.find_iter(&combined).count() != files.len()
        {
            return Err("fsharp-analysis-incomplete".into());
        }
        let located =
            Regex::new(r"(?m)^(.+?)\((\d+),\d+,\d+,\d+\):FSharpLint warning (FL\d+): (.+)$")
                .map_err(|_| "fsharp-diagnostic-parser")?;
        let mut diagnostics = Vec::new();
        for row in located.captures_iter(&combined) {
            let path = Path::new(&row[1])
                .strip_prefix(&command.cwd_rel)
                .map_err(|_| "fsharp-diagnostic-outside-stage")?
                .to_string_lossy()
                .replace('\\', "/");
            if !files.contains(&path) {
                return Err("fsharp-diagnostic-outside-input".into());
            }
            diagnostics.push(Diag {
                rule: format!("fsharplint:{}", &row[3]),
                severity: "warning",
                path,
                line: row[2].parse().map_err(|_| "diagnostic-line")?,
                message: row[4].chars().take(300).collect(),
            });
        }
        let summaries = Regex::new(r"========== Summary: (\d+) warnings ==========")
            .map_err(|_| "fsharp-summary-parser")?;
        let counts = summaries.captures_iter(&combined).collect::<Vec<_>>();
        if counts.len() != 1
            || counts[0][1].parse::<usize>().ok() != Some(diagnostics.len())
            || (exit != Some(0) && diagnostics.is_empty())
        {
            return Err("fsharp-summary-diagnostic-mismatch".into());
        }
        return Ok(diagnostics);
    }
    let located =
        Regex::new(r"(?m)^\s*(.+?)\((\d+)(?:,\d+)?\): (error|warning) ([A-Z]+\d+): (.+)$")
            .map_err(|_| "diagnostic-parser")?;
    let stage = Path::new(&command.cwd_rel);
    let mut diagnostics = Vec::new();
    for row in located.captures_iter(&combined) {
        let raw = Path::new(&row[1]);
        let relative = if raw.is_absolute() {
            raw.strip_prefix(stage)
                .map_err(|_| "diagnostic-outside-stage")?
        } else {
            raw
        };
        let path = relative.to_string_lossy().replace('\\', "/");
        if !safe_rel(&path) {
            return Err("diagnostic-path".into());
        }
        diagnostics.push(Diag {
            rule: format!("dotnet:{}", &row[4]),
            severity: if &row[3] == "error" {
                "error"
            } else {
                "warning"
            },
            path,
            line: row[2].parse().map_err(|_| "diagnostic-line")?,
            message: row[5].chars().take(300).collect(),
        });
    }
    if exit != Some(0) && diagnostics.is_empty() {
        return Err(format!("process-exit:{}", exit.unwrap_or(-1)));
    }
    if command.tool == "analyzer" && !combined.contains("Microsoft.CodeAnalysis.NetAnalyzers") {
        return Err("analyzer-execution-report-missing".into());
    }
    Ok(diagnostics)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn locked_cache_checks_archive_and_lock_content_hashes_independently() {
        let scratch = AuditScratch::create(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
        let packages = scratch.cache_dir().join("packages");
        let cache = packages.join("example.package/1.0.0");
        fs::create_dir_all(&cache).unwrap();
        let packages = fs::canonicalize(&packages).unwrap();
        let cache = packages.join("example.package/1.0.0");
        let archive_path = cache.join("example.package.1.0.0.nupkg");
        let sidecar_path = cache.join("example.package.1.0.0.nupkg.sha512");
        let metadata_path = cache.join(".nupkg.metadata");
        // Synthetic inputs test domain separation, never SDK qualification.
        let archive = b"archive including signature bytes";
        let archive_hash = base64(&Sha512::digest(archive));
        let content_hash = base64(&Sha512::digest(b"unsigned content"));
        assert_ne!(archive_hash, content_hash);
        let lock = json!({"version":1,"dependencies":{"net8.0":{"Example.Package":{
            "type":"Direct","resolved":"1.0.0","contentHash":content_hash
        }}}});
        let lock = serde_json::to_vec(&lock).unwrap();
        fs::write(&archive_path, archive).unwrap();
        fs::write(&sidecar_path, format!("{archive_hash}\n")).unwrap();
        let metadata =
            serde_json::to_vec(&json!({"version":2,"contentHash":content_hash})).unwrap();
        fs::write(&metadata_path, &metadata).unwrap();
        assert!(locked_cache(&lock, &packages).is_ok());

        fs::write(&sidecar_path, &content_hash).unwrap();
        assert!(locked_cache(&lock, &packages).is_err());
        fs::write(&sidecar_path, &archive_hash).unwrap();
        fs::write(&archive_path, b"changed archive").unwrap();
        assert!(locked_cache(&lock, &packages).is_err());
        fs::write(&archive_path, archive).unwrap();
        for metadata in [
            format!(r#"{{"contentHash":"{archive_hash}"}}"#),
            "{}".to_owned(),
            r#"{"contentHash":null}"#.to_owned(),
            "malformed metadata".to_owned(),
        ] {
            fs::write(&metadata_path, metadata).unwrap();
            assert!(locked_cache(&lock, &packages).is_err());
        }
        fs::remove_file(&metadata_path).unwrap();
        assert!(locked_cache(&lock, &packages).is_err());
        // Unsigned packages can share both hashes; equality is permitted.
        let unsigned_lock = json!({"version":1,"dependencies":{"net8.0":{"Example.Package":{
            "type":"Direct","resolved":"1.0.0","contentHash":archive_hash
        }}}});
        fs::write(
            &metadata_path,
            serde_json::to_vec(&json!({"contentHash":archive_hash})).unwrap(),
        )
        .unwrap();
        assert!(locked_cache(&serde_json::to_vec(&unsigned_lock).unwrap(), &packages).is_ok());
    }
    #[test]
    fn v1_keeps_each_language_and_refuses_external_msbuild_semantics() {
        for ext in ["csproj", "fsproj", "vbproj"] {
            let p = "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>";
            assert_eq!(project(p, ext).unwrap().0, ["net8.0"]);
            assert!(!project(p, ext).unwrap().1);
            assert!(project(
                &p.replace(
                    "</Project>",
                    "<Import Project=\"/tmp/evil.targets\" /></Project>"
                ),
                ext
            )
            .is_err());
            assert!(project(&p.replace("net8.0", "$(InjectedFramework)"), ext).is_err());
            assert!(project(&p.replace("net8.0", "net8.0-windows"), ext).is_err());
        }
    }
    #[test]
    fn trx_requires_nonempty_actual_executed_passes_and_matching_results() {
        let passed = json!([{"content":"<TestRun><Results><UnitTestResult outcome=\"Passed\" /></Results><Counters total=\"1\" executed=\"1\" passed=\"1\" failed=\"0\" /></TestRun>"}]);
        assert!(test_counts(&passed).is_ok());
        for content in ["", "<Counters total=\"0\" executed=\"0\" passed=\"0\" />", "<Counters total=\"1\" executed=\"0\" passed=\"0\" />", "<UnitTestResult outcome=\"Failed\" /><Counters total=\"1\" executed=\"1\" passed=\"0\" failed=\"1\" />", "<Counters total=\"1\" executed=\"1\" passed=\"1\" />"] {
            assert!(test_counts(&json!([{"content":content}])).is_err());
        }
        assert!(test_counts(&json!([])).is_err());
    }
}
