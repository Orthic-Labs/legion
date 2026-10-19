//! Frozen Gradle JVM/v1 SDK route. Default owner admission stays denied.
//! No bootstrap, dependency acquisition, installed-gradle bypass or synthetic receipt.
use super::tools::{self, Outcome, ToolContext, ToolEvidence};
use crate::inventory::InventoryEntry;
use crate::native_providers::security::producer::SandboxPolicy;
use legion_provider_sdk::ExternalToolRequest;
use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

pub(super) const TASKS: [&str; 5] = ["wrapper", "compile", "lint", "test", "dependency"];
const INPUTS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../scripts/ci/audit-jvm-sdk-inputs.json"
));
const DIST: &str = "wrapper/dists/gradle-9.2.1-bin/2t0n5ozlw9xmuyvbp7dnzaxug";
const MAX_PROJECT_BYTES: u64 = 16 * 1024 * 1024;

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
fn error(reason: &str) -> String {
    format!("jvm-v1:{reason}")
}
fn object(value: &Value) -> Result<&serde_json::Map<String, Value>, String> {
    value.as_object().ok_or_else(|| error("object-required"))
}
fn text(value: &Value) -> Result<&str, String> {
    value.as_str().ok_or_else(|| error("string-required"))
}
fn relative(raw: &str) -> bool {
    !raw.is_empty()
        && !raw.contains('\\')
        && Path::new(raw)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
}
fn safe_read(root: &Path, raw: &str, max: u64) -> Result<Vec<u8>, String> {
    if !relative(raw) {
        return Err(error("unsafe-input-path"));
    }
    let mut path = root.to_path_buf();
    for part in Path::new(raw).components() {
        path.push(part.as_os_str());
        if fs::symlink_metadata(&path)
            .map_err(|_| error("input-missing"))?
            .file_type()
            .is_symlink()
        {
            return Err(error("input-symlink"));
        }
    }
    let meta = fs::metadata(&path).map_err(|_| error("input-missing"))?;
    if !meta.is_file() || meta.len() > max {
        return Err(error("input-byte-limit"));
    }
    let bytes = fs::read(&path).map_err(|_| error("input-unreadable"))?;
    if bytes.len() as u64 > max {
        return Err(error("input-byte-limit"));
    }
    Ok(bytes)
}

/// Only actual digest-verified reads count as build context. Binary wrapper JARs
/// are context, never language source. Unsupported files stay outside credit.
pub(super) fn is_context(path: &str) -> bool {
    matches!(
        path.rsplit('/').next().unwrap_or(""),
        "build.gradle"
            | "settings.gradle"
            | "gradle.properties"
            | "gradlew"
            | "legion-jvm-sdk.json"
            | "gradle-wrapper.properties"
            | "gradle-wrapper.jar"
    )
}
pub(super) fn context_bytes(
    root: &Path,
    entry: &InventoryEntry,
    max: u64,
) -> Result<Vec<u8>, String> {
    let expected = entry
        .digest
        .as_deref()
        .ok_or_else(|| error("context-inventory-digest-missing"))?;
    let bytes = safe_read(root, &entry.path, max)?;
    if digest(&bytes) != expected {
        return Err(error("changed-since-inventory"));
    }
    Ok(bytes)
}

fn tree(root: &Path, max_bytes: u64, links: bool) -> Result<BTreeMap<String, String>, String> {
    fn visit(
        root: &Path,
        path: &Path,
        out: &mut BTreeMap<String, String>,
        remaining: &mut u64,
        links: bool,
    ) -> Result<(), String> {
        let meta = fs::symlink_metadata(path).map_err(|_| error("closure-unreadable"))?;
        if out.len() >= 50_000 {
            return Err(error("closure-file-limit"));
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| error("closure-escape"))?
            .to_string_lossy()
            .replace('\\', "/");
        if meta.file_type().is_symlink() {
            if !links
                || !fs::canonicalize(path)
                    .map_err(|_| error("closure-link-missing"))?
                    .starts_with(root)
            {
                return Err(error("closure-symlink"));
            }
            out.insert(
                relative,
                format!(
                    "symlink:{}",
                    fs::read_link(path)
                        .map_err(|_| error("closure-link"))?
                        .to_string_lossy()
                ),
            );
        } else if meta.is_dir() {
            for entry in fs::read_dir(path).map_err(|_| error("closure-directory"))? {
                visit(
                    root,
                    &entry.map_err(|_| error("closure-directory"))?.path(),
                    out,
                    remaining,
                    links,
                )?;
            }
        } else if meta.is_file() {
            if meta.len() > *remaining {
                return Err(error("closure-byte-limit"));
            }
            let bytes = fs::read(path).map_err(|_| error("closure-file"))?;
            *remaining = remaining
                .checked_sub(bytes.len() as u64)
                .ok_or_else(|| error("closure-byte-limit"))?;
            out.insert(relative, digest(&bytes));
        } else {
            return Err(error("closure-file-type"));
        }
        Ok(())
    }
    if !root.is_absolute()
        || root.is_symlink()
        || fs::canonicalize(root).map_err(|_| error("closure-root"))? != root
    {
        return Err(error("closure-root"));
    }
    let mut files = BTreeMap::new();
    let mut remaining = max_bytes;
    visit(root, root, &mut files, &mut remaining, links)?;
    if files.is_empty() {
        return Err(error("closure-empty"));
    }
    Ok(files)
}
fn copy_tree(source: &Path, target: &Path) -> Result<(), String> {
    fs::create_dir_all(target).map_err(|_| error("stage-directory"))?;
    for entry in fs::read_dir(source).map_err(|_| error("stage-source"))? {
        let entry = entry.map_err(|_| error("stage-source"))?;
        let path = entry.path();
        let dest = target.join(entry.file_name());
        let kind = entry.file_type().map_err(|_| error("stage-type"))?;
        if kind.is_symlink() {
            return Err(error("stage-symlink"));
        }
        if kind.is_dir() {
            copy_tree(&path, &dest)?;
        } else if kind.is_file() {
            fs::copy(path, dest).map_err(|_| error("stage-copy"))?;
        } else {
            return Err(error("stage-type"));
        }
    }
    Ok(())
}

struct Inputs {
    enrollment: Value,
    enrollment_path: PathBuf,
    enrollment_digest: String,
    project: Value,
    original: BTreeMap<String, String>,
    stage: PathBuf,
    home: PathBuf,
    build: PathBuf,
    java: PathBuf,
    roots: BTreeMap<String, PathBuf>,
    confinement: legion_effects::GradleBindOnlySandbox,
}
impl Inputs {
    fn load(
        ctx: &ToolContext<'_>,
        entries: &[InventoryEntry],
        selected: &BTreeSet<String>,
    ) -> Result<Self, String> {
        let raw = std::env::var_os("LEGION_JVM_SDK_ENROLLMENT_JSON")
            .ok_or_else(|| error("enrollment-missing"))?;
        let enrollment_path = fs::canonicalize(raw).map_err(|_| error("enrollment-path"))?;
        let enrollment_bytes =
            fs::read(&enrollment_path).map_err(|_| error("enrollment-unreadable"))?;
        if enrollment_bytes.len() > 10 * 1024 * 1024 {
            return Err(error("enrollment-size"));
        }
        let enrollment: Value =
            serde_json::from_slice(&enrollment_bytes).map_err(|_| error("enrollment-json"))?;
        let pins: Value = serde_json::from_str(INPUTS).map_err(|_| error("inputs-json"))?;
        if enrollment["schema"] != "legion-jvm-sdk-enrollment/1"
            || enrollment["lockDigest"] != digest(INPUTS.as_bytes())
            || enrollment["versions"] != pins["versions"]
            || enrollment["platform"] != "darwin-arm64"
            || !cfg!(all(target_os = "macos", target_arch = "aarch64"))
        {
            return Err(error("enrollment-identity"));
        }
        let mut roots = BTreeMap::new();
        for item in pins["assets"]
            .as_array()
            .ok_or_else(|| error("pins-assets"))?
        {
            let id = text(&item["id"])?;
            let enrolled = &enrollment["assets"][id];
            for key in ["id", "url", "sha256", "archive", "root"] {
                if enrolled[key] != item[key] {
                    return Err(error("enrollment-pin"));
                }
            }
            let path = PathBuf::from(text(&enrolled["path"])?);
            if !path.is_absolute()
                || path.is_symlink()
                || digest(&fs::read(&path).map_err(|_| error("archive-missing"))?)
                    != text(&item["sha256"])?
            {
                return Err(error("archive-digest"));
            }
            if !item["root"].is_null() {
                let root = PathBuf::from(text(&enrollment["toolchains"][id]["root"])?);
                if json!(tree(&root, 2 * 1024 * 1024 * 1024, true)?)
                    != enrollment["toolchains"][id]["files"]
                {
                    return Err(error("toolchain-drift"));
                }
                roots.insert(id.to_owned(), root);
            }
        }
        if roots.len() != 4 {
            return Err(error("toolchain-roots"));
        }
        let mut original = BTreeMap::new();
        let mut remaining = MAX_PROJECT_BYTES;
        for entry in entries {
            if !selected.contains(&entry.path) && !is_context(&entry.path) {
                return Err(error("unsupported-project-input"));
            }
            let bytes = context_bytes(ctx.root, entry, remaining)?;
            remaining = remaining
                .checked_sub(bytes.len() as u64)
                .ok_or_else(|| error("input-byte-limit"))?;
            if original
                .insert(entry.path.clone(), digest(&bytes))
                .is_some()
            {
                return Err(error("duplicate-input"));
            }
        }
        if tree(ctx.root, MAX_PROJECT_BYTES, false)? != original {
            return Err(error("project-closure-incomplete"));
        }
        let project: Value = serde_json::from_slice(&safe_read(
            ctx.root,
            "legion-jvm-sdk.json",
            MAX_PROJECT_BYTES,
        )?)
        .map_err(|_| error("project-contract-json"))?;
        if project["schema"] != "legion-jvm-sdk-project/1"
            || project["tasks"]
                != json!({"compile":"legionCompile","lint":"legionLint","dependency":"legionDependency","test":"legionTest"})
            || project["tests"]
                != json!(["java-answer", "kotlin-answer", "scala-answer", "kts-answer"])
        {
            return Err(error("project-contract-version"));
        }
        let sources = object(&project["sourceSets"])?;
        if sources.keys().map(String::as_str).collect::<BTreeSet<_>>()
            != ["java", "kotlin", "kts", "scala"].into_iter().collect()
        {
            return Err(error("source-variants"));
        }
        let mut declared = BTreeSet::new();
        for (language, paths) in sources {
            let paths = paths
                .as_array()
                .filter(|p| !p.is_empty())
                .ok_or_else(|| error("source-variant-empty"))?;
            for path in paths {
                let path = text(path)?;
                let extension = match language.as_str() {
                    "kotlin" => "kt",
                    other => other,
                };
                if !path.ends_with(&format!(".{extension}"))
                    || !selected.contains(path)
                    || !declared.insert(path.to_owned())
                {
                    return Err(error("source-set-closure"));
                }
            }
        }
        if declared != *selected {
            return Err(error("source-set-denominator"));
        }
        let wrapper = safe_read(
            ctx.root,
            "gradle/wrapper/gradle-wrapper.jar",
            MAX_PROJECT_BYTES,
        )?;
        let script = safe_read(ctx.root, "gradlew", MAX_PROJECT_BYTES)?;
        if digest(&wrapper) != enrollment["assets"]["wrapper"]["sha256"]
            || digest(&script) != enrollment["assets"]["script"]["sha256"]
        {
            return Err(error("wrapper-identity"));
        }
        let properties = String::from_utf8(safe_read(
            ctx.root,
            "gradle/wrapper/gradle-wrapper.properties",
            4096,
        )?)
        .map_err(|_| error("wrapper-properties"))?;
        let expected = concat!("distributionBase=GRADLE_USER_HOME\ndistributionPath=wrapper/dists\n", "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.2.1-bin.zip\n", "distributionSha256Sum=72f44c9f8ebcb1af43838f45ee5c4aa9c5444898b3468ab3f4af7b6076c5bc3f\n", "networkTimeout=1000\nvalidateDistributionUrl=true\nzipStoreBase=GRADLE_USER_HOME\nzipStorePath=wrapper/dists\n");
        if properties != expected {
            return Err(error("wrapper-properties"));
        }
        let stage = ctx.scratch.tmp_dir().join("jvm-source");
        let home = ctx.scratch.cache_dir().join("jvm-owned/home");
        let build = ctx.scratch.cache_dir().join("jvm-owned/build");
        if stage.exists() || home.exists() || build.exists() {
            return Err(error("scratch-reuse"));
        }
        fs::create_dir_all(&stage).map_err(|_| error("stage-root"))?;
        for path in original.keys() {
            let target = stage.join(path);
            fs::create_dir_all(target.parent().ok_or_else(|| error("stage-parent"))?)
                .map_err(|_| error("stage-parent"))?;
            fs::write(target, safe_read(ctx.root, path, MAX_PROJECT_BYTES)?)
                .map_err(|_| error("stage-write"))?;
        }
        if tree(&stage, MAX_PROJECT_BYTES, false)? != original {
            return Err(error("stage-drift"));
        }
        let mut confinement =
            legion_effects::GradleBindOnlySandbox::create(&ctx.scratch.cache_dir(), &stage)
                .map_err(|e| error(&e.as_str()))?;
        fs::create_dir_all(confinement.path().join("tmp")).map_err(|_| error("owned-temp"))?;
        let installed = home.join(DIST).join("gradle-9.2.1");
        copy_tree(&roots["gradle"], &installed)?;
        if tree(&installed, 2 * 1024 * 1024 * 1024, false)?
            != tree(&roots["gradle"], 2 * 1024 * 1024 * 1024, true)?
        {
            return Err(error("distribution-stage-drift"));
        }
        fs::write(home.join(DIST).join("gradle-9.2.1-bin.zip.ok"), [])
            .map_err(|_| error("wrapper-cache-marker"))?;
        fs::create_dir_all(&build).map_err(|_| error("build-root"))?;
        let java = roots["jdk"].join("bin/java");
        if !java.is_file() || java.is_symlink() {
            return Err(error("jdk-java-missing"));
        }
        let mut closure = BTreeMap::new();
        for (id, root) in &roots {
            for (path, value) in object(&enrollment["toolchains"][id]["files"])? {
                closure.insert(root.join(path), text(value)?.to_owned());
            }
        }
        for (path, value) in &original {
            closure.insert(stage.join(path), value.clone());
        }
        for (path, value) in tree(&installed, 2 * 1024 * 1024 * 1024, false)? {
            closure.insert(installed.join(path), value);
        }
        for asset in object(&enrollment["assets"])?.values() {
            closure.insert(
                PathBuf::from(text(&asset["path"])?),
                text(&asset["sha256"])?.to_owned(),
            );
        }
        confinement
            .seal(&java, closure)
            .map_err(|e| error(&e.as_str()))?;
        Ok(Self {
            enrollment,
            enrollment_path,
            enrollment_digest: digest(&enrollment_bytes),
            project,
            original,
            stage,
            home,
            build,
            java,
            roots,
            confinement,
        })
    }
    fn stable(&self, ctx: &ToolContext<'_>) -> Result<(), String> {
        if digest(&fs::read(&self.enrollment_path).map_err(|_| error("enrollment-missing"))?)
            != self.enrollment_digest
            || tree(ctx.root, MAX_PROJECT_BYTES, false)? != self.original
            || tree(&self.stage, MAX_PROJECT_BYTES, false)? != self.original
        {
            return Err(error("project-input-drift"));
        }
        for asset in object(&self.enrollment["assets"])?.values() {
            let path = Path::new(text(&asset["path"])?);
            if path.is_symlink()
                || digest(&fs::read(path).map_err(|_| error("archive-missing"))?)
                    != text(&asset["sha256"])?
            {
                return Err(error("archive-drift"));
            }
        }
        for (id, root) in &self.roots {
            if json!(tree(root, 2 * 1024 * 1024 * 1024, true)?)
                != self.enrollment["toolchains"][id]["files"]
            {
                return Err(error("toolchain-drift"));
            }
        }
        if json!(tree(
            &self.home.join(DIST).join("gradle-9.2.1"),
            2 * 1024 * 1024 * 1024,
            false
        )?) != self.enrollment["toolchains"]["gradle"]["files"]
        {
            return Err(error("distribution-stage-drift"));
        }
        Ok(())
    }
    fn args(&self, task: &str, _scratch: &Path) -> Vec<String> {
        self.confinement.args(task).unwrap_or_default()
    }
}

fn fail_all(evidence: &mut ToolEvidence, reason: &str) {
    for task in TASKS {
        evidence
            .outcomes
            .insert(task, Outcome::NotRun(reason.into()));
        evidence
            .gaps
            .push(format!("code.jvm:tool-not-run:{task}:{reason}"));
    }
}
fn raw(
    ctx: &ToolContext<'_>,
    record: Option<&legion_effects::ArtifactRecord>,
) -> Result<Vec<u8>, String> {
    let record = record.ok_or_else(|| error("output-absent"))?;
    tools::read_artifact(ctx.scratch, record).ok_or_else(|| error("output-digest"))
}
fn parse(
    task: &str,
    bytes: &[u8],
    inputs: &Inputs,
) -> Result<Vec<super::evidence::NativeFinding>, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| error("output-not-utf8"))?;
    if text.contains("Downloading ") || text.contains("Unzipping ") {
        return Err(error("wrapper-bootstrap-attempt"));
    }
    let mut findings = Vec::new();
    if task != "wrapper"
        && !text
            .lines()
            .any(|l| l == "LEGION_GRADLE_LAUNCH_MODE|wrapper-main")
    {
        return Err(error("gradle-inprocess-unproven"));
    }
    match task {
        "wrapper" => {
            if !text.contains("Gradle 9.2.1") {
                return Err(error("wrapper-version"));
            }
        }
        "compile" => {
            if !text
                .lines()
                .any(|l| l == "LEGION_COMPILE_DONE|java,kotlin,kts,scala")
            {
                return Err(error("compile-incomplete"));
            }
        }
        "lint" => {
            if !text
                .lines()
                .any(|l| l == "LEGION_LINT_DONE|java,kotlin,kts,scala")
            {
                return Err(error("lint-incomplete"));
            }
            let located = Regex::new(r"^(?:[we]: )?(?:file://)?(.+?\.(?:java|kt|kts|scala)):(\d+)(?::\d+)?: (warning|error): (.*)$").map_err(|_| error("diagnostic-regex"))?;
            let mut warned = BTreeSet::new();
            let mut exits = BTreeMap::new();
            for line in text.lines() {
                if let Some(rest) = line.strip_prefix("LEGION_NATIVE_EXIT|") {
                    let (language, code) =
                        rest.split_once('|').ok_or_else(|| error("native-exit"))?;
                    if exits.insert(language, code).is_some() {
                        return Err(error("duplicate-native-exit"));
                    }
                }
                if let Some(c) = located.captures(line) {
                    let path = Path::new(&c[1]);
                    let path = if path.is_absolute() {
                        path.strip_prefix(&inputs.stage)
                            .map_err(|_| error("diagnostic-outside-stage"))?
                            .to_path_buf()
                    } else {
                        path.to_path_buf()
                    };
                    let path = path.to_string_lossy().replace('\\', "/");
                    if !inputs.original.contains_key(&path) || c[3].eq("error") {
                        return Err(error("compiler-source-error"));
                    }
                    let language = match path.rsplit('.').next().unwrap_or("") {
                        "java" => "java",
                        "kt" => "kotlin",
                        "kts" => "kts",
                        "scala" => "scala",
                        _ => return Err(error("diagnostic-language")),
                    };
                    warned.insert(language.to_owned());
                    findings.push(super::evidence::NativeFinding {
                        rule: format!("jvm-compiler-warning:{language}").into(),
                        severity: "medium".into(),
                        path,
                        line: c[2].parse().map_err(|_| error("diagnostic-line"))?,
                        message: c[4].chars().take(300).collect(),
                    });
                }
            }
            for language in ["java", "kotlin", "kts", "scala"] {
                match exits.remove(language) {
                    Some("0") => {}
                    Some("1") if warned.contains(language) => {}
                    _ => return Err(error("lint-native-failure")),
                }
            }
            if !exits.is_empty() {
                return Err(error("lint-native-extra"));
            }
        }
        "dependency" => {
            if !text
                .lines()
                .any(|l| l == "LEGION_DEPENDENCY_DONE|runtimeClasspath")
                || !text
                    .lines()
                    .any(|l| l.starts_with("LEGION_COMPONENT|") && l.contains(":support"))
            {
                return Err(error("dependency-graph"));
            }
            let expected = BTreeSet::from([
                inputs.roots["kotlin"].join("lib/kotlin-stdlib.jar"),
                inputs.roots["scala"].join("lib/scala-library.jar"),
                inputs.build.join("support/libs/support.jar"),
            ]);
            let mut seen = BTreeSet::new();
            let mut source_sets = BTreeSet::new();
            for line in text.lines() {
                if let Some(rest) = line.strip_prefix("LEGION_ARTIFACT|runtimeClasspath|") {
                    let (path, sha) = rest
                        .rsplit_once('|')
                        .ok_or_else(|| error("dependency-artifact"))?;
                    let path = PathBuf::from(path);
                    if !expected.contains(&path)
                        || !seen.insert(path.clone())
                        || digest(
                            &fs::read(path).map_err(|_| error("dependency-artifact-missing"))?,
                        ) != sha
                    {
                        return Err(error("dependency-artifact-identity"));
                    }
                }
                if let Some(rest) = line.strip_prefix("LEGION_SOURCE|") {
                    if !source_sets.insert(rest.to_owned()) {
                        return Err(error("dependency-source-duplicate"));
                    }
                }
            }
            let declared = object(&inputs.project["sourceSets"])?
                .iter()
                .flat_map(|(language, paths)| {
                    paths
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(move |path| format!("{language}|{}", path.as_str().unwrap()))
                })
                .collect::<BTreeSet<_>>();
            if seen != expected || source_sets != declared {
                return Err(error("dependency-source-closure"));
            }
        }
        "test" => {
            let observed = text
                .lines()
                .filter_map(|l| l.strip_prefix("LEGION_ASSERT|"))
                .collect::<Vec<_>>();
            let expected = BTreeSet::from([
                "java-answer|pass",
                "kotlin-answer|pass",
                "scala-answer|pass",
                "kts-answer|pass",
            ]);
            if observed.len() != 4
                || observed.into_iter().collect::<BTreeSet<_>>() != expected
                || !text.lines().any(|l| l == "LEGION_TEST_DONE|3")
                || !text.lines().any(|l| l == "LEGION_KTS_DONE|1")
                || !text.lines().any(|l| l == "LEGION_PROJECT_TEST_DONE|4")
            {
                return Err(error("test-assertions-incomplete"));
            }
        }
        _ => return Err(error("unknown-task")),
    }
    Ok(findings)
}

pub(super) async fn run(
    ctx: &ToolContext<'_>,
    entries: &[InventoryEntry],
    selected: &BTreeSet<String>,
    cancellation: CancellationToken,
) -> ToolEvidence {
    let mut evidence = ToolEvidence::default();
    if ctx.sandbox != SandboxPolicy::Required {
        fail_all(&mut evidence, &error("authenticated-sandbox-required"));
        return evidence;
    }
    let mut inputs = match Inputs::load(ctx, entries, selected) {
        Ok(inputs) => inputs,
        Err(reason) => {
            fail_all(&mut evidence, &reason);
            return evidence;
        }
    };
    let started = Instant::now();
    for task in TASKS {
        let remaining = ctx
            .total_budget_ms
            .saturating_sub(started.elapsed().as_millis() as u64);
        if remaining == 0 {
            evidence.outcomes.insert(task, Outcome::Budget);
            continue;
        }
        if cancellation.is_cancelled() {
            evidence
                .outcomes
                .insert(task, Outcome::Failed("cancelled".into()));
            continue;
        }
        if let Err(reason) = inputs.stable(ctx) {
            fail_all(&mut evidence, &reason);
            break;
        }
        let (mut environment, mut allowed) =
            crate::native_providers::legacy_checks::audit_environment(ctx.scratch);
        for (name, value) in [
            (
                "PATH",
                format!(
                    "{}:/usr/bin:/bin",
                    inputs.roots["jdk"].join("bin").display()
                ),
            ),
            (
                "JAVA_HOME",
                inputs.roots["jdk"].to_string_lossy().into_owned(),
            ),
            (
                "GRADLE_USER_HOME",
                inputs.home.to_string_lossy().into_owned(),
            ),
            (
                "LEGION_KOTLIN_HOME",
                inputs.roots["kotlin"].to_string_lossy().into_owned(),
            ),
            (
                "LEGION_SCALA_HOME",
                inputs.roots["scala"].to_string_lossy().into_owned(),
            ),
            (
                "LEGION_JVM_BUILD",
                inputs.build.to_string_lossy().into_owned(),
            ),
            ("NO_COLOR", "1".into()),
            ("LC_ALL", "C".into()),
        ] {
            environment.insert(name.into(), value);
            allowed.insert(name.into());
        }
        let auth = match inputs
            .confinement
            .authenticate(task, &ctx.scratch.sandbox_dir())
        {
            Ok(auth) => auth,
            Err(_) => {
                evidence.outcomes.insert(task, Outcome::SandboxMissing);
                continue;
            }
        };
        let version_args = {
            let mut probe = auth
                .wrapped_args
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>();
            probe.push(inputs.java.to_string_lossy().into_owned());
            probe.extend(inputs.args("wrapper", ctx.scratch.root()));
            probe
        };
        let request = ExternalToolRequest {
            request_id: format!("audit:code.jvm:{task}:{}", ctx.inventory_digest),
            provider_id: "code.jvm".into(),
            plan_id: ctx.plan_digest.into(),
            policy_id: "audit".into(),
            task_id: Some(task.into()),
            expected_digest: fs::read(&auth.wrapped_executable)
                .ok()
                .map(|bytes| digest(&bytes)),
            executable: auth.wrapped_executable,
            args: auth.wrapped_args,
            cwd: inputs.stage.to_string_lossy().into_owned(),
            accepted_exit_codes: [0].into_iter().collect(),
            version_args,
            environment,
            environment_allowlist: allowed,
            requires_network_sandbox: true,
            sandbox: Some(legion_effects::SandboxReceipt {
                id: auth.id,
                network: auth.network,
                filesystem_scope: auth.filesystem_scope,
            }),
            timeout_ms: ctx.per_tool_timeout_ms.min(remaining).max(1),
            stdout_limit: ctx.output_limit,
            stderr_limit: ctx.output_limit,
            ..ExternalToolRequest::default()
        };
        let receipt = ctx.tool.execute(request, cancellation.clone()).await;
        let stdout = raw(ctx, receipt.stdout.as_ref());
        let stderr = raw(ctx, receipt.stderr.as_ref());
        let unconfirmed = inputs
            .confinement
            .retain_if_process_tree_unconfirmed(&receipt);
        let after = inputs.stable(ctx);
        let mut outcome = tools::classify(task, &receipt).unwrap_or(Outcome::Ran);
        let mut parsed = Vec::new();
        if outcome == Outcome::Ran {
            match (&stdout, &stderr) {
                (Ok(out), Ok(err)) => {
                    let mut combined = out.clone();
                    combined.push(b'\n');
                    combined.extend(err);
                    match parse(task, &combined, &inputs) {
                        Ok(found) => parsed = found,
                        Err(reason) => outcome = Outcome::Failed(reason),
                    }
                }
                _ => outcome = Outcome::Failed(error("raw-output-unavailable")),
            }
        }
        if let Err(reason) = &after {
            outcome = Outcome::Failed(reason.clone());
        }
        let version = receipt
            .executable
            .as_ref()
            .and_then(|identity| identity.version.output.clone())
            .unwrap_or_default();
        if outcome == Outcome::Ran && !version.contains("Gradle 9.2.1") {
            outcome = Outcome::Failed(error("version-probe"));
        }
        let retained = crate::execution_policy::receipt_json(&receipt);
        let summary = json!({"tool":task,"sdkReceipt":retained,"stdout":stdout.as_ref().ok().map(|b|json!({"digest":digest(b),"bytes":b.len(),"rawBytes":b})),"stderr":stderr.as_ref().ok().map(|b|json!({"digest":digest(b),"bytes":b.len(),"rawBytes":b})),"inputs":{"inventoryDigest":ctx.inventory_digest,"projectFiles":inputs.original,"sourceSets":inputs.project["sourceSets"],"tests":inputs.project["tests"],"enrollmentDigest":inputs.enrollment_digest,"toolchains":inputs.enrollment["toolchains"],"wrapperScriptDigest":inputs.enrollment["assets"]["script"]["sha256"],"wrapperJarDigest":inputs.enrollment["assets"]["wrapper"]["sha256"],"distributionArchiveDigest":inputs.enrollment["assets"]["gradle"]["sha256"],"unchanged":after.is_ok()},"operationContract":"jvm/v1","scope":"frozen Gradle project; compiler warning diagnostics only","outcome":format!("{outcome:?}")});
        evidence.receipts.push(summary.clone());
        if outcome == Outcome::Ran {
            evidence.tools.insert(task.into(),json!({"status":"pass","identity":{"name":"gradle-wrapper","version":version,"executableDigest":inputs.enrollment["assets"]["wrapper"]["sha256"]},"artifactDigest":stdout.as_ref().ok().map(|bytes|digest(bytes)),"scope":{"offline":true,"operationContract":"jvm/v1","runs":[summary]}}));
            evidence.findings.extend(parsed);
            if task == "dependency" {
                evidence
                    .validated_context
                    .insert("sourceSets".into(), inputs.project["sourceSets"].clone());
            }
        }
        evidence.outcomes.insert(task, outcome);
        if unconfirmed {
            evidence
                .gaps
                .push("code.jvm:platform_process_tree_unconfirmed".into());
            break;
        }
    }
    for task in TASKS {
        if evidence.outcomes.get(task) != Some(&Outcome::Ran) {
            evidence.gaps.push(format!(
                "code.jvm:{}",
                evidence
                    .outcomes
                    .get(task)
                    .map(|outcome| outcome.reason(task))
                    .unwrap_or_else(|| format!("tool-not-run:{task}"))
            ));
        }
    }
    evidence
}
