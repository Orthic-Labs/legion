//! Frozen JS source/tool closure & declared pnpm script execution over the SDK.
//! This module supplies evidence, never owner admission. Network denial remains
//! authenticated by the same SDK wrapper as type/lint; project writes are not denied.
use super::*;
use std::{fs, io::Read};

const MAX_NODES: usize = 60_000;
const MAX_DEPTH: usize = 64;
const MAX_BYTES: usize = 512 * 1024 * 1024;
const CONTEXT_SCHEMA: &str = "legion-javascript-source-context/1";

fn read(path: &Path, remaining: usize) -> Result<Vec<u8>, String> {
    let before = fs::symlink_metadata(path).map_err(|_| "input-unreadable")?;
    if !before.is_file() || before.len() > remaining as u64 {
        return Err("input-size-or-kind".into());
    }
    let mut file = fs::File::open(path).map_err(|_| "input-unreadable")?;
    let opened = file.metadata().map_err(|_| "input-unreadable")?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(remaining as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "input-unreadable")?;
    let after = fs::symlink_metadata(path).map_err(|_| "input-unreadable")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev()
            || before.ino() != opened.ino()
            || before.dev() != after.dev()
            || before.ino() != after.ino()
        {
            return Err("input-identity-changed".into());
        }
    }
    if bytes.len() > remaining
        || bytes.len() as u64 != before.len()
        || opened.len() != before.len()
        || after.len() != before.len()
        || before.modified().ok() != opened.modified().ok()
        || before.modified().ok() != after.modified().ok()
        || !after.is_file()
    {
        return Err("input-changed-or-oversize".into());
    }
    Ok(bytes)
}

fn safe_relative(value: &str) -> bool {
    !value.is_empty()
        && !value.contains('\\')
        && !Path::new(value).is_absolute()
        && Path::new(value)
            .components()
            .all(|p| matches!(p, Component::Normal(_)))
}

fn context_path(scratch: &AuditScratch, dir: &str) -> PathBuf {
    scratch.cache_dir().join(format!(
        "javascript-{}.json",
        sha256_text(dir.as_bytes()).trim_start_matches("sha256:")
    ))
}

/// Source maps are tied to frozen inventory digests, including manifest/script
/// bytes. Absent/other package managers are gaps rather than implicit fallbacks.
pub(super) fn plan(
    root: &Path,
    entries: &[InventoryEntry],
    selected: &BTreeSet<String>,
    scratch: &AuditScratch,
    plan: &mut Plan,
) {
    let dirs = cap_roots(
        dirs_named(entries, &["package.json"]).into_iter().collect(),
        "pnpm",
        &mut plan.notes,
    );
    for tool in ["build", "test"] {
        plan.not_planned.insert(tool, "no-declared-pnpm-script");
    }
    for dir in dirs {
        let package = root.join(&dir).join("package.json");
        let manifest = read(&package, MAX_MANIFEST_BYTES as usize)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok());
        let Some(manifest) = manifest else {
            plan.notes
                .push(format!("javascript-manifest-unreadable:{dir}"));
            continue;
        };
        let manager = manifest
            .get("packageManager")
            .and_then(Value::as_str)
            .unwrap_or("");
        let exact = Regex::new(r"^pnpm@(\d+\.\d+\.\d+)$").expect("constant regex");
        if !exact.is_match(manager) {
            plan.notes
                .push(format!("javascript-package-manager-unproven:{dir}"));
            continue;
        }
        for tool in ["build", "test"] {
            if manifest
                .get("scripts")
                .and_then(|v| v.get(tool))
                .and_then(Value::as_str)
                .is_none_or(|s| s.trim().is_empty())
            {
                plan.notes
                    .push(format!("javascript-script-missing:{tool}:{dir}"));
                continue;
            }
            plan.not_planned.remove(tool);
            plan.commands.push(Planned {
                tool,
                programs: &["pnpm"],
                local_bin: false,
                sibling_of: None,
                requires: Some("node"),
                cwd_rel: dir.clone(),
                args: vec!["run".into(), tool.into()],
                parser: Parser::Process,
                accepted: &[0],
                env: Vec::new(),
                diagnostics_on_stderr: false,
                source_path: None,
                source_digest: None,
            });
        }
    }
    // The same source context protects existing type/lint commands, including
    // configs that execute imports. No external source map is accepted.
    let files: BTreeMap<_, _> = entries
        .iter()
        .filter_map(|e| e.digest.as_ref().map(|d| (e.path.clone(), d.clone())))
        .collect();
    let missing = entries
        .iter()
        .any(|e| e.digest.is_none() || !safe_relative(&e.path));
    for command in &mut plan.commands {
        if command.parser == Parser::Tsc {
            command.args.push("--listFiles".into());
        }
        let home = scratch.cache_dir().join("javascript-home");
        if fs::create_dir_all(&home).is_err() {
            plan.not_planned
                .insert(command.tool, "javascript-home-unavailable");
        }
        for (name, path) in [
            ("HOME", home.clone()),
            ("USERPROFILE", home.clone()),
            ("XDG_CONFIG_HOME", home.join(".config")),
            ("APPDATA", home.join("AppData/Roaming")),
        ] {
            command
                .env
                .push((name, path.to_string_lossy().into_owned()));
        }
        command.env.push((
            "LEGION_AUDIT_JS_OUTPUT",
            scratch
                .cache_dir()
                .join("javascript-build")
                .to_string_lossy()
                .into_owned(),
        ));
        command.env.push(("CI", "true".into()));
        command.env.push(("COREPACK_ENABLE_NETWORK", "0".into()));
        let value = json!({"schema":CONTEXT_SCHEMA,"cwd":command.cwd_rel,"files":files,"selected":selected});
        let bytes = serde_json::to_vec(&value).expect("serializable context");
        if missing || fs::write(context_path(scratch, &command.cwd_rel), &bytes).is_err() {
            plan.not_planned
                .insert(command.tool, "javascript-context-unavailable");
        } else {
            command.source_digest = Some(sha256_text(&bytes));
        }
    }
}

fn package_root(executable: &Path) -> Result<PathBuf, String> {
    let mut current = fs::canonicalize(executable).map_err(|_| "tool-unreadable")?;
    current.pop();
    for _ in 0..8 {
        if current.join("package.json").is_file() {
            return Ok(current);
        }
        if !current.pop() {
            break;
        }
    }
    Err("tool-package-root-missing".into())
}

fn tree(root: &Path) -> Result<Value, String> {
    let root = fs::canonicalize(root).map_err(|_| "closure-root-missing")?;
    let mut pending = vec![(root.clone(), 0usize)];
    let mut files = BTreeMap::new();
    let mut links = BTreeMap::new();
    let mut directories = BTreeSet::new();
    let mut nodes = 0usize;
    let mut total = 0usize;
    while let Some((path, depth)) = pending.pop() {
        nodes += 1;
        if nodes > MAX_NODES || depth > MAX_DEPTH {
            return Err("closure-node-limit".into());
        }
        let rel = path
            .strip_prefix(&root)
            .map_err(|_| "closure-escape")?
            .to_string_lossy()
            .replace('\\', "/");
        let meta = fs::symlink_metadata(&path).map_err(|_| "closure-unreadable")?;
        if meta.is_symlink() {
            let raw = fs::read_link(&path).map_err(|_| "closure-link-unreadable")?;
            let mut relative_target = path
                .parent()
                .ok_or("closure-link-unreadable")?
                .strip_prefix(&root)
                .map_err(|_| "closure-link-escape")?
                .to_path_buf();
            for part in raw.components() {
                match part {
                    Component::Normal(value) => relative_target.push(value),
                    Component::CurDir => {}
                    Component::ParentDir if relative_target.pop() => {}
                    _ => return Err("closure-link-escape".into()),
                }
            }
            let target = fs::canonicalize(&path).map_err(|_| "closure-link-unreadable")?;
            if !target.starts_with(&root) {
                return Err("closure-link-escape".into());
            }
            links.insert(
                rel,
                fs::read_link(&path)
                    .map_err(|_| "closure-link-unreadable")?
                    .to_string_lossy()
                    .into_owned(),
            );
        } else if meta.is_dir() {
            directories.insert(rel);
            let mut children = Vec::new();
            for entry in fs::read_dir(&path).map_err(|_| "closure-unreadable")? {
                if nodes + pending.len() + children.len() >= MAX_NODES {
                    return Err("closure-node-limit".into());
                }
                children.push(entry.map_err(|_| "closure-unreadable")?.path());
            }
            children.sort();
            pending.extend(children.into_iter().rev().map(|p| (p, depth + 1)));
        } else if meta.is_file() {
            let bytes = read(&path, MAX_BYTES.saturating_sub(total))?;
            total += bytes.len();
            files.insert(
                rel,
                json!({"digest":sha256_text(&bytes),"bytes":bytes.len()}),
            );
        } else {
            return Err("closure-kind-unsupported".into());
        }
    }
    Ok(
        json!({"root":root,"files":files,"links":links,"directories":directories,"nodes":nodes,"bytes":total}),
    )
}

pub(super) fn snapshot(
    ctx: &ToolContext<'_>,
    command: &Planned,
    executable: &Path,
) -> Result<Value, String> {
    let bytes = read(
        &context_path(ctx.scratch, &command.cwd_rel),
        16 * 1024 * 1024,
    )?;
    if command.source_digest.as_deref() != Some(sha256_text(&bytes).as_str()) {
        return Err("context-digest-mismatch".into());
    }
    let context: Value = serde_json::from_slice(&bytes).map_err(|_| "context-malformed")?;
    if context["schema"] != CONTEXT_SCHEMA || context["cwd"] != command.cwd_rel {
        return Err("context-mismatch".into());
    }
    let files = context["files"]
        .as_object()
        .ok_or("context-files-missing")?;
    if files.len() > MAX_NODES {
        return Err("context-file-limit".into());
    }
    let mut total = 0;
    for (relative, expected) in files {
        if !safe_relative(relative) {
            return Err("context-path-invalid".into());
        }
        let path = ctx.root.join(relative);
        let canonical = fs::canonicalize(&path).map_err(|_| "source-unreadable")?;
        if canonical != path || !canonical.starts_with(ctx.root) {
            return Err("source-symlink-unproven".into());
        }
        let data = read(&path, MAX_BYTES.saturating_sub(total))?;
        total += data.len();
        if expected.as_str() != Some(sha256_text(&data).as_str()) {
            return Err("frozen-source-changed".into());
        }
    }
    let dirs = ctx.search_path.map(|s| s.to_vec()).unwrap_or_else(|| {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()).collect()
    });
    let node = dirs
        .iter()
        .find_map(|dir| in_dir(dir, "node"))
        .ok_or("node-missing")?;
    let node = fs::canonicalize(node).map_err(|_| "node-missing")?;
    let node_bytes = read(&node, MAX_BYTES)?;
    let package = package_root(executable)?;
    let node_modules = ctx.root.join("node_modules");
    if !node_modules.is_dir() {
        return Err("local-tool-closure-missing".into());
    }
    let mut pnpm_version = None;
    let pnpm = if command.programs.contains(&"pnpm") {
        let manifest: Value = serde_json::from_slice(&read(
            &package.join("package.json"),
            MAX_MANIFEST_BYTES as usize,
        )?)
        .map_err(|_| "pnpm-manifest-malformed")?;
        let declared: Value = serde_json::from_slice(&read(
            &ctx.root.join(&command.cwd_rel).join("package.json"),
            MAX_MANIFEST_BYTES as usize,
        )?)
        .map_err(|_| "manifest-malformed")?;
        let expected = format!(
            "pnpm@{}",
            manifest["version"].as_str().ok_or("pnpm-version-missing")?
        );
        if manifest["name"] != "pnpm" || declared["packageManager"] != expected {
            return Err("pnpm-declared-version-mismatch".into());
        }
        if ["dependencies", "optionalDependencies"].iter().any(|key| {
            manifest
                .get(*key)
                .is_some_and(|v| !v.is_object() || v.as_object().is_some_and(|m| !m.is_empty()))
        }) {
            return Err("pnpm-external-dependency-closure-unproven".into());
        }
        pnpm_version = manifest["version"].as_str().map(str::to_owned);
        Some(tree(&package)?)
    } else {
        None
    };
    Ok(
        json!({"schema":"legion-javascript-input-snapshot/1","sourceContextDigest":command.source_digest,
        "sourceFiles":files,"node":{"path":node,"digest":sha256_text(&node_bytes),"bytes":node_bytes.len()},
        "localPackages":tree(&node_modules)?,"projectManagerPackage":pnpm,"packageManagerVersion":pnpm_version,
        "compiledInputs":if command.tool == "test" && output_root(ctx).exists() { tree(&output_root(ctx))? } else { Value::Null }}),
    )
}

/// Strict JSON shape/count/exit reconciliation. Missing messages & malformed
/// rows cannot silently turn native failures into clean evidence.
pub(super) fn eslint(
    bytes: &[u8],
    exit: Option<i32>,
) -> Result<(Vec<Diag>, BTreeSet<String>), String> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| "unparseable-output")?;
    let rows = value.as_array().ok_or("unparseable-output")?;
    if rows.is_empty() {
        return Err("eslint-empty-scope".into());
    }
    let mut paths = BTreeSet::new();
    let mut out = Vec::new();
    let mut errors = 0u64;
    for row in rows {
        let file = row["filePath"]
            .as_str()
            .filter(|p| !p.is_empty())
            .ok_or("eslint-file-missing")?;
        if !paths.insert(file.to_owned()) {
            return Err("eslint-duplicate-file".into());
        }
        let messages = row["messages"]
            .as_array()
            .ok_or("eslint-messages-missing")?;
        let mut counts = [0u64; 3];
        for message in messages {
            let severity = message["severity"]
                .as_u64()
                .filter(|s| *s == 1 || *s == 2)
                .ok_or("eslint-severity-invalid")?;
            counts[severity as usize] += 1;
            let text = message["message"]
                .as_str()
                .filter(|s| !s.is_empty())
                .ok_or("eslint-message-invalid")?;
            let line = message["line"]
                .as_u64()
                .filter(|l| *l > 0)
                .ok_or("eslint-location-invalid")?;
            let rule = match &message["ruleId"] {
                Value::String(s) if !s.is_empty() => s.as_str(),
                Value::Null if message["fatal"] == true => "parse-error",
                _ => return Err("eslint-rule-invalid".into()),
            };
            out.push(Diag {
                rule: format!("eslint:{rule}"),
                severity: if severity == 2 { "error" } else { "warning" },
                path: file.into(),
                line: usize::try_from(line).map_err(|_| "eslint-location-invalid")?,
                message: shorten(text),
            });
        }
        if row["errorCount"].as_u64() != Some(counts[2])
            || row["warningCount"].as_u64() != Some(counts[1])
        {
            return Err("eslint-count-mismatch".into());
        }
        errors += counts[2];
    }
    if !matches!((exit, errors), (Some(0), 0) | (Some(1), 1..)) {
        return Err("eslint-exit-count-mismatch".into());
    }
    Ok((out, paths))
}

/// `tsc --pretty false --listFiles` is a closed union of located diagnostics,
/// their indented details, blank separators & real compiler input file names.
/// Arbitrary text (including malformed absolute-path diagnostics) is a gap.
pub(super) fn typescript(
    ctx: &ToolContext<'_>,
    command: &Planned,
    bytes: &[u8],
    exit: Option<i32>,
) -> Result<(Vec<Diag>, BTreeSet<String>), String> {
    typescript_output(ctx.root, &command.cwd_rel, bytes, exit)
}

fn typescript_output(
    root: &Path,
    cwd: &str,
    bytes: &[u8],
    exit: Option<i32>,
) -> Result<(Vec<Diag>, BTreeSet<String>), String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "tsc-output-not-utf8")?;
    let located = Regex::new(r"^(.+?)\((\d+),(\d+)\): (error|warning) (TS\d+): (.+)$")
        .expect("constant diagnostic regex");
    let canonical_root = fs::canonicalize(root).map_err(|_| "source-root-unreadable")?;
    let mut diagnostics = Vec::new();
    let mut covered = BTreeSet::new();
    let mut listed = BTreeSet::new();
    let mut detail = false;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Some(c) = located.captures(line) {
            let row = c[2]
                .parse::<usize>()
                .ok()
                .filter(|v| *v > 0)
                .ok_or("tsc-location-invalid")?;
            c[3].parse::<usize>()
                .ok()
                .filter(|v| *v > 0)
                .ok_or("tsc-location-invalid")?;
            let path = repo_relative(root, &canonical_root, cwd, &c[1])
                .ok_or("tsc-diagnostic-source-unbound")?;
            diagnostics.push(Diag {
                rule: format!("tsc:{}", &c[5]),
                severity: if &c[4] == "error" { "error" } else { "warning" },
                path,
                line: row,
                message: shorten(&c[6]),
            });
            detail = true;
            continue;
        }
        // Diagnostic chains are only admissible after an actual located
        // diagnostic; even then they can never supply clean evidence.
        if detail && line.starts_with("  ") {
            continue;
        }
        detail = false;
        let path = Path::new(line);
        if !path.is_absolute() || line.chars().any(|c| c.is_control()) {
            return Err("tsc-unrecognized-output".into());
        }
        let canonical = fs::canonicalize(path).map_err(|_| "tsc-unrecognized-output")?;
        if !canonical.starts_with(&canonical_root)
            || !canonical.is_file()
            || !matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("js" | "jsx" | "ts" | "tsx" | "cjs" | "mjs" | "cts" | "mts" | "json")
            )
            || !listed.insert(line.to_owned())
        {
            return Err("tsc-file-list-invalid".into());
        }
        let relative =
            repo_relative(root, &canonical_root, cwd, line).ok_or("tsc-file-list-unbound")?;
        covered.insert(relative);
    }
    if listed.is_empty()
        || !matches!(exit, Some(0..=2))
        || (exit == Some(0)) != diagnostics.is_empty()
    {
        return Err("tsc-exit-diagnostic-scope-mismatch".into());
    }
    Ok((diagnostics, covered))
}

pub(super) fn covered(
    ctx: &ToolContext<'_>,
    command: &Planned,
    bytes: &[u8],
    exit: Option<i32>,
) -> Result<BTreeSet<String>, String> {
    if command.parser == Parser::Tsc {
        return typescript(ctx, command, bytes, exit).map(|v| v.1);
    }
    let raw = eslint(bytes, exit)?.1;
    let canonical = fs::canonicalize(ctx.root).map_err(|_| "source-root-unreadable")?;
    Ok(raw
        .iter()
        .filter_map(|p| repo_relative(ctx.root, &canonical, &command.cwd_rel, p))
        .collect())
}

// These deliberately closed script/source grammars admit a bounded native
// compiler + planned Node-test route. Other scripts run, but cannot earn task
// evidence merely by returning zero. No stdout substring is assertion proof.
const BUILD_PREFIX: &str = "tsc --project ";
const BUILD_SUFFIX: &str = " --outDir \"$LEGION_AUDIT_JS_OUTPUT\" --listEmittedFiles --pretty false --noCheck --sourceMap --inlineSources";
const TEST_PREFIX: &str = "node --test --test-reporter=tap ";
const TEST_PREAMBLE: &str = "import test from 'node:test';\nimport path from 'node:path';\nimport {pathToFileURL} from 'node:url';\nconst output = process.env.LEGION_AUDIT_JS_OUTPUT;\nif (!output || !path.isAbsolute(output)) throw new Error('explicit scratch output required');\n";

fn frozen_context(ctx: &ToolContext<'_>, command: &Planned) -> Result<Value, String> {
    let bytes = read(&context_path(ctx.scratch, &command.cwd_rel), MAX_BYTES)?;
    if command.source_digest.as_deref() != Some(sha256_text(&bytes).as_str()) {
        return Err("operation-context-unbound".into());
    }
    serde_json::from_slice(&bytes).map_err(|_| "operation-context-malformed".into())
}

fn frozen_text(ctx: &ToolContext<'_>, context: &Value, relative: &str) -> Result<String, String> {
    if !safe_relative(relative) {
        return Err("operation-source-path-invalid".into());
    }
    let path = ctx.root.join(relative);
    if fs::canonicalize(&path).map_err(|_| "operation-source-missing")? != path {
        return Err("operation-source-link".into());
    }
    let bytes = read(&path, MAX_BYTES)?;
    if context["files"][relative].as_str() != Some(sha256_text(&bytes).as_str()) {
        return Err("operation-source-unbound".into());
    }
    String::from_utf8(bytes).map_err(|_| "operation-source-not-utf8".into())
}

fn in_cwd(command: &Planned, relative: &str) -> String {
    Path::new(&command.cwd_rel)
        .join(relative)
        .to_string_lossy()
        .replace('\\', "/")
}

fn output_root(ctx: &ToolContext<'_>) -> PathBuf {
    ctx.scratch.cache_dir().join("javascript-build")
}

// Pinned pnpm 11.24.0 single-script/inherit mode writes `$ <script>`
// to stderr; stdout stays the actual native compiler/test protocol. Frozen
// script bytes + exact native lifecycle spelling are both required.
fn lifecycle<'a>(script: &str, text: &'a str, stderr: &[u8]) -> Result<Vec<&'a str>, String> {
    let stderr = std::str::from_utf8(stderr).map_err(|_| "operation-stderr-not-utf8")?;
    if stderr != format!("$ {script}\n") {
        return Err("operation-lifecycle-output-unbound".into());
    }
    let lines: Vec<_> = text.lines().filter(|s| !s.is_empty()).collect();
    if lines.is_empty() {
        return Err("operation-output-empty".into());
    }
    Ok(lines)
}

fn emitted(
    ctx: &ToolContext<'_>,
    command: &Planned,
    context: &Value,
) -> Result<(Value, BTreeMap<String, String>), String> {
    let root = output_root(ctx);
    let snapshot = tree(&root)?;
    if !snapshot["links"]
        .as_object()
        .ok_or("build-links-missing")?
        .is_empty()
    {
        return Err("build-output-symlink".into());
    }
    let files = snapshot["files"].as_object().ok_or("build-files-missing")?;
    if files.is_empty() {
        return Err("build-output-empty".into());
    }
    let mut artifacts = BTreeMap::new();
    let mut mapped = BTreeMap::new();
    let mut total = 0usize;
    for relative in files.keys() {
        let bytes = read(
            &root.join(relative),
            (32 * 1024 * 1024usize).saturating_sub(total),
        )?;
        total += bytes.len();
        artifacts.insert(
            relative.clone(),
            json!({"digest":sha256_text(&bytes),"bytes":bytes.len(),"rawBytes":bytes}),
        );
    }
    for (relative, descriptor) in &artifacts {
        if !relative.ends_with(".map") {
            continue;
        }
        let raw: Vec<u8> = serde_json::from_value(descriptor["rawBytes"].clone())
            .map_err(|_| "build-map-bytes-invalid")?;
        let map: Value = serde_json::from_slice(&raw).map_err(|_| "build-map-malformed")?;
        let code = relative
            .strip_suffix(".map")
            .ok_or("build-map-name-invalid")?;
        let code_bytes: Vec<u8> = serde_json::from_value(
            artifacts.get(code).ok_or("build-code-missing")?["rawBytes"].clone(),
        )
        .map_err(|_| "build-code-bytes-invalid")?;
        let sources = map["sources"]
            .as_array()
            .ok_or("build-map-sources-missing")?;
        let contents = map["sourcesContent"]
            .as_array()
            .ok_or("build-map-content-missing")?;
        if map["version"] != 3
            || map["sourceRoot"] != ""
            || map["file"].as_str() != Path::new(code).file_name().and_then(|p| p.to_str())
            || sources.len() != 1
            || contents.len() != 1
            || map["mappings"].as_str().is_none_or(str::is_empty)
        {
            return Err("build-map-shape-invalid".into());
        }
        let source_name = sources[0].as_str().ok_or("build-map-source-invalid")?;
        let source = fs::canonicalize(
            root.join(relative)
                .parent()
                .ok_or("build-map-parent")?
                .join(source_name),
        )
        .map_err(|_| "build-map-source-missing")?;
        let source_rel = source
            .strip_prefix(ctx.root)
            .map_err(|_| "build-map-source-outside")?
            .to_str()
            .ok_or("build-map-source-invalid")?
            .replace('\\', "/");
        let original = frozen_text(ctx, context, &source_rel)?;
        if contents[0].as_str() != Some(original.as_str())
            || code_bytes.is_empty()
            || !std::str::from_utf8(&code_bytes)
                .map_err(|_| "build-code-not-utf8")?
                .trim_end()
                .ends_with(&format!(
                    "//# sourceMappingURL={}",
                    Path::new(relative)
                        .file_name()
                        .ok_or("build-map-name-invalid")?
                        .to_string_lossy()
                ))
            || mapped.insert(source_rel, code.to_owned()).is_some()
        {
            return Err("build-map-source-mismatch".into());
        }
    }
    if artifacts.len() != mapped.len() * 2 {
        return Err("build-output-unmapped".into());
    }
    let selected = context["selected"]
        .as_array()
        .ok_or("operation-selected-missing")?;
    for relative in selected.iter().filter_map(Value::as_str) {
        if [".d.ts", ".d.cts", ".d.mts"]
            .iter()
            .any(|suffix| relative.ends_with(*suffix))
        {
            continue;
        } // declarations genuinely emit no JavaScript
        if !mapped.contains_key(relative) {
            return Err("build-emitted-scope-incomplete".into());
        }
    }
    // Ensure every emitted input belongs to this frozen package, not a sibling.
    if mapped
        .keys()
        .any(|p| !Path::new(p).starts_with(&command.cwd_rel))
    {
        return Err("build-cwd-scope-mismatch".into());
    }
    Ok((json!(artifacts), mapped))
}

// Imported project code can otherwise replace test/assert APIs or print a
// forged protocol before tests register. Initial planned-Node route therefore
// admits only closed, side-effect-free module forms corresponding to its
// actual `answer()` assertion target. Unsupported module syntax is a gap.
fn assertion_module(source: &str) -> Result<(), String> {
    let source = source.strip_prefix("debugger;\n").unwrap_or(source);
    let source = if source.starts_with("const bad: number = 'wrong';\n") {
        &source["const bad: number = 'wrong';\n".len()..]
    } else if source.starts_with("/** @type {number} */ const bad = 'wrong';\n") {
        &source["/** @type {number} */ const bad = 'wrong';\n".len()..]
    } else {
        source
    };
    let pure = Regex::new(r"\A(?:export function answer\(\) \{ return -?[0-9]+; \}\n|function answer\(\) \{ return -?[0-9]+; \}\nmodule.exports = \{answer\};\n|function h\(_type, _props\) \{ return -?[0-9]+; \}\nconst view = <span />;\nexport function answer\(\) \{ return view; \}\n)\z").expect("constant pure-module grammar");
    if !pure.is_match(source) {
        return Err("test-imported-module-semantics-unsupported".into());
    }
    Ok(())
}

fn planned_assertions(source: &str) -> Result<Vec<(String, String)>, String> {
    let mut rest = source
        .strip_prefix(TEST_PREAMBLE)
        .ok_or("test-source-grammar-unsupported")?;
    // Anchored, whole-source grammar: one synchronous planned assertion per
    // imported emitted module; no hooks, skip/todo, arbitrary code or overrides.
    let block = Regex::new(r"\A\{\n  const loaded = await import\(pathToFileURL\(path.join\(output, '([A-Za-z0-9_./-]+)'\)\).href\);\n  test\('([A-Za-z0-9_./-]+)', \{plan:1\}, \(t\) => \{\n    t.assert.strictEqual\(\(loaded.answer \|\| loaded.default.answer\)\(\),(-?[0-9]+)\);\n  \}\);\n\}\n").expect("constant planned-test grammar");
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    while !rest.is_empty() {
        let capture = block
            .captures(rest)
            .ok_or("test-source-grammar-unsupported")?;
        if !safe_relative(&capture[1])
            || !safe_relative(&capture[2])
            || !seen.insert(capture[2].to_owned())
        {
            return Err("test-assertion-scope-invalid".into());
        }
        out.push((capture[2].to_owned(), capture[1].to_owned()));
        rest = &rest[capture.get(0).expect("whole match").end()..];
    }
    if out.is_empty() || out.len() > MAX_NODES {
        return Err("test-no-planned-assertions".into());
    }
    Ok(out)
}

fn duration(line: &str, prefix: &str) -> bool {
    line.strip_prefix(prefix)
        .and_then(|v| v.parse::<f64>().ok())
        .is_some_and(|v| v.is_finite() && v >= 0.0)
}

fn tap(lines: &[&str], planned: &[(String, String)]) -> Result<(), String> {
    let mut expected = vec!["TAP version 13".to_owned()];
    // Native Node's reporter emits one top-level result & a duration/type YAML
    // block per test; context.plan(1) itself rejects missing assertion calls.
    for (index, (name, _)) in planned.iter().enumerate() {
        expected.extend([
            format!("# Subtest: {name}"),
            format!("ok {} - {name}", index + 1),
            "  ---".into(),
            "<duration>".into(),
            "  type: 'test'".into(),
            "  ...".into(),
        ]);
    }
    let n = planned.len();
    expected.extend([
        format!("1..{n}"),
        format!("# tests {n}"),
        "# suites 0".into(),
        format!("# pass {n}"),
        "# fail 0".into(),
        "# cancelled 0".into(),
        "# skipped 0".into(),
        "# todo 0".into(),
        "<total-duration>".into(),
    ]);
    if lines.len() != expected.len() {
        return Err("test-tap-shape-mismatch".into());
    }
    for (actual, expected) in lines.iter().zip(expected) {
        if if expected == "<duration>" {
            !duration(actual, "  duration_ms: ")
        } else if expected == "<total-duration>" {
            !duration(actual, "# duration_ms ")
        } else {
            *actual != expected
        } {
            return Err("test-tap-plan-mismatch".into());
        }
    }
    Ok(())
}

/// Observe original artifacts & real native protocol, only after a successful
/// SDK execution. This auxiliary proof does not create or modify SDK receipts.
pub(super) fn operation(
    ctx: &ToolContext<'_>,
    command: &Planned,
    bytes: &[u8],
    stderr: &[u8],
    exit: Option<i32>,
) -> Result<(Value, BTreeSet<String>), String> {
    if exit != Some(0) {
        return Err("operation-exit-not-zero".into());
    }
    let context = frozen_context(ctx, command)?;
    let manifest: Value = serde_json::from_str(&frozen_text(
        ctx,
        &context,
        &in_cwd(command, "package.json"),
    )?)
    .map_err(|_| "operation-manifest-malformed")?;
    let script = manifest["scripts"][command.tool]
        .as_str()
        .ok_or("operation-script-missing")?;
    let text = std::str::from_utf8(bytes).map_err(|_| "operation-output-not-utf8")?;
    if manifest["packageManager"] != "pnpm@11.24.0" {
        return Err("operation-manager-protocol-unsupported".into());
    }
    let lines = lifecycle(script, text, stderr)?;
    let (artifacts, mapped) = emitted(ctx, command, &context)?;
    let covered: BTreeSet<_> = mapped.keys().cloned().collect();
    if command.tool == "build" {
        let config = script
            .strip_prefix(BUILD_PREFIX)
            .and_then(|s| s.strip_suffix(BUILD_SUFFIX))
            .filter(|p| {
                safe_relative(p) && p.ends_with(".json") && !p.contains(char::is_whitespace)
            })
            .ok_or("build-script-grammar-unsupported")?;
        frozen_text(ctx, &context, &in_cwd(command, config))?;
        let expected: BTreeSet<_> = artifacts
            .as_object()
            .ok_or("build-artifacts-invalid")?
            .keys()
            .map(|p| format!("TSFILE: {}", output_root(ctx).join(p).display()))
            .collect();
        if lines.len() != expected.len()
            || lines
                .iter()
                .map(|s| (*s).to_owned())
                .collect::<BTreeSet<_>>()
                != expected
        {
            return Err("build-emitted-list-mismatch".into());
        }
        Ok((
            json!({"schema":"legion-javascript-operation-observation/1","kind":"typescript-emission","script":script,"artifacts":artifacts,"sourceToOutput":mapped}),
            covered,
        ))
    } else {
        let path = script
            .strip_prefix(TEST_PREFIX)
            .filter(|p| safe_relative(p) && p.ends_with(".mjs") && !p.contains(char::is_whitespace))
            .ok_or("test-script-grammar-unsupported")?;
        let source = frozen_text(ctx, &context, &in_cwd(command, path))?;
        let planned = planned_assertions(&source)?;
        let mut asserted = BTreeSet::new();
        for (relative, output) in &planned {
            let relative = in_cwd(command, relative);
            assertion_module(&frozen_text(ctx, &context, &relative)?)?;
            if mapped.get(&relative) != Some(output) || !asserted.insert(relative) {
                return Err("test-compiled-source-unbound".into());
            }
        }
        let selected = context["selected"]
            .as_array()
            .ok_or("operation-selected-missing")?;
        for relative in selected.iter().filter_map(Value::as_str) {
            // These exact context roles remain in inventory/denominator & are
            // separately compiled/linted; declarations do not emit runnable JS.
            if [".d.ts", ".d.cts", ".d.mts"]
                .iter()
                .any(|suffix| relative.ends_with(*suffix))
                || relative == in_cwd(command, path)
                || relative == in_cwd(command, "eslint.config.mjs")
            {
                continue;
            }
            if !asserted.contains(relative) {
                return Err("test-assertion-scope-incomplete".into());
            }
        }
        tap(&lines, &planned)?;
        Ok((
            json!({"schema":"legion-javascript-operation-observation/1","kind":"node-planned-assertions","script":script,"testSource":in_cwd(command,path),"testSourceDigest":sha256_text(source.as_bytes()),"moduleSemantics":"closed-pure-answer-forms/1","assertionCount":planned.len(),"assertedSourcePaths":asserted,"sourceToOutput":mapped,"artifacts":artifacts}),
            covered,
        ))
    }
}

#[cfg(test)]
mod protocol_tests {
    use super::*;
    #[test]
    fn typescript_rejects_unknown_text_and_absolute_malformed_diagnostics() {
        let root = std::env::temp_dir().join(format!(
            "legion-tsc-parser-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let input = root.join("answer.ts");
        fs::write(&input, "export const answer = 42;\n").unwrap();
        let listed = format!("{}\n", input.display());
        assert!(typescript_output(&root, "", listed.as_bytes(), Some(0)).is_ok());
        for unknown in [
            "garbage diagnostic",
            "answer.ts(1,x): error TS2322: malformed",
        ] {
            assert!(typescript_output(
                &root,
                "",
                format!("{listed}{unknown}\n").as_bytes(),
                Some(0)
            )
            .is_err());
        }
        let malformed = format!(
            "{listed}{}(1,x): error TS2322: malformed\n",
            input.display()
        );
        assert!(typescript_output(&root, "", malformed.as_bytes(), Some(0)).is_err());
        let actual = format!("answer.ts(1,1): error TS2322: Type mismatch.\n{listed}");
        assert!(typescript_output(&root, "", actual.as_bytes(), Some(2)).is_ok());
        assert!(typescript_output(&root, "", actual.as_bytes(), Some(0)).is_err());
        assert!(
            typescript_output(&root, "", format!("{listed}{listed}").as_bytes(), Some(0)).is_err()
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn planned_tests_require_actual_assertions_and_whole_source() {
        assert!(assertion_module("export function answer() { return 42; }\n").is_ok());
        assert!(assertion_module(
            "import test from 'node:test';\nexport function answer() { return 42; }\n"
        )
        .is_err());
        assert!(planned_assertions(TEST_PREAMBLE).is_err());
        assert!(planned_assertions(&format!("{TEST_PREAMBLE}console.log('ok 1');\n")).is_err());
        let block = "{\n  const loaded = await import(pathToFileURL(path.join(output, 'answer.js')).href);\n  test('answer.js', {plan:1}, (t) => {\n    t.assert.strictEqual((loaded.answer || loaded.default.answer)(),42);\n  });\n}\n";
        assert_eq!(
            planned_assertions(&format!("{TEST_PREAMBLE}{block}"))
                .unwrap()
                .len(),
            1
        );
        assert!(planned_assertions(&format!(
            "{TEST_PREAMBLE}{}",
            block.replace(
                "    t.assert.strictEqual((loaded.answer || loaded.default.answer)(),42);\n",
                ""
            )
        ))
        .is_err());
        assert!(tap(
            &["TAP version 13", "1..0", "# pass 0"],
            &[("answer.js".into(), "answer.js".into())]
        )
        .is_err());
    }
}
