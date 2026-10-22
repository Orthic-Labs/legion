//! Offline, source-bound govulncheck v1.9.0 adapter (#84).
//!
//! A successful host-default symbol scan is not proof for excluded build tags,
//! platforms, cgo or workspace variants. Those remain counted gaps. This module
//! never supplies owner admission or a sandbox receipt.
use super::{sha256_text, Diag, Parser, Plan, Planned};
use crate::{inventory::InventoryEntry, native_providers::legacy_checks::AuditScratch};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

pub(super) const VERSION: &str = "v1.9.0";
const DB_FILES: usize = 4713;
const DB_DIGEST: &str = "sha256:2078b194f64c8032800c110f934156298103d3e504ef58e9919faf5e0f5b05ed";
const DB_MODIFIED: &str = "2026-10-21T00:27:29Z";
const MAX_FILES: usize = 20000;
const MAX_BYTES: u64 = 256 * 1024 * 1024;
const MAX_NODES: usize = MAX_FILES * 2;
const MAX_DEPTH: usize = 64;

fn safe_rel(s: &str) -> bool {
    !s.is_empty()
        && !s.chars().any(|c| matches!(c, '\\' | '\n' | '\r' | '\0'))
        && Path::new(s)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
}
fn platform_suffix(name: &str) -> bool {
    let stem = name
        .strip_suffix("_test.go")
        .or_else(|| name.strip_suffix(".go"))
        .unwrap_or(name);
    let suffix = stem.rsplit('_').next().unwrap_or_default();
    matches!(
        suffix,
        "aix"
            | "android"
            | "darwin"
            | "dragonfly"
            | "freebsd"
            | "hurd"
            | "illumos"
            | "ios"
            | "js"
            | "linux"
            | "nacl"
            | "netbsd"
            | "openbsd"
            | "plan9"
            | "solaris"
            | "wasip1"
            | "windows"
            | "zos"
            | "386"
            | "amd64"
            | "amd64p32"
            | "arm"
            | "armbe"
            | "arm64"
            | "arm64be"
            | "loong64"
            | "mips"
            | "mipsle"
            | "mips64"
            | "mips64le"
            | "mips64p32"
            | "mips64p32le"
            | "ppc"
            | "ppc64"
            | "ppc64le"
            | "riscv"
            | "riscv64"
            | "s390"
            | "s390x"
            | "sparc"
            | "sparc64"
            | "wasm"
    ) && stem.contains('_')
}
fn digest_map(files: &BTreeMap<String, String>) -> Result<String, String> {
    serde_json::to_vec(files)
        .map(|b| sha256_text(&b))
        .map_err(|e| e.to_string())
}
/// Every direct source/text read is bounded before allocation, including races
/// after metadata inspection. No byte or file receives credit after a change.
fn read_bounded(
    path: &Path,
    remaining: u64,
    expected: Option<&fs::Metadata>,
) -> Result<Vec<u8>, String> {
    let meta = fs::symlink_metadata(path).map_err(|_| "bounded-input-unreadable")?;
    if !meta.is_file() || meta.len() > remaining {
        return Err("bounded-input-limit-or-type".into());
    }
    if expected.is_some_and(|before| {
        !before.is_file()
            || before.len() != meta.len()
            || before.modified().ok() != meta.modified().ok()
    }) {
        return Err("bounded-input-changed".into());
    }
    let mut file = fs::File::open(path).map_err(|_| "bounded-input-unreadable")?;
    let opened = file.metadata().map_err(|_| "bounded-input-unreadable")?;
    if !opened.is_file()
        || opened.len() != meta.len()
        || opened.modified().ok() != meta.modified().ok()
    {
        return Err("bounded-input-changed".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(remaining.checked_add(1).ok_or("bounded-input-limit")?)
        .read_to_end(&mut bytes)
        .map_err(|_| "bounded-input-unreadable")?;
    let actual = u64::try_from(bytes.len()).map_err(|_| "bounded-input-limit")?;
    if actual > remaining {
        return Err("bounded-input-limit".into());
    }
    let after = file.metadata().map_err(|_| "bounded-input-unreadable")?;
    let path_after = fs::symlink_metadata(path).map_err(|_| "bounded-input-unreadable")?;
    if actual != opened.len()
        || !path_after.is_file()
        || after.len() != opened.len()
        || path_after.len() != opened.len()
        || after.modified().ok() != opened.modified().ok()
        || path_after.modified().ok() != opened.modified().ok()
    {
        return Err("bounded-input-changed".into());
    }
    Ok(bytes)
}
fn tree(root: &Path) -> Result<BTreeMap<String, String>, String> {
    fn walk(
        root: &Path,
        dir: &Path,
        files: &mut BTreeMap<String, String>,
        total: &mut u64,
        nodes: &mut usize,
        depth: usize,
    ) -> Result<(), String> {
        if depth > MAX_DEPTH {
            return Err("input-tree-limit".into());
        }
        for item in fs::read_dir(dir).map_err(|_| "input-tree-unreadable")? {
            *nodes = nodes.checked_add(1).ok_or("input-tree-limit")?;
            if *nodes > MAX_NODES {
                return Err("input-tree-limit".into());
            }
            let path = item.map_err(|_| "input-tree-unreadable")?.path();
            let meta = fs::symlink_metadata(&path).map_err(|_| "input-tree-unreadable")?;
            if meta.is_dir() {
                walk(root, &path, files, total, nodes, depth + 1)?;
            } else if meta.is_file() {
                let remaining = MAX_BYTES.checked_sub(*total).ok_or("input-tree-limit")?;
                if meta.len() > remaining || files.len() >= MAX_FILES {
                    return Err("input-tree-limit".into());
                }
                let rel = path
                    .strip_prefix(root)
                    .map_err(|_| "input-path")?
                    .to_str()
                    .ok_or("input-path")?
                    .replace('\\', "/");
                if !safe_rel(&rel) {
                    return Err("input-path".into());
                }
                let mut file = fs::File::open(&path).map_err(|_| "input-tree-unreadable")?;
                let opened = file.metadata().map_err(|_| "input-tree-unreadable")?;
                if !opened.is_file()
                    || opened.len() != meta.len()
                    || opened.modified().ok() != meta.modified().ok()
                {
                    return Err("input-tree-changed".into());
                }
                let mut bytes = Vec::new();
                (&mut file)
                    .take(remaining + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| "input-tree-unreadable")?;
                let actual = u64::try_from(bytes.len()).map_err(|_| "input-tree-limit")?;
                if actual > remaining {
                    return Err("input-tree-limit".into());
                }
                let after = file.metadata().map_err(|_| "input-tree-unreadable")?;
                let path_after =
                    fs::symlink_metadata(&path).map_err(|_| "input-tree-unreadable")?;
                if actual != opened.len()
                    || !path_after.is_file()
                    || after.len() != opened.len()
                    || path_after.len() != opened.len()
                    || after.modified().ok() != opened.modified().ok()
                    || path_after.modified().ok() != opened.modified().ok()
                {
                    return Err("input-tree-changed".into());
                }
                *total = total.checked_add(actual).ok_or("input-tree-limit")?;
                files.insert(rel, sha256_text(&bytes));
            } else {
                return Err("input-symlink-or-special-file".into());
            }
        }
        Ok(())
    }
    let canonical = fs::canonicalize(root).map_err(|_| "input-root-unreadable")?;
    if canonical != root || !root.is_dir() {
        return Err("input-root-not-canonical".into());
    }
    let mut files = BTreeMap::new();
    // Root itself counts even when empty; every child directory/file counts too.
    walk(root, root, &mut files, &mut 0, &mut 1, 0)?;
    Ok(files)
}
fn db_root() -> Result<PathBuf, String> {
    let p =
        PathBuf::from(std::env::var_os("LEGION_GOVULNCHECK_DB_ROOT").ok_or("official-db-missing")?);
    if !p.is_absolute() {
        return Err("official-db-not-absolute".into());
    }
    Ok(p)
}
fn db_url() -> Result<String, String> {
    let p = db_root()?;
    let s = p.to_str().ok_or("official-db-path")?;
    // Source-supported file URL; encode reserved/non-ASCII bytes, not separators.
    let mut url = String::from("file://");
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"/-._~:".contains(&b) {
            url.push(b as char);
        } else {
            url.push_str(&format!("%{b:02X}"));
        }
    }
    url.push('/');
    Ok(url)
}
fn stage(command: &Planned) -> Result<PathBuf, String> {
    if command.args.first().map(String::as_str) != Some("-C") {
        return Err("scanner-command".into());
    }
    command
        .args
        .get(1)
        .map(PathBuf::from)
        .ok_or_else(|| "scanner-command".into())
}
fn source_root(command: &Planned) -> Result<PathBuf, String> {
    let mut root = stage(command)?;
    for _ in Path::new(&command.cwd_rel).components() {
        root = root.parent().ok_or("source-root")?.to_path_buf();
    }
    Ok(root)
}
fn escaped(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_uppercase() {
            out.push('!');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}
fn b64(bytes: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            out.push(if i > c.len() {
                '='
            } else {
                T[((n >> (18 - 6 * i)) & 63) as usize] as char
            });
        }
    }
    out
}
/// Go's official sumdb/dirhash.Hash1: sorted SHA256 file lines, then SHA256/base64.
fn module_h1(root: &Path, module: &str, version: &str) -> Result<String, String> {
    if !safe_rel(module) || !safe_rel(version) {
        return Err("module-identity".into());
    }
    let files = tree(root)?;
    let mut outer = Sha256::new();
    for (path, digest) in files {
        outer.update(format!(
            "{}  {module}@{version}/{path}\n",
            digest.trim_start_matches("sha256:")
        ));
    }
    Ok(format!("h1:{}", b64(&outer.finalize())))
}
fn sums(snapshot: &Path) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    let mut total = 0u64;
    for name in tree(snapshot)?
        .keys()
        .filter(|p| p.rsplit('/').next() == Some("go.sum"))
    {
        let remaining = MAX_BYTES.checked_sub(total).ok_or("go-sum-limit")?;
        let bytes = read_bounded(&snapshot.join(name), remaining, None)?;
        total = total
            .checked_add(u64::try_from(bytes.len()).map_err(|_| "go-sum-limit")?)
            .ok_or("go-sum-limit")?;
        let text = String::from_utf8(bytes).map_err(|_| "go-sum-unreadable")?;
        for line in text.lines() {
            let p: Vec<_> = line.split_whitespace().collect();
            if p.len() != 3 {
                return Err("go-sum-malformed".into());
            }
            if p[1].ends_with("/go.mod") {
                continue;
            }
            if !p[1].starts_with('v') || !p[2].starts_with("h1:") {
                return Err("go-sum-malformed".into());
            }
            let key = format!("{}@{}", p[0], p[1]);
            if out
                .insert(key, p[2].to_owned())
                .is_some_and(|old| old != p[2])
            {
                return Err("go-sum-conflict".into());
            }
        }
    }
    Ok(out)
}
/// Replayed immediately before & after actual SDK execution. No receipt is synthesized.
/// Returned maps belong in retained receipt evidence even when execution fails.
pub(super) fn snapshot(command: &Planned) -> Result<Value, String> {
    let db = db_root()?;
    let db_files = tree(&db)?;
    if db_files.len() != DB_FILES || digest_map(&db_files)? != DB_DIGEST {
        return Err("official-db-closure-mismatch".into());
    }
    let source = source_root(command)?;
    let source_files = tree(&source)?;
    let expected = command
        .source_digest
        .as_deref()
        .ok_or("source-binding-missing")?;
    if digest_map(&source_files)? != expected {
        return Err("source-closure-changed".into());
    }
    let cache = PathBuf::from(std::env::var_os("GOMODCACHE").ok_or("module-cache-missing")?);
    let cache_files = tree(&cache)?;
    let home = command
        .env
        .iter()
        .find(|(name, _)| *name == "HOME")
        .map(|(_, p)| PathBuf::from(p))
        .ok_or("telemetry-home")?;
    let home_files = tree(&home)?;
    let mode = if cfg!(target_os = "macos") {
        "Library/Application Support/go/telemetry/mode"
    } else if cfg!(windows) {
        "AppData/Roaming/go/telemetry/mode"
    } else {
        ".config/go/telemetry/mode"
    };
    if home_files.get(mode).map(String::as_str) != Some(sha256_text(b"off").as_str()) {
        return Err("telemetry-mode-changed".into());
    }
    let mut modules = BTreeMap::new();
    for (key, expected) in sums(&source)? {
        let (module, version) = key.rsplit_once('@').ok_or("module-identity")?;
        let dir = cache.join(format!("{}@{}", escaped(module), escaped(version)));
        // Unused historical sums need not be populated. Every SBOM module is
        // independently required below to occur in this verified set.
        if dir.exists() {
            let actual = module_h1(&dir, module, version)?;
            if actual != expected {
                return Err("module-cache-checksum-mismatch".into());
            }
            modules.insert(key, actual);
        }
    }
    Ok(
        json!({"schema":"legion-govulncheck-input-snapshot/1", "databaseRoot":db,
        "databaseDigest":DB_DIGEST,"databaseFiles":db_files,"sourceRoot":source,
        "sourceDigest":expected,"sourceFiles":source_files,"moduleCacheRoot":cache,
        "moduleCacheDigest":digest_map(&cache_files)?,"moduleCacheFiles":cache_files,
        "verifiedModules":modules,"telemetryHome":home,"telemetryFiles":home_files}),
    )
}

pub(super) fn version_args() -> Result<Vec<String>, String> {
    Ok(vec!["-db".into(), db_url()?, "-version".into()])
}

pub(super) fn plan(
    root: &Path,
    entries: &[InventoryEntry],
    scratch: &AuditScratch,
    plan: &mut Plan,
) {
    if let Err(error) = plan_inner(root, entries, scratch, plan) {
        plan.not_planned
            .insert("vulnerability", "govulncheck-input-incomplete");
        plan.notes.push(format!("govulncheck:{error}"));
    }
}
fn plan_inner(
    root: &Path,
    entries: &[InventoryEntry],
    scratch: &AuditScratch,
    plan: &mut Plan,
) -> Result<(), String> {
    let repo = fs::canonicalize(root).map_err(|_| "repository-root")?;
    let db = db_root()?;
    if db.starts_with(&repo) {
        return Err("database-inside-project".into());
    }
    let modules: BTreeSet<_> = entries
        .iter()
        .filter(|e| e.path.rsplit('/').next() == Some("go.mod"))
        .map(|e| e.path.rsplit_once('/').map_or("", |(p, _)| p).to_owned())
        .collect();
    if modules.is_empty() {
        return Err("no-frozen-go-mod".into());
    }
    if modules.len() > 6 {
        return Err("module-limit".into());
    }
    let base = scratch.cache_dir().join("govulncheck");
    fs::create_dir_all(&base).map_err(|_| "snapshot-create")?;
    let mut commands = Vec::new();
    for dir in modules {
        let source = base.join(sha256_text(dir.as_bytes()).trim_start_matches("sha256:"));
        fs::create_dir(&source).map_err(|_| "snapshot-not-fresh")?;
        let mut total = 0u64;
        for entry in entries {
            if !safe_rel(&entry.path) {
                return Err("frozen-path".into());
            }
            let path = repo.join(&entry.path);
            let canonical = fs::canonicalize(&path).map_err(|_| "frozen-file-unreadable")?;
            if canonical != path || !canonical.starts_with(&repo) {
                return Err("frozen-path-symlink".into());
            }
            let meta = fs::symlink_metadata(&path).map_err(|_| "frozen-file-unreadable")?;
            if !meta.is_file() || meta.len() > MAX_BYTES {
                return Err("frozen-file-type-or-limit".into());
            }
            let remaining = MAX_BYTES.checked_sub(total).ok_or("snapshot-limit")?;
            if entries.len() > MAX_FILES {
                return Err("snapshot-limit".into());
            }
            let bytes = read_bounded(&path, remaining, Some(&meta))?;
            if entry.digest.as_deref() != Some(sha256_text(&bytes).as_str()) {
                return Err("frozen-file-digest".into());
            }
            total = total
                .checked_add(u64::try_from(bytes.len()).map_err(|_| "snapshot-limit")?)
                .ok_or("snapshot-limit")?;
            if entry.path.ends_with(".go") {
                let text = String::from_utf8_lossy(&bytes);
                let name = entry.path.rsplit('/').next().unwrap_or_default();
                if text.contains("//go:build")
                    || text.contains("// +build")
                    || regex::Regex::new(
                        r#"(?m)^\s*(?:import\s*)?(?:[A-Za-z_]\w*\s+)?(?:"C"|`C`)\s*(?://.*)?$"#,
                    )
                    .map_err(|_| "cgo-pattern")?
                    .is_match(&text)
                    || platform_suffix(name)
                    || name.starts_with('_')
                    || name.starts_with('.')
                    || entry.path.split('/').any(|p| {
                        p == "testdata" || p == "vendor" || p.starts_with('.') || p.starts_with('_')
                    })
                {
                    plan.notes
                        .push(format!("govulncheck:unproven-build-variant:{}", entry.path));
                }
            }
            if entry.path.ends_with("go.work") || entry.path.ends_with("go.mod") {
                let text = String::from_utf8_lossy(&bytes);
                if text
                    .lines()
                    .any(|l| matches!(l.split_whitespace().next(), Some("replace" | "use")))
                {
                    // Local graph edges require a separate frozen path-closure
                    // proof. Do not resolve them against the original project.
                    return Err("workspace-or-replacement-path-closure-unavailable".into());
                }
            }
            let destination = source.join(&entry.path);
            fs::create_dir_all(destination.parent().ok_or("snapshot-path")?)
                .map_err(|_| "snapshot-create")?;
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&destination)
                .map_err(|_| "snapshot-create")?;
            f.write_all(&bytes).map_err(|_| "snapshot-write")?;
        }
        let home = source.parent().ok_or("snapshot-path")?.join(format!(
            "home-{}",
            sha256_text(dir.as_bytes()).trim_start_matches("sha256:")
        ));
        fs::create_dir(&home).map_err(|_| "telemetry-home-not-fresh")?;
        let config = home.join(".config");
        let telemetry = if cfg!(target_os = "macos") {
            home.join("Library/Application Support/go/telemetry")
        } else if cfg!(windows) {
            home.join("AppData/Roaming/go/telemetry")
        } else {
            config.join("go/telemetry")
        };
        fs::create_dir_all(&telemetry).map_err(|_| "telemetry-mode")?;
        // Official x/telemetry Mode accepts legacy exact "off" mode content.
        fs::write(telemetry.join("mode"), b"off").map_err(|_| "telemetry-mode")?;
        let mut env = vec![
            ("GOPROXY", "off".into()),
            ("GOSUMDB", "off".into()),
            ("GOTOOLCHAIN", "local".into()),
            ("GOENV", "off".into()),
            ("GOWORK", "off".into()),
            ("GOFLAGS", "-mod=readonly".into()),
            ("CGO_ENABLED", "0".into()),
            ("HOME", home.to_string_lossy().into_owned()),
            ("XDG_CONFIG_HOME", config.to_string_lossy().into_owned()),
            (
                "APPDATA",
                home.join("AppData/Roaming").to_string_lossy().into_owned(),
            ),
        ];
        // No inherited GOFLAGS/GOVERSION/GOOS/GOARCH or telemetry-child control.
        env.shrink_to_fit();
        let source = fs::canonicalize(source).map_err(|_| "snapshot-path")?;
        let command = Planned {
            tool: "vulnerability",
            programs: &["govulncheck"],
            local_bin: false,
            sibling_of: Some("go"),
            requires: Some("go"),
            cwd_rel: dir.clone(),
            args: vec![
                "-C".into(),
                source.join(&dir).to_string_lossy().into_owned(),
                "-mode=source".into(),
                "-scan=symbol".into(),
                "-test".into(),
                "-json".into(),
                "-db".into(),
                db_url()?,
                "./...".into(),
            ],
            parser: Parser::Govulncheck,
            accepted: &[0],
            env,
            diagnostics_on_stderr: false,
            source_path: None,
            source_digest: Some(digest_map(&tree(&source)?)?),
        };
        // snapshot() hashes whole selected root, not merely module subtree.
        snapshot(&command)?;
        commands.push(command);
    }
    plan.commands.extend(commands);
    Ok(())
}

fn field<'a>(v: &'a Value, name: &str) -> Result<&'a str, String> {
    v.get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("missing-{name}"))
}
/// Strict pinned streaming protocol: JSON objects may span lines. A JSON scan
/// with findings exits zero; nonzero process exit never projects clean output.
pub(super) fn parse(
    bytes: &[u8],
    exit: Option<i32>,
    command: &Planned,
) -> Result<Vec<Diag>, String> {
    if exit != Some(0) {
        return Err("scanner-process-failed".into());
    }
    let snapshot = snapshot(command)?;
    let root = stage(command)?;
    let module_file = String::from_utf8(read_bounded(&root.join("go.mod"), MAX_BYTES, None)?)
        .map_err(|_| "module-manifest-unreadable")?;
    let main_module = module_file
        .lines()
        .find_map(|l| l.trim().strip_prefix("module "))
        .map(str::trim)
        .filter(|s| safe_rel(s))
        .ok_or("module-manifest-malformed")?;
    let messages: Vec<Value> = serde_json::Deserializer::from_slice(bytes)
        .into_iter::<Value>()
        .collect::<Result<_, _>>()
        .map_err(|_| "malformed-json-stream")?;
    if messages.is_empty() || messages.len() > 20000 {
        return Err("incomplete-json-stream".into());
    }
    let mut config = None;
    let mut sbom = None;
    let mut osvs = BTreeMap::new();
    let mut findings = Vec::new();
    for (i, message) in messages.into_iter().enumerate() {
        let object = message.as_object().ok_or("malformed-message")?;
        if object.len() != 1 {
            return Err("malformed-message".into());
        }
        let (kind, value) = object.iter().next().ok_or("malformed-message")?;
        if !value.is_object() {
            return Err("malformed-message".into());
        }
        match kind.as_str() {
            "config" if i == 0 && config.is_none() => config = Some(value.clone()),
            "SBOM" if sbom.is_none() => sbom = Some(value.clone()),
            "progress" => {}
            "osv" => {
                let id = field(value, "id")?;
                if !id.starts_with("GO-") {
                    return Err("malformed-osv".into());
                }
                if osvs
                    .insert(id.to_owned(), value.clone())
                    .is_some_and(|old| old != *value)
                {
                    return Err("conflicting-osv".into());
                }
            }
            "finding" => findings.push(value.clone()),
            _ => return Err("unexpected-message".into()),
        }
    }
    let config = config.ok_or("missing-config")?;
    for (key, expected) in [
        ("protocol_version", "v1.0.0"),
        ("scanner_name", "govulncheck"),
        ("scanner_version", VERSION),
        ("scan_level", "symbol"),
        ("scan_mode", "source"),
        ("db_last_modified", DB_MODIFIED),
    ] {
        if field(&config, key)? != expected {
            return Err(format!("scanner-config-{key}"));
        }
    }
    if field(&config, "db")? != db_url()? {
        return Err("scanner-database-mismatch".into());
    }
    let go = field(&config, "go_version")?;
    if !go.starts_with("go1.") {
        return Err("scanner-go-version".into());
    }
    let sbom = sbom.ok_or("missing-sbom")?;
    if field(&sbom, "go_version")? != go {
        return Err("sbom-go-version-mismatch".into());
    }
    let roots = sbom
        .get("roots")
        .and_then(Value::as_array)
        .filter(|r| !r.is_empty())
        .ok_or("empty-sbom-roots")?;
    if roots.iter().any(|r| {
        !r.as_str().is_some_and(|s| {
            s == main_module
                || s == format!("{main_module}.test")
                || s == format!("{main_module}_test")
                || s.starts_with(&format!("{main_module}/"))
        })
    }) {
        return Err("sbom-root-mismatch".into());
    }
    let modules = sbom
        .get("modules")
        .and_then(Value::as_array)
        .filter(|m| !m.is_empty())
        .ok_or("empty-sbom-modules")?;
    let verified = snapshot["verifiedModules"]
        .as_object()
        .ok_or("module-proof")?;
    for module in modules {
        let path = field(module, "path")?;
        let version = module
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if path == "stdlib" {
            if version != format!("v{}", &go[2..]) {
                return Err("sbom-stdlib-version".into());
            }
        } else if path == main_module && version.is_empty() {
        } else if !verified.contains_key(&format!("{path}@{version}")) {
            return Err("sbom-module-not-checksummed".into());
        }
    }
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for finding in findings {
        let id = field(&finding, "osv")?;
        let osv = osvs.get(id).ok_or("finding-without-osv")?;
        let trace = finding
            .get("trace")
            .and_then(Value::as_array)
            .filter(|t| !t.is_empty())
            .ok_or("finding-without-trace")?;
        for frame in trace {
            field(frame, "module")?;
        }
        if trace[0]
            .get("function")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .is_empty()
        {
            if trace.len() != 1 || trace[0].get("position").is_some() {
                return Err("malformed-lower-level-finding".into());
            }
            continue; // Symbol scan explicitly distinguishes imported from called.
        }
        let position = trace
            .iter()
            .rev()
            .find_map(|frame| {
                (frame.get("module").and_then(Value::as_str) == Some(main_module))
                    .then(|| frame.get("position"))
                    .flatten()
            })
            .ok_or("called-finding-without-selected-position")?;
        let path = field(position, "filename")?;
        let line = position
            .get("line")
            .and_then(Value::as_u64)
            .and_then(|n| usize::try_from(n).ok())
            .filter(|n| *n > 0)
            .ok_or("finding-line")?;
        if !safe_rel(path) || !path.ends_with(".go") {
            return Err("finding-path".into());
        }
        if seen.insert((id.to_owned(), path.to_owned(), line)) {
            let summary = osv.get("summary").and_then(Value::as_str).unwrap_or(id);
            out.push(Diag {
                rule: format!("govulncheck:{id}"),
                severity: "error",
                path: path.into(),
                line,
                message: format!("{id}: {}", summary.chars().take(250).collect::<String>()),
            });
        }
    }
    Ok(out)
}
