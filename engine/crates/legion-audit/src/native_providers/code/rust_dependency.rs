//! Explicit dependency/v1: one unchanged official RustSec advisory subset.
//! This bounded SDK assessment is never a full/current database or freshness claim.
use super::{dir_of, name_of, sha256_text, Diag, Parser, Plan, Planned};
use crate::{
    inventory::InventoryEntry,
    native_providers::legacy_checks::{parsers, AuditScratch},
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path},
};

const ADVISORY: &str = "crates/smallvec/RUSTSEC-2019-0009.md";
const ADVISORY_DIGEST: &str =
    "sha256:678bd66f3703ac7279a9b9fe4219fbe3903395d8411d899647ee8136d19241c5";
const SCOPE: &str = "official RustSec 999ec89d5d3f10f20be14750ec8c2d8b44e0ac9b unchanged RUSTSEC-2019-0009 subset; no full/current database, population or freshness claim";

fn pin() -> Result<&'static str, String> {
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Ok("sha256:33fbe81adca1b794f4ffe98574d59b0ebe6fcfdb310976fafed98a094c795111")
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        Ok("sha256:1a63bb3ab4f99a0220a8e4d8a677692afe5901cb44a949b2473c545a02028326")
    } else {
        Err("unsupported-pinned-cargo-audit-platform".into())
    }
}
fn canonical(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("input-not-absolute".into());
    }
    let mut part = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {
                part.push(component.as_os_str())
            }
            _ => return Err("input-not-normal".into()),
        }
        if fs::symlink_metadata(&part)
            .map_err(|_| "input-unreadable")?
            .file_type()
            .is_symlink()
        {
            return Err("input-symlink".into());
        }
    }
    if fs::canonicalize(path).map_err(|_| "input-canonical")? != path {
        return Err("input-alias".into());
    }
    Ok(())
}
fn tree(root: &Path) -> Result<BTreeMap<String, String>, String> {
    canonical(root)?;
    let mut files = BTreeMap::new();
    let mut total = 0u64;
    fn walk(
        root: &Path,
        path: &Path,
        files: &mut BTreeMap<String, String>,
        total: &mut u64,
        count: &mut usize,
    ) -> Result<(), String> {
        *count += 1;
        if *count > 20000 {
            return Err("input-entry-cap".into());
        }
        let m = fs::symlink_metadata(path).map_err(|_| "input-unreadable")?;
        if m.file_type().is_symlink() {
            return Err("input-symlink".into());
        }
        if m.is_dir() {
            for entry in fs::read_dir(path).map_err(|_| "input-directory")? {
                walk(
                    root,
                    &entry.map_err(|_| "input-directory-entry")?.path(),
                    files,
                    total,
                    count,
                )?;
            }
        } else {
            if !m.is_file() || m.len() > 1024 * 1024 {
                return Err("input-file-bound".into());
            }
            *total += m.len();
            if *total > 64 * 1024 * 1024 {
                return Err("input-total-bound".into());
            }
            use std::io::Read;
            let mut bytes = Vec::new();
            fs::File::open(path)
                .map_err(|_| "input-read")?
                .take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "input-read")?;
            if bytes.len() as u64 != m.len() {
                return Err("input-changed-during-read".into());
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|_| "input-outside")?
                .to_str()
                .ok_or("input-not-utf8")?
                .replace('\\', "/");
            files.insert(relative, sha256_text(&bytes));
        }
        Ok(())
    }
    let mut count = 0;
    walk(root, root, &mut files, &mut total, &mut count)?;
    Ok(files)
}
fn field<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> {
    v[key].as_str().ok_or_else(|| format!("binding-{key}"))
}
fn absent(path: &Path) -> Result<(), String> {
    // Parent directory itself is checked by tree/canonical before this call.
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err("unsupported-audit-configuration".into()),
    }
}

pub(super) fn plan(
    root: &Path,
    entries: &[InventoryEntry],
    scratch: &AuditScratch,
    plan: &mut Plan,
) {
    if let Err(reason) = prepare(root, entries, scratch, plan) {
        plan.not_planned
            .insert("dependency", "rust-dependency-input-unavailable");
        plan.notes
            .push(format!("rust-dependency-input-unavailable:{reason}"));
    }
}
fn prepare(
    root: &Path,
    entries: &[InventoryEntry],
    scratch: &AuditScratch,
    plan: &mut Plan,
) -> Result<(), String> {
    let root = fs::canonicalize(root).map_err(|_| "repository-root")?;
    let lock = entries
        .iter()
        .find(|entry| entry.path == "Cargo.lock")
        .ok_or("frozen-root-lock-missing")?;
    if entries
        .iter()
        .filter(|e| name_of(&e.path) == "Cargo.toml")
        .count()
        != 1
    {
        return Err("multiple-or-missing-manifests-unproven".into());
    }
    let mut frozen = BTreeMap::new();
    for entry in entries {
        if !Path::new(&entry.path)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
            || entry.path.is_empty()
        {
            return Err("frozen-path".into());
        }
        let digest = entry.digest.as_ref().ok_or("frozen-digest-missing")?;
        if frozen.insert(entry.path.clone(), digest.clone()).is_some() {
            return Err("duplicate-frozen-path".into());
        }
    }
    if tree(&root)? != frozen {
        return Err("source-frozen-closure-mismatch".into());
    }
    absent(&root.join(".cargo/audit.toml"))?;
    let database = std::env::var_os("LEGION_RUST_CODE_ADVISORY_DB")
        .ok_or("official-advisory-subset-unavailable")?;
    let database = std::path::PathBuf::from(database);
    let expected = BTreeMap::from([(ADVISORY.to_owned(), ADVISORY_DIGEST.to_owned())]);
    if tree(&database)? != expected {
        return Err("official-subset-mismatch".into());
    }
    let tool =
        std::env::var_os("LEGION_CARGO_AUDIT_BIN").ok_or("pinned-cargo-audit-unavailable")?;
    let tool = std::path::PathBuf::from(tool);
    canonical(&tool)?;
    if sha256_text(&fs::read(&tool).map_err(|_| "tool-unreadable")?) != pin()? {
        return Err("tool-pin-mismatch".into());
    }
    let home = scratch.cache_dir().join("rust-dependency-cargo-home");
    fs::create_dir_all(&home).map_err(|_| "isolated-cargo-home")?;
    canonical(&home)?;
    if !tree(&home)?.is_empty() {
        return Err("isolated-cargo-home-not-empty".into());
    }
    let binding = json!({"root":root,"sourceFiles":frozen,"database":database,"databaseFiles":expected,
        "cargoHome":home,"tool":tool,"toolDigest":pin()?,"lockPath":lock.path,"lockDigest":lock.digest,
        "scope":SCOPE});
    let command = Planned {
        tool: "dependency",
        programs: &["cargo-audit"],
        local_bin: false,
        sibling_of: None,
        requires: None,
        cwd_rel: dir_of(&lock.path),
        args: vec![
            "audit".into(),
            "--json".into(),
            "--file".into(),
            root.join(&lock.path).to_string_lossy().into_owned(),
            "--db".into(),
            database.to_string_lossy().into_owned(),
            "--no-fetch".into(),
            "--no-yanked".into(),
        ],
        parser: Parser::RustDependency,
        accepted: &[0, 1],
        env: vec![("CARGO_HOME", home.to_string_lossy().into_owned())],
        diagnostics_on_stderr: false,
        source_path: Some(lock.path.clone()),
        source_digest: lock.digest.clone(),
    };
    // No execution authority: this closure merely binds inputs for existing SDK admission.
    snapshot(&command, Some(&binding), &tool)?;
    plan.rust_dependency_bindings
        .insert(command.cwd_rel.clone(), binding);
    plan.commands.push(command);
    plan.notes
        .push("dependency-advisory-subset-only:no-full-current-rustsec-or-freshness-proof".into());
    Ok(())
}
pub(super) fn snapshot(
    command: &Planned,
    binding: Option<&Value>,
    executable: &Path,
) -> Result<Value, String> {
    let b = binding.ok_or("dependency-binding-missing")?;
    let root = Path::new(field(b, "root")?);
    let source = tree(root)?;
    if json!(source) != b["sourceFiles"] {
        return Err("source-closure-changed".into());
    }
    absent(&root.join(".cargo/audit.toml"))?;
    let database = Path::new(field(b, "database")?);
    let database_files = tree(database)?;
    if json!(database_files) != b["databaseFiles"] {
        return Err("database-closure-changed".into());
    }
    let home = Path::new(field(b, "cargoHome")?);
    if !tree(home)?.is_empty() {
        return Err("isolated-home-configuration-changed".into());
    }
    canonical(executable)?;
    if executable != Path::new(field(b, "tool")?)
        || sha256_text(&fs::read(executable).map_err(|_| "tool-read")?) != pin()?
    {
        return Err("tool-identity-changed".into());
    }
    if command.source_path.as_deref() != b["lockPath"].as_str()
        || command.source_digest != b["lockDigest"].as_str().map(str::to_owned)
    {
        return Err("lock-binding-mismatch".into());
    }
    Ok(
        json!({"schema":"legion-rust-dependency-input-snapshot/1","scope":SCOPE,"root":root,
        "sourceFiles":source,"database":database,"databaseFiles":database_files,"cargoHome":home,
        "cargoHomeFiles":{},"tool":executable,"toolDigest":pin()?,"lockPath":b["lockPath"],"lockDigest":b["lockDigest"],
        "auditConfiguration":"project absent; isolated empty Cargo home; --no-fetch --no-yanked; no ignores or target filters"}),
    )
}

fn affected(version: &str) -> Result<bool, String> {
    let parts = version
        .split('.')
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "unsupported-smallvec-version")?;
    if parts.len() != 3 {
        return Err("unsupported-smallvec-version".into());
    }
    Ok(parts[0] == 0 && parts[1] == 6 && (5..10).contains(&parts[2]))
}
pub(super) fn parse(
    bytes: &[u8],
    exit: Option<i32>,
    command: &Planned,
    binding: Option<&Value>,
) -> Result<Vec<Diag>, String> {
    let b = binding.ok_or("dependency-binding-missing")?;
    let lockpath = Path::new(field(b, "root")?).join(field(b, "lockPath")?);
    let text = fs::read_to_string(&lockpath).map_err(|_| "lock-read")?;
    if sha256_text(text.as_bytes()) != field(b, "lockDigest")? {
        return Err("lock-changed".into());
    }
    let lock: toml::Value = toml::from_str(&text).map_err(|_| "malformed-lock")?;
    let packages = lock
        .get("package")
        .and_then(toml::Value::as_array)
        .filter(|p| !p.is_empty())
        .ok_or("empty-or-invalid-lock")?;
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| "unparseable-dependency-report")?;
    let legacy =
        parsers::dispatch_json("cargo_audit", &value).ok_or("legacy-parser-unavailable")?;
    if legacy.malformed {
        return Err("legacy-malformed-report".into());
    }
    for (object, keys) in [
        (
            "database",
            &["advisory-count", "last-commit", "last-updated"][..],
        ),
        (
            "settings",
            &["target_arch", "target_os", "severity", "ignore"][..],
        ),
        ("lockfile", &["dependency-count"][..]),
        ("vulnerabilities", &["found", "count", "list"][..]),
    ] {
        let fields = value[object].as_object().ok_or("report-object-missing")?;
        if keys.iter().any(|key| !fields.contains_key(*key)) {
            return Err("report-field-missing".into());
        }
    }
    let list = value["vulnerabilities"]["list"]
        .as_array()
        .ok_or("missing-vulnerabilities-list")?;
    if legacy.findings_count != Some(list.len() as u64)
        || value["vulnerabilities"]["found"] != json!(!list.is_empty())
        || exit != Some(if list.is_empty() { 0 } else { 1 })
    {
        return Err("count-list-exit-mismatch".into());
    }
    if value["database"]["advisory-count"] != 1
        || !value["database"]["last-commit"].is_null()
        || !value["database"]["last-updated"].is_null()
        || value["lockfile"]["dependency-count"] != json!(packages.len())
    {
        return Err("database-lock-scope-mismatch".into());
    }
    for key in ["target_arch", "target_os", "ignore"] {
        if value["settings"][key] != json!([]) {
            return Err(format!("unproven-report-setting:{key}"));
        }
    }
    if !value["settings"]["severity"].is_null()
        || !value["warnings"].as_object().is_some_and(|w| w.is_empty())
    {
        return Err("unsupported-report-filter-or-warning".into());
    }
    let mut expected = BTreeSet::new();
    let mut all = BTreeSet::new();
    for package in packages {
        let name = package
            .get("name")
            .and_then(toml::Value::as_str)
            .ok_or("lock-package-name")?;
        let version = package
            .get("version")
            .and_then(toml::Value::as_str)
            .ok_or("lock-package-version")?;
        let source = package
            .get("source")
            .and_then(toml::Value::as_str)
            .unwrap_or("");
        if !all.insert((name.to_owned(), version.to_owned(), source.to_owned())) {
            return Err("duplicate-lock-package".into());
        }
        if name == "smallvec" && affected(version)? {
            if source != "registry+https://github.com/rust-lang/crates.io-index" {
                return Err("unsupported-smallvec-source".into());
            }
            expected.insert((version.to_owned(), source.to_owned()));
        }
    }
    let mut observed = BTreeSet::new();
    let mut out = Vec::new();
    for item in list {
        let package = &item["package"];
        let version = package["version"]
            .as_str()
            .ok_or("report-package-version")?;
        let source = package["source"].as_str().ok_or("report-package-source")?;
        if package["name"] != "smallvec"
            || item["advisory"]["id"] != "RUSTSEC-2019-0009"
            || item["advisory"]["package"] != "smallvec"
            || item["versions"]["patched"] != json!([">=0.6.10"])
            || item["versions"]["unaffected"] != json!(["<0.6.5"])
            || !expected.contains(&(version.to_owned(), source.to_owned()))
            || !observed.insert((version.to_owned(), source.to_owned()))
        {
            return Err("advisory-package-version-substitution".into());
        }
        let mut found = None;
        let offsets = text
            .match_indices("[[package]]")
            .map(|(offset, _)| offset)
            .collect::<Vec<_>>();
        for (index, offset) in offsets.iter().enumerate() {
            let end = offsets.get(index + 1).copied().unwrap_or(text.len());
            if let Ok(p) = toml::from_str::<toml::Value>(&text[offset + "[[package]]".len()..end]) {
                if p.get("name").and_then(toml::Value::as_str) == Some("smallvec")
                    && p.get("version").and_then(toml::Value::as_str) == Some(version)
                {
                    found = Some(text[..*offset].lines().count() + 1);
                    break;
                }
            }
        }
        out.push(Diag{rule:"cargo-audit:RUSTSEC-2019-0009".into(),severity:"critical",path:command.source_path.clone().ok_or("lock-path")?,
            line:found.ok_or("lock-package-location-missing")?,message:format!("smallvec {version}: RUSTSEC-2019-0009 (unchanged official advisory subset; unsafe soundness unassessed)")});
    }
    if observed != expected {
        return Err("advisory-recall-mismatch".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pinned_advisory_range_is_exact_and_unsupported_versions_fail_closed() {
        assert!(!affected("0.6.4").unwrap());
        assert!(affected("0.6.5").unwrap());
        assert!(affected("0.6.9").unwrap());
        assert!(!affected("0.6.10").unwrap());
        assert!(affected("0.6.9-beta.1").is_err());
        assert!(affected("0.6").is_err());
    }
    #[test]
    fn absent_or_substituted_binding_cannot_parse_as_clean() {
        let command = Planned {
            tool: "dependency",
            programs: &["cargo-audit"],
            local_bin: false,
            sibling_of: None,
            requires: None,
            cwd_rel: String::new(),
            args: Vec::new(),
            parser: Parser::RustDependency,
            accepted: &[0, 1],
            env: Vec::new(),
            diagnostics_on_stderr: false,
            source_path: None,
            source_digest: None,
        };
        assert!(parse(b"{}", Some(0), &command, None).is_err());
        assert!(parse(b"{}", Some(0), &command, Some(&json!({}))).is_err());
    }
}

#[cfg(test)]
mod report_refusal_tests {
    use super::*;
    // Parser unit inputs only. These values are never SDK receipts or qualification evidence.
    struct Fixture {
        root: std::path::PathBuf,
        binding: Value,
        command: Planned,
    }
    impl Fixture {
        fn new(vulnerable: bool) -> Self {
            let root = std::env::temp_dir().join(format!(
                "rust-dependency-parser-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&root).unwrap();
            let mut lock = String::from(
                "version = 4\n\n[[package]]\nname = \"fixture\"\nversion = \"0.0.0\"\n",
            );
            if vulnerable {
                lock.push_str("\n[[package]]\nname = \"smallvec\"\nversion = \"0.6.9\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n");
            }
            fs::write(root.join("Cargo.lock"), &lock).unwrap();
            let binding = json!({"root":root,"lockPath":"Cargo.lock","lockDigest":sha256_text(lock.as_bytes())});
            let command = Planned {
                tool: "dependency",
                programs: &["cargo-audit"],
                local_bin: false,
                sibling_of: None,
                requires: None,
                cwd_rel: String::new(),
                args: Vec::new(),
                parser: Parser::RustDependency,
                accepted: &[0, 1],
                env: Vec::new(),
                diagnostics_on_stderr: false,
                source_path: Some("Cargo.lock".into()),
                source_digest: Some(sha256_text(lock.as_bytes())),
            };
            Self {
                root,
                binding,
                command,
            }
        }
        fn report(&self, vulnerable: bool) -> Value {
            let list = if vulnerable {
                json!([{"advisory":{"id":"RUSTSEC-2019-0009","package":"smallvec"},"package":{"name":"smallvec","version":"0.6.9","source":"registry+https://github.com/rust-lang/crates.io-index"},"versions":{"patched":[">=0.6.10"],"unaffected":["<0.6.5"]}}])
            } else {
                json!([])
            };
            json!({"database":{"advisory-count":1,"last-commit":null,"last-updated":null},"lockfile":{"dependency-count":if vulnerable{2}else{1}},"settings":{"target_arch":[],"target_os":[],"severity":null,"ignore":[]},"vulnerabilities":{"found":vulnerable,"count":if vulnerable{1}else{0},"list":list},"warnings":{}})
        }
        fn parse(&self, report: &Value, exit: i32) -> Result<Vec<Diag>, String> {
            super::parse(
                &serde_json::to_vec(report).unwrap(),
                Some(exit),
                &self.command,
                Some(&self.binding),
            )
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    #[test]
    fn malformed_count_scope_filter_and_false_clean_reports_are_refused() {
        let clean = Fixture::new(false);
        let report = clean.report(false);
        assert!(clean.parse(&report, 0).unwrap().is_empty());
        assert!(super::parse(b"{", Some(0), &clean.command, Some(&clean.binding)).is_err());
        for control in [
            "count",
            "found",
            "database",
            "lock-count",
            "ignore",
            "missing-settings",
            "warnings",
            "exit",
        ] {
            let mut changed = report.clone();
            match control {
                "count" => changed["vulnerabilities"]["count"] = json!(1),
                "found" => changed["vulnerabilities"]["found"] = json!(true),
                "database" => changed["database"]["advisory-count"] = json!(2),
                "lock-count" => changed["lockfile"]["dependency-count"] = json!(2),
                "ignore" => changed["settings"]["ignore"] = json!(["RUSTSEC-2019-0009"]),
                "missing-settings" => {
                    changed.as_object_mut().unwrap().remove("settings");
                }
                "warnings" => changed["warnings"] = json!({"unmaintained":[]}),
                "exit" => {}
                _ => unreachable!(),
            }
            assert!(
                clean
                    .parse(&changed, if control == "exit" { 1 } else { 0 })
                    .is_err(),
                "{control}"
            );
        }
        let vulnerable = Fixture::new(true);
        let report = vulnerable.report(true);
        let findings = vulnerable.parse(&report, 1).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, "Cargo.lock");
        assert!(findings[0].line > 1);
        let mut false_clean = report.clone();
        false_clean["vulnerabilities"] = json!({"found":false,"count":0,"list":[]});
        assert!(vulnerable.parse(&false_clean, 0).is_err());
        for (object, key, value) in [
            ("advisory", "id", "RUSTSEC-0000-0000"),
            ("package", "version", "0.6.10"),
            ("package", "source", "path+file:///other"),
        ] {
            let mut changed = report.clone();
            changed["vulnerabilities"]["list"][0][object][key] = json!(value);
            assert!(vulnerable.parse(&changed, 1).is_err());
        }
        fs::write(vulnerable.root.join("Cargo.lock"), "changed").unwrap();
        assert!(vulnerable.parse(&report, 1).is_err());
    }
}
