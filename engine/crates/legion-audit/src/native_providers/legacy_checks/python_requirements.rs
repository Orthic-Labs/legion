//! Bounded pip-audit input: frozen exact repository pins, never host distributions.
//! Supported grammar intentionally excludes resolution, installs & project execution.
use super::{AuditScratch, LegacyCheckInput};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

pub(super) const KEY: &str = "pythonRequirements";
static NEXT: AtomicU64 = AtomicU64::new(0);

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn canonical_name(name: &str) -> Option<String> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes[bytes.len() - 1].is_ascii_alphanumeric()
        || !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(b))
    {
        return None;
    }
    let mut out = String::new();
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !out.ends_with('-') {
                out.push('-');
            }
        } else {
            out.push(c.to_ascii_lowercase());
        }
    }
    Some(out)
}

// Numeric release versions have identical packaging.Version display. Reject
// unresolved/noncanonical forms instead of inventing a PEP 440 normalizer.
fn exact_version(version: &str) -> bool {
    !version.is_empty()
        && version.split('.').all(|part| {
            !part.is_empty()
                && part.bytes().all(|b| b.is_ascii_digit())
                && (part.len() == 1 || !part.starts_with('0'))
        })
}

fn pins(text: &str, expected: &mut BTreeMap<String, String>) -> Result<(), String> {
    for (line_no, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, version) = line
            .split_once("==")
            .ok_or_else(|| format!("unsupported-requirement-line:{}", line_no + 1))?;
        let name = canonical_name(name)
            .ok_or_else(|| format!("unsupported-requirement-name:{}", line_no + 1))?;
        if !exact_version(version) {
            return Err(format!("unsupported-requirement-version:{}", line_no + 1));
        }
        if expected.insert(name.clone(), version.into()).is_some() {
            return Err(format!("duplicate-requirement:{name}"));
        }
    }
    Ok(())
}

pub(super) fn read_frozen(root: &Path, relative: &str, expected: &str) -> Result<Vec<u8>, String> {
    let relative_path = Path::new(relative);
    if relative_path
        .components()
        .any(|p| !matches!(p, Component::Normal(_)))
    {
        return Err(format!("unsafe-input-path:{relative}"));
    }
    let mut path = root.to_path_buf();
    for part in relative_path.components() {
        path.push(part.as_os_str());
        let meta = fs::symlink_metadata(&path).map_err(|_| format!("input-missing:{relative}"))?;
        if meta.file_type().is_symlink() {
            return Err(format!("input-symlink:{relative}"));
        }
    }
    let meta = fs::metadata(&path).map_err(|_| format!("input-unreadable:{relative}"))?;
    if !meta.is_file() || meta.len() > 1_048_576 {
        return Err(format!("input-not-bounded-file:{relative}"));
    }
    let bytes = fs::read(&path).map_err(|_| format!("input-unreadable:{relative}"))?;
    if digest(&bytes) != expected {
        return Err(format!("input-drift:{relative}"));
    }
    Ok(bytes)
}

pub(super) struct Prepared {
    pub args: Vec<String>,
    pub binding: Value,
    snapshots: Vec<(PathBuf, String)>,
}
impl Prepared {
    pub fn unchanged(&self, input: &LegacyCheckInput) -> bool {
        self.snapshots
            .iter()
            .all(|(p, d)| !p.is_symlink() && fs::read(p).is_ok_and(|bytes| digest(&bytes) == *d))
            && self.binding["files"].as_array().is_some_and(|files| {
                files.iter().all(|file| {
                    file["path"]
                        .as_str()
                        .zip(file["digest"].as_str())
                        .is_some_and(|(p, d)| read_frozen(&input.root, p, d).is_ok())
                })
            })
    }
}

// Windows read-only attributes prevent scratch cleanup. Restore only owned
// regular snapshots; never follow a replacement symlink during cleanup.
#[cfg(windows)]
impl Drop for Prepared {
    fn drop(&mut self) {
        for (path, _) in &self.snapshots {
            if let Ok(meta) = fs::symlink_metadata(path) {
                if meta.is_file() && !meta.file_type().is_symlink() {
                    let mut permissions = meta.permissions();
                    permissions.set_readonly(false);
                    let _ = fs::set_permissions(path, permissions);
                }
            }
        }
    }
}

pub(super) fn prepare(
    input: &LegacyCheckInput,
    scratch: &AuditScratch,
) -> Result<Prepared, String> {
    let mut expected = BTreeMap::new();
    let mut contents = Vec::new();
    for entry in &input.denominator.entries {
        let name = Path::new(&entry.path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        if !name.starts_with("requirements") || !name.ends_with(".txt") {
            return Err(format!("unsupported-python-input:{}", entry.path));
        }
        let hash = entry
            .digest
            .as_deref()
            .ok_or_else(|| format!("input-digest-missing:{}", entry.path))?;
        let bytes = read_frozen(&input.root, &entry.path, hash)?;
        let text =
            std::str::from_utf8(&bytes).map_err(|_| format!("input-not-utf8:{}", entry.path))?;
        pins(text, &mut expected).map_err(|e| format!("{}:{e}", entry.path))?;
        contents.push((entry.path.clone(), hash.to_owned(), bytes));
    }
    if contents.is_empty() || expected.is_empty() {
        return Err("requirements-pins-empty".into());
    }
    let directory = scratch.reports_dir().join(format!(
        "pip-audit-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(scratch.reports_dir())
        .map_err(|_| "snapshot-parent-unavailable".to_owned())?;
    fs::create_dir(&directory).map_err(|_| "snapshot-directory-unavailable".to_owned())?;
    let mut args: Vec<String> = ["--format", "json", "--disable-pip", "--no-deps", "--strict"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let mut files = Vec::new();
    let mut snapshots = Vec::new();
    for (index, (path, hash, bytes)) in contents.into_iter().enumerate() {
        let snapshot = directory.join(format!("requirements-{index}.txt"));
        let mut handle = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&snapshot)
            .map_err(|_| "snapshot-file-unavailable".to_owned())?;
        handle
            .write_all(&bytes)
            .map_err(|_| "snapshot-write-failed".to_owned())?;
        handle
            .sync_all()
            .map_err(|_| "snapshot-sync-failed".to_owned())?;
        let mut permissions = handle
            .metadata()
            .map_err(|_| "snapshot-metadata-unavailable".to_owned())?
            .permissions();
        permissions.set_readonly(true);
        handle
            .set_permissions(permissions)
            .map_err(|_| "snapshot-seal-failed".to_owned())?;
        args.extend(["-r".into(), snapshot.to_string_lossy().into_owned()]);
        files.push(
            json!({"path":path,"digest":hash,"snapshot":snapshot,"snapshotDigest":digest(&bytes)}),
        );
        snapshots.push((snapshot, hash));
    }
    let binding = json!({"schemaVersion":1,"scope":"exact-listed-pins-only; transitive dependencies not resolved",
        "inventoryDigest":input.inventory_digest,"denominatorDigest":input.denominator.digest,
        "files":files,"expectedPackages":expected});
    Ok(Prepared {
        args,
        binding,
        snapshots,
    })
}

/// Exact reconciliation precedes legacy summary projection. Empty, missing,
/// skipped, duplicated, extra, wrong-version & malformed rows stay incomplete.
pub(super) fn reconcile(binding: &Value, value: &Value) -> Option<u64> {
    let expected = binding["expectedPackages"].as_object()?;
    if expected.is_empty() {
        return None;
    }
    let rows = value.get("dependencies")?.as_array()?;
    if rows.len() != expected.len() || !value.get("fixes")?.as_array()?.is_empty() {
        return None;
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut count = 0_u64;
    for row in rows {
        if row.get("skip_reason").is_some() {
            return None;
        }
        let name = row.get("name")?.as_str()?;
        if canonical_name(name).as_deref() != Some(name) || !seen.insert(name) {
            return None;
        }
        let version = row.get("version")?.as_str()?;
        if expected.get(name)?.as_str()? != version {
            return None;
        }
        let vulns = row.get("vulns")?.as_array()?;
        for vuln in vulns {
            if vuln.get("id")?.as_str()?.is_empty() {
                return None;
            }
            if !vuln
                .get("fix_versions")?
                .as_array()?
                .iter()
                .all(|v| v.as_str().is_some())
            {
                return None;
            }
        }
        count = count.checked_add(u64::try_from(vulns.len()).ok()?)?;
    }
    Some(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_pin_grammar_never_admits_resolution_or_project_execution() {
        let mut expected = BTreeMap::new();
        pins(
            "# explicit pins\nSome__Name==1.2.0\nsix==1.17.0\n",
            &mut expected,
        )
        .unwrap();
        assert_eq!(
            expected,
            [
                ("six".into(), "1.17.0".into()),
                ("some-name".into(), "1.2.0".into())
            ]
            .into_iter()
            .collect()
        );
        for text in [
            "-r child.txt",
            "-c constraints.txt",
            "-e .",
            "package @ https://example.invalid/pkg.whl",
            "https://example.invalid/pkg.whl",
            "pkg==1.0; python_version>'3'",
            "pkg[extra]==1.0",
            "pkg>=1.0",
            "pkg==1.*",
            "pkg==01.2",
            "pkg==1.0 --hash=sha256:abc",
            "pkg==1.0 # comment",
            "pkg==1.0\\\n",
            "--index-url https://example.invalid",
            "pkg==1.0\npkg==1.0",
            "pkg==1.0rc1",
        ] {
            assert!(
                pins(text, &mut BTreeMap::new()).is_err(),
                "accepted unsupported input: {text}"
            );
        }
    }

    #[test]
    fn report_must_reconcile_every_exact_package_before_counting() {
        let binding = json!({"expectedPackages":{"six":"1.17.0"}});
        let clean =
            json!({"dependencies":[{"name":"six","version":"1.17.0","vulns":[]}],"fixes":[]});
        assert_eq!(reconcile(&binding, &clean), Some(0));
        let mut positive = clean.clone();
        positive["dependencies"][0]["vulns"] =
            json!([{"id":"GHSA-qualification","fix_versions":[]}]);
        assert_eq!(reconcile(&binding, &positive), Some(1));
        for pointer in [
            "/dependencies/0/name",
            "/dependencies/0/version",
            "/dependencies/0/vulns",
            "/fixes",
        ] {
            let mut broken = clean.clone();
            *broken.pointer_mut(pointer).unwrap() = Value::Null;
            assert_eq!(reconcile(&binding, &broken), None);
        }
        for broken in [
            json!({"dependencies":[],"fixes":[]}),
            json!({"dependencies":[{"name":"six","skip_reason":"not found"}],"fixes":[]}),
            json!({"dependencies":[{"name":"six","version":"1.16.0","vulns":[]}],"fixes":[]}),
            json!({"dependencies":[{"name":"extra","version":"1.17.0","vulns":[]}],"fixes":[]}),
            json!({"dependencies":[{"name":"six","version":"1.17.0","vulns":[]},{"name":"six","version":"1.17.0","vulns":[]}],"fixes":[]}),
        ] {
            assert_eq!(reconcile(&binding, &broken), None);
        }
        let mut skipped = clean.clone();
        skipped["dependencies"][0]["skip_reason"] = Value::Null;
        assert_eq!(reconcile(&binding, &skipped), None);
    }
}
